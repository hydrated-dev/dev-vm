import Foundation
import Dispatch
@preconcurrency import Virtualization

final class VirtualMachineRunner: NSObject, PortForwardingController, @unchecked Sendable {
    private let config: VMConfig
    private let bundle: ValidatedGuestBundle
    private let machineIdentifier: VZGenericMachineIdentifier
    private weak var approvalController: ProxyApprovalController?
    private let eventHandler: (String) -> Void
    private let queue = DispatchQueue(label: "vzm.vm")
    private let signalQueue = DispatchQueue(label: "vzm.signal")

    private var virtualMachine: VZVirtualMachine?
    private var guestServices: GuestServiceStack?
    private var delegateRef: VMDelegate?
    private var sigintSource: DispatchSourceSignal?
    private var sigtermSource: DispatchSourceSignal?
    private let completionSemaphore = DispatchSemaphore(value: 0)
    private var exitError: Error?
    private var consoleInputHandle: FileHandle?
    private var consoleOutputHandle: FileHandle?

    init(
        config: VMConfig,
        bundle: ValidatedGuestBundle,
        machineIdentifier: VZGenericMachineIdentifier,
        approvalController: ProxyApprovalController?,
        eventHandler: @escaping (String) -> Void
    ) {
        self.config = config
        self.bundle = bundle
        self.machineIdentifier = machineIdentifier
        self.approvalController = approvalController
        self.eventHandler = eventHandler
    }

    func run() throws {
        guard VZVirtualMachine.isSupported else {
            throw CLIError("Virtualization is not supported on this host")
        }

        let vmConfiguration = try makeConfiguration()
        let virtualMachine = VZVirtualMachine(configuration: vmConfiguration, queue: queue)
        self.virtualMachine = virtualMachine

        let delegate = VMDelegate(
            didStop: { [weak self] error in
                if let error {
                    self?.eventHandler("guest stopped with error: \(error.localizedDescription)")
                    self?.exitError = error
                } else {
                    self?.eventHandler("guest stopped")
                }
                self?.guestServices?.stop()
                self?.completionSemaphore.signal()
            }
        )
        delegateRef = delegate
        virtualMachine.delegate = delegate

        eventHandler("name: \(config.name)")
        eventHandler("bundle: \(config.bundlePath)")
        eventHandler("root mode: \(config.rootMode.rawValue)")
        eventHandler("root disk: \(config.rootDiskPath)")
        eventHandler("data disk: \(config.dataDiskPath)")
        eventHandler("ssh port: \(config.hostSSHPort)")
        eventHandler("starting virtual machine")

        let startSemaphore = DispatchSemaphore(value: 0)
        let virtualMachineBox = UncheckedSendableBox(virtualMachine)
        queue.async { [weak self] in
            virtualMachineBox.value.start { result in
                switch result {
                case .success:
                    guard let self else {
                        startSemaphore.signal()
                        return
                    }
                    if let socketDevice = virtualMachineBox.value.socketDevices.first as? VZVirtioSocketDevice {
                        do {
                            let guestServices = GuestServiceStack(
                                socketDevice: socketDevice,
                                virtualMachineQueue: self.queue,
                                config: self.config,
                                approvalController: self.approvalController,
                                eventHandler: self.eventHandler
                            )
                            try guestServices.start()
                            self.guestServices = guestServices
                        } catch {
                            self.exitError = error
                            self.eventHandler("startup failure: \(error.localizedDescription)")
                            self.forceStop()
                        }
                    } else {
                        self.exitError = CLIError("virtual machine started without a virtio socket device")
                        self.forceStop()
                    }
                case .failure(let error):
                    self?.exitError = error
                    self?.eventHandler("startup failure: \(error.localizedDescription)")
                }
                startSemaphore.signal()
            }
        }
        startSemaphore.wait()

        if let exitError, virtualMachine.state != .running {
            throw exitError
        }

        installSignalHandlers()
        completionSemaphore.wait()

        if let exitError {
            throw exitError
        }
    }

    func requestShutdown() {
        queue.async { [weak self] in
            guard let self, let virtualMachine = self.virtualMachine else {
                self?.completionSemaphore.signal()
                return
            }

            self.eventHandler("termination requested")
            if virtualMachine.canRequestStop {
                do {
                    try virtualMachine.requestStop()
                    self.eventHandler("requested guest shutdown")
                } catch {
                    self.eventHandler("graceful shutdown request failed: \(error.localizedDescription)")
                }
            }

            self.queue.asyncAfter(deadline: .now() + Constants.shutdownTimeoutSeconds) { [weak self] in
                guard let self, let virtualMachine = self.virtualMachine else { return }
                guard virtualMachine.state != .stopped else { return }
                self.eventHandler("forced termination")
                self.forceStop()
            }
        }
    }

    private func forceStop() {
        guard let virtualMachine else {
            completionSemaphore.signal()
            return
        }

        if virtualMachine.canStop {
            virtualMachine.stop { [weak self] error in
                if let error {
                    self?.exitError = error
                }
                self?.completionSemaphore.signal()
            }
        } else if virtualMachine.state == .stopped || virtualMachine.state == .error {
            completionSemaphore.signal()
        }
    }

    private func installSignalHandlers() {
        signal(SIGINT, SIG_IGN)
        signal(SIGTERM, SIG_IGN)

        let intSource = DispatchSource.makeSignalSource(signal: SIGINT, queue: signalQueue)
        intSource.setEventHandler { [weak self] in
            self?.requestShutdown()
        }
        intSource.resume()
        sigintSource = intSource

        let termSource = DispatchSource.makeSignalSource(signal: SIGTERM, queue: signalQueue)
        termSource.setEventHandler { [weak self] in
            self?.requestShutdown()
        }
        termSource.resume()
        sigtermSource = termSource
    }

    func isPortForwardEnabled(_ port: UInt16) -> Bool {
        queue.sync {
            guestServices?.isPortForwardEnabled(port) ?? false
        }
    }

    func setPortForwardingEnabled(_ enabled: Bool, for port: UInt16) throws {
        let errorBox = SynchronizedValue<Error?>(nil)
        let semaphore = DispatchSemaphore(value: 0)

        queue.async { [weak self] in
            defer { semaphore.signal() }
            guard let self else {
                errorBox.set(CLIError("virtual machine is no longer available"))
                return
            }
            guard let guestServices = self.guestServices else {
                errorBox.set(CLIError("port forwarding is not available until the VM finishes starting"))
                return
            }

            do {
                if enabled {
                    try guestServices.enablePortForwarding(port)
                } else {
                    try guestServices.disablePortForwarding(port)
                }
            } catch {
                errorBox.set(error)
            }
        }

        semaphore.wait()
        if let error = errorBox.value {
            throw error
        }
    }

    private func makeConfiguration() throws -> VZVirtualMachineConfiguration {
        let platform = VZGenericPlatformConfiguration()
        platform.machineIdentifier = machineIdentifier

        let rootDiskAttachment = try VZDiskImageStorageDeviceAttachment(
            url: URL(fileURLWithPath: config.rootDiskPath),
            readOnly: false
        )
        let dataDiskAttachment = try VZDiskImageStorageDeviceAttachment(
            url: URL(fileURLWithPath: config.dataDiskPath),
            readOnly: false
        )
        let bootLoader = VZLinuxBootLoader(kernelURL: bundle.kernelURL)
        bootLoader.initialRamdiskURL = bundle.initrdURL
        bootLoader.commandLine = bundle.manifest.commandLine

        guard let consoleInputHandle = FileHandle(forReadingAtPath: "/dev/null") else {
            throw CLIError("failed to open /dev/null for guest console input")
        }
        let consoleOutputHandle = FileHandle.standardOutput
        self.consoleInputHandle = consoleInputHandle
        self.consoleOutputHandle = consoleOutputHandle

        let consoleAttachment = VZFileHandleSerialPortAttachment(
            fileHandleForReading: consoleInputHandle,
            fileHandleForWriting: consoleOutputHandle
        )
        let consolePort = VZVirtioConsoleDeviceSerialPortConfiguration()
        consolePort.attachment = consoleAttachment

        let vmConfiguration = VZVirtualMachineConfiguration()
        vmConfiguration.bootLoader = bootLoader
        vmConfiguration.platform = platform
        vmConfiguration.memorySize = Constants.defaultMemoryBytes
        vmConfiguration.cpuCount = Constants.defaultCPUCount
        vmConfiguration.storageDevices = [
            VZVirtioBlockDeviceConfiguration(attachment: rootDiskAttachment),
            VZVirtioBlockDeviceConfiguration(attachment: dataDiskAttachment),
        ]
        vmConfiguration.serialPorts = [consolePort]
        vmConfiguration.socketDevices = [VZVirtioSocketDeviceConfiguration()]
        vmConfiguration.entropyDevices = [VZVirtioEntropyDeviceConfiguration()]

        try vmConfiguration.validate()

        return vmConfiguration
    }
}

final class VMDelegate: NSObject, VZVirtualMachineDelegate {
    private let didStopHandler: (Error?) -> Void

    init(didStop: @escaping (Error?) -> Void) {
        didStopHandler = didStop
    }

    func guestDidStop(_ virtualMachine: VZVirtualMachine) {
        didStopHandler(nil)
    }

    func virtualMachine(_ virtualMachine: VZVirtualMachine, didStopWithError error: Error) {
        didStopHandler(error)
    }
}
