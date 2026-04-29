@preconcurrency import AppKit
import Foundation

struct RunCommand {
    let store: VMStore

    func run(options: RunOptions) throws {
        guard store.vmExists(options.name) else {
            throw CLIError("VM '\(options.name.rawValue)' does not exist")
        }

        let config = try store.loadConfig(name: options.name)
        let bundle = try store.validateGuestBundle(config.bundlePath)
        let paths = store.paths(for: options.name)
        let machineIdentifier = try store.loadMachineIdentifier(name: options.name)

        let probeFD = try SocketSupport.createListeningSocket(port: config.hostSSHPort)
        SocketSupport.closeQuietly(probeFD)

        let runtimeLock = RuntimeLock(paths: paths)
        try runtimeLock.acquire()
        defer {
            runtimeLock.release()
        }

        let eventHandler: (String) -> Void = { message in
            let output = message.contains("failure") || message.contains("error") ? stderr : stdout
            fputs("\(message)\n", output)
        }

        let approvalController = MenuBarProxyApprovalController(eventHandler: eventHandler)
        MainActor.assumeIsolated {
            approvalController.start()
        }

        let runner = VirtualMachineRunner(
            config: config,
            bundle: bundle,
            machineIdentifier: machineIdentifier,
            approvalController: approvalController,
            eventHandler: eventHandler
        )
        approvalController.portForwardingController = runner
        approvalController.stopRequested = {
            runner.requestShutdown()
        }

        let runError = SynchronizedValue<Error?>(nil)
        DispatchQueue.global(qos: .userInitiated).async {
            do {
                try runner.run()
            } catch {
                runError.set(error)
            }

            Task { @MainActor in
                approvalController.stop()
                NSApplication.shared.stop(nil)
                Self.wakeApplicationEventLoop()
            }
        }

        MainActor.assumeIsolated {
            NSApplication.shared.run()
        }

        if let error = runError.value {
            throw error
        }
    }

    @MainActor
    private static func wakeApplicationEventLoop() {
        guard let event = NSEvent.otherEvent(
            with: .applicationDefined,
            location: .zero,
            modifierFlags: [],
            timestamp: ProcessInfo.processInfo.systemUptime,
            windowNumber: 0,
            context: nil,
            subtype: 0,
            data1: 0,
            data2: 0
        ) else {
            return
        }
        NSApplication.shared.postEvent(event, atStart: false)
    }
}
