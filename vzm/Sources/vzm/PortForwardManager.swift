import Foundation
@preconcurrency import Virtualization

final class PortForwardManager: @unchecked Sendable {
    private let socketDevice: VZVirtioSocketDevice
    private let virtualMachineQueue: DispatchQueue
    private let eventHandler: (String) -> Void
    private let stateQueue = DispatchQueue(label: "vzm.port-forward-manager")
    private var activeForwards: [UInt16: TCPToVsockPortForward] = [:]

    init(
        socketDevice: VZVirtioSocketDevice,
        virtualMachineQueue: DispatchQueue,
        eventHandler: @escaping (String) -> Void
    ) {
        self.socketDevice = socketDevice
        self.virtualMachineQueue = virtualMachineQueue
        self.eventHandler = eventHandler
    }

    func isEnabled(port: UInt16) -> Bool {
        stateQueue.sync {
            activeForwards[port] != nil
        }
    }

    func enable(port: UInt16) throws {
        guard Constants.supportedForwardedTCPPorts.contains(port) else {
            throw CLIError("unsupported forwarded port \(port)")
        }

        if isEnabled(port: port) {
            return
        }

        let forward = TCPToVsockPortForward(
            socketDevice: socketDevice,
            virtualMachineQueue: virtualMachineQueue,
            hostPort: port,
            guestVsockPort: UInt32(port),
            logPrefix: "port forward :\(port)",
            eventHandler: eventHandler
        )
        try forward.start()
        stateQueue.sync {
            activeForwards[port] = forward
        }
        eventHandler("port forward enabled on 127.0.0.1:\(port)")
    }

    func disable(port: UInt16) throws {
        guard Constants.supportedForwardedTCPPorts.contains(port) else {
            throw CLIError("unsupported forwarded port \(port)")
        }

        let forward = stateQueue.sync {
            activeForwards.removeValue(forKey: port)
        }
        guard let forward else {
            return
        }

        forward.stop()
        eventHandler("port forward disabled on 127.0.0.1:\(port)")
    }

    func stop() {
        let portsAndForwards = stateQueue.sync {
            let value = activeForwards
            activeForwards.removeAll()
            return value
        }

        portsAndForwards.values.forEach { $0.stop() }
    }
}
