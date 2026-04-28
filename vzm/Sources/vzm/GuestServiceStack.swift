import Foundation
@preconcurrency import Virtualization

final class GuestServiceStack: @unchecked Sendable {
    private let socketDevice: VZVirtioSocketDevice
    private let virtualMachineQueue: DispatchQueue
    private let config: VMConfig
    private weak var approvalController: ProxyApprovalController?
    private let eventHandler: (String) -> Void

    private var bridge: SSHBridge?
    private var httpsProxy: HTTPSProxyManager?
    private var outboundSSHProxy: OutboundSSHProxyManager?

    init(
        socketDevice: VZVirtioSocketDevice,
        virtualMachineQueue: DispatchQueue,
        config: VMConfig,
        approvalController: ProxyApprovalController?,
        eventHandler: @escaping (String) -> Void
    ) {
        self.socketDevice = socketDevice
        self.virtualMachineQueue = virtualMachineQueue
        self.config = config
        self.approvalController = approvalController
        self.eventHandler = eventHandler
    }

    func start() throws {
        let proxy = try HTTPSProxyManager(
            socketDevice: socketDevice,
            approvalController: approvalController,
            eventHandler: eventHandler
        )
        proxy.start()
        httpsProxy = proxy
        eventHandler("https proxy listening on vsock port \(Constants.hostHTTPSProxyVsockPort)")
        eventHandler("https proxy allowlist: \(Constants.initialHTTPSProxyAllowlist.sorted().joined(separator: ", "))")
        eventHandler("https request allowlist: \(Constants.initialHTTPSRequestAllowlist.sorted().joined(separator: ", "))")

        let outboundSSHProxy = OutboundSSHProxyManager(
            socketDevice: socketDevice,
            approvalController: approvalController,
            eventHandler: eventHandler
        )
        outboundSSHProxy.start()
        self.outboundSSHProxy = outboundSSHProxy
        eventHandler("outbound ssh proxy listening on vsock port \(Constants.hostOutboundSSHVsockPort)")
        eventHandler("outbound ssh proxy allowlist: \(Constants.initialOutboundSSHHost):\(Constants.initialOutboundSSHPort)")

        let bridge = SSHBridge(
            socketDevice: socketDevice,
            virtualMachineQueue: virtualMachineQueue,
            hostPort: config.hostSSHPort,
            eventHandler: eventHandler
        )
        try bridge.start()
        self.bridge = bridge
        eventHandler("ssh bridge listening on 127.0.0.1:\(config.hostSSHPort)")
    }

    func stop() {
        httpsProxy?.stop()
        outboundSSHProxy?.stop()
        bridge?.stop()
    }
}
