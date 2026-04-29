import Foundation
import Darwin
@preconcurrency import Virtualization

final class OutboundSSHProxyManager: NSObject, VZVirtioSocketListenerDelegate, @unchecked Sendable {
    private let socketDevice: VZVirtioSocketDevice
    private weak var approvalController: ProxyApprovalController?
    private let eventHandler: (String) -> Void
    private let stateQueue = DispatchQueue(label: "vzm.outbound-ssh-proxy")
    private let listener = VZVirtioSocketListener()
    private let sessions = VsockSessionRegistry<OutboundSSHProxySession>()

    init(
        socketDevice: VZVirtioSocketDevice,
        approvalController: ProxyApprovalController?,
        eventHandler: @escaping (String) -> Void
    ) {
        self.socketDevice = socketDevice
        self.approvalController = approvalController
        self.eventHandler = eventHandler
        super.init()
        listener.delegate = self
    }

    func start() {
        socketDevice.setSocketListener(listener, forPort: Constants.hostOutboundSSHVsockPort)
    }

    func stop() {
        socketDevice.removeSocketListener(forPort: Constants.hostOutboundSSHVsockPort)
        stateQueue.sync {
            sessions.closeAll()
        }
    }

    func listener(
        _ listener: VZVirtioSocketListener,
        shouldAcceptNewConnection connection: VZVirtioSocketConnection,
        from socketDevice: VZVirtioSocketDevice
    ) -> Bool {
        let connectionBox = UncheckedSendableBox(connection)
        stateQueue.async { [weak self, connectionBox] in
            guard let self else {
                connectionBox.value.close()
                return
            }

            let sessions = self.sessions
            let stateQueue = self.stateQueue
            let session = OutboundSSHProxySession(
                connection: connectionBox.value,
                approvalController: self.approvalController,
                eventHandler: self.eventHandler
            ) { id in
                stateQueue.async {
                    sessions.remove(id: id)
                }
            }
            sessions.insertAndStart(session)
        }
        return true
    }
}

final class OutboundSSHProxySession: ManagedSession, @unchecked Sendable {
    let id = UUID()

    private let connection: VZVirtioSocketConnection
    private weak var approvalController: ProxyApprovalController?
    private let eventHandler: (String) -> Void
    private let onClose: (UUID) -> Void
    private var thread: Thread?
    private var closed = false

    init(
        connection: VZVirtioSocketConnection,
        approvalController: ProxyApprovalController?,
        eventHandler: @escaping (String) -> Void,
        onClose: @escaping (UUID) -> Void
    ) {
        self.connection = connection
        self.approvalController = approvalController
        self.eventHandler = eventHandler
        self.onClose = onClose
    }

    func start() {
        let thread = Thread { [weak self] in
            self?.run()
        }
        self.thread = thread
        thread.start()
    }

    func close() {
        guard !closed else { return }
        closed = true
        connection.close()
        onClose(id)
    }

    private func run() {
        defer { close() }

        do {
            let approvalRequest = ProxyApprovalRequest.outboundSSH(
                host: Constants.initialOutboundSSHHost,
                port: Constants.initialOutboundSSHPort
            )
            let approvalRequestID = try approve(approvalRequest)
            defer {
                approvalController?.finishRequest(requestID: approvalRequestID)
            }

            let resolvedEndpoints = try DestinationResolution.resolvePublicEndpoints(
                host: Constants.initialOutboundSSHHost,
                port: Constants.initialOutboundSSHPort
            )
            logResolution(resolvedEndpoints)

            let upstreamFD = try connectUpstream(using: resolvedEndpoints.publicEndpoints)
            defer {
                SocketSupport.closeQuietly(upstreamFD)
            }

            let relay = RawFDRelay(leftFD: connection.fileDescriptor, rightFD: upstreamFD)
            relay.start()
            relay.wait()
        } catch {
            eventHandler("outbound ssh proxy session failed: \(error.localizedDescription)")
        }
    }

    private func connectUpstream(using endpoints: [ResolvedEndpoint]) throws -> Int32 {
        var lastError: Error?
        for endpoint in endpoints {
            do {
                let fd = try SocketSupport.connectTCP(endpoint: endpoint)
                eventHandler("outbound ssh proxy connected \(Constants.initialOutboundSSHHost):\(Constants.initialOutboundSSHPort) via \(endpoint.ipAddress)")
                return fd
            } catch {
                lastError = error
                eventHandler("outbound ssh proxy connect failed via \(endpoint.ipAddress): \(error.localizedDescription)")
            }
        }
        throw lastError ?? CLIError("outbound ssh proxy had no validated upstream endpoints")
    }

    private func logResolution(_ resolved: DestinationResolution.FilteredEndpoints) {
        if !resolved.blockedEndpoints.isEmpty {
            let blocked = resolved.blockedEndpoints.map(\.ipAddress).sorted().joined(separator: ", ")
            let allowed = resolved.publicEndpoints.map(\.ipAddress).sorted().joined(separator: ", ")
            eventHandler(
                "outbound ssh proxy filtered \(Constants.initialOutboundSSHHost):\(Constants.initialOutboundSSHPort); kept [\(allowed)] blocked [\(blocked)]"
            )
        } else {
            let allowed = resolved.publicEndpoints.map(\.ipAddress).sorted().joined(separator: ", ")
            eventHandler(
                "outbound ssh proxy resolved \(Constants.initialOutboundSSHHost):\(Constants.initialOutboundSSHPort) to [\(allowed)]"
            )
        }
    }

    private func approve(_ request: ProxyApprovalRequest) throws -> UUID {
        try ProxyApprovalGate(controller: approvalController, eventHandler: eventHandler)
            .requireApproval(
                request: request,
                logPrefix: "outbound ssh proxy",
                deniedError: CLIError("outbound ssh request denied by user"),
                cancelledError: CLIError("outbound ssh request cancelled")
            )
    }
}
