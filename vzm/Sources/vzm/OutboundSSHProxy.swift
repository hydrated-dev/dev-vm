import Foundation
import Darwin
@preconcurrency import Virtualization

final class OutboundSSHProxyManager: NSObject, VZVirtioSocketListenerDelegate, @unchecked Sendable {
    private let socketDevice: VZVirtioSocketDevice
    private weak var approvalController: ProxyApprovalController?
    private let eventHandler: (String) -> Void
    private let stateQueue = DispatchQueue(label: "vzm.outbound-ssh-proxy")
    private let listener = VZVirtioSocketListener()
    private var sessions: [UUID: OutboundSSHProxySession] = [:]

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
            sessions.values.forEach { $0.close() }
            sessions.removeAll()
        }
    }

    func listener(
        _ listener: VZVirtioSocketListener,
        shouldAcceptNewConnection connection: VZVirtioSocketConnection,
        from socketDevice: VZVirtioSocketDevice
    ) -> Bool {
        stateQueue.async { [weak self] in
            guard let self else {
                connection.close()
                return
            }

            let session = OutboundSSHProxySession(
                connection: connection,
                approvalController: self.approvalController,
                eventHandler: self.eventHandler
            ) { [weak self] id in
                self?.stateQueue.async {
                    self?.sessions.removeValue(forKey: id)
                }
            }
            self.sessions[session.id] = session
            session.start()
        }
        return true
    }
}

final class OutboundSSHProxySession: @unchecked Sendable {
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

            let upstreamFD = try SocketSupport.connectTCP(
                host: Constants.initialOutboundSSHHost,
                port: Constants.initialOutboundSSHPort
            )
            defer {
                SocketSupport.closeQuietly(upstreamFD)
            }

            eventHandler("outbound ssh proxy connected \(Constants.initialOutboundSSHHost):\(Constants.initialOutboundSSHPort)")
            let relay = RawFDRelay(leftFD: connection.fileDescriptor, rightFD: upstreamFD)
            relay.start()
            relay.wait()
        } catch {
            eventHandler("outbound ssh proxy session failed: \(error.localizedDescription)")
        }
    }

    private func approve(_ request: ProxyApprovalRequest) throws -> UUID {
        guard let approvalController else {
            throw CLIError("outbound ssh approval UI unavailable for \(request.destination)")
        }

        let (requestID, decision) = approvalController.requestApproval(request: request)
        switch decision {
        case .approve:
            eventHandler("outbound ssh proxy approved \(request.destination)")
            return requestID
        case .deny:
            eventHandler("outbound ssh proxy denied \(request.destination)")
            throw CLIError("outbound ssh request denied by user")
        case .cancel:
            eventHandler("outbound ssh proxy cancelled \(request.destination)")
            throw CLIError("outbound ssh request cancelled")
        }
    }
}
