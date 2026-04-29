import Foundation
import Darwin
import Network
@preconcurrency import Virtualization

final class HTTPSProxyManager: NSObject, VZVirtioSocketListenerDelegate, @unchecked Sendable {
    private let socketDevice: VZVirtioSocketDevice
    private let eventHandler: (String) -> Void
    private let stateQueue = DispatchQueue(label: "vzm.https-proxy")
    private let proxyListener = VZVirtioSocketListener()
    private let caListener = VZVirtioSocketListener()
    private let sessions = VsockSessionRegistry<HTTPSProxySession>()
    private var caConnections: [VZVirtioSocketConnection] = []
    private let caStore: ProxyCAStore
    private let policy: HTTPSProxyPolicy
    private let secretStore: SecretStore
    private weak var approvalController: ProxyApprovalController?

    init(
        socketDevice: VZVirtioSocketDevice,
        approvalController: ProxyApprovalController?,
        eventHandler: @escaping (String) -> Void
    ) throws {
        self.socketDevice = socketDevice
        self.approvalController = approvalController
        self.eventHandler = eventHandler
        caStore = try ProxyCAStore()
        policy = HTTPSProxyPolicy()
        secretStore = SecretStore()
        super.init()
        proxyListener.delegate = self
        caListener.delegate = self
    }

    func start() {
        socketDevice.setSocketListener(proxyListener, forPort: Constants.hostHTTPSProxyVsockPort)
        socketDevice.setSocketListener(caListener, forPort: Constants.hostHTTPSProxyCAPort)
    }

    func stop() {
        socketDevice.removeSocketListener(forPort: Constants.hostHTTPSProxyVsockPort)
        socketDevice.removeSocketListener(forPort: Constants.hostHTTPSProxyCAPort)
        approvalController?.cancelAllPendingRequests()
        stateQueue.sync {
            sessions.closeAll()
            caConnections.forEach { $0.close() }
            caConnections.removeAll()
        }
    }

    func listener(
        _ listener: VZVirtioSocketListener,
        shouldAcceptNewConnection connection: VZVirtioSocketConnection,
        from socketDevice: VZVirtioSocketDevice
    ) -> Bool {
        let connectionBox = UncheckedSendableBox(connection)
        if listener === caListener {
            stateQueue.async { [weak self, connectionBox] in
                self?.serveCA(connectionBox.value)
            }
            return true
        }

        stateQueue.async { [weak self, connectionBox] in
            guard let self else {
                connectionBox.value.close()
                return
            }
            let sessions = self.sessions
            let stateQueue = self.stateQueue
            let session = HTTPSProxySession(
                connection: connectionBox.value,
                caStore: self.caStore,
                policy: self.policy,
                secretStore: self.secretStore,
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

    private func serveCA(_ connection: VZVirtioSocketConnection) {
        caConnections.append(connection)
        let fd = connection.fileDescriptor
        _ = caStore.caCertificatePEM.withUnsafeBytes { bytes in
            write(fd, bytes.baseAddress, bytes.count)
        }
        connection.close()
        caConnections.removeAll { $0 === connection }
    }
}

struct HTTPSProxyPolicy {
    private let allowedRequests: Set<String>

    init(allowedRequests: Set<String> = Constants.initialHTTPSRequestAllowlist) {
        self.allowedRequests = allowedRequests
    }

    // Requests using secrets always require approval, even if the URL is allowlisted.
    func allowsRequestWithoutPrompt(_ request: HTTPSProxyRequest) -> Bool {
        allowedRequests.contains(request.policyKey) && request.secretNames.isEmpty
    }
}

struct HTTPSProxyRequest: Sendable {
    let method: String
    let scheme: String
    let host: String
    let port: UInt16
    let path: String
    let url: String
    let httpVersion: String
    let secretNames: [String]

    var policyKey: String {
        "\(method.uppercased()) \(url)"
    }

    var displayName: String {
        "\(method.uppercased()) \(url)"
    }
}

final class HTTPSProxySession: ManagedSession, @unchecked Sendable {
    let id = UUID()

    private let connection: VZVirtioSocketConnection
    private let caStore: ProxyCAStore
    private let policy: HTTPSProxyPolicy
    private let secretStore: SecretStore
    private weak var approvalController: ProxyApprovalController?
    private let eventHandler: (String) -> Void
    private let onClose: (UUID) -> Void
    private var thread: Thread?
    private var closed = false

    init(
        connection: VZVirtioSocketConnection,
        caStore: ProxyCAStore,
        policy: HTTPSProxyPolicy,
        secretStore: SecretStore,
        approvalController: ProxyApprovalController?,
        eventHandler: @escaping (String) -> Void,
        onClose: @escaping (UUID) -> Void
    ) {
        self.connection = connection
        self.caStore = caStore
        self.policy = policy
        self.secretStore = secretStore
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
        let guestFD = connection.fileDescriptor

        do {
            let connectRequest = try HTTPConnectRequest.read(from: guestFD)

            SocketSupport.writeAll("HTTP/1.1 200 Connection Established\r\n\r\n", to: guestFD)
            eventHandler("https proxy accepted CONNECT \(connectRequest.host):\(connectRequest.port)")

            let leafIdentity = try caStore.identity(for: connectRequest.host)
            eventHandler("https proxy preparing guest TLS for \(connectRequest.host)")
            let guestTLS = try LoopbackTLSTerminator(identity: leafIdentity)
            defer { guestTLS.close() }

            eventHandler("https proxy bridging guest TLS on 127.0.0.1:\(guestTLS.port)")
            let loopbackFD = try SocketSupport.connectTCP(host: "127.0.0.1", port: guestTLS.port)
            let rawBridge = RawFDRelay(leftFD: guestFD, rightFD: loopbackFD)
            rawBridge.start()
            defer {
                rawBridge.close()
                SocketSupport.closeQuietly(loopbackFD)
            }

            let guestConnection = try guestTLS.acceptConnection()
            eventHandler("https proxy guest TLS established for \(connectRequest.host)")

            var bufferedGuestData = Data()
            requestLoop: while true {
                let nextRequest: HTTPRequestReadResult?
                do {
                    nextRequest = try HTTPRequestParser.readNextRequest(
                        from: guestConnection,
                        bufferedData: bufferedGuestData,
                        connectHost: connectRequest.host,
                        connectPort: connectRequest.port
                    )
                } catch {
                    let rejected = HTTPSProxyDeniedError(
                        status: 505,
                        reason: "HTTP Version Not Supported",
                        message: error.localizedDescription
                    )
                    try? guestConnection.sendBlocking(rejected.responseData)
                    throw error
                }

                guard let nextRequest else {
                    break requestLoop
                }
                bufferedGuestData = nextRequest.remainingBytes

                let mutatedRequest: MutatedHTTPRequest
                do {
                    mutatedRequest = try HTTPRequestMutator(secretStore: secretStore).mutate(nextRequest.request)
                } catch {
                    let rejected = HTTPSProxyDeniedError(
                        status: 502,
                        reason: "Bad Gateway",
                        message: error.localizedDescription
                    )
                    try? guestConnection.sendBlocking(rejected.responseData)
                    throw error
                }

                let approvalRequestID: UUID?
                do {
                    approvalRequestID = try approve(mutatedRequest.request)
                } catch let denied as HTTPSProxyDeniedError {
                    try? guestConnection.sendBlocking(denied.responseData)
                    throw denied
                }

                do {
                    defer {
                        if let approvalRequestID {
                            approvalController?.finishRequest(requestID: approvalRequestID)
                        }
                    }

                    let resolvedEndpoints = try resolveApprovedDestination(
                        host: connectRequest.host,
                        port: connectRequest.port
                    )
                    let upstreamConnection = try connectUpstream(
                        hostname: connectRequest.host,
                        port: connectRequest.port,
                        resolvedEndpoints: resolvedEndpoints
                    )
                    defer { upstreamConnection.cancel() }
                    try mutatedRequest.write(to: upstreamConnection)
                    try NetworkConnectionRelay.relayResponse(from: upstreamConnection, to: guestConnection)
                } catch let denied as HTTPSProxyDeniedError {
                    try? guestConnection.sendBlocking(denied.responseData)
                    throw denied
                }
            }
        } catch {
            eventHandler("https proxy session failed: \(error.localizedDescription)")
        }
    }

    // This is intentionally called only after request approval so no DNS or upstream
    // connection metadata can leave the host before approval.
    private func resolveApprovedDestination(host: String, port: UInt16) throws -> DestinationResolution.FilteredEndpoints {
        do {
            let resolved = try DestinationResolution.resolvePublicEndpoints(host: host, port: port)
            logResolution(host: host, port: port, resolved: resolved)
            return resolved
        } catch let error as DestinationSafetyError {
            eventHandler("https proxy blocked upstream \(host):\(port): \(error.localizedDescription)")
            throw HTTPSProxyDeniedError(
                status: blockedUpstreamStatus(for: error),
                reason: blockedUpstreamStatus(for: error) == 403 ? "Forbidden" : "Bad Gateway",
                message: "upstream destination was not allowed"
            )
        }
    }

    private func logResolution(
        host: String,
        port: UInt16,
        resolved: DestinationResolution.FilteredEndpoints
    ) {
        if !resolved.blockedEndpoints.isEmpty {
            let blocked = resolved.blockedEndpoints.map(\.ipAddress).sorted().joined(separator: ", ")
            let allowed = resolved.publicEndpoints.map(\.ipAddress).sorted().joined(separator: ", ")
            eventHandler(
                "https proxy filtered upstream \(host):\(port); kept [\(allowed)] blocked [\(blocked)]"
            )
        } else {
            let allowed = resolved.publicEndpoints.map(\.ipAddress).sorted().joined(separator: ", ")
            eventHandler("https proxy resolved upstream \(host):\(port) to [\(allowed)]")
        }
    }

    private func connectUpstream(
        hostname: String,
        port: UInt16,
        resolvedEndpoints: DestinationResolution.FilteredEndpoints
    ) throws -> NWConnection {
        var lastError: Error?
        for endpoint in resolvedEndpoints.publicEndpoints {
            do {
                let connection = try NetworkTLSConnection.connect(hostname: hostname, endpoint: endpoint)
                eventHandler("https proxy upstream TLS established for \(hostname):\(port) via \(endpoint.ipAddress)")
                return connection
            } catch {
                lastError = error
                eventHandler("https proxy upstream connect failed for \(hostname):\(port) via \(endpoint.ipAddress): \(error.localizedDescription)")
            }
        }
        throw lastError ?? CLIError("failed to connect to any validated endpoint for \(hostname):\(port)")
    }

    private func blockedUpstreamStatus(for error: DestinationSafetyError) -> Int {
        switch error {
        case .noPublicEndpoints:
            return 403
        case .resolutionFailed:
            return 502
        }
    }

    private func approve(_ request: HTTPSProxyRequest) throws -> UUID? {
        if policy.allowsRequestWithoutPrompt(request) {
            eventHandler("https proxy allowed \(request.displayName)")
            return nil
        }

        if !request.secretNames.isEmpty {
            eventHandler("https proxy request uses secrets \(request.secretNames.joined(separator: ", ")) for \(request.displayName)")
        }

        guard let approvalController else {
            throw CLIError("https proxy approval UI unavailable for \(request.displayName)")
        }

        return try ProxyApprovalGate(controller: approvalController, eventHandler: eventHandler)
            .requireApproval(
                request: .https(request),
                logPrefix: "https proxy",
                unavailableTarget: request.displayName,
                deniedError: HTTPSProxyDeniedError(status: 403, reason: "Forbidden", message: "request denied by user"),
                cancelledError: HTTPSProxyDeniedError(status: 503, reason: "Service Unavailable", message: "request cancelled")
            )
    }
}
