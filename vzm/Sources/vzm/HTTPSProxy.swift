import Foundation
import Darwin
import Network
import Security
@preconcurrency import Virtualization

final class HTTPSProxyManager: NSObject, VZVirtioSocketListenerDelegate {
    private let socketDevice: VZVirtioSocketDevice
    private let eventHandler: (String) -> Void
    private let stateQueue = DispatchQueue(label: "vzm.https-proxy")
    private let proxyListener = VZVirtioSocketListener()
    private let caListener = VZVirtioSocketListener()
    private var sessions: [UUID: HTTPSProxySession] = [:]
    private var caConnections: [VZVirtioSocketConnection] = []
    private let caStore: ProxyCAStore
    private let policy: HTTPSProxyPolicy

    init(socketDevice: VZVirtioSocketDevice, eventHandler: @escaping (String) -> Void) throws {
        self.socketDevice = socketDevice
        self.eventHandler = eventHandler
        caStore = try ProxyCAStore()
        policy = HTTPSProxyPolicy(allowedDestinations: Constants.initialHTTPSProxyAllowlist)
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
        stateQueue.sync {
            sessions.values.forEach { $0.close() }
            sessions.removeAll()
            caConnections.forEach { $0.close() }
            caConnections.removeAll()
        }
    }

    func listener(
        _ listener: VZVirtioSocketListener,
        shouldAcceptNewConnection connection: VZVirtioSocketConnection,
        from socketDevice: VZVirtioSocketDevice
    ) -> Bool {
        if listener === caListener {
            stateQueue.async { [weak self] in
                self?.serveCA(connection)
            }
            return true
        }

        stateQueue.async { [weak self] in
            guard let self else {
                connection.close()
                return
            }
            let session = HTTPSProxySession(
                connection: connection,
                caStore: self.caStore,
                policy: self.policy,
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
    private let allowedDestinations: Set<String>

    init(allowedDestinations: Set<String>) {
        self.allowedDestinations = allowedDestinations
    }

    func allows(host: String, port: UInt16) -> Bool {
        allowedDestinations.contains("\(host.lowercased()):\(port)")
    }
}

final class HTTPSProxySession {
    let id = UUID()

    private let connection: VZVirtioSocketConnection
    private let caStore: ProxyCAStore
    private let policy: HTTPSProxyPolicy
    private let eventHandler: (String) -> Void
    private let onClose: (UUID) -> Void
    private var thread: Thread?
    private var closed = false

    init(
        connection: VZVirtioSocketConnection,
        caStore: ProxyCAStore,
        policy: HTTPSProxyPolicy,
        eventHandler: @escaping (String) -> Void,
        onClose: @escaping (UUID) -> Void
    ) {
        self.connection = connection
        self.caStore = caStore
        self.policy = policy
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
            let request = try HTTPConnectRequest.read(from: guestFD)
            guard policy.allows(host: request.host, port: request.port) else {
                eventHandler("https proxy denied CONNECT \(request.host):\(request.port)")
                SocketSupport.writeAll("HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n", to: guestFD)
                return
            }

            SocketSupport.writeAll("HTTP/1.1 200 Connection Established\r\n\r\n", to: guestFD)
            eventHandler("https proxy allowed CONNECT \(request.host):\(request.port)")

            let leafIdentity = try caStore.identity(for: request.host)
            eventHandler("https proxy preparing guest TLS for \(request.host)")
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
            eventHandler("https proxy guest TLS established for \(request.host)")
            let upstreamConnection = try NetworkTLSConnection.connect(host: request.host, port: request.port)
            eventHandler("https proxy upstream TLS established for \(request.host):\(request.port)")
            try NetworkConnectionRelay.relay(left: guestConnection, right: upstreamConnection)
        } catch {
            eventHandler("https proxy session failed: \(error.localizedDescription)")
        }
    }
}

struct HTTPConnectRequest {
    let host: String
    let port: UInt16

    static func read(from fd: Int32) throws -> HTTPConnectRequest {
        var data = Data()
        var byte = UInt8(0)

        while data.count < 16 * 1024 {
            let count = Darwin.read(fd, &byte, 1)
            if count == 0 {
                throw CLIError("proxy client closed before sending CONNECT")
            }
            if count < 0 {
                throw CLIError("proxy read failed: \(String(cString: strerror(errno)))")
            }
            data.append(byte)
            if data.suffix(4) == Data([13, 10, 13, 10]) {
                break
            }
        }

        guard let header = String(data: data, encoding: .utf8) else {
            throw CLIError("proxy request was not valid UTF-8")
        }
        guard let requestLine = header.split(separator: "\r\n", maxSplits: 1).first else {
            throw CLIError("proxy request was empty")
        }
        let parts = requestLine.split(separator: " ")
        guard parts.count >= 3, parts[0].uppercased() == "CONNECT" else {
            throw CLIError("proxy only supports HTTP CONNECT")
        }

        let authority = String(parts[1])
        let split = authority.split(separator: ":", maxSplits: 1)
        guard split.count == 2, let port = UInt16(split[1]) else {
            throw CLIError("CONNECT authority must be host:port")
        }
        let host = split[0].lowercased()
        guard host.range(of: #"^[a-z0-9.-]+$"#, options: .regularExpression) != nil else {
            throw CLIError("CONNECT host contains unsupported characters")
        }
        return HTTPConnectRequest(host: host, port: port)
    }
}

final class ProxyCAStore {
    private static let leafIdentityPassphrase = "vzm-proxy"

    let caCertificatePEM: Data

    private let root: URL
    private let caKey: URL
    private let caCertificate: URL
    private let leafDirectory: URL
    private let fileManager = FileManager.default

    init() throws {
        let appSupport = try fileManager.url(
            for: .applicationSupportDirectory,
            in: .userDomainMask,
            appropriateFor: nil,
            create: true
        )
        root = appSupport.appendingPathComponent("vzm", isDirectory: true)
            .appendingPathComponent("proxy", isDirectory: true)
        caKey = root.appendingPathComponent("ca.key")
        caCertificate = root.appendingPathComponent("ca.pem")
        leafDirectory = root.appendingPathComponent("leaf", isDirectory: true)

        try fileManager.createDirectory(at: leafDirectory, withIntermediateDirectories: true)
        if !fileManager.fileExists(atPath: caKey.path) || !fileManager.fileExists(atPath: caCertificate.path) {
            try Self.runOpenSSL([
                "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                "-keyout", caKey.path,
                "-out", caCertificate.path,
                "-sha256", "-days", "3650",
                "-subj", "/CN=vzm HTTPS Proxy Root CA",
                "-addext", "basicConstraints=critical,CA:TRUE",
                "-addext", "keyUsage=critical,keyCertSign,cRLSign"
            ])
        }
        caCertificatePEM = try Data(contentsOf: caCertificate)
    }

    func identity(for host: String) throws -> ProxyIdentity {
        let safeHost = host.replacingOccurrences(of: ".", with: "_")
        let key = leafDirectory.appendingPathComponent("\(safeHost).key")
        let csr = leafDirectory.appendingPathComponent("\(safeHost).csr")
        let cert = leafDirectory.appendingPathComponent("\(safeHost).pem")
        let ext = leafDirectory.appendingPathComponent("\(safeHost).ext")
        let p12 = leafDirectory.appendingPathComponent("\(safeHost).p12")

        if !fileManager.fileExists(atPath: p12.path) {
            try generateLeafIdentity(host: host, key: key, csr: csr, cert: cert, ext: ext, p12: p12)
        }

        do {
            return try importLeafIdentity(host: host, p12: p12)
        } catch {
            try? fileManager.removeItem(at: key)
            try? fileManager.removeItem(at: csr)
            try? fileManager.removeItem(at: cert)
            try? fileManager.removeItem(at: ext)
            try? fileManager.removeItem(at: p12)
            try generateLeafIdentity(host: host, key: key, csr: csr, cert: cert, ext: ext, p12: p12)
            return try importLeafIdentity(host: host, p12: p12)
        }
    }

    private func generateLeafIdentity(host: String, key: URL, csr: URL, cert: URL, ext: URL, p12: URL) throws {
        try Self.runOpenSSL([
            "req", "-newkey", "rsa:2048", "-nodes",
            "-keyout", key.path,
            "-out", csr.path,
            "-subj", "/CN=\(host)"
        ])
        try """
        subjectAltName=DNS:\(host)
        basicConstraints=critical,CA:FALSE
        keyUsage=critical,digitalSignature,keyEncipherment
        extendedKeyUsage=serverAuth
        """.write(to: ext, atomically: true, encoding: .utf8)
        try Self.runOpenSSL([
            "x509", "-req",
            "-in", csr.path,
            "-CA", caCertificate.path,
            "-CAkey", caKey.path,
            "-CAcreateserial",
            "-out", cert.path,
            "-days", "825",
            "-sha256",
            "-extfile", ext.path
        ])
        try Self.runOpenSSL([
            "pkcs12", "-export",
            "-inkey", key.path,
            "-in", cert.path,
            "-certfile", caCertificate.path,
            "-out", p12.path,
            "-passout", "pass:\(Self.leafIdentityPassphrase)"
        ])
    }

    private func importLeafIdentity(host: String, p12: URL) throws -> ProxyIdentity {
        let data = try Data(contentsOf: p12)
        var items: CFArray?
        let status = SecPKCS12Import(
            data as CFData,
            [kSecImportExportPassphrase: Self.leafIdentityPassphrase] as CFDictionary,
            &items
        )
        guard status == errSecSuccess,
              let item = (items as? [[String: Any]])?.first,
              let identityValue = item[kSecImportItemIdentity as String] else {
            throw CLIError("failed to import generated leaf identity for \(host): \(status)")
        }
        return ProxyIdentity(identity: identityValue as! SecIdentity, caCertificate: try caSecCertificate())
    }

    private func caSecCertificate() throws -> SecCertificate {
        let data = try Data(contentsOf: caCertificate)
        guard let text = String(data: data, encoding: .utf8),
              let body = text
                .replacingOccurrences(of: "-----BEGIN CERTIFICATE-----", with: "")
                .replacingOccurrences(of: "-----END CERTIFICATE-----", with: "")
                .components(separatedBy: .whitespacesAndNewlines)
                .joined()
                .data(using: .utf8),
              let der = Data(base64Encoded: body),
              let certificate = SecCertificateCreateWithData(nil, der as CFData) else {
            throw CLIError("failed to load proxy CA certificate")
        }
        return certificate
    }

    private static func runOpenSSL(_ arguments: [String]) throws {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/openssl")
        process.arguments = arguments
        let errorPipe = Pipe()
        process.standardError = errorPipe
        try process.run()
        process.waitUntilExit()
        guard process.terminationStatus == 0 else {
            let errorData = errorPipe.fileHandleForReading.readDataToEndOfFile()
            let message = String(data: errorData, encoding: .utf8) ?? "openssl failed"
            throw CLIError(message.trimmingCharacters(in: .whitespacesAndNewlines))
        }
    }
}

struct ProxyIdentity {
    let identity: SecIdentity
    let caCertificate: SecCertificate
}

final class LoopbackTLSTerminator {
    let port: UInt16

    private let listener: NWListener
    private let queue = DispatchQueue(label: "vzm.https-proxy.loopback-tls")
    private let acceptedConnection = SynchronizedValue<NWConnection?>(nil)
    private let acceptSemaphore = DispatchSemaphore(value: 0)

    init(identity: ProxyIdentity) throws {
        let tlsOptions = NWProtocolTLS.Options()
        let certificateChain = [identity.caCertificate] as CFArray
        guard let securityIdentity = sec_identity_create_with_certificates(identity.identity, certificateChain) else {
            throw CLIError("failed to create Network.framework TLS identity")
        }
        sec_protocol_options_set_local_identity(tlsOptions.securityProtocolOptions, securityIdentity)
        sec_protocol_options_set_peer_authentication_required(tlsOptions.securityProtocolOptions, false)

        let parameters = NWParameters(tls: tlsOptions, tcp: NWProtocolTCP.Options())
        parameters.acceptLocalOnly = true
        parameters.allowLocalEndpointReuse = false

        listener = try NWListener(using: parameters, on: .any)
        listener.newConnectionLimit = 1

        let readySemaphore = DispatchSemaphore(value: 0)
        let readyError = SynchronizedValue<Error?>(nil)

        listener.stateUpdateHandler = { state in
            switch state {
            case .ready:
                readySemaphore.signal()
            case .failed(let error):
                readyError.set(error)
                readySemaphore.signal()
            default:
                break
            }
        }
        listener.newConnectionHandler = { [acceptedConnection, acceptSemaphore] connection in
            acceptedConnection.set(connection)
            acceptSemaphore.signal()
        }
        listener.start(queue: queue)
        readySemaphore.wait()

        if let readyError = readyError.value {
            throw CLIError("failed to start loopback TLS listener: \(readyError.localizedDescription)")
        }
        guard let listenerPort = listener.port else {
            throw CLIError("loopback TLS listener did not publish a port")
        }
        port = listenerPort.rawValue
    }

    func acceptConnection() throws -> NWConnection {
        acceptSemaphore.wait()
        guard let connection = acceptedConnection.value else {
            throw CLIError("loopback TLS listener did not accept a connection")
        }
        try connection.startAndWait(queue: queue)
        return connection
    }

    func close() {
        acceptedConnection.value?.cancel()
        listener.cancel()
    }
}

enum NetworkTLSConnection {
    static func connect(host: String, port: UInt16) throws -> NWConnection {
        let tlsOptions = NWProtocolTLS.Options()
        sec_protocol_options_set_tls_server_name(tlsOptions.securityProtocolOptions, host)
        let parameters = NWParameters(tls: tlsOptions, tcp: NWProtocolTCP.Options())
        parameters.preferNoProxies = true

        let connection = NWConnection(
            host: NWEndpoint.Host(host),
            port: NWEndpoint.Port(rawValue: port)!,
            using: parameters
        )
        try connection.startAndWait(queue: DispatchQueue(label: "vzm.https-proxy.upstream.\(host)"))
        return connection
    }
}

enum NetworkConnectionRelay {
    static func relay(left: NWConnection, right: NWConnection) throws {
        let group = DispatchGroup()
        let errors = RelayErrorBox()

        @Sendable func record(_ error: Error) {
            errors.record(error)
        }

        group.enter()
        DispatchQueue.global().async {
            defer { group.leave() }
            defer {
                left.cancel()
                right.cancel()
            }
            do {
                try pump(from: left, to: right)
            } catch {
                record(error)
            }
        }

        group.enter()
        DispatchQueue.global().async {
            defer { group.leave() }
            defer {
                left.cancel()
                right.cancel()
            }
            do {
                try pump(from: right, to: left)
            } catch {
                record(error)
            }
        }

        group.wait()
        if let firstError = errors.firstError {
            throw firstError
        }
    }

    private static func pump(from source: NWConnection, to destination: NWConnection) throws {
        while true {
            guard let data = try source.receiveBlocking(maxLength: 16 * 1024) else {
                return
            }
            try destination.sendBlocking(data)
        }
    }
}

final class RawFDRelay {
    private let leftFD: Int32
    private let rightFD: Int32
    private let group = DispatchGroup()

    init(leftFD: Int32, rightFD: Int32) {
        self.leftFD = leftFD
        self.rightFD = rightFD
    }

    func start() {
        group.enter()
        DispatchQueue.global().async { [leftFD, rightFD, group] in
            defer { group.leave() }
            Self.pump(from: leftFD, to: rightFD)
            _ = shutdown(leftFD, SHUT_RDWR)
            _ = shutdown(rightFD, SHUT_RDWR)
        }

        group.enter()
        DispatchQueue.global().async { [leftFD, rightFD, group] in
            defer { group.leave() }
            Self.pump(from: rightFD, to: leftFD)
            _ = shutdown(leftFD, SHUT_RDWR)
            _ = shutdown(rightFD, SHUT_RDWR)
        }
    }

    func close() {
        _ = shutdown(leftFD, SHUT_RDWR)
        _ = shutdown(rightFD, SHUT_RDWR)
        group.wait()
    }

    private static func pump(from sourceFD: Int32, to destinationFD: Int32) {
        var buffer = [UInt8](repeating: 0, count: 16 * 1024)
        while true {
            let bytesRead = read(sourceFD, &buffer, buffer.count)
            if bytesRead <= 0 {
                return
            }

            var totalWritten = 0
            while totalWritten < bytesRead {
                let written = buffer.withUnsafeBytes { bytes in
                    write(destinationFD, bytes.baseAddress!.advanced(by: totalWritten), bytesRead - totalWritten)
                }
                if written <= 0 {
                    return
                }
                totalWritten += written
            }
        }
    }
}

extension NWConnection {
    func startAndWait(queue: DispatchQueue) throws {
        let semaphore = DispatchSemaphore(value: 0)
        let stateBox = SynchronizedValue<NWConnection.State?>(nil)

        stateUpdateHandler = { state in
            switch state {
            case .ready, .failed, .cancelled:
                stateBox.set(state)
                semaphore.signal()
            default:
                break
            }
        }
        start(queue: queue)
        semaphore.wait()

        switch stateBox.value {
        case .ready:
            return
        case .failed(let error):
            throw CLIError("network connection failed: \(error.localizedDescription)")
        case .cancelled:
            throw CLIError("network connection was cancelled")
        default:
            throw CLIError("network connection did not become ready")
        }
    }

    func receiveBlocking(maxLength: Int) throws -> Data? {
        let semaphore = DispatchSemaphore(value: 0)
        let result = SynchronizedValue<Result<Data?, Error>?>(nil)

        receive(minimumIncompleteLength: 1, maximumLength: maxLength) { content, _, isComplete, error in
            if let error {
                result.set(.failure(error))
            } else if let content, !content.isEmpty {
                result.set(.success(content))
            } else if isComplete {
                result.set(.success(nil))
            } else {
                result.set(.success(nil))
            }
            semaphore.signal()
        }
        semaphore.wait()

        switch result.value {
        case .success(let data):
            return data
        case .failure(let error):
            throw error
        case nil:
            throw CLIError("network receive completed without a result")
        }
    }

    func sendBlocking(_ data: Data) throws {
        let semaphore = DispatchSemaphore(value: 0)
        let result = SynchronizedValue<Error?>(nil)

        send(content: data, contentContext: .defaultStream, isComplete: false, completion: .contentProcessed { error in
            result.set(error)
            semaphore.signal()
        })
        semaphore.wait()

        if let error = result.value {
            throw error
        }
    }
}

final class SynchronizedValue<Value>: @unchecked Sendable {
    private let lock = NSLock()
    private var storedValue: Value

    init(_ value: Value) {
        storedValue = value
    }

    var value: Value {
        lock.lock()
        defer { lock.unlock() }
        return storedValue
    }

    func set(_ value: Value) {
        lock.lock()
        storedValue = value
        lock.unlock()
    }
}

private final class RelayErrorBox: @unchecked Sendable {
    private let lock = NSLock()
    private var storedError: Error?

    var firstError: Error? {
        lock.lock()
        defer { lock.unlock() }
        return storedError
    }

    func record(_ error: Error) {
        lock.lock()
        if storedError == nil {
            storedError = error
        }
        lock.unlock()
    }
}
