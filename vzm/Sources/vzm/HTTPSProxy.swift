import Foundation
import Darwin
import Network
import Security
@preconcurrency import Virtualization

final class HTTPSProxyManager: NSObject, VZVirtioSocketListenerDelegate, @unchecked Sendable {
    private let socketDevice: VZVirtioSocketDevice
    private let eventHandler: (String) -> Void
    private let stateQueue = DispatchQueue(label: "vzm.https-proxy")
    private let proxyListener = VZVirtioSocketListener()
    private let caListener = VZVirtioSocketListener()
    private var sessions: [UUID: HTTPSProxySession] = [:]
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
        policy = HTTPSProxyPolicy(allowedDestinations: Constants.initialHTTPSProxyAllowlist)
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
                secretStore: self.secretStore,
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
    private let allowedRequests: Set<String>

    init(
        allowedDestinations: Set<String>,
        allowedRequests: Set<String> = Constants.initialHTTPSRequestAllowlist
    ) {
        self.allowedDestinations = allowedDestinations
        self.allowedRequests = allowedRequests
    }

    func allows(host: String, port: UInt16) -> Bool {
        allowedDestinations.contains("\(host.lowercased()):\(port)")
    }

    func allows(request: HTTPSProxyRequest) -> Bool {
        allowedRequests.contains(request.policyKey)
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

final class HTTPSProxySession: @unchecked Sendable {
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

            let initialRequest: ParsedHTTPRequest
            do {
                initialRequest = try HTTPRequestParser.readFirstRequest(
                    from: guestConnection,
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
            let mutatedRequest: MutatedHTTPRequest
            do {
                mutatedRequest = try HTTPRequestMutator(secretStore: secretStore).mutate(initialRequest)
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
            defer {
                if let approvalRequestID {
                    approvalController?.finishRequest(requestID: approvalRequestID)
                }
            }

            let upstreamConnection = try NetworkTLSConnection.connect(host: connectRequest.host, port: connectRequest.port)
            eventHandler("https proxy upstream TLS established for \(connectRequest.host):\(connectRequest.port)")
            try mutatedRequest.write(to: upstreamConnection)
            try NetworkConnectionRelay.relay(left: guestConnection, right: upstreamConnection)
        } catch {
            eventHandler("https proxy session failed: \(error.localizedDescription)")
        }
    }

    private func approve(_ request: HTTPSProxyRequest) throws -> UUID? {
        if policy.allows(request: request) || policy.allows(host: request.host, port: request.port) {
            eventHandler("https proxy allowed \(request.displayName)")
            return nil
        }

        guard let approvalController else {
            throw CLIError("https proxy approval UI unavailable for \(request.displayName)")
        }

        let (requestID, decision) = approvalController.requestApproval(request: .https(request))
        switch decision {
        case .approve:
            eventHandler("https proxy approved \(request.displayName)")
            return requestID
        case .deny:
            eventHandler("https proxy denied \(request.displayName)")
            throw HTTPSProxyDeniedError(status: 403, reason: "Forbidden", message: "request denied by user")
        case .cancel:
            eventHandler("https proxy cancelled \(request.displayName)")
            throw HTTPSProxyDeniedError(status: 503, reason: "Service Unavailable", message: "request cancelled")
        }
    }
}

struct HTTPSProxyDeniedError: Error, LocalizedError {
    let status: Int
    let reason: String
    let message: String

    var errorDescription: String? {
        message
    }

    var responseData: Data {
        let body = "\(status) \(reason)\n"
        var response = "HTTP/1.1 \(status) \(reason)\r\n"
        response += "Content-Type: text/plain\r\n"
        response += "Content-Length: \(body.utf8.count)\r\n"
        response += "Connection: close\r\n"
        response += "\r\n"
        response += body
        return Data(response.utf8)
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

struct ParsedHTTPRequest {
    let request: HTTPSProxyRequest
    let bytes: Data
    let bodyStartIndex: Int
    let contentLength: Int?
}

enum HTTPRequestParser {
    static func readFirstRequest(
        from connection: NWConnection,
        connectHost: String,
        connectPort: UInt16
    ) throws -> ParsedHTTPRequest {
        var data = Data()
        let headerTerminator = Data([13, 10, 13, 10])

        while data.count < 64 * 1024 {
            guard let chunk = try connection.receiveBlocking(maxLength: 16 * 1024) else {
                throw CLIError("guest closed TLS before sending HTTP request")
            }
            data.append(chunk)

            if data.starts(with: Data("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".utf8)) {
                throw CLIError("guest attempted HTTP/2 despite proxy HTTP/1.1 ALPN")
            }
            if data.range(of: headerTerminator) != nil {
                var parsed = try parse(data, connectHost: connectHost, connectPort: connectPort)
                if let contentLength = parsed.contentLength {
                    guard contentLength <= Constants.maxHTTPSProxyBufferedBodyBytes else {
                        throw CLIError("HTTP request body exceeded \(Constants.maxHTTPSProxyBufferedBodyBytes) byte proxy buffering limit")
                    }
                    let expectedByteCount = parsed.bodyStartIndex + contentLength
                    while data.count < expectedByteCount {
                        guard let chunk = try connection.receiveBlocking(maxLength: min(16 * 1024, expectedByteCount - data.count)) else {
                            throw CLIError("guest closed TLS before sending complete HTTP request body")
                        }
                        data.append(chunk)
                    }
                    parsed = try parse(data, connectHost: connectHost, connectPort: connectPort)
                }
                return parsed
            }
        }

        throw CLIError("HTTP request headers exceeded 64 KiB")
    }

    private static func parse(_ data: Data, connectHost: String, connectPort: UInt16) throws -> ParsedHTTPRequest {
        guard let headerEnd = data.range(of: Data([13, 10, 13, 10]))?.lowerBound else {
            throw CLIError("HTTP request headers were incomplete")
        }
        let bodyStartIndex = headerEnd + 4
        let headerBytes = data.prefix(upTo: headerEnd)
        guard let headerText = String(data: headerBytes, encoding: .utf8) else {
            throw CLIError("HTTP request headers were not valid UTF-8")
        }

        let lines = headerText.components(separatedBy: "\r\n")
        guard let requestLine = lines.first, !requestLine.isEmpty else {
            throw CLIError("HTTP request line was empty")
        }

        let parts = requestLine.split(separator: " ", maxSplits: 2).map(String.init)
        guard parts.count == 3 else {
            throw CLIError("HTTP request line was malformed")
        }

        let method = parts[0].uppercased()
        let target = parts[1]
        let version = parts[2].uppercased()
        guard version == "HTTP/1.1" else {
            throw CLIError("proxy only supports HTTP/1.1 after TLS, got \(parts[2])")
        }

        let hostHeader = headerValue(named: "host", in: lines)
        var requestHost = normalizedHost(hostHeader) ?? connectHost
        var requestPort = connectPort
        var scheme = "https"
        let path: String
        let url: String

        if target.lowercased().hasPrefix("https://") || target.lowercased().hasPrefix("http://") {
            guard let components = URLComponents(string: target), let parsedHost = components.host else {
                throw CLIError("absolute HTTP request target was not a valid URL")
            }
            scheme = components.scheme?.lowercased() ?? "https"
            requestHost = parsedHost.lowercased()
            requestPort = UInt16(components.port ?? (scheme == "https" ? 443 : 80))
            let encodedPath = components.percentEncodedPath.isEmpty ? "/" : components.percentEncodedPath
            path = encodedPath + (components.percentEncodedQuery.map { "?\($0)" } ?? "")
            url = "\(scheme)://\(requestHost)\(portSuffix(requestPort, scheme: scheme))\(path)"
        } else if target.hasPrefix("/") {
            path = target
            url = "https://\(requestHost)\(portSuffix(requestPort, scheme: "https"))\(path)"
        } else {
            throw CLIError("HTTP request target must be origin-form or absolute-form")
        }

        let request = HTTPSProxyRequest(
            method: method,
            scheme: scheme,
            host: requestHost.lowercased(),
            port: requestPort,
            path: path,
            url: url,
            httpVersion: version,
            secretNames: []
        )
        return ParsedHTTPRequest(
            request: request,
            bytes: data,
            bodyStartIndex: bodyStartIndex,
            contentLength: try contentLength(in: lines)
        )
    }

    private static func headerValue(named name: String, in lines: [String]) -> String? {
        for line in lines.dropFirst() {
            let parts = line.split(separator: ":", maxSplits: 1)
            guard parts.count == 2, parts[0].lowercased() == name else { continue }
            return parts[1].trimmingCharacters(in: .whitespacesAndNewlines)
        }
        return nil
    }

    private static func normalizedHost(_ value: String?) -> String? {
        guard let value, !value.isEmpty else { return nil }
        if value.hasPrefix("[") {
            return value
        }
        return value.split(separator: ":", maxSplits: 1).first.map { String($0).lowercased() }
    }

    private static func contentLength(in lines: [String]) throws -> Int? {
        guard let value = headerValue(named: "content-length", in: lines) else { return nil }
        guard let contentLength = Int(value), contentLength >= 0 else {
            throw CLIError("invalid Content-Length header")
        }
        return contentLength
    }

    private static func portSuffix(_ port: Int?, scheme: String) -> String {
        guard let port else { return "" }
        return portSuffix(UInt16(port), scheme: scheme)
    }

    private static func portSuffix(_ port: UInt16, scheme: String) -> String {
        if scheme == "https", port == 443 {
            return ""
        }
        if scheme == "http", port == 80 {
            return ""
        }
        return ":\(port)"
    }
}

struct HTTPRequestMutator {
    private static let markerPrefix = Data("vzm:".utf8)

    let secretStore: SecretStore

    func mutate(_ request: ParsedHTTPRequest) throws -> MutatedHTTPRequest {
        guard request.bytes.range(of: Self.markerPrefix) != nil else {
            return MutatedHTTPRequest(request: request.request, bytes: request.bytes)
        }
        guard var text = String(data: request.bytes, encoding: .utf8) else {
            throw CLIError("secret placeholder replacement requires UTF-8 HTTP request bytes")
        }

        let matches = Self.secretReferences(in: text)
        guard !matches.isEmpty else {
            return MutatedHTTPRequest(request: request.request, bytes: request.bytes)
        }

        let uniqueIDs = Array(Set(matches.map(\.id)))
        let secrets = try uniqueIDs.map { try secretStore.get(id: $0) }
        let secretsByID = Dictionary(uniqueKeysWithValues: secrets.map { ($0.id, $0) })
        for secret in secrets {
            guard secret.allows(host: request.request.host) else {
                throw CLIError("secret '\(secret.name)' is not allowed for \(request.request.host)")
            }
        }
        for match in matches.reversed() {
            guard let secret = secretsByID[match.id] else { continue }
            text.replaceSubrange(match.range, with: secret.value)
        }

        let updatedText = try updateContentLength(in: text, original: request)
        guard let bytes = updatedText.data(using: .utf8) else {
            throw CLIError("mutated HTTP request was not valid UTF-8")
        }

        let secretNames = Array(Set(secrets.map(\.name))).sorted()
        let updatedRequest = HTTPSProxyRequest(
            method: request.request.method,
            scheme: request.request.scheme,
            host: request.request.host,
            port: request.request.port,
            path: request.request.path,
            url: request.request.url,
            httpVersion: request.request.httpVersion,
            secretNames: secretNames
        )
        return MutatedHTTPRequest(request: updatedRequest, bytes: bytes)
    }

    private func updateContentLength(in text: String, original request: ParsedHTTPRequest) throws -> String {
        guard request.contentLength != nil else {
            return text
        }
        guard let headerRange = text.range(of: "\r\n\r\n") else {
            throw CLIError("mutated HTTP request headers were incomplete")
        }

        let body = text[headerRange.upperBound...]
        let length = body.data(using: .utf8)?.count ?? body.utf8.count
        let headers = String(text[..<headerRange.lowerBound])
        let lines = headers.components(separatedBy: "\r\n")
        let updatedLines = lines.map { line -> String in
            let parts = line.split(separator: ":", maxSplits: 1)
            guard parts.count == 2, parts[0].lowercased() == "content-length" else {
                return line
            }
            return "\(parts[0]): \(length)"
        }
        return updatedLines.joined(separator: "\r\n") + "\r\n\r\n" + body
    }

    private static func secretReferences(in text: String) -> [(range: Range<String.Index>, id: UUID)] {
        let pattern = #"vzm:([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})"#
        guard let regex = try? NSRegularExpression(pattern: pattern) else { return [] }
        let range = NSRange(text.startIndex..<text.endIndex, in: text)
        return regex.matches(in: text, range: range).compactMap { match in
            guard let fullRange = Range(match.range(at: 0), in: text),
                  let uuidRange = Range(match.range(at: 1), in: text),
                  let id = UUID(uuidString: String(text[uuidRange])) else {
                return nil
            }
            return (range: fullRange, id: id)
        }
    }
}

struct MutatedHTTPRequest {
    let request: HTTPSProxyRequest
    let bytes: Data

    func write(to connection: NWConnection) throws {
        try connection.sendBlocking(bytes)
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
        TLSOptions.forceHTTP11(tlsOptions)

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
        TLSOptions.forceHTTP11(tlsOptions)
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

enum TLSOptions {
    static func forceHTTP11(_ options: NWProtocolTLS.Options) {
        "http/1.1".withCString { protocolName in
            sec_protocol_options_add_tls_application_protocol(options.securityProtocolOptions, protocolName)
        }
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

    func wait() {
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
