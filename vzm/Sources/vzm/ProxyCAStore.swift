import Foundation
import Network
import Security

final class ProxyCAStore {
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
        let keyDER = leafDirectory.appendingPathComponent("\(safeHost).key.der")
        let csr = leafDirectory.appendingPathComponent("\(safeHost).csr")
        let cert = leafDirectory.appendingPathComponent("\(safeHost).pem")
        let certDER = leafDirectory.appendingPathComponent("\(safeHost).der")
        let ext = leafDirectory.appendingPathComponent("\(safeHost).ext")

        if !fileManager.fileExists(atPath: key.path) || !fileManager.fileExists(atPath: cert.path) {
            try generateLeafIdentity(host: host, key: key, keyDER: keyDER, csr: csr, cert: cert, certDER: certDER, ext: ext)
        }

        do {
            return try loadLeafIdentity(host: host, key: key, keyDER: keyDER, cert: cert, certDER: certDER)
        } catch {
            try? fileManager.removeItem(at: key)
            try? fileManager.removeItem(at: keyDER)
            try? fileManager.removeItem(at: csr)
            try? fileManager.removeItem(at: cert)
            try? fileManager.removeItem(at: certDER)
            try? fileManager.removeItem(at: ext)
            try generateLeafIdentity(host: host, key: key, keyDER: keyDER, csr: csr, cert: cert, certDER: certDER, ext: ext)
            return try loadLeafIdentity(host: host, key: key, keyDER: keyDER, cert: cert, certDER: certDER)
        }
    }

    private func generateLeafIdentity(host: String, key: URL, keyDER: URL, csr: URL, cert: URL, certDER: URL, ext: URL) throws {
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
            "rsa",
            "-in", key.path,
            "-outform", "DER",
            "-out", keyDER.path
        ])
        try Self.runOpenSSL([
            "x509",
            "-in", cert.path,
            "-outform", "DER",
            "-out", certDER.path
        ])
    }

    private func loadLeafIdentity(host: String, key: URL, keyDER: URL, cert: URL, certDER: URL) throws -> ProxyIdentity {
        if !fileManager.fileExists(atPath: keyDER.path) {
            try Self.runOpenSSL([
                "rsa",
                "-in", key.path,
                "-outform", "DER",
                "-out", keyDER.path
            ])
        }
        if !fileManager.fileExists(atPath: certDER.path) {
            try Self.runOpenSSL([
                "x509",
                "-in", cert.path,
                "-outform", "DER",
                "-out", certDER.path
            ])
        }

        let keyData = try Data(contentsOf: keyDER)
        var keyError: Unmanaged<CFError>?
        let keyAttributes: [CFString: Any] = [
            kSecAttrKeyType: kSecAttrKeyTypeRSA,
            kSecAttrKeyClass: kSecAttrKeyClassPrivate,
            kSecAttrKeySizeInBits: 2048,
            kSecReturnPersistentRef: false
        ]
        guard let privateKey = SecKeyCreateWithData(keyData as CFData, keyAttributes as CFDictionary, &keyError) else {
            let message = keyError?.takeRetainedValue().localizedDescription ?? "unknown error"
            throw CLIError("failed to load generated leaf private key for \(host): \(message)")
        }

        let certificateData = try Data(contentsOf: certDER)
        guard let certificate = SecCertificateCreateWithData(nil, certificateData as CFData) else {
            throw CLIError("failed to load generated leaf certificate for \(host)")
        }
        guard let identity = SecIdentityCreate(nil, certificate, privateKey) else {
            throw CLIError("failed to create generated leaf identity for \(host)")
        }
        return ProxyIdentity(identity: identity, caCertificate: try caSecCertificate())
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
