import Dispatch
import Foundation
import Network
import Security

enum NetworkTLSConnection {
    static func connect(hostname: String, endpoint: ResolvedEndpoint) throws -> NWConnection {
        let tlsOptions = NWProtocolTLS.Options()
        sec_protocol_options_set_tls_server_name(tlsOptions.securityProtocolOptions, hostname)
        sec_protocol_options_set_verify_block(tlsOptions.securityProtocolOptions, { _, trust, complete in
            let secTrust = sec_trust_copy_ref(trust).takeRetainedValue()
            let policy = SecPolicyCreateSSL(true, hostname as CFString)
            SecTrustSetPolicies(secTrust, policy)
            complete(SecTrustEvaluateWithError(secTrust, nil))
        }, DispatchQueue.global())
        TLSOptions.forceHTTP11(tlsOptions)
        let parameters = NWParameters(tls: tlsOptions, tcp: NWProtocolTCP.Options())
        parameters.preferNoProxies = true

        let connection = NWConnection(
            host: NWEndpoint.Host(endpoint.ipAddress),
            port: NWEndpoint.Port(rawValue: endpoint.port)!,
            using: parameters
        )
        try connection.startAndWait(queue: DispatchQueue(label: "vzm.https-proxy.upstream.\(hostname).\(endpoint.ipAddress)"))
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

    static func relayResponse(from source: NWConnection, to destination: NWConnection) throws {
        while true {
            guard let data = try source.receiveBlocking(maxLength: 16 * 1024) else {
                return
            }
            try destination.sendBlocking(data)
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
