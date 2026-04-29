import Foundation
import Darwin

enum SocketSupport {
    static func createListeningSocket(port: UInt16) throws -> Int32 {
        let fd = socket(AF_INET, SOCK_STREAM, 0)
        guard fd >= 0 else {
            throw CLIError("failed to create listening socket: \(String(cString: strerror(errno)))")
        }

        var yes: Int32 = 1
        guard setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &yes, socklen_t(MemoryLayout<Int32>.size)) == 0 else {
            let message = String(cString: strerror(errno))
            close(fd)
            throw CLIError("failed to configure listening socket: \(message)")
        }

        var address = sockaddr_in()
        address.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        address.sin_family = sa_family_t(AF_INET)
        address.sin_port = port.bigEndian
        address.sin_addr = in_addr(s_addr: inet_addr("127.0.0.1"))

        let bindResult = withUnsafePointer(to: &address) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                bind(fd, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        }
        guard bindResult == 0 else {
            let message = String(cString: strerror(errno))
            close(fd)
            throw CLIError("failed to bind 127.0.0.1:\(port): \(message)")
        }

        guard listen(fd, SOMAXCONN) == 0 else {
            let message = String(cString: strerror(errno))
            close(fd)
            throw CLIError("failed to listen on 127.0.0.1:\(port): \(message)")
        }

        return fd
    }

    static func setNonBlocking(_ fd: Int32) throws {
        let flags = fcntl(fd, F_GETFL)
        guard flags >= 0, fcntl(fd, F_SETFL, flags | O_NONBLOCK) == 0 else {
            throw CLIError("failed to set nonblocking mode: \(String(cString: strerror(errno)))")
        }
    }

    static func closeQuietly(_ fd: Int32) {
        guard fd >= 0 else { return }
        _ = shutdown(fd, SHUT_RDWR)
        _ = close(fd)
    }

    static func writeAll(_ string: String, to fd: Int32) {
        guard let data = string.data(using: .utf8) else { return }
        data.withUnsafeBytes { bytes in
            guard let baseAddress = bytes.baseAddress else { return }
            var written = 0
            while written < bytes.count {
                let count = write(fd, baseAddress.advanced(by: written), bytes.count - written)
                if count <= 0 {
                    return
                }
                written += count
            }
        }
    }

    static func connectTCP(host: String, port: UInt16) throws -> Int32 {
        let endpoints = try DestinationResolution.resolveEndpoints(host: host, port: port)
        var lastError = "unknown error"
        for endpoint in endpoints {
            do {
                return try connectTCP(endpoint: endpoint)
            } catch {
                lastError = error.localizedDescription
            }
        }
        throw CLIError("failed to connect to \(host):\(port): \(lastError)")
    }

    static func connectTCP(endpoint: ResolvedEndpoint) throws -> Int32 {
        let fd = socket(endpoint.family, SOCK_STREAM, IPPROTO_TCP)
        guard fd >= 0 else {
            throw CLIError("failed to create TCP socket for \(endpoint.description): \(String(cString: strerror(errno)))")
        }

        let connectResult = endpoint.withSockAddrPointer { address, addressLength in
            Darwin.connect(fd, address, addressLength)
        }
        guard connectResult == 0 else {
            let message = String(cString: strerror(errno))
            closeQuietly(fd)
            throw CLIError("failed to connect to \(endpoint.description): \(message)")
        }

        return fd
    }
}
