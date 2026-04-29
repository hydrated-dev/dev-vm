import Darwin
import Foundation

struct ResolvedEndpoint: Sendable {
    let hostname: String
    let port: UInt16
    let family: Int32
    let address: sockaddr_storage
    let addressLength: socklen_t
    let ipAddress: String

    init(hostname: String, port: UInt16, info: addrinfo) throws {
        guard let aiAddr = info.ai_addr else {
            throw CLIError("resolved address for \(hostname):\(port) was missing")
        }
        self.hostname = hostname
        self.port = port
        family = info.ai_family
        addressLength = info.ai_addrlen

        var storage = sockaddr_storage()
        memcpy(&storage, aiAddr, Int(info.ai_addrlen))
        address = storage
        ipAddress = try Self.describeIPAddress(family: info.ai_family, address: storage, addressLength: info.ai_addrlen)
    }

    init(hostname: String, port: UInt16, ipAddress: String) throws {
        self.hostname = hostname
        self.port = port
        self.ipAddress = ipAddress

        var storage = sockaddr_storage()
        if ipAddress.contains(":") {
            var address = sockaddr_in6()
            address.sin6_len = UInt8(MemoryLayout<sockaddr_in6>.size)
            address.sin6_family = sa_family_t(AF_INET6)
            address.sin6_port = port.bigEndian
            let parseStatus = ipAddress.withCString {
                inet_pton(AF_INET6, $0, &address.sin6_addr)
            }
            guard parseStatus == 1 else {
                throw CLIError("invalid IPv6 address '\(ipAddress)'")
            }
            family = AF_INET6
            addressLength = socklen_t(MemoryLayout<sockaddr_in6>.size)
            memcpy(&storage, &address, MemoryLayout<sockaddr_in6>.size)
        } else {
            var address = sockaddr_in()
            address.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
            address.sin_family = sa_family_t(AF_INET)
            address.sin_port = port.bigEndian
            let parseStatus = ipAddress.withCString {
                inet_pton(AF_INET, $0, &address.sin_addr)
            }
            guard parseStatus == 1 else {
                throw CLIError("invalid IPv4 address '\(ipAddress)'")
            }
            family = AF_INET
            addressLength = socklen_t(MemoryLayout<sockaddr_in>.size)
            memcpy(&storage, &address, MemoryLayout<sockaddr_in>.size)
        }
        address = storage
    }

    var description: String {
        "\(ipAddress):\(port)"
    }

    func withSockAddrPointer<Result>(_ body: (UnsafePointer<sockaddr>, socklen_t) throws -> Result) rethrows -> Result {
        var address = self.address
        return try withUnsafePointer(to: &address) {
            try $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                try body($0, addressLength)
            }
        }
    }

    private static func describeIPAddress(family: Int32, address: sockaddr_storage, addressLength: socklen_t) throws -> String {
        var hostBuffer = [CChar](repeating: 0, count: Int(NI_MAXHOST))
        var copy = address
        let status = withUnsafePointer(to: &copy) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                getnameinfo($0, addressLength, &hostBuffer, socklen_t(hostBuffer.count), nil, 0, NI_NUMERICHOST)
            }
        }
        guard status == 0 else {
            throw CLIError("failed to format resolved address: \(String(cString: gai_strerror(status)))")
        }
        guard family == AF_INET || family == AF_INET6 else {
            throw CLIError("unsupported resolved address family \(family)")
        }
        let length = hostBuffer.firstIndex(of: 0) ?? hostBuffer.endIndex
        let bytes = hostBuffer[..<length].map { UInt8(bitPattern: $0) }
        return String(decoding: bytes, as: UTF8.self)
    }
}

enum DestinationSafetyError: Error, LocalizedError {
    case resolutionFailed(host: String, port: UInt16, message: String)
    case noPublicEndpoints(host: String, port: UInt16, blocked: [String])

    var errorDescription: String? {
        switch self {
        case .resolutionFailed(let host, let port, let message):
            return "failed to resolve \(host):\(port): \(message)"
        case .noPublicEndpoints(let host, let port, let blocked):
            if blocked.isEmpty {
                return "\(host):\(port) resolved to no usable public endpoints"
            }
            return "\(host):\(port) resolved only to blocked endpoints: \(blocked.joined(separator: ", "))"
        }
    }
}

enum DestinationResolution {
    struct FilteredEndpoints: Sendable {
        let publicEndpoints: [ResolvedEndpoint]
        let blockedEndpoints: [ResolvedEndpoint]
    }

    static func resolveEndpoints(host: String, port: UInt16) throws -> [ResolvedEndpoint] {
        var hints = addrinfo(
            ai_flags: AI_ADDRCONFIG,
            ai_family: AF_UNSPEC,
            ai_socktype: SOCK_STREAM,
            ai_protocol: IPPROTO_TCP,
            ai_addrlen: 0,
            ai_canonname: nil,
            ai_addr: nil,
            ai_next: nil
        )
        var result: UnsafeMutablePointer<addrinfo>?
        let status = getaddrinfo(host, String(port), &hints, &result)
        guard status == 0, let result else {
            throw DestinationSafetyError.resolutionFailed(
                host: host,
                port: port,
                message: String(cString: gai_strerror(status))
            )
        }
        defer { freeaddrinfo(result) }

        var endpoints: [ResolvedEndpoint] = []
        var seen = Set<String>()
        var cursor: UnsafeMutablePointer<addrinfo>? = result
        while let info = cursor {
            if let endpoint = try? ResolvedEndpoint(hostname: host, port: port, info: info.pointee) {
                let key = "\(endpoint.family)-\(endpoint.ipAddress)-\(endpoint.port)"
                if seen.insert(key).inserted {
                    endpoints.append(endpoint)
                }
            }
            cursor = info.pointee.ai_next
        }
        return endpoints
    }

    static func filterPublicEndpoints(_ endpoints: [ResolvedEndpoint]) -> FilteredEndpoints {
        FilteredEndpoints(
            publicEndpoints: endpoints.filter(isPublicEndpoint),
            blockedEndpoints: endpoints.filter { !isPublicEndpoint($0) }
        )
    }

    static func resolvePublicEndpoints(host: String, port: UInt16) throws -> FilteredEndpoints {
        let endpoints = try resolveEndpoints(host: host, port: port)
        let filtered = filterPublicEndpoints(endpoints)
        guard !filtered.publicEndpoints.isEmpty else {
            throw DestinationSafetyError.noPublicEndpoints(
                host: host,
                port: port,
                blocked: filtered.blockedEndpoints.map(\.ipAddress)
            )
        }
        return filtered
    }

    static func isPublicEndpoint(_ endpoint: ResolvedEndpoint) -> Bool {
        switch endpoint.family {
        case AF_INET:
            return endpoint.withSockAddrPointer { address, _ in
                let ipv4 = UnsafeRawPointer(address).assumingMemoryBound(to: sockaddr_in.self).pointee.sin_addr
                return isPublicIPv4(ipv4)
            }
        case AF_INET6:
            return endpoint.withSockAddrPointer { address, _ in
                let ipv6 = UnsafeRawPointer(address).assumingMemoryBound(to: sockaddr_in6.self).pointee.sin6_addr
                return isPublicIPv6(ipv6)
            }
        default:
            return false
        }
    }

    private static func isPublicIPv4(_ address: in_addr) -> Bool {
        let octets = withUnsafeBytes(of: address.s_addr) { rawBytes in
            Array(rawBytes)
        }
        guard octets.count == 4 else { return false }

        let a = octets[0]
        let b = octets[1]

        if a == 0 { return false }
        if a == 10 { return false }
        if a == 100, (64...127).contains(b) { return false }
        if a == 127 { return false }
        if a == 169, b == 254 { return false }
        if a == 172, (16...31).contains(b) { return false }
        if a == 192, b == 0, octets[2] == 0 { return false }
        if a == 192, b == 0, octets[2] == 2 { return false }
        if a == 192, b == 168 { return false }
        if a == 198, (18...19).contains(b) { return false }
        if a == 198, b == 51, octets[2] == 100 { return false }
        if a == 203, b == 0, octets[2] == 113 { return false }
        if a >= 224 { return false }
        return true
    }

    private static func isPublicIPv6(_ address: in6_addr) -> Bool {
        let octets = withUnsafeBytes(of: address.__u6_addr.__u6_addr8) { rawBytes in
            Array(rawBytes)
        }
        guard octets.count == 16 else { return false }

        if octets.allSatisfy({ $0 == 0 }) { return false }
        if octets.dropLast().allSatisfy({ $0 == 0 }) && octets.last == 1 { return false }
        if octets[0] == 0xfc || octets[0] == 0xfd { return false }
        if octets[0] == 0xfe, (octets[1] & 0xc0) == 0x80 { return false }
        if octets[0] == 0xff { return false }
        if octets[0] == 0xfe, (octets[1] & 0xc0) == 0xc0 { return false }
        if octets[0] == 0x20, octets[1] == 0x01, octets[2] == 0x0d, octets[3] == 0xb8 { return false }

        if octets[0...9].allSatisfy({ $0 == 0 }) && octets[10] == 0xff && octets[11] == 0xff {
            var ipv4 = in_addr()
            withUnsafeMutableBytes(of: &ipv4.s_addr) { rawBytes in
                rawBytes[0] = octets[12]
                rawBytes[1] = octets[13]
                rawBytes[2] = octets[14]
                rawBytes[3] = octets[15]
            }
            return isPublicIPv4(ipv4)
        }

        return true
    }
}
