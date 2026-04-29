import Darwin
import Foundation
import Network

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
        return try parse(header: header)
    }

    static func parse(header: String) throws -> HTTPConnectRequest {
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

struct HTTPRequestReadResult {
    let request: ParsedHTTPRequest
    let remainingBytes: Data
}

enum HTTPRequestParser {
    static func readNextRequest(
        from connection: NWConnection,
        bufferedData initialData: Data,
        connectHost: String,
        connectPort: UInt16
    ) throws -> HTTPRequestReadResult? {
        var data = initialData
        let headerTerminator = Data([13, 10, 13, 10])

        while data.count < 64 * 1024 {
            if data.starts(with: Data("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".utf8)) {
                throw CLIError("guest attempted HTTP/2 despite proxy HTTP/1.1 ALPN")
            }
            if let headerRange = data.range(of: headerTerminator) {
                let headerEnd = headerRange.lowerBound
                let bodyStartIndex = headerEnd + 4
                let headerBytes = data.prefix(upTo: headerEnd)
                guard let headerText = String(data: headerBytes, encoding: .utf8) else {
                    throw CLIError("HTTP request headers were not valid UTF-8")
                }

                let lines = headerText.components(separatedBy: "\r\n")
                let contentLength = try contentLength(in: lines)
                if headerValue(named: "transfer-encoding", in: lines) != nil {
                    throw CLIError("proxy does not support Transfer-Encoding request bodies")
                }

                let expectedByteCount = bodyStartIndex + (contentLength ?? 0)
                if let contentLength {
                    guard contentLength <= Constants.maxHTTPSProxyBufferedBodyBytes else {
                        throw CLIError("HTTP request body exceeded \(Constants.maxHTTPSProxyBufferedBodyBytes) byte proxy buffering limit")
                    }
                }

                while data.count < expectedByteCount {
                    guard let chunk = try connection.receiveBlocking(maxLength: min(16 * 1024, expectedByteCount - data.count)) else {
                        throw CLIError("guest closed TLS before sending complete HTTP request body")
                    }
                    data.append(chunk)
                }

                let requestBytes = Data(data.prefix(expectedByteCount))
                let remainingBytes = Data(data.dropFirst(expectedByteCount))
                let parsed = try parse(
                    requestBytes,
                    connectHost: connectHost,
                    connectPort: connectPort,
                    contentLengthOverride: contentLength
                )
                return HTTPRequestReadResult(request: parsed, remainingBytes: remainingBytes)
            }

            guard let chunk = try connection.receiveBlocking(maxLength: 16 * 1024) else {
                if data.isEmpty {
                    return nil
                }
                throw CLIError("guest closed TLS before sending HTTP request")
            }
            data.append(chunk)
        }

        throw CLIError("HTTP request headers exceeded 64 KiB")
    }

    static func parse(
        _ data: Data,
        connectHost: String,
        connectPort: UInt16,
        contentLengthOverride: Int? = nil
    ) throws -> ParsedHTTPRequest {
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

        guard requestHost == connectHost.lowercased(), requestPort == connectPort else {
            throw CLIError(
                "HTTP request authority \(requestHost):\(requestPort) did not match CONNECT destination \(connectHost.lowercased()):\(connectPort)"
            )
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
            contentLength: try (contentLengthOverride ?? contentLength(in: lines))
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

    static func secretReferences(in text: String) -> [(range: Range<String.Index>, id: UUID)] {
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

    func preparedForUpstream() throws -> Data {
        guard let headerEnd = bytes.range(of: Data([13, 10, 13, 10]))?.lowerBound else {
            throw CLIError("mutated HTTP request headers were incomplete")
        }
        let bodyStartIndex = headerEnd + 4
        let headerBytes = bytes.prefix(upTo: headerEnd)
        let bodyBytes = bytes.dropFirst(bodyStartIndex)
        guard let headerText = String(data: headerBytes, encoding: .utf8) else {
            throw CLIError("mutated HTTP request headers were not valid UTF-8")
        }

        let lines = headerText.components(separatedBy: "\r\n")
        guard let requestLine = lines.first else {
            throw CLIError("mutated HTTP request line was missing")
        }

        var rewrittenLines = [requestLine]
        var insertedConnectionClose = false
        for line in lines.dropFirst() {
            let parts = line.split(separator: ":", maxSplits: 1)
            guard parts.count == 2 else {
                rewrittenLines.append(line)
                continue
            }

            let headerName = parts[0].trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
            if headerName == "proxy-connection" {
                continue
            }
            if headerName == "connection" {
                rewrittenLines.append("Connection: close")
                insertedConnectionClose = true
                continue
            }
            rewrittenLines.append(line)
        }

        if !insertedConnectionClose {
            rewrittenLines.append("Connection: close")
        }

        var rewritten = Data(rewrittenLines.joined(separator: "\r\n").utf8)
        rewritten.append(Data([13, 10, 13, 10]))
        rewritten.append(bodyBytes)
        return rewritten
    }

    func write(to connection: NWConnection) throws {
        try connection.sendBlocking(preparedForUpstream())
    }
}
