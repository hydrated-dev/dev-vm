import Foundation
import XCTest
@testable import vzm

final class ParsingTests: XCTestCase {
    func testDiskSizeParsesBinarySuffixes() throws {
        XCTAssertEqual(try DiskSize(argument: "1k").bytes, 1024)
        XCTAssertEqual(try DiskSize(argument: "2m").bytes, 2 * 1024 * 1024)
        XCTAssertEqual(try DiskSize(argument: "3g").bytes, 3 * 1024 * 1024 * 1024)
    }

    func testConnectRequestParsesAuthority() throws {
        let request = try HTTPConnectRequest.parse(header: "CONNECT Example.COM:443 HTTP/1.1\r\nHost: Example.COM:443\r\n\r\n")
        XCTAssertEqual(request.host, "example.com")
        XCTAssertEqual(request.port, 443)
    }

    func testHTTPRequestParserHandlesOriginForm() throws {
        let data = Data("GET /path?q=1 HTTP/1.1\r\nHost: Example.COM\r\n\r\n".utf8)
        let parsed = try HTTPRequestParser.parse(data, connectHost: "example.com", connectPort: 443)

        XCTAssertEqual(parsed.request.method, "GET")
        XCTAssertEqual(parsed.request.host, "example.com")
        XCTAssertEqual(parsed.request.port, 443)
        XCTAssertEqual(parsed.request.path, "/path?q=1")
        XCTAssertEqual(parsed.request.url, "https://example.com/path?q=1")
    }

    func testHTTPRequestParserHandlesAbsoluteForm() throws {
        let data = Data("POST https://Example.COM:8443/api HTTP/1.1\r\nHost: ignored.test\r\nContent-Length: 4\r\n\r\nbody".utf8)
        let parsed = try HTTPRequestParser.parse(data, connectHost: "example.com", connectPort: 8443)

        XCTAssertEqual(parsed.request.method, "POST")
        XCTAssertEqual(parsed.request.host, "example.com")
        XCTAssertEqual(parsed.request.port, 8443)
        XCTAssertEqual(parsed.request.url, "https://example.com:8443/api")
        XCTAssertEqual(parsed.contentLength, 4)
    }

    func testHTTPRequestParserRejectsOriginFormHostMismatch() throws {
        let data = Data("GET /path HTTP/1.1\r\nHost: allowed.example\r\n\r\n".utf8)

        XCTAssertThrowsError(try HTTPRequestParser.parse(data, connectHost: "attacker.example", connectPort: 443)) { error in
            XCTAssertEqual(
                error.localizedDescription,
                "HTTP request authority allowed.example:443 did not match CONNECT destination attacker.example:443"
            )
        }
    }

    func testHTTPRequestParserRejectsAbsoluteFormAuthorityMismatch() throws {
        let data = Data("POST https://allowed.example/api HTTP/1.1\r\nHost: ignored.test\r\nContent-Length: 4\r\n\r\nbody".utf8)

        XCTAssertThrowsError(try HTTPRequestParser.parse(data, connectHost: "attacker.example", connectPort: 443)) { error in
            XCTAssertEqual(
                error.localizedDescription,
                "HTTP request authority allowed.example:443 did not match CONNECT destination attacker.example:443"
            )
        }
    }

    func testSecretReferenceDetection() throws {
        let id = UUID()
        let references = HTTPRequestMutator.secretReferences(in: "Authorization: Bearer vzm:\(id.uuidString)")

        XCTAssertEqual(references.map(\.id), [id])
    }

    func testHTTPRequestParserRejectsTransferEncodingRequestBodies() throws {
        let data = Data("POST /upload HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding: chunked\r\n\r\n".utf8)

        XCTAssertThrowsError(
            try HTTPRequestParser.parse(data, connectHost: "example.com", connectPort: 443)
        ) { error in
            XCTAssertEqual(error.localizedDescription, "proxy does not support Transfer-Encoding request bodies")
        }
    }

    func testMutatedRequestPreparedForUpstreamForcesConnectionClose() throws {
        let request = MutatedHTTPRequest(
            request: HTTPSProxyRequest(
                method: "GET",
                scheme: "https",
                host: "example.com",
                port: 443,
                path: "/",
                url: "https://example.com/",
                httpVersion: "HTTP/1.1",
                secretNames: []
            ),
            bytes: Data("GET / HTTP/1.1\r\nHost: example.com\r\nConnection: keep-alive\r\nProxy-Connection: keep-alive\r\n\r\n".utf8)
        )

        let prepared = try request.preparedForUpstream()
        let text = try XCTUnwrap(String(data: prepared, encoding: .utf8))
        XCTAssertTrue(text.contains("\r\nConnection: close\r\n"))
        XCTAssertFalse(text.contains("Proxy-Connection:"))
        XCTAssertFalse(text.contains("keep-alive"))
    }
}
