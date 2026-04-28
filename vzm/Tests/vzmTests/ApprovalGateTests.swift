import Foundation
import XCTest
@testable import vzm

final class ApprovalGateTests: XCTestCase {
    func testApprovalGateReturnsRequestIDWhenApproved() throws {
        let controller = MockApprovalController(decision: .approve)
        let gate = ProxyApprovalGate(controller: controller, eventHandler: { _ in })
        let id = try gate.requireApproval(
            request: .outboundSSH(host: "github.com", port: 22),
            logPrefix: "outbound ssh proxy",
            deniedError: CLIError("denied"),
            cancelledError: CLIError("cancelled")
        )

        XCTAssertEqual(id, controller.requestID)
    }

    func testApprovalGateThrowsMappedDeniedError() throws {
        let controller = MockApprovalController(decision: .deny)
        let gate = ProxyApprovalGate(controller: controller, eventHandler: { _ in })

        XCTAssertThrowsError(try gate.requireApproval(
            request: .outboundSSH(host: "github.com", port: 22),
            logPrefix: "outbound ssh proxy",
            deniedError: CLIError("denied"),
            cancelledError: CLIError("cancelled")
        )) { error in
            XCTAssertEqual((error as? CLIError)?.message, "denied")
        }
    }

    func testApprovalGateThrowsMappedCancelledError() throws {
        let controller = MockApprovalController(decision: .cancel)
        let gate = ProxyApprovalGate(controller: controller, eventHandler: { _ in })

        XCTAssertThrowsError(try gate.requireApproval(
            request: .outboundSSH(host: "github.com", port: 22),
            logPrefix: "outbound ssh proxy",
            deniedError: CLIError("denied"),
            cancelledError: CLIError("cancelled")
        )) { error in
            XCTAssertEqual((error as? CLIError)?.message, "cancelled")
        }
    }
}

private final class MockApprovalController: ProxyApprovalController {
    let requestID = UUID()
    let decision: ProxyApprovalDecision

    init(decision: ProxyApprovalDecision) {
        self.decision = decision
    }

    func requestApproval(request: ProxyApprovalRequest) -> (UUID, ProxyApprovalDecision) {
        (requestID, decision)
    }

    func finishRequest(requestID: UUID) {}

    func cancelAllPendingRequests() {}
}
