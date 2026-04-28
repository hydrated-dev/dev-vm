import Foundation

struct ProxyApprovalGate {
    weak var controller: ProxyApprovalController?
    let eventHandler: (String) -> Void

    func requireApproval(
        request: ProxyApprovalRequest,
        logPrefix: String,
        unavailableTarget: String? = nil,
        deniedError: @autoclosure () -> Error,
        cancelledError: @autoclosure () -> Error
    ) throws -> UUID {
        guard let controller else {
            throw CLIError("\(logPrefix) approval UI unavailable for \(unavailableTarget ?? request.destination)")
        }

        let (requestID, decision) = controller.requestApproval(request: request)
        switch decision {
        case .approve:
            eventHandler("\(logPrefix) approved \(request.destination)")
            return requestID
        case .deny:
            eventHandler("\(logPrefix) denied \(request.destination)")
            throw deniedError()
        case .cancel:
            eventHandler("\(logPrefix) cancelled \(request.destination)")
            throw cancelledError()
        }
    }
}
