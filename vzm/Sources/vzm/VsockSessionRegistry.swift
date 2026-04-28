import Foundation

protocol ManagedSession: AnyObject {
    var id: UUID { get }
    func start()
    func close()
}

final class VsockSessionRegistry<Session: ManagedSession>: @unchecked Sendable {
    private var sessions: [UUID: Session] = [:]

    func insertAndStart(_ session: Session) {
        sessions[session.id] = session
        session.start()
    }

    func remove(id: UUID) {
        sessions.removeValue(forKey: id)
    }

    func closeAll() {
        sessions.values.forEach { $0.close() }
        sessions.removeAll()
    }
}
