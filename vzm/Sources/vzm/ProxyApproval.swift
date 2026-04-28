@preconcurrency import AppKit
import Foundation

enum ProxyApprovalDecision {
    case approve
    case deny
    case cancel
}

enum ProxyApprovalKind: Sendable {
    case https
    case ssh
}

struct ProxyApprovalRequest: Sendable {
    let kind: ProxyApprovalKind
    let title: String
    let destination: String
    let detail: String
    let protocolName: String

    static func https(_ request: HTTPSProxyRequest) -> ProxyApprovalRequest {
        ProxyApprovalRequest(
            kind: .https,
            title: request.displayName,
            destination: request.url,
            detail: "URL: \(request.url)",
            protocolName: request.httpVersion
        )
    }

    static func outboundSSH(host: String, port: UInt16) -> ProxyApprovalRequest {
        ProxyApprovalRequest(
            kind: .ssh,
            title: "SSH \(host):\(port)",
            destination: "\(host):\(port)",
            detail: "Destination: \(host):\(port)",
            protocolName: "SSH"
        )
    }
}

protocol ProxyApprovalController: AnyObject {
    func requestApproval(request: ProxyApprovalRequest) -> (UUID, ProxyApprovalDecision)
    func finishRequest(requestID: UUID)
    func cancelAllPendingRequests()
}

private final class PendingProxyApproval: @unchecked Sendable {
    let id = UUID()
    let request: ProxyApprovalRequest
    let requestedAt = Date()
    let semaphore = DispatchSemaphore(value: 0)

    private let lock = NSLock()
    private var storedDecision: ProxyApprovalDecision?

    init(request: ProxyApprovalRequest) {
        self.request = request
    }

    var destination: String {
        request.title
    }

    var isResolved: Bool {
        lock.lock()
        defer { lock.unlock() }
        return storedDecision != nil
    }

    func resolve(_ decision: ProxyApprovalDecision) {
        lock.lock()
        if storedDecision == nil {
            storedDecision = decision
            lock.unlock()
            semaphore.signal()
        } else {
            lock.unlock()
        }
    }

    func waitForDecision() -> ProxyApprovalDecision {
        semaphore.wait()
        lock.lock()
        defer { lock.unlock() }
        return storedDecision ?? .cancel
    }
}

final class MenuBarProxyApprovalController: NSObject, ProxyApprovalController, @unchecked Sendable {
    var stopRequested: (() -> Void)?

    private let eventHandler: (String) -> Void
    private let lock = NSLock()
    private var pendingRequests: [UUID: PendingProxyApproval] = [:]
    private var orderedRequestIDs: [UUID] = []
    private var statusItem: NSStatusItem?
    private var currentItem: NSMenuItem?
    private var urlItem: NSMenuItem?
    private var protocolItem: NSMenuItem?
    private var approveItem: NSMenuItem?
    private var denyItem: NSMenuItem?

    init(eventHandler: @escaping (String) -> Void) {
        self.eventHandler = eventHandler
        super.init()
    }

    func start() {
        precondition(Thread.isMainThread)
        NSApplication.shared.setActivationPolicy(.accessory)

        let statusItem = NSStatusBar.system.statusItem(withLength: NSStatusItem.variableLength)
        statusItem.button?.title = "vzm"

        let menu = NSMenu()
        currentItem = NSMenuItem(title: "No pending proxy requests", action: nil, keyEquivalent: "")
        urlItem = NSMenuItem(title: "Detail: unavailable", action: nil, keyEquivalent: "")
        protocolItem = NSMenuItem(title: "Protocol: unavailable", action: nil, keyEquivalent: "")
        approveItem = NSMenuItem(title: "Approve Current", action: #selector(approveCurrent), keyEquivalent: "a")
        denyItem = NSMenuItem(title: "Deny Current", action: #selector(denyCurrent), keyEquivalent: "d")

        approveItem?.target = self
        denyItem?.target = self
        approveItem?.keyEquivalentModifierMask = [.command]
        denyItem?.keyEquivalentModifierMask = [.command]

        menu.addItem(currentItem!)
        menu.addItem(urlItem!)
        menu.addItem(protocolItem!)
        menu.addItem(.separator())
        menu.addItem(approveItem!)
        menu.addItem(denyItem!)
        menu.addItem(.separator())

        let stopItem = NSMenuItem(title: "Stop VM", action: #selector(stopVM), keyEquivalent: "q")
        stopItem.target = self
        stopItem.keyEquivalentModifierMask = [.command]
        menu.addItem(stopItem)

        statusItem.menu = menu
        self.statusItem = statusItem
        refreshMenu()
    }

    func stop() {
        cancelAllPendingRequests()
        DispatchQueue.main.async { [weak self] in
            guard let self, let statusItem = self.statusItem else { return }
            NSStatusBar.system.removeStatusItem(statusItem)
            self.statusItem = nil
        }
    }

    func requestApproval(request proxyRequest: ProxyApprovalRequest) -> (UUID, ProxyApprovalDecision) {
        let request = PendingProxyApproval(request: proxyRequest)
        lock.lock()
        pendingRequests[request.id] = request
        orderedRequestIDs.append(request.id)
        lock.unlock()

        switch proxyRequest.kind {
        case .https:
            eventHandler("https proxy pending \(request.destination)")
        case .ssh:
            eventHandler("outbound ssh proxy pending \(request.destination)")
        }
        DispatchQueue.main.async { [weak self] in
            self?.refreshMenu()
        }

        let decision = request.waitForDecision()

        if decision != .approve {
            removeRequest(id: request.id)
        }

        DispatchQueue.main.async { [weak self] in
            self?.refreshMenu()
        }
        return (request.id, decision)
    }

    func finishRequest(requestID: UUID) {
        removeRequest(id: requestID)
        DispatchQueue.main.async { [weak self] in
            self?.refreshMenu()
        }
    }

    func cancelAllPendingRequests() {
        lock.lock()
        let requests = Array(pendingRequests.values)
        lock.unlock()
        requests.forEach { $0.resolve(.cancel) }
    }

    @objc private func approveCurrent() {
        resolveCurrent(.approve)
    }

    @objc private func denyCurrent() {
        resolveCurrent(.deny)
    }

    @objc private func stopVM() {
        stopRequested?()
    }

    private func resolveCurrent(_ decision: ProxyApprovalDecision) {
        guard let request = currentRequest() else { return }
        request.resolve(decision)
    }

    private func currentRequest() -> PendingProxyApproval? {
        lock.lock()
        defer { lock.unlock() }
        guard let id = orderedRequestIDs.first(where: { pendingRequests[$0]?.isResolved == false }) else { return nil }
        return pendingRequests[id]
    }

    private func visibleRequest() -> PendingProxyApproval? {
        lock.lock()
        defer { lock.unlock() }
        guard let id = orderedRequestIDs.first else { return nil }
        return pendingRequests[id]
    }

    private func pendingCount() -> Int {
        lock.lock()
        defer { lock.unlock() }
        return pendingRequests.values.filter { !$0.isResolved }.count
    }

    private func removeRequest(id: UUID) {
        lock.lock()
        pendingRequests.removeValue(forKey: id)
        orderedRequestIDs.removeAll { $0 == id }
        lock.unlock()
    }

    private func refreshMenu() {
        precondition(Thread.isMainThread)
        let request = visibleRequest()
        let count = pendingCount()

        if let request {
            statusItem?.button?.title = count > 1 ? "vzm \(count)!" : (count == 1 ? "vzm !" : "vzm")
            currentItem?.title = request.isResolved ? "Approved: \(request.destination)" : "Pending: \(request.destination)"
            currentItem?.isEnabled = false
            urlItem?.title = request.request.detail
            protocolItem?.title = "Protocol: \(request.request.protocolName)"
            approveItem?.isEnabled = count > 0
            denyItem?.isEnabled = count > 0
        } else {
            statusItem?.button?.title = "vzm"
            currentItem?.title = "No pending proxy requests"
            currentItem?.isEnabled = false
            urlItem?.title = "Detail: unavailable"
            protocolItem?.title = "Protocol: unavailable"
            approveItem?.isEnabled = false
            denyItem?.isEnabled = false
        }
    }
}
