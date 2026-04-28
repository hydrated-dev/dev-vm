@preconcurrency import AppKit
import Foundation

enum ProxyApprovalDecision {
    case approve
    case deny
    case cancel
}

protocol HTTPSProxyApprovalController: AnyObject {
    func requestApproval(host: String, port: UInt16) -> (UUID, ProxyApprovalDecision)
    func updatePath(requestID: UUID, path: String)
    func finishRequest(requestID: UUID)
    func cancelAllPendingRequests()
}

private final class PendingProxyApproval: @unchecked Sendable {
    let id = UUID()
    let host: String
    let port: UInt16
    let requestedAt = Date()
    let semaphore = DispatchSemaphore(value: 0)

    private let lock = NSLock()
    private var storedDecision: ProxyApprovalDecision?
    private var storedPath: String?

    init(host: String, port: UInt16) {
        self.host = host
        self.port = port
    }

    var destination: String {
        "\(host):\(port)"
    }

    var path: String? {
        lock.lock()
        defer { lock.unlock() }
        return storedPath
    }

    var isResolved: Bool {
        lock.lock()
        defer { lock.unlock() }
        return storedDecision != nil
    }

    func setPath(_ path: String) {
        lock.lock()
        storedPath = path
        lock.unlock()
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

final class MenuBarProxyApprovalController: NSObject, HTTPSProxyApprovalController, @unchecked Sendable {
    var stopRequested: (() -> Void)?

    private let eventHandler: (String) -> Void
    private let lock = NSLock()
    private var pendingRequests: [UUID: PendingProxyApproval] = [:]
    private var orderedRequestIDs: [UUID] = []
    private var statusItem: NSStatusItem?
    private var currentItem: NSMenuItem?
    private var pathItem: NSMenuItem?
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
        currentItem = NSMenuItem(title: "No pending HTTPS requests", action: nil, keyEquivalent: "")
        pathItem = NSMenuItem(title: "Path: unavailable", action: nil, keyEquivalent: "")
        approveItem = NSMenuItem(title: "Approve Current", action: #selector(approveCurrent), keyEquivalent: "a")
        denyItem = NSMenuItem(title: "Deny Current", action: #selector(denyCurrent), keyEquivalent: "d")

        approveItem?.target = self
        denyItem?.target = self
        approveItem?.keyEquivalentModifierMask = [.command]
        denyItem?.keyEquivalentModifierMask = [.command]

        menu.addItem(currentItem!)
        menu.addItem(pathItem!)
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

    func requestApproval(host: String, port: UInt16) -> (UUID, ProxyApprovalDecision) {
        let request = PendingProxyApproval(host: host, port: port)
        lock.lock()
        pendingRequests[request.id] = request
        orderedRequestIDs.append(request.id)
        lock.unlock()

        eventHandler("https proxy pending CONNECT \(request.destination)")
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

    func updatePath(requestID: UUID, path: String) {
        lock.lock()
        let request = pendingRequests[requestID]
        lock.unlock()

        request?.setPath(path)
        DispatchQueue.main.async { [weak self] in
            self?.refreshMenu()
        }
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
            pathItem?.title = "Path: \(request.path ?? "unavailable")"
            approveItem?.isEnabled = count > 0
            denyItem?.isEnabled = count > 0
        } else {
            statusItem?.button?.title = "vzm"
            currentItem?.title = "No pending HTTPS requests"
            currentItem?.isEnabled = false
            pathItem?.title = "Path: unavailable"
            approveItem?.isEnabled = false
            denyItem?.isEnabled = false
        }
    }
}
