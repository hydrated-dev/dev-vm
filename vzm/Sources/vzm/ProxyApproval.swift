@preconcurrency import AppKit
import Carbon
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
    let usesSecret: Bool
    let secretNames: [String]

    static func https(_ request: HTTPSProxyRequest) -> ProxyApprovalRequest {
        ProxyApprovalRequest(
            kind: .https,
            title: request.displayName,
            destination: request.url,
            detail: "URL: \(request.url)",
            protocolName: request.httpVersion,
            usesSecret: !request.secretNames.isEmpty,
            secretNames: request.secretNames
        )
    }

    static func outboundSSH(host: String, port: UInt16) -> ProxyApprovalRequest {
        ProxyApprovalRequest(
            kind: .ssh,
            title: "SSH \(host):\(port)",
            destination: "\(host):\(port)",
            detail: "Destination: \(host):\(port)",
            protocolName: "SSH",
            usesSecret: false,
            secretNames: []
        )
    }

    var menuBarTitle: String {
        switch kind {
        case .https:
            return "HTTPS \(abbreviatedHTTPSDestination())"
        case .ssh:
            return "SSH \(destination)"
        }
    }

    private func abbreviatedHTTPSDestination() -> String {
        guard let components = URLComponents(string: destination), let host = components.host else {
            return destination.truncatedForMenuBar(maxLength: 42)
        }

        let path = components.percentEncodedPath
        guard !path.isEmpty, path != "/" else {
            return host
        }

        return "\(host)\(path)".truncatedForMenuBar(maxLength: 42)
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
    private var hotKeys: ProxyApprovalHotKeys?

    init(eventHandler: @escaping (String) -> Void) {
        self.eventHandler = eventHandler
        super.init()
    }

    @MainActor
    func start() {
        precondition(Thread.isMainThread)
        NSApplication.shared.setActivationPolicy(.accessory)

        let statusItem = NSStatusBar.system.statusItem(withLength: NSStatusItem.variableLength)
        statusItem.button?.title = "vzm"

        let menu = NSMenu()
        currentItem = NSMenuItem(title: "No pending proxy requests", action: nil, keyEquivalent: "")
        urlItem = NSMenuItem(title: "Detail: unavailable", action: nil, keyEquivalent: "")
        protocolItem = NSMenuItem(title: "Protocol: unavailable", action: nil, keyEquivalent: "")
        approveItem = NSMenuItem(title: "Approve Current (Cmd+Shift+9)", action: #selector(approveCurrent), keyEquivalent: "a")
        denyItem = NSMenuItem(title: "Deny Current (Cmd+Shift+0)", action: #selector(denyCurrent), keyEquivalent: "d")

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
        installHotKeys()
        refreshMenu()
    }

    func stop() {
        cancelAllPendingRequests()
        Task { @MainActor [weak self] in
            guard let self, let statusItem = self.statusItem else { return }
            self.hotKeys?.stop()
            self.hotKeys = nil
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
        Task { @MainActor [weak self] in
            self?.refreshMenu()
        }

        let decision = request.waitForDecision()

        if decision != .approve {
            removeRequest(id: request.id)
        }

        Task { @MainActor [weak self] in
            self?.refreshMenu()
        }
        return (request.id, decision)
    }

    func finishRequest(requestID: UUID) {
        removeRequest(id: requestID)
        Task { @MainActor [weak self] in
            self?.refreshMenu()
        }
    }

    func cancelAllPendingRequests() {
        lock.lock()
        let requests = Array(pendingRequests.values)
        lock.unlock()
        requests.forEach { $0.resolve(.cancel) }
    }

    @MainActor
    @objc private func approveCurrent() {
        resolveCurrent(.approve)
    }

    @MainActor
    @objc private func denyCurrent() {
        resolveCurrent(.deny)
    }

    @MainActor
    @objc private func stopVM() {
        stopRequested?()
    }

    @MainActor
    private func installHotKeys() {
        let hotKeys = ProxyApprovalHotKeys(
            approve: { [weak self] in
                Task { @MainActor in
                    self?.resolveCurrent(.approve)
                }
            },
            deny: { [weak self] in
                Task { @MainActor in
                    self?.resolveCurrent(.deny)
                }
            }
        )

        do {
            try hotKeys.start()
            self.hotKeys = hotKeys
        } catch {
            eventHandler("proxy approval global hotkeys unavailable: \(error)")
        }
    }

    @MainActor
    private func resolveCurrent(_ decision: ProxyApprovalDecision) {
        guard let request = currentRequest() else { return }
        request.resolve(decision)
        refreshMenu()
    }

    private func currentRequest() -> PendingProxyApproval? {
        lock.lock()
        defer { lock.unlock() }
        guard let id = orderedRequestIDs.first(where: { pendingRequests[$0]?.isResolved == false }) else { return nil }
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

    @MainActor
    private func refreshMenu() {
        precondition(Thread.isMainThread)
        let request = currentRequest()
        let count = pendingCount()

        if let request {
            let countPrefix = count > 1 ? "(\(count)) " : ""
            let secretPrefix = request.request.usesSecret ? "⚠ " : ""
            statusItem?.button?.title = "vzm \(countPrefix)\(secretPrefix)\(request.request.menuBarTitle)"
            currentItem?.title = "Pending: \(request.destination)"
            currentItem?.isEnabled = false
            urlItem?.title = request.request.detail
            if request.request.usesSecret {
                protocolItem?.title = "Secret used: \(request.request.secretNames.joined(separator: ", "))"
            } else {
                protocolItem?.title = "Protocol: \(request.request.protocolName)"
            }
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

private final class ProxyApprovalHotKeys: @unchecked Sendable {
    private enum HotKeyID: UInt32, Sendable {
        case approve = 1
        case deny = 2
    }

    private let approve: @Sendable () -> Void
    private let deny: @Sendable () -> Void
    private var handlerRef: EventHandlerRef?
    private var hotKeyRefs: [EventHotKeyRef] = []

    init(approve: @escaping @Sendable () -> Void, deny: @escaping @Sendable () -> Void) {
        self.approve = approve
        self.deny = deny
    }

    deinit {
        stop()
    }

    func start() throws {
        var eventType = EventTypeSpec(eventClass: OSType(kEventClassKeyboard), eventKind: UInt32(kEventHotKeyPressed))
        let installStatus = InstallEventHandler(
            GetApplicationEventTarget(),
            { _, event, userData in
                guard let event, let userData else {
                    return OSStatus(eventNotHandledErr)
                }

                var hotKeyID = EventHotKeyID()
                let status = GetEventParameter(
                    event,
                    EventParamName(kEventParamDirectObject),
                    EventParamType(typeEventHotKeyID),
                    nil,
                    MemoryLayout<EventHotKeyID>.size,
                    nil,
                    &hotKeyID
                )
                guard status == noErr else {
                    return status
                }

                let hotKeys = Unmanaged<ProxyApprovalHotKeys>.fromOpaque(userData).takeUnretainedValue()
                hotKeys.handle(id: hotKeyID.id)
                return noErr
            },
            1,
            &eventType,
            Unmanaged.passUnretained(self).toOpaque(),
            &handlerRef
        )
        guard installStatus == noErr else {
            throw CLIError("failed to install hotkey handler: \(installStatus)")
        }

        do {
            try register(keyCode: UInt32(kVK_ANSI_9), modifiers: UInt32(cmdKey | shiftKey), id: .approve)
            try register(keyCode: UInt32(kVK_ANSI_0), modifiers: UInt32(cmdKey | shiftKey), id: .deny)
        } catch {
            stop()
            throw error
        }
    }

    func stop() {
        hotKeyRefs.forEach { UnregisterEventHotKey($0) }
        hotKeyRefs.removeAll()

        if let handlerRef {
            RemoveEventHandler(handlerRef)
            self.handlerRef = nil
        }
    }

    private func register(keyCode: UInt32, modifiers: UInt32, id: HotKeyID) throws {
        let hotKeyID = EventHotKeyID(signature: Self.signature, id: id.rawValue)
        var hotKeyRef: EventHotKeyRef?
        let status = RegisterEventHotKey(
            keyCode,
            modifiers,
            hotKeyID,
            GetApplicationEventTarget(),
            0,
            &hotKeyRef
        )
        guard status == noErr, let hotKeyRef else {
            let keyName = id == .approve ? "9" : "0"
            throw CLIError("failed to register Cmd+Shift+\(keyName): \(status)")
        }
        hotKeyRefs.append(hotKeyRef)
    }

    private func handle(id: UInt32) {
        guard let hotKeyID = HotKeyID(rawValue: id) else { return }
        DispatchQueue.main.async { [approve, deny] in
            switch hotKeyID {
            case .approve:
                approve()
            case .deny:
                deny()
            }
        }
    }

    private static let signature: OSType = fourCharCode("vzmA")

    private static func fourCharCode(_ string: String) -> OSType {
        string.utf8.reduce(0) { ($0 << 8) + OSType($1) }
    }
}

private extension String {
    func truncatedForMenuBar(maxLength: Int) -> String {
        guard count > maxLength, maxLength > 3 else { return self }
        let endIndex = index(startIndex, offsetBy: maxLength - 3)
        return "\(self[..<endIndex])..."
    }
}
