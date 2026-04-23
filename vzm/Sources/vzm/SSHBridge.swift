import Foundation
import Darwin
import Virtualization

final class SSHBridge: NSObject {
    private let socketDevice: VZVirtioSocketDevice
    private let virtualMachineQueue: DispatchQueue
    private let hostPort: UInt16
    private let eventHandler: (String) -> Void
    private let stateQueue = DispatchQueue(label: "vzm.ssh-bridge")
    private var listenerFD: Int32 = -1
    private var listenerSource: DispatchSourceRead?
    private var sessions: [UUID: BridgeSession] = [:]

    init(
        socketDevice: VZVirtioSocketDevice,
        virtualMachineQueue: DispatchQueue,
        hostPort: UInt16,
        eventHandler: @escaping (String) -> Void
    ) {
        self.socketDevice = socketDevice
        self.virtualMachineQueue = virtualMachineQueue
        self.hostPort = hostPort
        self.eventHandler = eventHandler
    }

    func start() throws {
        listenerFD = try SocketSupport.createListeningSocket(port: hostPort)
        try SocketSupport.setNonBlocking(listenerFD)

        let source = DispatchSource.makeReadSource(fileDescriptor: listenerFD, queue: stateQueue)
        source.setEventHandler { [weak self] in
            self?.acceptLoop()
        }
        source.setCancelHandler { [listenerFD] in
            SocketSupport.closeQuietly(listenerFD)
        }
        listenerSource = source
        source.resume()
    }

    func stop() {
        stateQueue.sync {
            listenerSource?.cancel()
            listenerSource = nil
            sessions.values.forEach { $0.close() }
            sessions.removeAll()
        }
    }

    private func acceptLoop() {
        while true {
            var address = sockaddr_storage()
            var addressLength = socklen_t(MemoryLayout<sockaddr_storage>.size)
            let hostFD = withUnsafeMutablePointer(to: &address) {
                $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                    accept(listenerFD, $0, &addressLength)
                }
            }

            if hostFD < 0 {
                if errno == EAGAIN || errno == EWOULDBLOCK {
                    break
                }
                eventHandler("ssh bridge accept failed: \(String(cString: strerror(errno)))")
                break
            }

            do {
                try SocketSupport.setNonBlocking(hostFD)
            } catch {
                SocketSupport.closeQuietly(hostFD)
                eventHandler("ssh bridge setup failed: \(error.localizedDescription)")
                continue
            }

            virtualMachineQueue.async { [weak self] in
                guard let self else {
                    SocketSupport.closeQuietly(hostFD)
                    return
                }

                self.socketDevice.connect(toPort: Constants.guestSSHVsockPort) { [weak self] result in
                    guard let self else {
                        SocketSupport.closeQuietly(hostFD)
                        return
                    }

                    self.stateQueue.async {
                        switch result {
                        case .success(let connection):
                            let session = BridgeSession(
                                hostFD: hostFD,
                                guestConnection: connection
                            ) { [weak self] identifier in
                                self?.stateQueue.async {
                                    self?.sessions.removeValue(forKey: identifier)
                                }
                            }
                            self.sessions[session.id] = session
                            session.start()
                        case .failure(let error):
                            SocketSupport.closeQuietly(hostFD)
                            self.eventHandler("ssh forwarding connection failed: \(error.localizedDescription)")
                        }
                    }
                }
            }
        }
    }
}

final class BridgeSession {
    let id = UUID()

    private let hostFD: Int32
    private let guestConnection: VZVirtioSocketConnection
    private let onClose: (UUID) -> Void
    private var hostSource: DispatchSourceRead?
    private var guestSource: DispatchSourceRead?
    private var isClosed = false

    init(hostFD: Int32, guestConnection: VZVirtioSocketConnection, onClose: @escaping (UUID) -> Void) {
        self.hostFD = hostFD
        self.guestConnection = guestConnection
        self.onClose = onClose
    }

    func start() {
        let guestFD = guestConnection.fileDescriptor

        hostSource = DispatchSource.makeReadSource(fileDescriptor: hostFD, queue: .global())
        hostSource?.setEventHandler { [weak self] in
            self?.pump(from: self?.hostFD ?? -1, to: guestFD)
        }
        hostSource?.setCancelHandler { [hostFD] in
            SocketSupport.closeQuietly(hostFD)
        }

        guestSource = DispatchSource.makeReadSource(fileDescriptor: guestFD, queue: .global())
        guestSource?.setEventHandler { [weak self] in
            self?.pump(from: guestFD, to: self?.hostFD ?? -1)
        }
        guestSource?.setCancelHandler { [weak guestConnection] in
            guestConnection?.close()
        }

        hostSource?.resume()
        guestSource?.resume()
    }

    func close() {
        guard !isClosed else { return }
        isClosed = true
        hostSource?.cancel()
        guestSource?.cancel()
        hostSource = nil
        guestSource = nil
        onClose(id)
    }

    private func pump(from sourceFD: Int32, to destinationFD: Int32) {
        guard sourceFD >= 0, destinationFD >= 0 else {
            close()
            return
        }

        var buffer = [UInt8](repeating: 0, count: 16 * 1024)
        let bytesRead = read(sourceFD, &buffer, buffer.count)

        if bytesRead == 0 {
            close()
            return
        }

        if bytesRead < 0 {
            if errno == EAGAIN || errno == EWOULDBLOCK {
                return
            }
            close()
            return
        }

        var totalWritten = 0
        while totalWritten < bytesRead {
            let written = buffer.withUnsafeBytes { bytes in
                write(destinationFD, bytes.baseAddress!.advanced(by: totalWritten), bytesRead - totalWritten)
            }

            if written < 0 {
                if errno == EAGAIN || errno == EWOULDBLOCK {
                    continue
                }
                close()
                return
            }

            totalWritten += written
        }
    }
}
