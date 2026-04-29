import Foundation
import Darwin
@preconcurrency import Virtualization

final class TCPToVsockPortForward: NSObject, @unchecked Sendable {
    private let socketDevice: VZVirtioSocketDevice
    private let virtualMachineQueue: DispatchQueue
    private let hostPort: UInt16
    private let guestVsockPort: UInt32
    private let logPrefix: String
    private let eventHandler: (String) -> Void
    private let stateQueue = DispatchQueue(label: "vzm.tcp-to-vsock-port-forward.\(UUID().uuidString)")
    private var listenerFD: Int32 = -1
    private var listenerSource: DispatchSourceRead?
    private let sessions = VsockSessionRegistry<BridgeSession>()

    init(
        socketDevice: VZVirtioSocketDevice,
        virtualMachineQueue: DispatchQueue,
        hostPort: UInt16,
        guestVsockPort: UInt32,
        logPrefix: String,
        eventHandler: @escaping (String) -> Void
    ) {
        self.socketDevice = socketDevice
        self.virtualMachineQueue = virtualMachineQueue
        self.hostPort = hostPort
        self.guestVsockPort = guestVsockPort
        self.logPrefix = logPrefix
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
            sessions.closeAll()
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
                eventHandler("\(logPrefix) accept failed: \(String(cString: strerror(errno)))")
                break
            }

            do {
                try SocketSupport.setNonBlocking(hostFD)
            } catch {
                SocketSupport.closeQuietly(hostFD)
                eventHandler("\(logPrefix) setup failed: \(error.localizedDescription)")
                continue
            }

            virtualMachineQueue.async { [weak self] in
                guard let self else {
                    SocketSupport.closeQuietly(hostFD)
                    return
                }

                let sessions = self.sessions
                let stateQueue = self.stateQueue
                let eventHandler = UncheckedSendableBox(self.eventHandler)
                self.socketDevice.connect(toPort: self.guestVsockPort) { result in
                    let resultBox = UncheckedSendableBox(result)
                    stateQueue.async {
                        switch resultBox.value {
                        case .success(let connection):
                            let session = BridgeSession(
                                hostFD: hostFD,
                                guestConnection: connection
                            ) { identifier in
                                stateQueue.async {
                                    sessions.remove(id: identifier)
                                }
                            }
                            sessions.insertAndStart(session)
                        case .failure(let error):
                            SocketSupport.closeQuietly(hostFD)
                            eventHandler.value("\(self.logPrefix) connection failed: \(error.localizedDescription)")
                        }
                    }
                }
            }
        }
    }
}
