import Dispatch
import Darwin
import Foundation

final class RawFDRelay {
    private let leftFD: Int32
    private let rightFD: Int32
    private let group = DispatchGroup()

    init(leftFD: Int32, rightFD: Int32) {
        self.leftFD = leftFD
        self.rightFD = rightFD
    }

    func start() {
        group.enter()
        DispatchQueue.global().async { [leftFD, rightFD, group] in
            defer { group.leave() }
            Self.pump(from: leftFD, to: rightFD)
            _ = shutdown(leftFD, SHUT_RDWR)
            _ = shutdown(rightFD, SHUT_RDWR)
        }

        group.enter()
        DispatchQueue.global().async { [leftFD, rightFD, group] in
            defer { group.leave() }
            Self.pump(from: rightFD, to: leftFD)
            _ = shutdown(leftFD, SHUT_RDWR)
            _ = shutdown(rightFD, SHUT_RDWR)
        }
    }

    func close() {
        _ = shutdown(leftFD, SHUT_RDWR)
        _ = shutdown(rightFD, SHUT_RDWR)
        group.wait()
    }

    func wait() {
        group.wait()
    }

    private static func pump(from sourceFD: Int32, to destinationFD: Int32) {
        var buffer = [UInt8](repeating: 0, count: 16 * 1024)
        while true {
            let bytesRead = read(sourceFD, &buffer, buffer.count)
            if bytesRead <= 0 {
                return
            }

            var totalWritten = 0
            while totalWritten < bytesRead {
                let written = buffer.withUnsafeBytes { bytes in
                    write(destinationFD, bytes.baseAddress!.advanced(by: totalWritten), bytesRead - totalWritten)
                }
                if written <= 0 {
                    return
                }
                totalWritten += written
            }
        }
    }
}
