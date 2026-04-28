import Foundation

final class SynchronizedValue<Value>: @unchecked Sendable {
    private let lock = NSLock()
    private var storedValue: Value

    init(_ value: Value) {
        storedValue = value
    }

    var value: Value {
        lock.lock()
        defer { lock.unlock() }
        return storedValue
    }

    func set(_ value: Value) {
        lock.lock()
        storedValue = value
        lock.unlock()
    }
}

final class RelayErrorBox: @unchecked Sendable {
    private let lock = NSLock()
    private var storedError: Error?

    var firstError: Error? {
        lock.lock()
        defer { lock.unlock() }
        return storedError
    }

    func record(_ error: Error) {
        lock.lock()
        if storedError == nil {
            storedError = error
        }
        lock.unlock()
    }
}

final class UncheckedSendableBox<Value>: @unchecked Sendable {
    let value: Value

    init(_ value: Value) {
        self.value = value
    }
}
