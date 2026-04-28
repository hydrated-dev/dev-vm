import Foundation
import Security

struct StoredSecret: Codable, Sendable {
    let id: UUID
    let name: String
    let value: String
    let allowedDomains: Set<String>

    func allows(host: String) -> Bool {
        allowedDomains.isEmpty || allowedDomains.contains(Self.normalizedDomain(host))
    }

    static func normalizedDomain(_ value: String) -> String {
        value.trimmingCharacters(in: .whitespacesAndNewlines)
            .lowercased()
            .trimmingCharacters(in: CharacterSet(charactersIn: "."))
    }
}

struct SecretCreateOptions {
    let name: String
    let domains: [String]
}

struct SecretDeleteOptions {
    let id: UUID
}

struct SecretStore {
    private static let service = "vzm.secret"

    func create(name: String, value: String, domains: [String]) throws -> UUID {
        let trimmedName = name.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmedName.isEmpty else {
            throw CLIError("secret name must not be empty")
        }

        let id = UUID()
        let secret = StoredSecret(
            id: id,
            name: trimmedName,
            value: value,
            allowedDomains: Set(domains.map(StoredSecret.normalizedDomain).filter { !$0.isEmpty })
        )
        let data = try JSONEncoder().encode(secret)
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: Self.service,
            kSecAttrAccount as String: id.uuidString.lowercased(),
            kSecAttrLabel as String: "vzm secret: \(trimmedName)",
            kSecAttrDescription as String: "vzm managed secret",
            kSecValueData as String: data,
        ]

        let status = SecItemAdd(query as CFDictionary, nil)
        guard status == errSecSuccess else {
            throw CLIError("failed to store secret in Keychain: \(Self.message(for: status))")
        }
        return id
    }

    func get(id: UUID) throws -> StoredSecret {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: Self.service,
            kSecAttrAccount as String: id.uuidString.lowercased(),
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne,
        ]

        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        guard status != errSecItemNotFound else {
            throw CLIError("secret not found: \(id.uuidString.lowercased())")
        }
        guard status == errSecSuccess, let data = result as? Data else {
            throw CLIError("failed to read secret from Keychain: \(Self.message(for: status))")
        }
        return try JSONDecoder().decode(StoredSecret.self, from: data)
    }

    func delete(id: UUID) throws {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: Self.service,
            kSecAttrAccount as String: id.uuidString.lowercased(),
        ]

        let status = SecItemDelete(query as CFDictionary)
        guard status != errSecItemNotFound else {
            throw CLIError("secret not found: \(id.uuidString.lowercased())")
        }
        guard status == errSecSuccess else {
            throw CLIError("failed to delete secret from Keychain: \(Self.message(for: status))")
        }
    }

    private static func message(for status: OSStatus) -> String {
        if let message = SecCopyErrorMessageString(status, nil) {
            return "\(message) (\(status))"
        }
        return "\(status)"
    }
}

struct SecretCommand {
    func create(options: SecretCreateOptions) throws {
        let data = FileHandle.standardInput.readDataToEndOfFile()
        guard let value = String(data: data, encoding: .utf8) else {
            throw CLIError("secret value must be valid UTF-8")
        }
        let id = try SecretStore().create(name: options.name, value: value, domains: options.domains)
        print(id.uuidString.lowercased())
    }

    func delete(options: SecretDeleteOptions) throws {
        try SecretStore().delete(id: options.id)
    }
}
