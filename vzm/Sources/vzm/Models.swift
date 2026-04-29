import Foundation
import Virtualization

enum Constants {
    static let configSchemaVersion = 3
    static let bundleSchemaVersion = 1
    static let guestSSHVsockPort: UInt32 = 22
    static let hostHTTPSProxyVsockPort: UInt32 = 3128
    static let hostHTTPSProxyCAPort: UInt32 = 3129
    static let hostOutboundSSHVsockPort: UInt32 = 2223
    static let initialOutboundSSHHost = "github.com"
    static let initialOutboundSSHPort: UInt16 = 22
    static let initialHTTPSRequestAllowlist: Set<String> = [
        "GET https://storage.googleapis.com/bushel-distro/bushelpowered.settings.gradle.kts",
    ]
    static let maxHTTPSProxyBufferedBodyBytes = 1024 * 1024
    static let defaultMemoryBytes: UInt64 = 4 * 1024 * 1024 * 1024
    static let defaultCPUCount = 2
    static let shutdownTimeoutSeconds: TimeInterval = 30
    static let supportedArchitecture = "aarch64"
    static let supportedForwardedTCPPorts: [UInt16] = [3000, 5173]
}

struct VMName: Codable, Hashable, LosslessStringConvertible {
    let rawValue: String

    init(rawValue: String) throws {
        guard rawValue.range(of: #"^[a-z0-9_-]+$"#, options: .regularExpression) != nil else {
            throw CLIError("invalid VM name '\(rawValue)'; use lowercase letters, numbers, '-' or '_'")
        }
        self.rawValue = rawValue
    }

    init?(_ description: String) {
        try? self.init(rawValue: description)
    }

    var description: String { rawValue }
}

struct Port: Codable, Hashable {
    let value: UInt16

    init(_ value: Int) throws {
        guard (1...65535).contains(value) else {
            throw CLIError("invalid TCP port '\(value)'")
        }
        self.value = UInt16(value)
    }
}

struct DiskSize: Codable, Hashable {
    let bytes: UInt64

    init(bytes: UInt64) throws {
        guard bytes > 0 else {
            throw CLIError("disk size must be greater than zero")
        }
        self.bytes = bytes
    }

    init(argument: String) throws {
        let trimmed = argument.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else {
            throw CLIError("disk size must not be empty")
        }

        let suffix = trimmed.last?.isLetter == true ? String(trimmed.suffix(1)).lowercased() : ""
        let numberPart = suffix.isEmpty ? trimmed : String(trimmed.dropLast())
        guard let base = UInt64(numberPart), base > 0 else {
            throw CLIError("invalid disk size '\(argument)'")
        }

        let multiplier: UInt64
        switch suffix {
        case "":
            multiplier = 1
        case "k":
            multiplier = 1024
        case "m":
            multiplier = 1024 * 1024
        case "g":
            multiplier = 1024 * 1024 * 1024
        case "t":
            multiplier = 1024 * 1024 * 1024 * 1024
        default:
            throw CLIError("invalid disk size suffix in '\(argument)'; use k, m, g, or t")
        }

        let bytes = base.multipliedReportingOverflow(by: multiplier)
        guard !bytes.overflow else {
            throw CLIError("disk size '\(argument)' is too large")
        }

        try self.init(bytes: bytes.partialValue)
    }
}

enum RootMode: String, Codable {
    case ephemeral
    case persistent
}

enum DiskRole: String, Codable {
    case data
    case root
}

struct GuestBundleManifest: Codable {
    let schemaVersion: Int
    let architecture: String
    let kernel: String
    let initrd: String
    let rootfs: String
    let rootMode: RootMode
    let commandLine: String
    let requiredDisks: [DiskRole]
}

struct ValidatedGuestBundle {
    let root: URL
    let manifestURL: URL
    let manifest: GuestBundleManifest
    let kernelURL: URL
    let initrdURL: URL
    let rootfsURL: URL
}

struct VMConfig: Codable {
    let schemaVersion: Int
    let name: String
    let bundlePath: String
    let hostSSHPort: UInt16
    let rootDiskPath: String
    let dataDiskPath: String
    let dataDiskSizeBytes: UInt64
    let rootMode: RootMode
    let createdAt: Date
}

struct VMPaths {
    let root: URL
    let config: URL
    let machineIdentifier: URL
    let disksDirectory: URL
    let rootDisk: URL
    let dataDisk: URL
    let runtimeDirectory: URL
    let lock: URL
    let pid: URL

    init(root: URL) {
        self.root = root
        config = root.appendingPathComponent("config.json")
        machineIdentifier = root.appendingPathComponent("machine-identifier")
        disksDirectory = root.appendingPathComponent("disks", isDirectory: true)
        rootDisk = disksDirectory.appendingPathComponent("root.img")
        dataDisk = disksDirectory.appendingPathComponent("data.img")
        runtimeDirectory = root.appendingPathComponent("runtime", isDirectory: true)
        lock = runtimeDirectory.appendingPathComponent("lock")
        pid = runtimeDirectory.appendingPathComponent("pid")
    }
}

extension VZGenericMachineIdentifier {
    convenience init(data: Data) throws {
        guard let identifier = VZGenericMachineIdentifier(dataRepresentation: data) else {
            throw CLIError("stored machine identifier is invalid")
        }
        self.init(dataRepresentation: identifier.dataRepresentation)!
    }
}
