import Foundation
import Darwin
import Virtualization

struct VMStore {
    let rootDirectory: URL
    private let fileManager = FileManager.default
    private let encoder: JSONEncoder
    private let decoder: JSONDecoder

    init() throws {
        rootDirectory = try fileManager
            .url(for: .applicationSupportDirectory, in: .userDomainMask, appropriateFor: nil, create: true)
            .appendingPathComponent("vzm", isDirectory: true)
            .appendingPathComponent("vms", isDirectory: true)
        do {
            try fileManager.createDirectory(at: rootDirectory, withIntermediateDirectories: true)
        } catch {
            throw CLIError("failed to initialize VM storage at '\(rootDirectory.path)': \(error.localizedDescription)")
        }

        encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        encoder.dateEncodingStrategy = .iso8601

        decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
    }

    func paths(for name: VMName) -> VMPaths {
        VMPaths(root: rootDirectory.appendingPathComponent(name.rawValue, isDirectory: true))
    }

    func vmExists(_ name: VMName) -> Bool {
        fileManager.fileExists(atPath: paths(for: name).root.path)
    }

    func loadConfig(name: VMName) throws -> VMConfig {
        let data = try Data(contentsOf: paths(for: name).config)
        do {
            let config = try decoder.decode(VMConfig.self, from: data)
            guard config.schemaVersion == Constants.configSchemaVersion else {
                throw CLIError("unsupported config schema version \(config.schemaVersion); expected \(Constants.configSchemaVersion)")
            }
            return config
        } catch {
            if let cliError = error as? CLIError {
                throw cliError
            }
            throw CLIError("failed to decode config for '\(name.rawValue)': \(error.localizedDescription)")
        }
    }

    func saveConfig(_ config: VMConfig, for name: VMName) throws {
        let data = try encoder.encode(config)
        try data.write(to: paths(for: name).config, options: .atomic)
    }

    func createVMDirectory(_ name: VMName) throws {
        let paths = paths(for: name)
        do {
            try fileManager.createDirectory(at: paths.root, withIntermediateDirectories: false)
            try fileManager.createDirectory(at: paths.disksDirectory, withIntermediateDirectories: true)
            try fileManager.createDirectory(at: paths.runtimeDirectory, withIntermediateDirectories: true)
        } catch let error as CocoaError where error.code == .fileWriteFileExists {
            throw CLIError("VM '\(name.rawValue)' already exists")
        } catch {
            throw CLIError("failed to create VM directory '\(paths.root.path)': \(error.localizedDescription)")
        }
    }

    func listConfigs() throws -> [VMConfig] {
        let children = try fileManager.contentsOfDirectory(at: rootDirectory, includingPropertiesForKeys: [.isDirectoryKey], options: [.skipsHiddenFiles])
        return try children.compactMap { child in
            let values = try child.resourceValues(forKeys: [.isDirectoryKey])
            guard values.isDirectory == true else {
                return nil
            }
            let configURL = child.appendingPathComponent("config.json")
            guard fileManager.fileExists(atPath: configURL.path) else {
                return nil
            }
            let data = try Data(contentsOf: configURL)
            let config = try decoder.decode(VMConfig.self, from: data)
            guard config.schemaVersion == Constants.configSchemaVersion else {
                return nil
            }
            return config
        }
    }

    func validateGuestBundle(_ path: String) throws -> ValidatedGuestBundle {
        let rootURL = URL(fileURLWithPath: path).standardizedFileURL
        var isDirectory: ObjCBool = false
        guard fileManager.fileExists(atPath: rootURL.path, isDirectory: &isDirectory), isDirectory.boolValue else {
            throw CLIError("guest bundle does not exist at '\(path)'")
        }

        let manifestURL = rootURL.appendingPathComponent("manifest.json")
        guard fileManager.fileExists(atPath: manifestURL.path) else {
            throw CLIError("guest bundle '\(path)' is missing manifest.json")
        }

        let manifestData = try Data(contentsOf: manifestURL)
        let manifest: GuestBundleManifest
        do {
            manifest = try decoder.decode(GuestBundleManifest.self, from: manifestData)
        } catch {
            throw CLIError("failed to decode bundle manifest at '\(manifestURL.path)': \(error.localizedDescription)")
        }

        guard manifest.schemaVersion == Constants.bundleSchemaVersion else {
            throw CLIError("unsupported bundle schema version \(manifest.schemaVersion); expected \(Constants.bundleSchemaVersion)")
        }
        guard manifest.architecture == Constants.supportedArchitecture else {
            throw CLIError("unsupported guest architecture '\(manifest.architecture)'; expected \(Constants.supportedArchitecture)")
        }
        guard manifest.rootMode == .persistent else {
            throw CLIError("unsupported root mode '\(manifest.rootMode.rawValue)'; only 'persistent' is currently supported")
        }
        guard manifest.requiredDisks.contains(.data) else {
            throw CLIError("bundle manifest must declare a required 'data' disk")
        }
        guard manifest.requiredDisks.allSatisfy({ $0 == .data }) else {
            throw CLIError("bundle manifest declares unsupported disk roles; only 'data' is currently supported")
        }

        let kernelURL = try validateBundleFile(root: rootURL, relativePath: manifest.kernel, label: "kernel")
        let initrdURL = try validateBundleFile(root: rootURL, relativePath: manifest.initrd, label: "initrd")
        let rootfsURL = try validateBundleFile(root: rootURL, relativePath: manifest.rootfs, label: "rootfs")
        guard !manifest.commandLine.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
            throw CLIError("bundle manifest commandLine must not be empty")
        }

        return ValidatedGuestBundle(
            root: rootURL,
            manifestURL: manifestURL,
            manifest: manifest,
            kernelURL: kernelURL,
            initrdURL: initrdURL,
            rootfsURL: rootfsURL
        )
    }

    func createSparseDisk(at url: URL, sizeBytes: UInt64) throws {
        let fd = open(url.path, O_RDWR | O_CREAT | O_EXCL, S_IRUSR | S_IWUSR)
        guard fd >= 0 else {
            throw CLIError("failed to create disk image at '\(url.path)': \(String(cString: strerror(errno)))")
        }
        defer { close(fd) }

        guard ftruncate(fd, off_t(sizeBytes)) == 0 else {
            throw CLIError("failed to size disk image at '\(url.path)': \(String(cString: strerror(errno)))")
        }
    }

    func cloneImage(from source: URL, to destination: URL) throws {
        let result = source.withUnsafeFileSystemRepresentation { srcFS in
            destination.withUnsafeFileSystemRepresentation { dstFS in
                copyfile(srcFS, dstFS, nil, UInt32(COPYFILE_ALL | COPYFILE_CLONE))
            }
        }

        guard result == 0 else {
            let error = String(cString: strerror(errno))
            throw CLIError("failed to clone image to '\(destination.path)': \(error)")
        }
    }

    func saveMachineIdentifier(_ identifier: VZGenericMachineIdentifier, for name: VMName) throws {
        try identifier.dataRepresentation.write(to: paths(for: name).machineIdentifier, options: .atomic)
    }

    func loadMachineIdentifier(name: VMName) throws -> VZGenericMachineIdentifier {
        let data = try Data(contentsOf: paths(for: name).machineIdentifier)
        return try VZGenericMachineIdentifier(data: data)
    }

    private func validateBundleFile(root: URL, relativePath: String, label: String) throws -> URL {
        let candidate = URL(fileURLWithPath: relativePath, relativeTo: root).standardizedFileURL
        guard candidate.path.hasPrefix(root.path + "/") else {
            throw CLIError("bundle \(label) path '\(relativePath)' must stay within the bundle directory")
        }

        var isDirectory: ObjCBool = false
        guard fileManager.fileExists(atPath: candidate.path, isDirectory: &isDirectory), !isDirectory.boolValue else {
            throw CLIError("bundle \(label) does not exist at '\(candidate.path)'")
        }
        return candidate
    }
}
