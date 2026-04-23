import Foundation
import Virtualization

struct CreateCommand {
    let store: VMStore

    func run(options: CreateOptions) throws {
        let bundle = try store.validateGuestBundle(options.bundlePath)
        let existing = try store.listConfigs()
        if existing.contains(where: { $0.hostSSHPort == options.sshPort.value }) {
            throw CLIError("SSH port \(options.sshPort.value) is already configured by another VM")
        }

        try store.createVMDirectory(options.name)
        let paths = store.paths(for: options.name)

        do {
            let machineIdentifier = VZGenericMachineIdentifier()
            try store.cloneImage(from: bundle.rootfsURL, to: paths.rootDisk)
            try store.createSparseDisk(at: paths.dataDisk, sizeBytes: options.dataDiskSize.bytes)
            try store.saveMachineIdentifier(machineIdentifier, for: options.name)
            let config = VMConfig(
                schemaVersion: Constants.configSchemaVersion,
                name: options.name.rawValue,
                bundlePath: bundle.root.path,
                hostSSHPort: options.sshPort.value,
                rootDiskPath: paths.rootDisk.path,
                dataDiskPath: paths.dataDisk.path,
                dataDiskSizeBytes: options.dataDiskSize.bytes,
                rootMode: bundle.manifest.rootMode,
                createdAt: Date(),
            )
            try store.saveConfig(config, for: options.name)
        } catch {
            try? FileManager.default.removeItem(at: paths.root)
            throw error
        }

        print("created VM '\(options.name.rawValue)'")
        print("bundle: \(bundle.root.path)")
        print("root disk: \(paths.rootDisk.path)")
        print("data disk: \(paths.dataDisk.path)")
        print("data disk size: \(options.dataDiskSize.bytes) bytes")
        print("ssh port: \(options.sshPort.value)")
    }
}
