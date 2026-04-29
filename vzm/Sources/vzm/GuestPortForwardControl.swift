import Foundation

struct GuestPortForwardControl {
    let hostSSHPort: UInt16

    func start(port: UInt16) throws {
        let unit = unitName(for: port)
        try? stop(port: port)

        try runSSHCommand([
            "/run/current-system/sw/bin/systemd-run",
            "--unit", unit,
            "--service-type=simple",
            "--property", "Restart=no",
            "--collect",
            "/run/current-system/sw/bin/socat",
            "VSOCK-LISTEN:\(port),fork,reuseaddr",
            "TCP:127.0.0.1:\(port)",
        ])

        try runSSHCommand([
            "/run/current-system/sw/bin/systemctl",
            "is-active",
            "--quiet",
            unit,
        ])
    }

    func stop(port: UInt16) throws {
        let unit = unitName(for: port)
        try runSSHCommand([
            "/run/current-system/sw/bin/systemctl",
            "stop",
            unit,
        ])
        try? runSSHCommand([
            "/run/current-system/sw/bin/systemctl",
            "reset-failed",
            unit,
        ])
    }

    private func runSSHCommand(_ remoteArguments: [String]) throws {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/ssh")
        process.arguments = [
            "-p", String(hostSSHPort),
            "-o", "BatchMode=yes",
            "-o", "StrictHostKeyChecking=no",
            "-o", "UserKnownHostsFile=/dev/null",
            "-o", "ConnectTimeout=5",
            "-o", "LogLevel=ERROR",
            "\(Constants.defaultGuestSSHUser)@127.0.0.1",
        ] + remoteArguments

        let outputPipe = Pipe()
        let errorPipe = Pipe()
        process.standardOutput = outputPipe
        process.standardError = errorPipe

        try process.run()
        process.waitUntilExit()

        guard process.terminationStatus == 0 else {
            let errorData = errorPipe.fileHandleForReading.readDataToEndOfFile()
            let outputData = outputPipe.fileHandleForReading.readDataToEndOfFile()
            let message = String(data: errorData, encoding: .utf8)?.trimmingCharacters(in: .whitespacesAndNewlines)
                ?? String(data: outputData, encoding: .utf8)?.trimmingCharacters(in: .whitespacesAndNewlines)
                ?? "ssh command failed"
            throw CLIError(message.isEmpty ? "ssh command failed" : message)
        }
    }

    private func unitName(for port: UInt16) -> String {
        "vzm-port-forward-\(port)"
    }
}
