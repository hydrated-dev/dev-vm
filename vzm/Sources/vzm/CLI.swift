import Foundation

struct CLI {
    private let command: Command

    init(arguments: [String]) throws {
        guard let first = arguments.first else {
            throw CLIError(Self.usage())
        }

        switch first {
        case "create":
            command = .create(try Self.parseCreate(arguments: Array(arguments.dropFirst())))
        case "run":
            command = .run(try Self.parseRun(arguments: Array(arguments.dropFirst())))
        case "--help", "-h", "help":
            throw CLIError(Self.usage())
        default:
            throw CLIError("unknown command '\(first)'\n\n" + Self.usage())
        }
    }

    func run() throws {
        let store = try VMStore()

        switch command {
        case .create(let options):
            try CreateCommand(store: store).run(options: options)
        case .run(let options):
            try RunCommand(store: store).run(options: options)
        }
    }

    private static func parseCreate(arguments: [String]) throws -> CreateOptions {
        guard let nameArgument = arguments.first, !nameArgument.hasPrefix("-") else {
            throw CLIError("usage: vzm create <name> --bundle <path> --ssh-port <port> --data-disk-size <size>")
        }

        var bundlePath: String?
        var sshPort: Int?
        var dataDiskSize: DiskSize?
        var index = 1

        while index < arguments.count {
            let argument = arguments[index]
            switch argument {
            case "--bundle":
                index += 1
                guard index < arguments.count else {
                    throw CLIError("missing value for --bundle")
                }
                bundlePath = arguments[index]
            case "--ssh-port":
                index += 1
                guard index < arguments.count else {
                    throw CLIError("missing value for --ssh-port")
                }
                guard let parsed = Int(arguments[index]) else {
                    throw CLIError("invalid ssh port '\(arguments[index])'")
                }
                sshPort = parsed
            case "--data-disk-size":
                index += 1
                guard index < arguments.count else {
                    throw CLIError("missing value for --data-disk-size")
                }
                dataDiskSize = try DiskSize(argument: arguments[index])
            case "--help", "-h":
                throw CLIError("usage: vzm create <name> --bundle <path> --ssh-port <port> --data-disk-size <size>")
            default:
                throw CLIError("unknown argument '\(argument)'")
            }
            index += 1
        }

        guard let bundlePath else {
            throw CLIError("missing required --bundle")
        }
        guard let sshPort else {
            throw CLIError("missing required --ssh-port")
        }
        guard let dataDiskSize else {
            throw CLIError("missing required --data-disk-size")
        }

        return CreateOptions(
            name: try VMName(rawValue: nameArgument),
            bundlePath: bundlePath,
            sshPort: try Port(sshPort),
            dataDiskSize: dataDiskSize
        )
    }

    private static func parseRun(arguments: [String]) throws -> RunOptions {
        guard let nameArgument = arguments.first, !nameArgument.hasPrefix("-") else {
            throw CLIError("usage: vzm run <name>")
        }
        guard arguments.count == 1 else {
            throw CLIError("usage: vzm run <name>")
        }
        return RunOptions(name: try VMName(rawValue: nameArgument))
    }

    private static func usage() -> String {
        """
        usage:
          vzm create <name> --bundle <path> --ssh-port <port> --data-disk-size <size>
          vzm run <name>
        """
    }

    private enum Command {
        case create(CreateOptions)
        case run(RunOptions)
    }
}

struct CreateOptions {
    let name: VMName
    let bundlePath: String
    let sshPort: Port
    let dataDiskSize: DiskSize
}

struct RunOptions {
    let name: VMName
}

struct CLIError: Error, LocalizedError {
    let message: String
    var errorDescription: String? { message }

    init(_ message: String) {
        self.message = message
    }
}
