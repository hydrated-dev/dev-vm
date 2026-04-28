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
        case "secret":
            command = .secret(try Self.parseSecret(arguments: Array(arguments.dropFirst())))
        case "--help", "-h", "help":
            throw CLIError(Self.usage())
        default:
            throw CLIError("unknown command '\(first)'\n\n" + Self.usage())
        }
    }

    func run() throws {
        switch command {
        case .create(let options):
            let store = try VMStore()
            try CreateCommand(store: store).run(options: options)
        case .run(let options):
            let store = try VMStore()
            try RunCommand(store: store).run(options: options)
        case .secret(let command):
            let secretCommand = SecretCommand()
            switch command {
            case .create(let options):
                try secretCommand.create(options: options)
            case .delete(let options):
                try secretCommand.delete(options: options)
            }
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

    private static func parseSecret(arguments: [String]) throws -> SecretSubcommand {
        guard let subcommand = arguments.first else {
            throw CLIError(secretUsage())
        }

        switch subcommand {
        case "create":
            return .create(try parseSecretCreate(arguments: Array(arguments.dropFirst())))
        case "delete":
            return .delete(try parseSecretDelete(arguments: Array(arguments.dropFirst())))
        case "--help", "-h", "help":
            throw CLIError(secretUsage())
        default:
            throw CLIError("unknown secret command '\(subcommand)'\n\n" + secretUsage())
        }
    }

    private static func parseSecretCreate(arguments: [String]) throws -> SecretCreateOptions {
        var name: String?
        var domains: [String] = []
        var index = 0

        while index < arguments.count {
            let argument = arguments[index]
            switch argument {
            case "--name":
                index += 1
                guard index < arguments.count else {
                    throw CLIError("missing value for --name")
                }
                name = arguments[index]
            case "--domain":
                index += 1
                guard index < arguments.count else {
                    throw CLIError("missing value for --domain")
                }
                domains.append(arguments[index])
            case "--help", "-h":
                throw CLIError("usage: vzm secret create --name <display-name> [--domain <host>]...")
            default:
                throw CLIError("unknown argument '\(argument)'")
            }
            index += 1
        }

        guard let name else {
            throw CLIError("missing required --name")
        }
        return SecretCreateOptions(name: name, domains: domains)
    }

    private static func parseSecretDelete(arguments: [String]) throws -> SecretDeleteOptions {
        guard arguments.count == 1 else {
            throw CLIError("usage: vzm secret delete <uuid>")
        }
        guard let id = UUID(uuidString: arguments[0]) else {
            throw CLIError("invalid secret uuid '\(arguments[0])'")
        }
        return SecretDeleteOptions(id: id)
    }

    private static func usage() -> String {
        """
        usage:
          vzm create <name> --bundle <path> --ssh-port <port> --data-disk-size <size>
          vzm run <name>
          vzm secret create --name <display-name> [--domain <host>]...
          vzm secret delete <uuid>
        """
    }

    private static func secretUsage() -> String {
        """
        usage:
          vzm secret create --name <display-name> [--domain <host>]...
          vzm secret delete <uuid>
        """
    }

    private enum Command {
        case create(CreateOptions)
        case run(RunOptions)
        case secret(SecretSubcommand)
    }
}

enum SecretSubcommand {
    case create(SecretCreateOptions)
    case delete(SecretDeleteOptions)
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
