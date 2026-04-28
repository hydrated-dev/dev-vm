// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "vzm",
    platforms: [
        .macOS(.v13),
    ],
    products: [
        .executable(name: "vzm", targets: ["vzm"]),
    ],
    targets: [
        .executableTarget(
            name: "vzm",
            linkerSettings: [
                .linkedFramework("Virtualization"),
                .linkedFramework("Network"),
                .linkedFramework("Security"),
            ]
        ),
    ]
)
