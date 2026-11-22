// swift-tools-version:5.10
import PackageDescription

let package = Package(
    name: "NimbusDrop",
    platforms: [.macOS("15.0")],
    products: [
        .executable(name: "NimbusDrop", targets: ["NimbusDrop"]),
    ],
    dependencies: [
        // Ours, MIT, no dependencies of its own: the GitHub-release auto-updater. Pinned by
        // Package.resolved; a new tag reaches this app only when someone bumps it here.
        .package(url: "https://github.com/njoubert/nimbus-updater.git", from: "1.4.0"),
    ],
    targets: [
        // Everything that moves bytes or finds peers, with no AppKit: the wire protocol, the
        // manifest, the resume ledger, the sender and the receiver, Bonjour. The tests drive
        // whole drops through it over loopback.
        .target(
            name: "NimbusDropCore",
            linkerSettings: [
                .linkedFramework("Network"),
                .linkedFramework("SystemConfiguration"),
                .linkedLibrary("z"),
            ]
        ),
        .testTarget(name: "NimbusDropCoreTests", dependencies: ["NimbusDropCore"]),
        // The menu bar item, the window, the save prompt and the command line. build.sh wraps
        // the binary into Nimbus Drop.app.
        .executableTarget(
            name: "NimbusDrop",
            dependencies: [
                "NimbusDropCore",
                .product(name: "NimbusUpdater", package: "nimbus-updater"),
            ],
            linkerSettings: [
                .linkedFramework("AppKit"),
                .linkedFramework("SwiftUI"),
                .linkedFramework("ServiceManagement"),
                .linkedFramework("UserNotifications"),
            ]
        ),
    ]
)
