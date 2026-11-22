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
        // A middleman for testing only, never part of the app: a TCP proxy that sits between a
        // sender and a receiver and misbehaves on cue (throttles, stalls, drops connections,
        // flips bits). It knows nothing of the protocol.
        .target(name: "NimbusDropChaos"),
        // The same proxy from the command line, to put between two real Macs.
        .executableTarget(name: "nimbus-chaos", dependencies: ["NimbusDropChaos"]),
        // Whole drops sent through the proxy: what the protocol does when the network turns bad.
        .testTarget(name: "NimbusDropChaosTests", dependencies: ["NimbusDropCore", "NimbusDropChaos"]),
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
