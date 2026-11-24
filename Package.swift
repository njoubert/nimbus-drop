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
        // The engine, in layers. A target may import only what it lists here, so the arrows
        // below are enforced by the compiler; `scripts/check-layers.py` holds each layer to the
        // system frameworks it is allowed. What one layer needs of another is `package`, not
        // `public`: the split adds nothing to what the app can see.
        //
        //   NimbusBase              errors, the log, Sanitize, Format, the Tuning namespace
        //   NimbusCrypto            PURE: no socket, file, clock, lock or thread. The cryptography
        //                           of protocol 3 and the pairing transaction as a state machine.
        //                           What the formal models in formal/ are about.
        //   NimbusNet               Socket, Deadline, this Mac's addresses
        //   NimbusSafeStorageCore   a manifest and every file operation a receiver performs
        //   NimbusSecurityCore      Trust, the trust file, Channel, pairing, retirement
        //   NimbusDiscovery         Bonjour and probing
        //   NimbusTransferCore      drops: the sender, the listener, the receiver, the speed test
        //   NimbusDropCore          all of it under one name, and what only an app needs
        .target(name: "NimbusBase"),
        .target(name: "NimbusCrypto", dependencies: ["NimbusBase"]),
        .target(name: "NimbusNet", dependencies: ["NimbusBase"], linkerSettings: [.linkedFramework("SystemConfiguration")]),
        .target(name: "NimbusSafeStorageCore", dependencies: ["NimbusBase"]),
        .target(name: "NimbusSecurityCore", dependencies: ["NimbusBase", "NimbusCrypto", "NimbusNet"],
                linkerSettings: [.linkedFramework("IOKit")]),
        .target(name: "NimbusDiscovery", dependencies: ["NimbusBase", "NimbusCrypto", "NimbusNet", "NimbusSecurityCore"],
                linkerSettings: [.linkedFramework("Network"), .linkedFramework("SystemConfiguration")]),
        .target(name: "NimbusTransferCore",
                dependencies: ["NimbusBase", "NimbusCrypto", "NimbusNet", "NimbusSafeStorageCore", "NimbusSecurityCore"]),
        .target(
            name: "NimbusDropCore",
            dependencies: ["NimbusBase", "NimbusCrypto", "NimbusNet", "NimbusSafeStorageCore", "NimbusSecurityCore", "NimbusDiscovery",
                           "NimbusTransferCore"]
        ),
        // The pure module by itself: the pairing machine, attacked, and written out as the
        // transition relation that TLC checks against its specification (formal/tla).
        .testTarget(name: "NimbusCryptoTests", dependencies: ["NimbusCrypto"]),
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
