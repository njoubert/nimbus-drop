// Copyright (C) 2026 Niels Joubert
// SPDX-License-Identifier: GPL-3.0-or-later
import Foundation
import NimbusDropCore

/// What the app remembers, in UserDefaults.
enum Settings {
    static let didChange = Notification.Name("com.njoubert.nimbusdrop.settingsChanged")
    private static var d: UserDefaults { .standard }

    /// A random value made at each launch: how this Mac leaves its own Bonjour record out of
    /// its list. It identifies nothing and lasts no longer than the process; who a Mac is, is
    /// its key (`trust`).
    static let launchID = UUID().uuidString

    static var identity: Identity {
        Identity(name: LocalHost.name, id: launchID,
                 appVersion: Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String ?? "dev")
    }

    /// Where this copy keeps its identity: a folder per bundle id, so the development copy and
    /// the installed one are different Macs to each other.
    static var bundleID: String { Bundle.main.bundleIdentifier ?? "com.njoubert.nimbusdrop.cli" }

    /// On unless the person turned it off; remembered across launches.
    static var receiving: Bool {
        get { d.object(forKey: "receiving") as? Bool ?? true }
        set { d.set(newValue, forKey: "receiving"); NotificationCenter.default.post(name: didChange, object: nil) }
    }

    /// Parallel data connections per drop.
    static var streams: Int {
        get { let n = d.integer(forKey: "streams"); return n == 0 ? defaultStreams : max(1, min(32, n)) }
        set { d.set(newValue, forKey: "streams"); NotificationCenter.default.post(name: didChange, object: nil) }
    }
    /// Macs added by address ("192.168.1.20" or "host:port"), for when Bonjour does not find them.
    static var manualDestinations: [String] {
        get { d.stringArray(forKey: "manualDestinations") ?? [] }
        set { d.set(newValue, forKey: "manualDestinations") }
    }

    /// Take drops only from the local network: on unless the person turned it off.
    static var localOnly: Bool {
        get { d.object(forKey: "localOnly") as? Bool ?? true }
        set { d.set(newValue, forKey: "localOnly") }
    }

    /// Destinations as a compact list rather than a grid of tiles.
    static var listLayout: Bool {
        get { d.bool(forKey: "listLayout") }
        set { d.set(newValue, forKey: "listLayout") }
    }

    static let defaultStreams = 8
    static let streamChoices = [1, 2, 4, 8, 16]
}
