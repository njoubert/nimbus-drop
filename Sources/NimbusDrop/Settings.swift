// Copyright (C) 2026 Niels Joubert
// SPDX-License-Identifier: GPL-3.0-or-later
import Foundation
import NimbusDropCore

/// What the app remembers, in UserDefaults.
enum Settings {
    static let didChange = Notification.Name("com.njoubert.nimbusdrop.settingsChanged")
    private static var d: UserDefaults { .standard }

    /// Made once per Mac (per defaults domain). It is how a Mac leaves itself out of its own
    /// list, and part of what identifies a drop when it is re-sent to be continued.
    static var deviceID: String {
        if let id = d.string(forKey: "deviceID") { return id }
        let id = UUID().uuidString
        d.set(id, forKey: "deviceID")
        return id
    }

    static var identity: Identity { Identity(name: LocalHost.name, id: deviceID) }

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
    static let defaultStreams = 8
    static let streamChoices = [1, 2, 4, 8, 16]
}
