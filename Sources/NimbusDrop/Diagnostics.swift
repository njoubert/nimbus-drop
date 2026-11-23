// Copyright (C) 2026 Niels Joubert
// SPDX-License-Identifier: GPL-3.0-or-later
import Foundation

/// The app's flight recorder, as in Nimbus Leviton Bar: every line that goes to the log file is
/// also kept here, in memory, for the Internals panel to show live. It records from launch, not
/// from when the panel opens (what is worth seeing has usually happened by the time anyone
/// looks), and it is bounded: the newest `capacity` lines.
///
/// Safe from any thread: one lock, and nothing is called while it is held. The panel polls
/// `version` rather than being called back.
final class Diagnostics: @unchecked Sendable {
    static let shared = Diagnostics()
    static let capacity = 3000

    /// Which stream a line belongs to: the panel's filter and its middle column.
    enum Kind: String, CaseIterable, Sendable {
        case drop = "DROP"
        case discovery = "NET"
        case app = "APP"
    }

    struct Event: Identifiable, Sendable {
        let id: Int
        let at: Date
        let kind: Kind
        /// For a drop's line: its tag, "3F9A2C send".
        let tag: String?
        let text: String
        let isError: Bool
    }

    private let lock = NSLock()
    private var events: [Event] = []
    private var nextID = 0
    private var _version = 0

    /// Changes whenever anything is recorded or cleared.
    var version: Int { lock.withLock { _version } }
    var all: [Event] { lock.withLock { events } }

    func clear() {
        lock.withLock { events = []; _version += 1 }
    }

    /// Takes a log line as the engine and the app write it and files it under its kind.
    func record(_ line: String) {
        var kind = Kind.app, tag: String?, text = line
        if line.hasPrefix("["), let end = line.firstIndex(of: "]") {
            kind = .drop
            tag = String(line[line.index(after: line.startIndex)..<end])
            text = String(line[line.index(after: end)...]).trimmingCharacters(in: .whitespaces)
        } else if line.hasPrefix("discovery:") {
            kind = .discovery
            text = String(line.dropFirst("discovery:".count)).trimmingCharacters(in: .whitespaces)
        }
        let lowered = text.lowercased()
        let isError = ["failed", "lost", "damaged", "gave up", "cannot", "could not", "no sign of life", "moved nothing"].contains { lowered.contains($0) }
        lock.withLock {
            nextID += 1
            events.append(Event(id: nextID, at: Date(), kind: kind, tag: tag, text: text, isError: isError))
            if events.count > Self.capacity { events.removeFirst(events.count - Self.capacity) }
            _version += 1
        }
    }
}
