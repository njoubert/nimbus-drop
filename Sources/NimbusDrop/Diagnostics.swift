// Copyright (C) 2026 Niels Joubert
// SPDX-License-Identifier: GPL-3.0-or-later
import Foundation
import NimbusDropCore

/// The app's flight recorder, as in Nimbus Leviton Bar: every line that goes to the log file is
/// also kept here, in memory, for the Internals panel to show live. It records from launch, not
/// from when the panel opens (what is worth seeing has usually happened by the time anyone
/// looks), it starts each launch with the end of the log file (so earlier runs are there too),
/// and it is bounded: the newest `capacity` lines.
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
        let level: LogLevel
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

    /// Fills the buffer with the end of the log file, so that what happened before this launch
    /// (which is often the thing being looked for) is in the panel too. The file is the record;
    /// this is its last `capacity` lines read back.
    func seed(from url: URL) {
        let stamp = DateFormatter()
        stamp.locale = Locale(identifier: "en_US_POSIX")
        stamp.dateFormat = "yyyy-MM-dd HH:mm:ss.SSS"
        var lines: [Substring] = []
        // The file before the last rotation first, so a recent rotation does not empty the panel.
        for file in [url.appendingPathExtension("1"), url] {
            guard let text = try? String(contentsOf: file, encoding: .utf8) else { continue }
            lines += text.split(separator: "\n", omittingEmptySubsequences: true)
        }
        for line in lines.suffix(Self.capacity) where line.count > 24 {
            let cut = line.index(line.startIndex, offsetBy: 23)
            guard let at = stamp.date(from: String(line[..<cut])) else { continue }
            var rest = line[line.index(after: cut)...]
            // "INFO  …": the level, in five columns. Lines from before levels existed have none.
            var level = LogLevel.info
            if rest.count > 6, let parsed = LogLevel(label: String(rest.prefix(5))), rest[rest.index(rest.startIndex, offsetBy: 5)] == " " {
                level = parsed
                rest = rest.dropFirst(6)
            }
            record(level, String(rest), at: at)
        }
    }

    /// Takes a log line as the engine and the app write it and files it under its kind. Its
    /// level is the one it was written with.
    func record(_ level: LogLevel, _ line: String, at: Date = Date()) {
        var kind = Kind.app, tag: String?, text = line
        if line.hasPrefix("["), let end = line.firstIndex(of: "]") {
            kind = .drop
            tag = String(line[line.index(after: line.startIndex)..<end])
            text = String(line[line.index(after: end)...]).trimmingCharacters(in: .whitespaces)
        } else if line.hasPrefix("discovery:") {
            kind = .discovery
            text = String(line.dropFirst("discovery:".count)).trimmingCharacters(in: .whitespaces)
        }
        lock.withLock {
            nextID += 1
            events.append(Event(id: nextID, at: at, kind: kind, tag: tag, text: text, level: level))
            if events.count > Self.capacity { events.removeFirst(events.count - Self.capacity) }
            _version += 1
        }
    }
}
