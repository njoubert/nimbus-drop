// Copyright (C) 2026 Niels Joubert
// SPDX-License-Identifier: GPL-3.0-or-later
import Foundation

/// How much a log line matters. Set where the line is written, by what it reports; nothing
/// downstream guesses it from the words ("0 damaged, connections lost 0" is a good drop).
///
/// - `debug`: detail for following the engine step by step (connections opened, what a round
///   sent, where a partial folder is).
/// - `info`: the story of a drop and of the network as a person would tell it (offered,
///   accepted, moving, done; a Mac found or gone).
/// - `warn`: trouble the drop is getting past (a connection lost, a damaged chunk, the control
///   connection gone and being won back, a reconnect attempt that did not get through).
/// - `error`: trouble that ended something (a drop failed, reconnecting given up, cannot listen).
public enum LogLevel: Int, Comparable, CaseIterable, Sendable {
    case debug, info, warn, error

    public static func < (a: LogLevel, b: LogLevel) -> Bool { a.rawValue < b.rawValue }

    /// As it is written in the log file: a fixed five columns.
    public var label: String {
        switch self {
        case .debug: return "DEBUG"
        case .info: return "INFO "
        case .warn: return "WARN "
        case .error: return "ERROR"
        }
    }

    public init?(label: String) {
        switch label.trimmingCharacters(in: .whitespaces) {
        case "DEBUG": self = .debug
        case "INFO": self = .info
        case "WARN": self = .warn
        case "ERROR": self = .error
        default: return nil
        }
    }
}

/// The debug log: what the engine and the app did, in order, with times and levels. One line per
/// event, for working out afterwards why a drop went the way it did. Where the lines go is the
/// app's business (`sink`); with no sink set, nothing is recorded and nothing is spent.
public enum DropLog {
    nonisolated(unsafe) public static var sink: (@Sendable (LogLevel, String) -> Void)?

    public static func write(_ line: @autoclosure () -> String, _ level: LogLevel = .info) {
        guard let sink else { return }
        sink(level, line())
    }
}

/// A value behind a lock, for the small shared tables the engine keeps.
public final class Locked<T>: @unchecked Sendable {
    private let lock = NSLock()
    private var value: T
    public init(_ value: T) { self.value = value }
    public func withLock<R>(_ body: (inout T) -> R) -> R {
        lock.lock()
        defer { lock.unlock() }
        return body(&value)
    }
}

/// A log file that looks after itself: lines are stamped and appended from any thread, and when
/// the file passes `rotateAt` it becomes `<name>.1` (replacing the one before) and a new file
/// starts. So there are at most two files and a bounded amount of disk.
public final class LogFile: @unchecked Sendable {
    public let url: URL
    private let rotateAt: Int
    private let queue = DispatchQueue(label: "com.njoubert.nimbusdrop.log")
    private var handle: FileHandle?
    private var size = 0
    private let stamp: DateFormatter = {
        let f = DateFormatter()
        f.locale = Locale(identifier: "en_US_POSIX")
        f.dateFormat = "yyyy-MM-dd HH:mm:ss.SSS"
        return f
    }()

    public init(url: URL, rotateAt: Int = 4 << 20) {
        self.url = url
        self.rotateAt = rotateAt
    }

    public func append(_ line: String) {
        let now = Date()
        queue.async { [self] in
            if handle == nil { open() }
            guard let handle, let data = "\(stamp.string(from: now)) \(line)\n".data(using: .utf8) else { return }
            handle.write(data)
            size += data.count
            if size > rotateAt { rotate() }
        }
    }

    /// Waits for everything appended so far to be on disk (the tests, and quitting).
    public func flush() { queue.sync { try? handle?.synchronize() } }

    private func open() {
        let fm = FileManager.default
        try? fm.createDirectory(at: url.deletingLastPathComponent(), withIntermediateDirectories: true)
        if !fm.fileExists(atPath: url.path) { fm.createFile(atPath: url.path, contents: nil) }
        handle = try? FileHandle(forWritingTo: url)
        size = Int((try? handle?.seekToEnd()) ?? 0)
    }

    private func rotate() {
        try? handle?.close()
        let old = url.appendingPathExtension("1")
        try? FileManager.default.removeItem(at: old)
        try? FileManager.default.moveItem(at: url, to: old)
        handle = nil
        size = 0
        open()
    }
}
