// Copyright (C) 2026 Niels Joubert
// SPDX-License-Identifier: GPL-3.0-or-later
import Foundation

/// The debug log: what the engine and the app did, in order, with times. One line per event,
/// for working out afterwards why a drop went the way it did. Where the lines go is the app's
/// business (`sink`); with no sink set, nothing is recorded and nothing is spent.
public enum DropLog {
    nonisolated(unsafe) public static var sink: (@Sendable (String) -> Void)?

    public static func write(_ line: @autoclosure () -> String) {
        guard let sink else { return }
        sink(line())
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
