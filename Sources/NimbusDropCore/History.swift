// Copyright (C) 2026 Niels Joubert
// SPDX-License-Identifier: GPL-3.0-or-later
import Foundation

/// One finished drop, as the History window shows it: what, who, when, how it ended.
public struct HistoryEntry: Codable, Identifiable, Equatable, Sendable {
    public enum Outcome: String, Codable, Sendable { case completed, failed, declined, cancelled }

    public var id: UUID
    public var date: Date
    public var sent: Bool
    public var title: String
    public var peerName: String
    public var peerAddress: String
    public var files: Int
    public var bytes: Int64
    /// Seconds the bytes took to move, when they did.
    public var seconds: Double?
    public var outcome: Outcome
    /// Why it failed or was declined.
    public var detail: String?
    /// Received drops: where the items were saved.
    public var savedPaths: [String]
    /// What the drop got past, or was stopped by (absent in entries written before 0.2.0).
    public var rounds: Int?
    public var connectionsLost: Int?
    public var damagedChunks: Int?
    public var reconnects: Int?
    public var retransmittedChunks: Int?
    public var skippedLinks: Int?

    public init(id: UUID = UUID(), date: Date, sent: Bool, title: String, peerName: String, peerAddress: String,
                files: Int, bytes: Int64, seconds: Double?, outcome: Outcome, detail: String?, savedPaths: [String]) {
        self.id = id; self.date = date; self.sent = sent; self.title = title; self.peerName = peerName
        self.peerAddress = peerAddress; self.files = files; self.bytes = bytes; self.seconds = seconds
        self.outcome = outcome; self.detail = detail; self.savedPaths = savedPaths
    }
}

/// The record of past drops, kept in one JSON file on this Mac and nowhere else. Newest first,
/// and no more than `limit` of them.
public struct HistoryStore {
    public static let limit = 500
    public let url: URL
    public private(set) var entries: [HistoryEntry]

    /// Reads the file; one that is missing or unreadable is an empty history, not an error.
    public init(url: URL) {
        self.url = url
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        entries = (try? Data(contentsOf: url)).flatMap { try? decoder.decode([HistoryEntry].self, from: $0) } ?? []
    }

    public mutating func add(_ entry: HistoryEntry) {
        entries.insert(entry, at: 0)
        if entries.count > Self.limit { entries.removeLast(entries.count - Self.limit) }
        save()
    }

    public mutating func clear() {
        entries = []
        save()
    }

    private func save() {
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        encoder.outputFormatting = [.prettyPrinted]
        try? FileManager.default.createDirectory(at: url.deletingLastPathComponent(), withIntermediateDirectories: true)
        try? encoder.encode(entries).write(to: url, options: .atomic)
    }
}
