// Copyright (C) 2026 Niels Joubert
// SPDX-License-Identifier: GPL-3.0-or-later
import Darwin
import Foundation

/// Which chunks of a drop are already on the receiver's disk. An append-only file of
/// `(file, chunk)` pairs beside the partial data, written after each chunk lands, so a drop that
/// is interrupted (the app quit, the link dropped, the lid closed) continues where it stopped.
///
/// The records reach the page cache, not the platter: they survive the process, not a power cut.
/// A receiver that lost power mid-drop should have its partial folder deleted rather than resumed.
final class Ledger: @unchecked Sendable {
    private let manifest: Manifest
    private let lock = NSLock()
    private var done = Set<UInt64>()
    /// Chunks still missing, per manifest entry.
    private var remaining: [Int32]
    private var fd: Int32 = -1
    private(set) var doneBytes: Int64 = 0
    private(set) var doneFiles = 0

    private static func pack(_ file: Int, _ chunk: Int) -> UInt64 { UInt64(file) << 32 | UInt64(chunk) }

    /// Opens (or starts) the ledger at `url`. A record counts only if the file it speaks of is
    /// still there under `root` and long enough to hold that chunk; the rest are forgotten.
    init(url: URL, manifest: Manifest, root: URL) throws {
        self.manifest = manifest
        remaining = manifest.entries.indices.map { Int32(manifest.chunkCount($0)) }

        var kept: [(Int, Int)] = []
        if let data = try? Data(contentsOf: url) {
            var sizes: [Int: Int64] = [:]
            data.withUnsafeBytes { raw in
                for i in 0..<(raw.count / 8) {
                    let file = Int(UInt32(bigEndian: raw.loadUnaligned(fromByteOffset: i * 8, as: UInt32.self)))
                    let chunk = Int(UInt32(bigEndian: raw.loadUnaligned(fromByteOffset: i * 8 + 4, as: UInt32.self)))
                    guard file < manifest.entries.count, chunk < manifest.chunkCount(file) else { continue }
                    let onDisk: Int64
                    if let s = sizes[file] { onDisk = s } else {
                        var st = stat()
                        onDisk = lstat(root.appendingPathComponent(manifest.entries[file].path).path, &st) == 0
                            && st.st_mode & S_IFMT == S_IFREG ? Int64(st.st_size) : -1
                        sizes[file] = onDisk
                    }
                    let end = Int64(chunk) * Int64(manifest.chunkSize) + Int64(manifest.chunkLength(file: file, chunk: chunk))
                    if onDisk >= end, done.insert(Ledger.pack(file, chunk)).inserted { kept.append((file, chunk)) }
                }
            }
        }
        for (file, chunk) in kept { account(file, chunk) }

        // Rewritten compacted, so a torn tail or a forgotten record does not linger.
        var out = Data(capacity: kept.count * 8)
        for (file, chunk) in kept { Ledger.append(file, chunk, to: &out) }
        try out.write(to: url)
        fd = open(url.path, O_WRONLY | O_APPEND)
        guard fd >= 0 else { throw errnoError("Cannot write the resume ledger") }
    }

    deinit { if fd >= 0 { close(fd) } }

    private static func append(_ file: Int, _ chunk: Int, to data: inout Data) {
        var f = UInt32(file).bigEndian, c = UInt32(chunk).bigEndian
        withUnsafeBytes(of: &f) { data.append(contentsOf: $0) }
        withUnsafeBytes(of: &c) { data.append(contentsOf: $0) }
    }

    private func account(_ file: Int, _ chunk: Int) {
        doneBytes += Int64(manifest.chunkLength(file: file, chunk: chunk))
        remaining[file] -= 1
        if remaining[file] == 0 { doneFiles += 1 }
    }

    /// Notes a chunk as written. Returns whether that completed its file.
    @discardableResult
    func record(file: Int, chunk: Int) throws -> Bool {
        lock.lock()
        defer { lock.unlock() }
        guard done.insert(Ledger.pack(file, chunk)).inserted else { return false }
        account(file, chunk)
        var record = Data(capacity: 8)
        Ledger.append(file, chunk, to: &record)
        let wrote = record.withUnsafeBytes { write(fd, $0.baseAddress, 8) }
        guard wrote == 8 else { throw errnoError("Cannot write the resume ledger") }
        return remaining[file] == 0
    }

    var isComplete: Bool {
        lock.lock()
        defer { lock.unlock() }
        return remaining.allSatisfy { $0 == 0 }
    }

    /// What the sender may skip.
    func plan(token: String) -> Plan {
        lock.lock()
        defer { lock.unlock() }
        var complete: [Int] = []
        var partial: [Int: [Int]] = [:]
        for key in done {
            let file = Int(key >> 32)
            if remaining[file] != 0 { partial[file, default: []].append(Int(key & 0xFFFF_FFFF)) }
        }
        for (file, left) in remaining.enumerated() where left == 0 && manifest.chunkCount(file) > 0 { complete.append(file) }
        return Plan(token: token, completeFiles: complete,
                    partialFiles: partial.keys.sorted().map { Plan.Partial(file: $0, chunks: partial[$0]!.sorted()) })
    }
}
