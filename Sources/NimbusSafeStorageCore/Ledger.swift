// Copyright (C) 2026 Niels Joubert
// SPDX-License-Identifier: GPL-3.0-or-later
import Darwin
import Foundation
import NimbusBase

/// Which chunks of a drop are already on the receiver's disk. An append-only file of
/// `(file, chunk)` pairs beside the partial data, written after each chunk lands, so a drop that
/// is interrupted (the app quit, the link dropped, the lid closed) continues where it stopped.
///
/// The records reach the page cache, not the platter: they survive the process, not a power cut.
/// A receiver that lost power mid-drop should have its partial folder deleted rather than resumed.
package final class Ledger: @unchecked Sendable {
    private let manifest: Manifest
    private let lock = NSLock()
    private var done = Set<UInt64>()
    /// Chunks still missing, per manifest entry.
    private var remaining: [Int32]
    private var fd: Int32 = -1
    private var _doneBytes: Int64 = 0
    private var _doneFiles = 0
    package var doneBytes: Int64 { lock.withLock { _doneBytes } }
    package var doneFiles: Int { lock.withLock { _doneFiles } }

    private static func pack(_ file: Int, _ chunk: Int) -> UInt64 { UInt64(file) << 32 | UInt64(chunk) }

    /// Opens (or starts) the ledger: the file beside the tree's root that has the last name of
    /// `url`. A record counts only if the file it speaks of is still there in the tree, an
    /// ordinary file long enough to hold that chunk; the rest are forgotten.
    ///
    /// It is opened once, through the tree (`SafeTree.openBeside`: no symlink, an ordinary
    /// file, one name), and read, rewritten and appended to through that one descriptor. It
    /// used to go by its path, three times: with a link put where the ledger was, the file at
    /// the other end was read, emptied, and had the drop's records appended to it.
    package init(url: URL, manifest: Manifest, tree: SafeTree) throws {
        self.manifest = manifest
        remaining = manifest.entries.indices.map { Int32(clamping: manifest.chunkCount($0)) }
        fd = try tree.openBeside(url.lastPathComponent)

        var st = stat()
        fstat(fd, &st)
        var data = Data(count: Int(max(0, st.st_size)))
        let got = data.withUnsafeMutableBytes { raw -> Int in
            var n = 0
            while n < raw.count {
                let r = pread(fd, raw.baseAddress! + n, raw.count - n, off_t(n))
                if r > 0 { n += r } else if r == 0 || errno != EINTR { break }
            }
            return n
        }
        data.count = got

        var kept: [(Int, Int)] = []
        var sizes: [Int: Int64] = [:]
        data.withUnsafeBytes { raw in
            for i in 0..<(raw.count / 8) {
                let file = Int(UInt32(bigEndian: raw.loadUnaligned(fromByteOffset: i * 8, as: UInt32.self)))
                let chunk = Int(UInt32(bigEndian: raw.loadUnaligned(fromByteOffset: i * 8 + 4, as: UInt32.self)))
                guard file < manifest.entries.count, chunk < manifest.chunkCount(file) else { continue }
                let onDisk: Int64
                if let s = sizes[file] { onDisk = s } else {
                    onDisk = tree.fileSize(manifest.entries[file].path) ?? -1
                    sizes[file] = onDisk
                }
                let end = Int64(chunk) * Int64(manifest.chunkSize) + Int64(manifest.chunkLength(file: file, chunk: chunk))
                if onDisk >= end, done.insert(Ledger.pack(file, chunk)).inserted { kept.append((file, chunk)) }
            }
        }
        for (file, chunk) in kept { account(file, chunk) }

        // Rewritten compacted, so a torn tail or a forgotten record does not linger.
        var out = Data(capacity: kept.count * 8)
        for (file, chunk) in kept { Ledger.append(file, chunk, to: &out) }
        let rewritten = ftruncate(fd, 0) == 0 && out.withUnsafeBytes { raw -> Bool in
            var n = 0
            while n < raw.count {
                let w = write(fd, raw.baseAddress! + n, raw.count - n)
                if w > 0 { n += w } else if errno != EINTR { return false }
            }
            return true
        }
        guard rewritten else {
            let error = errnoError("Cannot write the resume ledger")
            close(fd)
            fd = -1
            throw error
        }
    }

    deinit { if fd >= 0 { close(fd) } }

    private static func append(_ file: Int, _ chunk: Int, to data: inout Data) {
        var f = UInt32(file).bigEndian, c = UInt32(chunk).bigEndian
        withUnsafeBytes(of: &f) { data.append(contentsOf: $0) }
        withUnsafeBytes(of: &c) { data.append(contentsOf: $0) }
    }

    private func account(_ file: Int, _ chunk: Int) {
        _doneBytes += Int64(manifest.chunkLength(file: file, chunk: chunk))
        remaining[file] -= 1
        if remaining[file] == 0 { _doneFiles += 1 }
    }

    /// Notes a chunk as written. Returns whether that completed its file.
    @discardableResult
    package func record(file: Int, chunk: Int) throws -> Bool {
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

    package var isComplete: Bool {
        lock.lock()
        defer { lock.unlock() }
        return remaining.allSatisfy { $0 == 0 }
    }

    /// What the sender may skip.
    package func plan() -> Plan {
        lock.lock()
        defer { lock.unlock() }
        var complete: [Int] = []
        var partial: [Int: [Int]] = [:]
        for key in done {
            let file = Int(key >> 32)
            if remaining[file] != 0 { partial[file, default: []].append(Int(key & 0xFFFF_FFFF)) }
        }
        for (file, left) in remaining.enumerated() where left == 0 && manifest.chunkCount(file) > 0 { complete.append(file) }
        return Plan(completeFiles: complete,
                    partialFiles: partial.keys.sorted().map { Plan.Partial(file: $0, chunks: partial[$0]!.sorted()) })
    }
}
