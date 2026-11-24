// Copyright (C) 2026 Niels Joubert
// SPDX-License-Identifier: GPL-3.0-or-later
import CryptoKit
import Darwin
import Foundation
import NimbusBase

/// Everything in a drop: every folder, file and symlink with its size, time and mode. Folders
/// come before what they hold.
public struct Manifest: Codable, Equatable, Sendable {
    public enum Kind: Int, Codable, Sendable { case file = 0, directory = 1, symlink = 2 }

    public struct Entry: Codable, Equatable, Sendable {
        /// Relative, `/`-separated, starting with the top-level item's name.
        public var path: String
        public var kind: Kind
        public var size: Int64
        /// Modification time, seconds since 1970.
        public var mtime: Double
        /// Permission bits (`st_mode & 0o7777`).
        public var mode: UInt16
        public var link: String?

        enum CodingKeys: String, CodingKey { case path = "p", kind = "k", size = "s", mtime = "m", mode = "o", link = "l" }

        public init(path: String, kind: Kind, size: Int64 = 0, mtime: Double = 0, mode: UInt16 = 0o644, link: String? = nil) {
            self.path = path; self.kind = kind; self.size = size; self.mtime = mtime; self.mode = mode; self.link = link
        }
    }

    public var chunkSize: Int
    public var entries: [Entry]

    public init(chunkSize: Int, entries: [Entry]) {
        self.chunkSize = chunkSize
        self.entries = entries
    }

    public var totalBytes: Int64 { entries.reduce(0) { $0 + ($1.kind == .file ? $1.size : 0) } }
    public var fileCount: Int { entries.reduce(0) { $0 + ($1.kind == .file ? 1 : 0) } }
    public var topLevelNames: [String] { entries.filter { !$0.path.contains("/") }.map(\.path) }

    public func chunkCount(_ file: Int) -> Int {
        let e = entries[file]
        guard e.kind == .file, e.size > 0 else { return 0 }
        return Int((e.size + Int64(chunkSize) - 1) / Int64(chunkSize))
    }

    public func chunkLength(file: Int, chunk: Int) -> Int {
        let size = entries[file].size
        let start = Int64(chunk) * Int64(chunkSize)
        return Int(min(Int64(chunkSize), size - start))
    }

    /// Identifies this exact drop from this sender: same paths, sizes and times give the same
    /// key, which is how a re-sent drop finds the partial folder of its earlier attempt.
    public func key(senderID: String) -> String {
        var hash = SHA256()
        hash.update(data: Data("\(senderID)\n\(chunkSize)\n".utf8))
        for e in entries {
            hash.update(data: Data("\(e.path)\0\(e.kind.rawValue)\0\(e.size)\0\(e.mtime)\0\(e.link ?? "")\n".utf8))
        }
        return hash.finalize().map { String(format: "%02x", $0) }.joined()
    }

    /// The most entries a manifest may have, and the largest file: bounds that keep hostile
    /// numbers from overflowing the arithmetic done with them, far above any real drop.
    public static let maxEntries = 2_000_000
    public static let maxFileSize: Int64 = 1 << 50
    /// And the most bytes in all. Without it the sum itself overflowed: 8,192 files of the
    /// largest size come to 2^63, and adding them up trapped. One accepted drop (or none, for
    /// a key with a standing grant) crashed the receiver (found by an independent review,
    /// 2026-11-24; the comment that said it could not happen had multiplied wrongly).
    public static let maxTotalBytes: Int64 = 1 << 60

    /// What the disk will take two names to be the same by: a Mac's volume is, by default,
    /// insensitive to case and to how accents are composed.
    static func folded(_ path: String) -> String { path.precomposedStringWithCanonicalMapping.lowercased() }

    /// Whether a symlink at `path` pointing to `link` stays inside its own top-level item.
    /// A link that does not (an absolute one, or one that climbs out with "..") is not
    /// recreated by a receiver: it would leave in the received folder a door to somewhere else
    /// on that Mac. The rule is strict on purpose: "relative, with any ".." only at the start
    /// and no more of them than there are folders to climb". A link like "a/../b" is refused
    /// though it is harmless, because telling the harmless ones apart means resolving links
    /// through other links.
    public static func linkStaysInside(path: String, link: String) -> Bool {
        guard !link.isEmpty, !link.hasPrefix("/") else { return false }
        // Folders between the top-level item and the link: "Photos/a/b/link" has two.
        let room = path.split(separator: "/").count - 2
        guard room >= 0 else { return false }   // the top-level item itself is a link: nothing to stay inside
        var climbing = true, climbed = 0
        for part in link.split(separator: "/", omittingEmptySubsequences: true) where part != "." {
            if part == ".." {
                guard climbing else { return false }
                climbed += 1
            } else {
                climbing = false
            }
        }
        return climbed <= room
    }

    /// What a receiver checks before it creates anything: a manifest is input from another
    /// machine, and its paths become paths on this one. This is the check of the text;
    /// `SafeTree` is the check against the disk, and both must hold.
    public func validate() throws {
        guard chunkSize >= 4096, chunkSize <= 64 << 20 else { throw DropError("The drop's chunk size is not acceptable") }
        guard !entries.isEmpty else { throw DropError("The drop is empty") }
        guard entries.count <= Self.maxEntries else { throw DropError("The drop lists more entries than can be accepted") }
        var directories = Set<String>()
        var seen = Set<String>()
        var total: Int64 = 0
        for e in entries {
            let parts = e.path.split(separator: "/", omittingEmptySubsequences: false)
            guard !e.path.isEmpty, !e.path.hasPrefix("/"), !e.path.utf8.contains(0),
                  parts.allSatisfy({ !$0.isEmpty && $0 != "." && $0 != ".." && $0.utf8.count <= 255 }) else {
                throw DropError("The drop contains an unsafe path: \(Sanitize.label(e.path, limit: 120))")
            }
            // Unique as the disk sees names, not only as text: "x" and "X" are one file here, and
            // a drop that used both for different things could aim a write through a symlink.
            guard seen.insert(Self.folded(e.path)).inserted else {
                throw DropError("The drop lists \(Sanitize.label(e.path, limit: 120)) twice (names that differ only in case are one name on a Mac)")
            }
            if parts.count > 1 {
                // The parent must be a folder this manifest made, never a symlink or something
                // already on disk.
                let parent = Self.folded(parts.dropLast().joined(separator: "/"))
                guard directories.contains(parent) else { throw DropError("The drop puts \(Sanitize.label(e.path, limit: 120)) outside its folders") }
            }
            // A time that is a number a calendar could hold (the year 5000 is generous).
            guard e.mtime.isFinite, abs(e.mtime) < 1e11 else { throw DropError("The drop has an impossible date for \(Sanitize.label(e.path, limit: 120))") }
            switch e.kind {
            case .directory: directories.insert(Self.folded(e.path))
            case .file:
                guard e.size >= 0, e.size <= Self.maxFileSize else { throw DropError("The drop has an impossible size for \(Sanitize.label(e.path, limit: 120))") }
                // A chunk is named on the wire by 32 bits; a file of more chunks than that cannot be sent.
                guard e.size / Int64(chunkSize) < Int64(UInt32.max) else { throw DropError("The drop has a file of more chunks than can be numbered: \(Sanitize.label(e.path, limit: 120))") }
                // Both are at most 2^60 here, so neither the test nor the sum can overflow.
                guard e.size <= Self.maxTotalBytes - total else { throw DropError("The drop is larger than can be accepted") }
                total += e.size
            case .symlink:
                guard let l = e.link, !l.isEmpty, !l.utf8.contains(0), l.utf8.count <= Int(PATH_MAX) else {
                    throw DropError("The drop has an unusable link at \(Sanitize.label(e.path, limit: 120))")
                }
            }
        }
    }
}

/// A manifest and where each of its entries lives on the sending Mac.
public struct ScannedDrop: Sendable {
    public var manifest: Manifest
    /// Absolute source path per entry.
    public var sources: [String]

    public init(manifest: Manifest, sources: [String]) {
        self.manifest = manifest
        self.sources = sources
    }
}

public enum Scanner {
    /// The default chunk: big enough that per-chunk costs vanish, small enough that eight
    /// streams hold 32 MB of buffers and a resumed drop loses little.
    public static let defaultChunkSize = 4 << 20

    /// Walks the given files and folders. Symlinks are sent as symlinks, never followed;
    /// sockets, devices and pipes are skipped.
    public static func scan(_ urls: [URL], chunkSize: Int = defaultChunkSize, cancelled: () -> Bool = { false }) throws -> ScannedDrop {
        var entries: [Manifest.Entry] = []
        var sources: [String] = []
        var topNames = Set<String>()

        func add(path: String, relative: String) throws {
            if cancelled() { throw DropError("Cancelled") }
            var st = stat()
            guard lstat(path, &st) == 0 else { throw errnoError("Cannot read \(path)") }
            let mtime = Double(st.st_mtimespec.tv_sec) + Double(st.st_mtimespec.tv_nsec) / 1e9
            let mode = UInt16(st.st_mode & 0o7777)
            switch st.st_mode & S_IFMT {
            case S_IFDIR:
                entries.append(.init(path: relative, kind: .directory, mtime: mtime, mode: mode))
                sources.append(path)
                let names: [String]
                do { names = try FileManager.default.contentsOfDirectory(atPath: path).sorted() }
                catch { throw DropError("Cannot read the folder \(path): \(error.localizedDescription)") }
                for name in names { try add(path: path + "/" + name, relative: relative + "/" + name) }
            case S_IFREG:
                guard access(path, R_OK) == 0 else { throw errnoError("Cannot read \(path)") }
                entries.append(.init(path: relative, kind: .file, size: Int64(st.st_size), mtime: mtime, mode: mode))
                sources.append(path)
            case S_IFLNK:
                var buffer = [CChar](repeating: 0, count: Int(PATH_MAX) + 1)
                let n = readlink(path, &buffer, Int(PATH_MAX))
                guard n > 0 else { throw errnoError("Cannot read the link \(path)") }
                buffer[n] = 0
                entries.append(.init(path: relative, kind: .symlink, mtime: mtime, mode: mode, link: String(cString: buffer)))
                sources.append(path)
            default:
                break
            }
        }

        for url in urls {
            let path = url.standardizedFileURL.path
            // Two dragged items can share a name (a.jpg from two folders); the second is renamed
            // the way the receiver renames a collision.
            let name = Naming.unique(url.lastPathComponent, isDirectory: url.hasDirectoryPath) { topNames.contains($0) }
            topNames.insert(name)
            try add(path: path, relative: name)
        }
        guard !entries.isEmpty else { throw DropError("Nothing to send") }
        return ScannedDrop(manifest: Manifest(chunkSize: chunkSize, entries: entries), sources: sources)
    }
}

public enum Naming {
    /// Finder's "keep both": `Photos` → `Photos 2`, `a.jpg` → `a 2.jpg`, counting up until
    /// `taken` says the name is free.
    public static func unique(_ name: String, isDirectory: Bool, taken: (String) -> Bool) -> String {
        guard taken(name) else { return name }
        var stem = name, ext = ""
        if !isDirectory, let dot = name.lastIndex(of: "."), dot != name.startIndex {
            stem = String(name[..<dot])
            ext = String(name[dot...])
        }
        var n = 2
        while taken("\(stem) \(n)\(ext)") { n += 1 }
        return "\(stem) \(n)\(ext)"
    }
}
