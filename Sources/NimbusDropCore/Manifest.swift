// Copyright (C) 2026 Niels Joubert
// SPDX-License-Identifier: GPL-3.0-or-later
import CryptoKit
import Darwin
import Foundation
import zlib

/// Everything in a drop: every folder, file and symlink with its size, time and mode. Folders
/// come before what they hold.
public struct Manifest: Codable, Equatable {
    public enum Kind: Int, Codable { case file = 0, directory = 1, symlink = 2 }

    public struct Entry: Codable, Equatable {
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

    /// What a receiver checks before it creates anything: a manifest is input from another
    /// machine, and its paths become paths on this one.
    public func validate() throws {
        guard chunkSize >= 4096, chunkSize <= 64 << 20 else { throw DropError("The drop's chunk size is not acceptable") }
        var directories = Set<String>()
        var seen = Set<String>()
        for e in entries {
            let parts = e.path.split(separator: "/", omittingEmptySubsequences: false)
            guard !e.path.isEmpty, !e.path.hasPrefix("/"), !e.path.utf8.contains(0),
                  parts.allSatisfy({ !$0.isEmpty && $0 != "." && $0 != ".." && $0.utf8.count <= 255 }) else {
                throw DropError("The drop contains an unsafe path: \(e.path)")
            }
            guard seen.insert(e.path).inserted else { throw DropError("The drop lists \(e.path) twice") }
            if parts.count > 1 {
                // The parent must be a folder this manifest made, never a symlink or something
                // already on disk.
                let parent = parts.dropLast().joined(separator: "/")
                guard directories.contains(parent) else { throw DropError("The drop puts \(e.path) outside its folders") }
            }
            switch e.kind {
            case .directory: directories.insert(e.path)
            case .file: guard e.size >= 0 else { throw DropError("The drop has a negative size for \(e.path)") }
            case .symlink: guard let l = e.link, !l.isEmpty else { throw DropError("The drop has an empty link at \(e.path)") }
            }
        }
        guard !entries.isEmpty else { throw DropError("The drop is empty") }
    }
}

/// A manifest and where each of its entries lives on the sending Mac.
public struct ScannedDrop {
    public var manifest: Manifest
    /// Absolute source path per entry.
    public var sources: [String]
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

/// CRC-32 (zlib's, which uses the CPU's CRC instructions on Apple silicon). `seed` continues an
/// earlier checksum, so a header and its chunk are covered as one.
@inline(__always)
func checksum(_ p: UnsafeRawPointer, _ count: Int, seed: UInt32 = 0) -> UInt32 {
    UInt32(truncatingIfNeeded: crc32(uLong(seed), p.assumingMemoryBound(to: UInt8.self), uInt(count)))
}
