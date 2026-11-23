// Copyright (C) 2026 Niels Joubert
// SPDX-License-Identifier: GPL-3.0-or-later
import Darwin
import Foundation

/// Every file operation a receiver performs on a drop, confined to one folder.
///
/// A manifest's paths come from another machine. `Manifest.validate` checks them as text, and
/// text is not what the disk goes by: on a Mac's case-insensitive volume `Photos/x` and
/// `Photos/X` are one name, so a manifest could call one a symlink out of the drop and the
/// other a folder with a file in it, pass every textual check, and have the file land wherever
/// the symlink pointed (found by a security review on 2026-11-22: one accepted drop could
/// write `~/Library/LaunchAgents/evil.plist`).
///
/// So nothing here trusts a path. Each one is walked from the root a component at a time with
/// `openat(…, O_NOFOLLOW | O_DIRECTORY)`, which refuses anything on the way that is not a real
/// directory; and whatever is found already in place (a resumed drop, or a name the disk
/// considers taken) must be exactly the kind of thing the manifest says, or the drop ends.
final class SafeTree {
    private let root: Int32
    /// The directory the last operation was in: entries arrive folder by folder.
    private var cachedPath: String?
    private var cachedFD: Int32 = -1

    init(root url: URL) throws {
        root = open(url.path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW)
        guard root >= 0 else { throw errnoError("Cannot open \(url.path)") }
    }

    deinit {
        if cachedFD >= 0 { close(cachedFD) }
        close(root)
    }

    private static func split(_ path: String) -> (parent: String, name: String) {
        guard let slash = path.lastIndex(of: "/") else { return ("", path) }
        return (String(path[..<slash]), String(path[path.index(after: slash)...]))
    }

    /// The directory holding `path`, opened without following a symlink anywhere on the way.
    /// The descriptor belongs to the tree; do not close it.
    private func parent(of path: String) throws -> (fd: Int32, name: String) {
        let (dir, name) = Self.split(path)
        if dir.isEmpty { return (root, name) }
        if dir == cachedPath { return (cachedFD, name) }
        var fd = dup(root)
        guard fd >= 0 else { throw errnoError("Cannot open the drop's folder") }
        for component in dir.split(separator: "/") {
            let next = openat(fd, String(component), O_RDONLY | O_DIRECTORY | O_NOFOLLOW)
            close(fd)
            guard next >= 0 else {
                throw DropError("\(dir) is not a folder inside the drop (\(String(cString: strerror(errno)))); the drop was refused")
            }
            fd = next
        }
        if cachedFD >= 0 { close(cachedFD) }
        cachedPath = dir
        cachedFD = fd
        return (fd, name)
    }

    private func kind(_ fd: Int32, _ name: String) -> mode_t? {
        var st = stat()
        return fstatat(fd, name, &st, AT_SYMLINK_NOFOLLOW) == 0 ? st.st_mode & S_IFMT : nil
    }

    /// Makes a folder. One already there must be a folder, not something else under that name.
    func makeDirectory(_ path: String) throws {
        let (fd, name) = try parent(of: path)
        if mkdirat(fd, name, 0o700) == 0 { return }
        guard errno == EEXIST, kind(fd, name) == S_IFDIR else {
            throw DropError("\(path) cannot be made a folder: something else has that name; the drop was refused")
        }
    }

    /// Makes a symlink. One already there must be the same link.
    func makeSymlink(_ path: String, to target: String) throws {
        let (fd, name) = try parent(of: path)
        if symlinkat(target, fd, name) == 0 { return }
        var buffer = [CChar](repeating: 0, count: Int(PATH_MAX) + 1)
        let n = errno == EEXIST && kind(fd, name) == S_IFLNK ? readlinkat(fd, name, &buffer, Int(PATH_MAX)) : -1
        guard n >= 0, String(decoding: buffer.prefix(n).map { UInt8(bitPattern: $0) }, as: UTF8.self) == target else {
            throw DropError("\(path) cannot be made a link: something else has that name; the drop was refused")
        }
    }

    /// Opens a file for writing, creating it if need be. It is never a symlink and never
    /// anything but an ordinary file. The caller closes the descriptor.
    func openFile(_ path: String) throws -> Int32 {
        let (dir, name) = try parent(of: path)
        let fd = openat(dir, name, O_WRONLY | O_CREAT | O_NOFOLLOW, 0o600)
        guard fd >= 0 else { throw errnoError("Cannot create \(path)") }
        var st = stat()
        guard fstat(fd, &st) == 0, st.st_mode & S_IFMT == S_IFREG, st.st_nlink == 1 else {
            close(fd)
            throw DropError("\(path) is not an ordinary file; the drop was refused")
        }
        return fd
    }

    /// The size of the ordinary file at `path`, or nil when there is none (or it is something else).
    func fileSize(_ path: String) -> Int64? {
        guard let (fd, name) = try? parent(of: path) else { return nil }
        var st = stat()
        guard fstatat(fd, name, &st, AT_SYMLINK_NOFOLLOW) == 0, st.st_mode & S_IFMT == S_IFREG else { return nil }
        return Int64(st.st_size)
    }

    /// Sets the modification time and the permission bits of the thing itself, never of
    /// something it might point to.
    func finish(_ path: String, mtime: Double, mode: mode_t) {
        guard let (fd, name) = try? parent(of: path) else { return }
        var times = [timespec(tv_sec: 0, tv_nsec: Int(UTIME_OMIT)),
                     timespec(tv_sec: Int(mtime), tv_nsec: Int((mtime - mtime.rounded(.down)) * 1e9))]
        utimensat(fd, name, &times, AT_SYMLINK_NOFOLLOW)
        fchmodat(fd, name, mode, AT_SYMLINK_NOFOLLOW)
    }

    /// Lets go of the cached directory (before the tree is moved).
    func release() {
        if cachedFD >= 0 { close(cachedFD) }
        cachedFD = -1
        cachedPath = nil
    }
}
