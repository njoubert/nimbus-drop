// Copyright (C) 2026 Niels Joubert
// SPDX-License-Identifier: GPL-3.0-or-later
import Darwin
import Foundation
import NimbusBase

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
package final class SafeTree {
    /// The folder the root is in: a drop's partial folder. Held from the start, like the root,
    /// so that what is done later is done to these two folders and not to whatever has been
    /// given their names since.
    private let holder: Int32
    private let root: Int32
    /// The directory the last operation was in: entries arrive folder by folder.
    private var cachedPath: String?
    private var cachedFD: Int32 = -1

    /// Opens the tree at `url`, making it and the folder that holds it if they are not there.
    /// Neither is reached through a symlink. Refusing one at the root alone was not enough: a
    /// partial folder that was itself a link to somewhere else had the whole drop built
    /// there (`…/items` under it is a real folder, wherever it is). What leads to the folder
    /// that holds the root is the destination the person chose, and is taken as given.
    package init(root url: URL) throws {
        let folder = url.deletingLastPathComponent().path, name = url.lastPathComponent
        // (`mkdir` makes nothing where a link has the name, and `open` is told not to follow one.)
        mkdir(folder, 0o777)
        let holder = open(folder, O_RDONLY | O_DIRECTORY | O_NOFOLLOW)
        guard holder >= 0 else {
            throw errno == ELOOP || errno == ENOTDIR
                ? DropError("\(Sanitize.label(url.deletingLastPathComponent().lastPathComponent, limit: 160)) is in the way and is not a folder; the drop was refused")
                : errnoError("Cannot write to \(folder)")
        }
        mkdirat(holder, name, 0o777)
        let root = openat(holder, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW)
        guard root >= 0 else {
            let error = errnoError("Cannot open \(url.path)")
            close(holder)
            throw error
        }
        self.holder = holder
        self.root = root
    }

    deinit {
        if cachedFD >= 0 { close(cachedFD) }
        close(root)
        close(holder)
    }

    private static func split(_ path: String) -> (parent: String, name: String) {
        guard let slash = path.lastIndex(of: "/") else { return ("", path) }
        return (String(path[..<slash]), String(path[path.index(after: slash)...]))
    }

    /// Whether every part of `path` is a name: not empty, not "." or "..", and with no NUL in
    /// it (so the path is not absolute, and does not end in a slash, either).
    ///
    /// `Manifest.validate` refuses the same text before a drop begins, and for these paths it
    /// was the only gate: ".." is a real folder, which no refusal to follow symlinks minds, so
    /// a tree asked for `../x` made `x` outside itself. The tree does not rely on being asked
    /// only for what was checked elsewhere. (One pass over the bytes; nothing is allocated.)
    private static func isInside(_ path: String) -> Bool {
        var length = 0, dots = 0
        for byte in path.utf8 {
            if byte == 0 { return false }
            if byte == UInt8(ascii: "/") {
                if length == 0 || (dots == length && length <= 2) { return false }
                length = 0
                dots = 0
            } else {
                length += 1
                if byte == UInt8(ascii: ".") { dots += 1 }
            }
        }
        return length > 0 && !(dots == length && length <= 2)
    }

    /// The directory holding `path`, opened without following a symlink anywhere on the way.
    /// The descriptor belongs to the tree; do not close it.
    private func parent(of path: String) throws -> (fd: Int32, name: String) {
        guard Self.isInside(path) else { throw DropError("\(Sanitize.label(path, limit: 120)) is not a path inside the drop; the drop was refused") }
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

    /// One thing on a disk, whatever it is called.
    private struct Identity: Hashable { let device: dev_t, inode: ino_t }
    /// Which entry of the manifest each thing in the tree has been taken for.
    private var claimed: [Identity: String] = [:]

    /// Notes that the thing `st` describes is the manifest's entry `path`. Two entries are
    /// never one thing: a second path arriving at something an earlier one was taken for ends
    /// the drop.
    ///
    /// This is the disk's answer to "are these two names one name?", which the text of a
    /// manifest cannot give for every disk. `Manifest.validate` folds case and how accents are
    /// composed; a Mac's own volume folds case in full, so that `Maße.txt` and `Masse.txt` are
    /// two entries that pass and one file here. The second used to be opened as the first (it
    /// was there, and an ordinary file), the chunks of both went into it, the ledger called
    /// both complete, and the drop was put in place and reported complete with the wrong bytes.
    private func claim(_ st: stat, for path: String) throws {
        let id = Identity(device: st.st_dev, inode: st.st_ino)
        guard let other = claimed[id] else { claimed[id] = path; return }
        // (Compared as bytes: two spellings that are one text to Swift are still two entries.)
        guard other.utf8.elementsEqual(path.utf8) else {
            throw DropError("\(Sanitize.label(path, limit: 120)) and \(Sanitize.label(other, limit: 120)) are one name on this disk; the drop was refused")
        }
    }

    /// Makes a folder. One already there must be a folder, not something else under that
    /// name, and not the folder of another entry.
    package func makeDirectory(_ path: String) throws {
        let (fd, name) = try parent(of: path)
        var st = stat()
        guard mkdirat(fd, name, 0o700) == 0 || errno == EEXIST, fstatat(fd, name, &st, AT_SYMLINK_NOFOLLOW) == 0, st.st_mode & S_IFMT == S_IFDIR else {
            throw DropError("\(path) cannot be made a folder: something else has that name; the drop was refused")
        }
        try claim(st, for: path)
    }

    /// Makes a symlink. One already there must be the same link, and not another entry's.
    package func makeSymlink(_ path: String, to target: String) throws {
        let (fd, name) = try parent(of: path)
        if symlinkat(target, fd, name) != 0 {
            var buffer = [CChar](repeating: 0, count: Int(PATH_MAX) + 1)
            let n = errno == EEXIST && kind(fd, name) == S_IFLNK ? readlinkat(fd, name, &buffer, Int(PATH_MAX)) : -1
            guard n >= 0, String(decoding: buffer.prefix(n).map { UInt8(bitPattern: $0) }, as: UTF8.self) == target else {
                throw DropError("\(path) cannot be made a link: something else has that name; the drop was refused")
            }
        }
        var st = stat()
        guard fstatat(fd, name, &st, AT_SYMLINK_NOFOLLOW) == 0, st.st_mode & S_IFMT == S_IFLNK else {
            throw DropError("\(path) cannot be made a link: something else has that name; the drop was refused")
        }
        try claim(st, for: path)
    }

    /// Opens a file for writing, creating it if need be. It is never a symlink, never anything
    /// but an ordinary file with one name, and never the file of another entry. The caller
    /// closes the descriptor.
    package func openFile(_ path: String) throws -> Int32 {
        let (dir, name) = try parent(of: path)
        let fd = openat(dir, name, O_WRONLY | O_CREAT | O_NOFOLLOW, 0o600)
        guard fd >= 0 else { throw errnoError("Cannot create \(path)") }
        var st = stat()
        guard fstat(fd, &st) == 0, st.st_mode & S_IFMT == S_IFREG, st.st_nlink == 1 else {
            close(fd)
            throw DropError("\(path) is not an ordinary file; the drop was refused")
        }
        do { try claim(st, for: path) } catch {
            close(fd)
            throw error
        }
        return fd
    }

    /// Opens the file called `name` in the folder that holds the root (a drop's ledger lives
    /// there, beside the tree), for reading and for appending, making it if it is not there.
    /// Like a file of the tree it is never a symlink, and never anything but an ordinary file
    /// with one name: what is written to it goes nowhere else. The caller closes the descriptor.
    package func openBeside(_ name: String) throws -> Int32 {
        guard Self.isOneName(name) else { throw DropError("\(Sanitize.label(name, limit: 120)) is not a file beside the drop") }
        let fd = openat(holder, name, O_RDWR | O_APPEND | O_CREAT | O_NOFOLLOW, 0o600)
        guard fd >= 0 else {
            throw errno == ELOOP ? DropError("The resume ledger is a link; the drop was refused") : errnoError("Cannot open the resume ledger")
        }
        var st = stat()
        guard fstat(fd, &st) == 0, st.st_mode & S_IFMT == S_IFREG, st.st_nlink == 1 else {
            close(fd)
            throw DropError("The resume ledger is not an ordinary file; the drop was refused")
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

    /// Sets the modification time and the permission bits of what the manifest has at `path`
    /// (a folder, or else a file), and marks it quarantined when a mark is given: through a
    /// descriptor of the thing itself, after looking at what that descriptor is. A folder must
    /// be a folder, and a file an ordinary file with one name, as when it was opened to be
    /// written; anything else ends the drop.
    ///
    /// The three used to be set by name, on whatever had it, and a name that was not there was
    /// passed over. With a file of an interrupted drop changed for a second name for a file
    /// elsewhere, and the ledger made to say it had all arrived (so that it was never opened
    /// to be written, which would have refused it), that other file was given the drop's
    /// mode, time and mark, and its second name was moved into the destination.
    package func finish(_ path: String, directory: Bool = false, mtime: Double, mode: mode_t, quarantine: [UInt8]? = nil) throws {
        let (fd, name) = try parent(of: path)
        let item = openat(fd, name, O_RDONLY | O_NOFOLLOW | (directory ? O_DIRECTORY : 0))
        var st = stat()
        guard item >= 0, fstat(item, &st) == 0,
              directory ? st.st_mode & S_IFMT == S_IFDIR : st.st_mode & S_IFMT == S_IFREG && st.st_nlink == 1 else {
            if item >= 0 { close(item) }
            throw DropError("\(Sanitize.label(path, limit: 120)) is not the \(directory ? "folder" : "file") the drop put there; the drop was refused")
        }
        defer { close(item) }
        // Every file and folder of a drop comes through here, also one this run never opened
        // because the ledger said it was all there: two entries that are one thing stop here at the latest.
        try claim(st, for: path)
        if let quarantine { fsetxattr(item, Quarantine.attribute, quarantine, quarantine.count, 0, 0) }
        var times = [timespec(tv_sec: 0, tv_nsec: Int(UTIME_OMIT)),
                     timespec(tv_sec: Int(mtime), tv_nsec: Int((mtime - mtime.rounded(.down)) * 1e9))]
        futimens(item, &times)
        fchmod(item, mode)
    }

    /// Moves the top-level item `item` out of the tree into `folder` (an open directory: the
    /// destination) under `name`, replacing nothing: false when something there has that
    /// name already, whatever it is (a link to nowhere included). The name is asked for by
    /// taking it. Asking first and moving after left a gap in which two drops finishing
    /// together both saw a name free, and the second `rename` replaced the first one's file.
    ///
    /// Both ends go by descriptor. The item is taken from the root this tree has held open
    /// since the drop began, not from wherever a path to it leads by now: with `items` moved
    /// aside mid-drop and a link to another folder put in its place, a move by path took that
    /// other folder's things.
    package func place(_ item: String, in folder: Int32, as name: String) throws -> Bool {
        guard Self.isOneName(item), Self.isOneName(name) else { throw DropError("\(Sanitize.label(item, limit: 120)) cannot be put in place under that name") }
        if renameatx_np(root, item, folder, name, UInt32(RENAME_EXCL)) == 0 { return true }
        if errno == EEXIST { return false }
        guard errno == ENOTSUP else { throw errnoError("Cannot move \(item) into place") }
        // A volume that cannot refuse and move in one step (exFAT and MS-DOS volumes say so;
        // checked on exFAT, 2026-11-24): look, then move. The gap is back there, and only there.
        var st = stat()
        if fstatat(folder, name, &st, AT_SYMLINK_NOFOLLOW) == 0 { return false }
        guard errno == ENOENT, renameat(root, item, folder, name) == 0 else { throw errnoError("Cannot move \(item) into place") }
        return true
    }

    /// Whether `url` still names the folder this tree's root is in, and not something that
    /// has been given that folder's name since the drop began.
    package func isHeld(at url: URL) -> Bool {
        var mine = stat(), there = stat()
        return fstat(holder, &mine) == 0 && lstat(url.path, &there) == 0 && mine.st_dev == there.st_dev && mine.st_ino == there.st_ino
    }

    /// One component, and neither of the two that mean somewhere else.
    private static func isOneName(_ name: String) -> Bool { isInside(name) && !name.utf8.contains(UInt8(ascii: "/")) }

    /// Lets go of the cached directory (before the tree is moved).
    package func release() {
        if cachedFD >= 0 { close(cachedFD) }
        cachedFD = -1
        cachedPath = nil
    }
}
