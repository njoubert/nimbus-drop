// Copyright (C) 2026 Niels Joubert
// SPDX-License-Identifier: GPL-3.0-or-later
import CryptoKit
import Foundation
import XCTest
@testable import NimbusBase
@testable import NimbusCrypto
@testable import NimbusDiscovery
@testable import NimbusDropCore
@testable import NimbusNet
@testable import NimbusSafeStorageCore
@testable import NimbusSecurityCore
@testable import NimbusTransferCore

/// `docs/security/filesystem-containment.md`, as tests: every change a drop makes to the disk is
/// one the destination and the accepted manifest allow.
///
/// Each test works in a folder of its own with a home in it: the destination (`Downloads`),
/// things the person already had there, and, beside it, things that are none of a drop's
/// business (`Documents`, `Library/LaunchAgents`, a script, a link). The whole folder is read
/// before and after (`snapshot`: path, kind, size, inode, link count, mode, both times, a hash
/// of the contents, a link's target, the names of extended attributes) and `assertContained`
/// holds the difference to the claim: outside the destination nothing differs in any way;
/// inside it nothing that was there differs, and what is new is what a manifest names, of the
/// kind and no larger than it says. An error returned is not taken as evidence of anything.
///
/// The attacker is a paired Mac that means harm (it holds valid keys and sends any manifest
/// and any records), and, with a lower bar, somebody on this Mac changing the destination
/// between two steps of a drop. Those steps are the protocol's: a drop driven by hand
/// (`Hand`) stops wherever the test wants it to.
final class ContainmentTests: XCTestCase {
    var sandbox: URL!
    let chunk = 16 * 1024
    /// The paired Mac that means harm, and the Mac it sends to.
    var mallory: TestMac!
    var victim: TestMac!

    var home: URL { sandbox.appendingPathComponent("home") }
    /// The folder the person chose.
    var dst: URL { home.appendingPathComponent("Downloads") }
    var documents: URL { home.appendingPathComponent("Documents") }
    var agents: URL { home.appendingPathComponent("Library/LaunchAgents") }
    /// What a sender sends from.
    var src: URL { sandbox.appendingPathComponent("src") }

    override func setUpWithError() throws {
        let fm = FileManager.default
        sandbox = fm.temporaryDirectory.appendingPathComponent("nimbusdrop-containment-\(UUID().uuidString)")
        for dir in ["home/Downloads/Mine", "home/Library/LaunchAgents", "home/Documents/Taxes", "src"] {
            try fm.createDirectory(at: sandbox.appendingPathComponent(dir), withIntermediateDirectories: true)
        }
        // Outside the destination: none of this may change in any way.
        try Data("secret".utf8).write(to: documents.appendingPathComponent("secret.txt"))
        chmod(documents.appendingPathComponent("secret.txt").path, 0o600)
        try Data(repeating: 0x5A, count: chunk * 4).write(to: documents.appendingPathComponent("large.bin"))
        try Data("2025".utf8).write(to: documents.appendingPathComponent("Taxes/2025.txt"))
        try Data("#!/bin/sh\n".utf8).write(to: home.appendingPathComponent("profile.sh"))
        chmod(home.appendingPathComponent("profile.sh").path, 0o755)
        try fm.createSymbolicLink(atPath: home.appendingPathComponent("link").path, withDestinationPath: "Documents")
        // Inside it: what the person already had, which no drop may touch either.
        try Data("mine".utf8).write(to: dst.appendingPathComponent("mine.txt"))
        try Data("kept".utf8).write(to: dst.appendingPathComponent("Mine/kept.txt"))

        fm.createFile(atPath: src.appendingPathComponent("case-probe").path, contents: nil)
        foldsCase = fm.fileExists(atPath: src.appendingPathComponent("CASE-PROBE").path)
        try fm.removeItem(at: src.appendingPathComponent("case-probe"))

        Tuning.reconnectSeconds = 1
        Tuning.arrivalsPerAddress = 500   // both ends of every test are at one address
        let (a, b) = Trust.paired("mallory", "victim")
        mallory = try TestMac("mallory", trust: a)
        victim = try TestMac("victim", trust: b)
        let dst = dst
        victim.listener.onOffer = { [weak victim] s in
            victim?.offers.withLock { $0.append(s) }
            s.accept(destination: dst)
        }
    }

    override func tearDownWithError() throws {
        Tuning.reconnectSeconds = 60
        Tuning.arrivalsPerAddress = 200
        mallory = nil
        victim = nil
        try? FileManager.default.removeItem(at: sandbox)
    }

    // MARK: The snapshot

    /// One thing on disk, as `lstat` and a reading of it describe it. Nothing is followed.
    struct Item: Equatable, CustomStringConvertible {
        var kind = "", size: Int64 = 0, inode: UInt64 = 0, links = 0, mode: UInt16 = 0
        var mtime = "", ctime = "", hash = "", target = "", xattrs: [String] = []

        var description: String {
            "\(kind) \(size) bytes, inode \(inode), \(links) links, mode \(String(mode, radix: 8)), mtime \(mtime), ctime \(ctime)"
                + (hash.isEmpty ? "" : ", sha \(hash)") + (target.isEmpty ? "" : ", → \(target)") + (xattrs.isEmpty ? "" : ", xattrs \(xattrs)")
        }
    }
    typealias Snapshot = [String: Item]

    static func sha(_ data: Data) -> String { SHA256.hash(data: data).prefix(8).map { String(format: "%02x", $0) }.joined() }

    /// Everything under the sandbox, by path relative to it.
    func snapshot() -> Snapshot {
        var out: Snapshot = [:]
        func visit(_ path: String, _ rel: String) {
            var st = stat()
            guard lstat(path, &st) == 0 else { return }
            var item = Item(size: Int64(st.st_size), inode: UInt64(st.st_ino), links: Int(st.st_nlink), mode: UInt16(st.st_mode & 0o7777),
                            mtime: "\(st.st_mtimespec.tv_sec).\(st.st_mtimespec.tv_nsec)", ctime: "\(st.st_ctimespec.tv_sec).\(st.st_ctimespec.tv_nsec)")
            let n = listxattr(path, nil, 0, XATTR_NOFOLLOW)
            if n > 0 {
                var names = [CChar](repeating: 0, count: n)
                listxattr(path, &names, n, XATTR_NOFOLLOW)
                item.xattrs = names.split(separator: 0).map { String(decoding: $0.map { UInt8(bitPattern: $0) }, as: UTF8.self) }.sorted()
            }
            switch st.st_mode & S_IFMT {
            case S_IFREG:
                item.kind = "file"
                item.hash = (try? Data(contentsOf: URL(fileURLWithPath: path))).map(Self.sha) ?? "unreadable"
            case S_IFLNK:
                item.kind = "link"
                item.target = (try? FileManager.default.destinationOfSymbolicLink(atPath: path)) ?? "?"
            case S_IFDIR:
                item.kind = "dir"
                for name in ((try? FileManager.default.contentsOfDirectory(atPath: path)) ?? []).sorted() {
                    visit(path + "/" + name, rel.isEmpty ? name : rel + "/" + name)
                }
            case S_IFIFO: item.kind = "fifo"
            default: item.kind = "other"
            }
            out[rel.isEmpty ? "." : rel] = item
        }
        visit(sandbox.path, "")
        return out
    }

    // MARK: The claim

    /// A manifest the person accepted, from the Mac that proved `senderID`: what may appear in
    /// the destination on its account.
    struct Allowed {
        var manifest: Manifest
        var senderID: String
        /// The bytes of its files, where the test knows them: checked once a file is in place.
        var contents: [String: Data] = [:]

        /// The partial folder a receiver builds this drop in.
        var partial: String {
            "\(String((manifest.topLevelNames.first ?? "Drop").prefix(80))).\(manifest.key(senderID: senderID).prefix(32)).nimbusdrop-partial"
        }
    }

    func allowed(_ manifest: Manifest, from mac: TestMac, contents: [String: Data] = [:]) -> Allowed {
        Allowed(manifest: manifest, senderID: mac.key.raw.map { String(format: "%02x", $0) }.joined(), contents: contents)
    }

    static let inside = "home/Downloads"

    /// The names "keep both" may give `name`.
    static func kept(_ name: String, isDirectory: Bool) -> [String] {
        var taken: Set<String> = [name]
        for _ in 0..<12 {
            let next = Naming.unique(name, isDirectory: isDirectory) { taken.contains($0) }
            taken.insert(next)
        }
        return Array(taken.subtracting([name]))
    }

    /// Whether a link at `path` (inside the items of a drop) pointing to `target` stays inside
    /// its top-level item, worked out here and not by the code under test: followed as text, it
    /// may never stand above the item, and it may not be absolute.
    static func staysInside(path: String, target: String) -> Bool {
        guard !target.isEmpty, !target.hasPrefix("/") else { return false }
        var depth = path.split(separator: "/").count - 1   // folders above the link, the top-level item included
        guard depth >= 1 else { return false }
        for part in target.split(separator: "/") where part != "." {
            depth += part == ".." ? -1 : 1
            if depth < 1 { return false }
        }
        return true
    }

    /// What is wrong with `item` standing for the manifest's entry at `path`, or nil.
    static func problem(_ path: String, _ item: Item, _ a: Allowed, placed: Bool) -> String? {
        guard let e = a.manifest.entries.first(where: { $0.path == path }) else { return "the manifest has no entry \(path)" }
        switch e.kind {
        case .directory:
            guard item.kind == "dir" else { return "\(path) is a \(item.kind) where the manifest has a folder" }
            if placed, item.mode != (e.mode & 0o777) | 0o700 { return "\(path) has mode \(String(item.mode, radix: 8))" }
        case .file:
            guard item.kind == "file" else { return "\(path) is a \(item.kind) where the manifest has a file" }
            guard item.links == 1 else { return "\(path) has \(item.links) names" }
            guard item.size <= e.size else { return "\(path) holds \(item.size) bytes where the manifest says \(e.size)" }
            if placed {
                guard item.size == e.size else { return "\(path) holds \(item.size) bytes of \(e.size)" }
                guard item.mode == (e.mode & 0o777) | 0o600 else { return "\(path) has mode \(String(item.mode, radix: 8))" }
                guard item.mtime.hasPrefix("\(Int(e.mtime)).") else { return "\(path) has the time \(item.mtime), not \(e.mtime)" }
                if let bytes = a.contents[path], sha(bytes) != item.hash { return "\(path) does not hold the bytes that were sent" }
            }
        case .symlink:
            guard item.kind == "link" else { return "\(path) is a \(item.kind) where the manifest has a link" }
            guard item.target == e.link else { return "\(path) points to \(item.target), not \(e.link ?? "")" }
            guard staysInside(path: path, target: item.target), Manifest.linkStaysInside(path: path, link: item.target) else {
                return "\(path) points out of the drop, to \(item.target)"
            }
        }
        return nil
    }

    /// Why `rel` (a path in the destination) is not something an accepted manifest allows
    /// there, or nil. `existed`: the top-level names the destination had before.
    static func unauthorised(_ rel: String, _ item: Item, _ allowing: [Allowed], existed: (String) -> Bool) -> String? {
        let parts = rel.split(separator: "/", maxSplits: 1).map(String.init)
        let top = parts[0], rest = parts.count > 1 ? parts[1] : ""
        // A partial folder: its ledger and, under `items`, what the manifest names.
        for a in allowing where top == a.partial {
            if rest.isEmpty || rest == "items" { return item.kind == "dir" ? nil : "it is a \(item.kind)" }
            if rest == "ledger" { return item.kind == "file" && item.links == 1 ? nil : "the ledger is a \(item.kind) with \(item.links) names" }
            guard rest.hasPrefix("items/") else { return "a partial folder holds a ledger and items, not this" }
            return problem(String(rest.dropFirst(6)), item, a, placed: false)
        }
        // A top-level item in place, under its own name or a "keep both" one. Never a name
        // the destination already had: nothing is merged into what was there.
        guard !existed(top) else { return "\(top) was there before the drop" }
        var why = "no accepted manifest names it"
        for a in allowing {
            for e in a.manifest.entries where !e.path.contains("/") {
                guard top == e.path || kept(e.path, isDirectory: e.kind == .directory).contains(top) else { continue }
                guard let p = problem(rest.isEmpty ? e.path : e.path + "/" + rest, item, a, placed: true) else { return nil }
                why = p
            }
        }
        return why
    }

    /// The claim, on two snapshots. `ignoring`: paths (and what is under them) that the test
    /// itself changed in between, as the local actor.
    func assertContained(_ before: Snapshot, _ after: Snapshot, allowing: [Allowed] = [], ignoring: [String] = [],
                         _ what: String = "", file: StaticString = #filePath, line: UInt = #line) {
        let inside = Self.inside
        func isInside(_ p: String) -> Bool { p.hasPrefix(inside + "/") }
        func ignored(_ p: String) -> Bool { ignoring.contains { p == $0 || p.hasPrefix($0 + "/") } }
        func existed(_ top: String) -> Bool { before[inside + "/" + top] != nil }
        func fail(_ message: String) { XCTFail((what.isEmpty ? "" : what + ": ") + message, file: file, line: line) }

        /// Whether `path` was a drop's own material in its partial folder: the folder, its ledger, what its manifest names.
        func own(_ path: String, _ item: Item) -> Bool {
            guard isInside(path) else { return false }
            let rel = String(path.dropFirst(inside.count + 1))
            return allowing.contains(where: { rel == $0.partial || rel.hasPrefix($0.partial + "/") }) && Self.unauthorised(rel, item, allowing, existed: existed) == nil
        }
        for (path, was) in before.sorted(by: { $0.key < $1.key }) where !ignored(path) && path != inside {
            guard let now = after[path] else {
                // A drop's own material leaves its partial folder when the drop is put in place
                // (where it is looked at again, as something new). Nothing else may go.
                if !own(path, was) { fail("\(path) is gone") }
                continue
            }
            guard now != was else { continue }
            // And until then it moves on: the ledger grows, a file gains chunks. It stays the thing it was.
            if own(path, was), own(path, now), now.inode == was.inode { continue }
            fail("\(path) changed:\n   was \(was)\n   now \(now)")
        }
        for (path, now) in after.sorted(by: { $0.key < $1.key }) where before[path] == nil && !ignored(path) {
            guard isInside(path) else { fail("\(path) appeared outside the destination: \(now)"); continue }
            if let why = Self.unauthorised(String(path.dropFirst(inside.count + 1)), now, allowing, existed: existed) {
                fail("\(path) appeared in the destination and no accepted manifest allows it: \(why) (\(now))")
            }
        }
    }

    // MARK: A drop driven by hand

    /// The sending side of a drop, by hand, on a proved and paired channel: any manifest, then
    /// any records under the drop's own keys, one step at a time.
    final class Hand {
        let peer: ReviewTests.RawPeer
        let manifest: Manifest
        let port: UInt16
        /// The receiver's answer to the manifest: a plan, or an error.
        let reply: (type: UInt8, body: Data)
        private(set) var opened = 0
        private var conn: UInt64 = 0
        private lazy var keys = DropKeys(master: peer.master)

        /// Offers `manifest` (as what it is, unless `items` says otherwise), and answers the accept with it, or with `raw`.
        init(_ manifest: Manifest, from sender: TestMac, to receiver: TestMac, items: [String]? = nil, raw: Data? = nil) throws {
            self.manifest = manifest
            port = receiver.port
            peer = try ReviewTests.RawPeer(port: receiver.port, keys: sender.trust.keyPair)
            peer.socket.setReadTimeout(15)
            try peer.hello(.drop)
            try peer.json(.offer, Offer(items: items ?? manifest.topLevelNames, fileCount: manifest.fileCount, totalBytes: manifest.totalBytes))
            guard try peer.read().type == FrameType.accept.rawValue else { throw DropError("the offer was not accepted") }
            if let raw { try peer.message(FrameType.manifest.rawValue, raw) } else { try peer.json(.manifest, manifest) }
            reply = try peer.read()
        }

        var planned: Bool { reply.type == FrameType.plan.rawValue }
        /// Why the receiver refused, when it did.
        var refusal: String? { reply.type == FrameType.error.rawValue ? (try? decode(Reason.self, from: reply.body).message) : nil }

        /// Opens a data connection and proves it belongs to the drop.
        func attach() throws -> (Socket, CipherState) {
            conn += 1
            opened += 1
            let s = try Socket.connect(host: "127.0.0.1", port: port)
            s.setReadTimeout(5)
            try Opening.data.withUnsafeBytes { try s.writeAll($0.baseAddress!, 5) }
            var challenge = Data(count: 16)
            try challenge.withUnsafeMutableBytes { try s.readExactly($0.baseAddress!, 16) }
            let message = keys.sessionID + Crypto.be64(conn) + keys.attachTag(conn: conn, challenge: challenge)
            try message.withUnsafeBytes { try s.writeAll($0.baseAddress!, message.count) }
            return (s, keys.stream(conn))
        }

        /// A record as it goes on the wire, saying whatever it is told to say.
        static func record(_ cipher: inout CipherState, file: UInt32, chunk: UInt32, length: UInt32? = nil, bytes: Data) throws -> Data {
            let header = RecordHeader(file: file, chunk: chunk, length: length ?? UInt32(bytes.count)).bytes
            return try cipher.seal(header) + cipher.seal(bytes, ad: header)
        }

        /// The honest records of file `index` holding `bytes`.
        func chunks(of index: Int, _ bytes: Data, only: [Int]? = nil) -> [(file: UInt32, chunk: UInt32, bytes: Data)] {
            (only ?? Array(0..<manifest.chunkCount(index))).map { c in
                let start = c * manifest.chunkSize
                return (UInt32(index), UInt32(c), bytes.subdata(in: start..<min(bytes.count, start + manifest.chunkSize)))
            }
        }

        /// One data connection carrying `records` and then the end marker. Returns when the
        /// receiver has dealt with all of it and closed the connection: nothing of these
        /// records is still on its way to the disk.
        func stream(_ records: [(file: UInt32, chunk: UInt32, bytes: Data)]) throws {
            var (s, cipher) = try attach()
            for r in records {
                let record = try Self.record(&cipher, file: r.file, chunk: r.chunk, bytes: r.bytes)
                try? record.withUnsafeBytes { try s.writeAll($0.baseAddress!, record.count) }
            }
            let end = try RecordHeader.sealEnd(&cipher)
            try? end.withUnsafeBytes { try s.writeAll($0.baseAddress!, end.count) }
            guard until(10, { s.waitReadable(milliseconds: 0) }) else { throw DropError("the receiver did not finish with a data connection") }
            s.shutdown()
        }

        /// "Every chunk has been sent." The answer is another plan, complete, or an error.
        func done() throws -> (type: UInt8, body: Data) {
            try peer.json(.done, Done(streams: opened, resent: nil))
            return try peer.read()
        }

        func hangUp() { peer.socket.shutdown() }
    }

    /// The whole of a drop by hand: every file's records on one connection, then done.
    @discardableResult
    func deliver(_ hand: Hand, _ contents: [String: Data], file: StaticString = #filePath, line: UInt = #line) throws -> (type: UInt8, body: Data) {
        var records: [(file: UInt32, chunk: UInt32, bytes: Data)] = []
        for (i, e) in hand.manifest.entries.enumerated() where e.kind == .file && e.size > 0 {
            records += hand.chunks(of: i, try XCTUnwrap(contents[e.path], "no bytes for \(e.path)", file: file, line: line))
        }
        if !records.isEmpty { try hand.stream(records) }
        return try hand.done()
    }

    /// The receiving side of the drop offered last, once it has ended.
    @discardableResult
    func ended(_ seconds: Double = 15, file: StaticString = #filePath, line: UInt = #line) throws -> ReceiveSession {
        let session = try XCTUnwrap(victim.offers.withLock { $0.last }, "no offer reached the receiver", file: file, line: line)
        XCTAssertTrue(until(seconds) { session.state.isFinal }, "the receiving side is still \(session.state)", file: file, line: line)
        // Its own thread has let go of the disk.
        session.waitUntilOver()
        return session
    }

    func bytes(_ count: Int, seed: UInt8) -> Data { Data((0..<count).map { UInt8(truncatingIfNeeded: $0 &* 31 &+ Int(seed)) }) }

    /// Whether the volume the tests run on takes names that differ only in case for one name
    /// (the default on a Mac). Where a test needs the other kind of volume, it says so and is skipped.
    var foldsCase = true

    // MARK: An honest drop

    func testAnHonestDropPutsOnlyWhatItsManifestNamesInTheDestination() throws {
        let fm = FileManager.default
        let photos = src.appendingPathComponent("Photos")
        try fm.createDirectory(at: photos.appendingPathComponent("sub/deeper"), withIntermediateDirectories: true)
        try fm.createDirectory(at: photos.appendingPathComponent("empty folder"), withIntermediateDirectories: true)
        var contents: [String: Data] = [:]
        for (name, count) in [("big.bin", chunk * 9 + 123), ("one-chunk.bin", chunk), ("sub/tiny.txt", 7), ("sub/empty.txt", 0), ("sub/deeper/a.jpg", 3000)] {
            contents["Photos/" + name] = bytes(count, seed: UInt8(name.count))
            try contents["Photos/" + name]!.write(to: photos.appendingPathComponent(name))
        }
        try fm.createSymbolicLink(atPath: photos.appendingPathComponent("link").path, withDestinationPath: "sub/tiny.txt")
        try fm.createSymbolicLink(atPath: photos.appendingPathComponent("sub/up").path, withDestinationPath: "../big.bin")
        try fm.createSymbolicLink(atPath: photos.appendingPathComponent("out").path, withDestinationPath: "/etc/hosts")
        chmod(photos.appendingPathComponent("sub/tiny.txt").path, 0o755)
        chmod(photos.appendingPathComponent("sub/deeper").path, 0o750)
        try fm.setAttributes([.modificationDate: Date(timeIntervalSince1970: 1_600_000_000)], ofItemAtPath: photos.appendingPathComponent("big.bin").path)
        contents["note.txt"] = Data("a loose file".utf8)
        try contents["note.txt"]!.write(to: src.appendingPathComponent("note.txt"))
        let scanned = try Scanner.scan([photos, src.appendingPathComponent("note.txt")], chunkSize: chunk)

        let before = snapshot()
        let s = SendSession(urls: [], host: "127.0.0.1", port: victim.port, peerName: "victim", identity: mallory.identity, trust: mallory.trust,
                            streams: 4, chunkSize: chunk, prescanned: scanned)
        s.start()
        XCTAssertTrue(until(30) { s.state.isFinal })
        XCTAssertEqual(s.state, .completed)
        XCTAssertEqual(try ended().state, .completed)
        let after = snapshot()
        assertContained(before, after, allowing: [allowed(scanned.manifest, from: mallory, contents: contents)])
        // And all of it is there: the claim above is about what may appear, this is that it did.
        let placed = Set(after.keys.filter { $0.hasPrefix(Self.inside + "/") && before[$0] == nil }.map { String($0.dropFirst(Self.inside.count + 1)) })
        XCTAssertEqual(placed, Set(scanned.manifest.entries.map(\.path)).subtracting(["Photos/out"]), "everything but the link out of the drop")
        XCTAssertEqual(after[Self.inside + "/Photos/big.bin"]?.xattrs, ["com.apple.quarantine"])
    }

    // MARK: (a) Hostile manifests

    /// Paths no manifest may hold: absolute, climbing, standing still, empty, too long, with a
    /// NUL; an entry twice, two kinds under one name, a child of nothing, of a file, of a link.
    /// Each is offered honestly (the offer says what the manifest says), so that the path is
    /// the only thing wrong with it, as a file, a folder and a link in turn.
    func testAManifestThatReachesOutOrNamesAThingTwiceMakesNothing() throws {
        let long = String(repeating: "n", count: 256)
        let paths = ["/etc/evil", "/", "//", "../evil", "..", ".", "./evil", "ok/../evil", "ok/../../evil", "ok/./evil", "ok//evil", "ok/", "ok/..", "ok/.",
                     "", "ok/../../../Library/LaunchAgents/evil.plist", "../Mine/kept.txt", "../../Documents/secret.txt", long, "ok/" + long,
                     "nul\0byte", "ok/nul\0/evil", "ok/evil\0"]
        var manifests: [[Manifest.Entry]] = []
        for path in paths {
            manifests.append([.init(path: "ok", kind: .directory), .init(path: path, kind: .file, size: 5)])
            manifests.append([.init(path: "ok", kind: .directory), .init(path: path, kind: .directory), .init(path: path + "/evil", kind: .file, size: 5)])
            if path.hasPrefix("ok/") || path.hasPrefix("..") {
                manifests.append([.init(path: "ok", kind: .directory), .init(path: path, kind: .symlink, link: "x")])
            }
        }
        manifests += [
            [.init(path: "f", kind: .file, size: 5), .init(path: "f", kind: .file, size: 5)],
            [.init(path: "f", kind: .file, size: 5), .init(path: "f", kind: .directory)],
            [.init(path: "d", kind: .directory), .init(path: "d", kind: .symlink, link: "x")],
            [.init(path: "d", kind: .directory), .init(path: "d/x", kind: .file, size: 5), .init(path: "d/x", kind: .directory)],
            [.init(path: "ghost/x", kind: .file, size: 5)],
            [.init(path: "f", kind: .file, size: 5), .init(path: "f/x", kind: .file, size: 5)],
            [.init(path: "l", kind: .symlink, link: "."), .init(path: "l/x", kind: .file, size: 5)],
            [.init(path: "d", kind: .directory), .init(path: "d/l", kind: .symlink, link: ".."), .init(path: "d/l/x", kind: .file, size: 5)],
            [.init(path: "d", kind: .directory), .init(path: "d/l", kind: .symlink, link: documents.path), .init(path: "d/l/secret.txt", kind: .file, size: 5)],
            [.init(path: "d", kind: .directory), .init(path: "d/l", kind: .symlink, link: ""), .init(path: "d/n", kind: .symlink, link: "a\0b")],
        ]
        let before = snapshot()
        for entries in manifests {
            let what = entries.map { "\($0.kind) \($0.path.debugDescription)" }.joined(separator: ", ")
            let hand = try Hand(Manifest(chunkSize: chunk, entries: entries), from: mallory, to: victim)
            XCTAssertNotNil(hand.refusal, "accepted: \(what)")
            XCTAssertThrowsError(try Manifest(chunkSize: chunk, entries: entries).validate(), what)
            guard case .failed = try ended().state else { XCTFail("the drop went on: \(what)"); continue }
            assertContained(before, snapshot(), what)
            hand.hangUp()
        }
    }

    /// The same from below the level of a `Manifest`: bytes where a manifest belongs that are
    /// not text, or text that is not a manifest.
    func testAManifestThatIsNotOneMakesNothing() throws {
        func manifest(path: Data) -> Data { Data(#"{"chunkSize":16384,"entries":[{"p":""#.utf8) + path + Data(#"","k":0,"s":5,"m":0,"o":420}]}"#.utf8) }
        let raws: [Data] = [
            manifest(path: Data([0x61, 0xFF, 0xFE, 0x62])),              // not UTF-8
            manifest(path: Data([0xC0, 0xAF, 0x2E, 0x2E, 0xC0, 0xAF])),  // "/../" in overlong form
            manifest(path: Data([0xED, 0xA0, 0x80])),                    // half a surrogate pair, encoded
            manifest(path: Data(#"\ud800"#.utf8)),                       // and escaped
            manifest(path: Data(#"a\u0000b"#.utf8)),
            manifest(path: Data(#"..\/..\/Documents\/secret.txt"#.utf8)),
            Data(#"{"chunkSize":16384,"entries":[{"p":7,"k":0,"s":5,"m":0,"o":420}]}"#.utf8),
            Data(#"{"chunkSize":16384,"entries":[{"p":["a"],"k":0,"s":5,"m":0,"o":420}]}"#.utf8),
            Data(#"{"chunkSize":16384,"entries":[{"p":"a","k":7,"s":5,"m":0,"o":420}]}"#.utf8),
            Data(#"{"chunkSize":16384,"entries":[{"p":"a","k":0,"s":5,"m":0,"o":99999999}]}"#.utf8),
            Data(#"{"chunkSize":16384,"entries":[{"k":0,"s":5,"m":0,"o":420}]}"#.utf8),
            Data(#"{"chunkSize":16384,"entries":[]}"#.utf8), Data("[]".utf8), Data(),
        ]
        let offered = Manifest(chunkSize: chunk, entries: [.init(path: "a", kind: .file, size: 5)])
        let before = snapshot()
        for raw in raws {
            let hand = try Hand(offered, from: mallory, to: victim, raw: raw)
            XCTAssertNotNil(hand.refusal, String(decoding: raw, as: UTF8.self))
            try ended()
            assertContained(before, snapshot(), String(decoding: raw, as: UTF8.self))
            hand.hangUp()
        }
    }

    /// Names that are two as text and one on a Mac's disk: in case, and in how an accent is
    /// composed. The text of the manifest is what refuses them (`Manifest.folded`); the disk is
    /// not asked. On a volume that tells such names apart the drop is refused all the same.
    func testNamesTheDiskTakesForOneNameAreRefusedAsTextAndMakeNothing() throws {
        let clashes: [[Manifest.Entry]] = [
            [.init(path: "d", kind: .directory), .init(path: "d/x", kind: .symlink, link: "../../../../Library/LaunchAgents"),
             .init(path: "d/X", kind: .directory), .init(path: "d/X/evil.plist", kind: .file, size: 5)],
            [.init(path: "d", kind: .directory), .init(path: "D", kind: .directory)],
            [.init(path: "d", kind: .directory), .init(path: "d/a.txt", kind: .file, size: 5), .init(path: "d/A.TXT", kind: .file, size: 5)],
            [.init(path: "Caf\u{E9}", kind: .file, size: 5), .init(path: "Cafe\u{301}", kind: .file, size: 5)],
            [.init(path: "d", kind: .directory), .init(path: "d/\u{C5}", kind: .directory), .init(path: "d/a\u{30A}", kind: .file, size: 5)],
            [.init(path: "top", kind: .symlink, link: "/tmp"), .init(path: "TOP", kind: .directory), .init(path: "TOP/f", kind: .file, size: 5)],
        ]
        let before = snapshot()
        for entries in clashes {
            let what = entries.map(\.path).joined(separator: ", ")
            XCTAssertThrowsError(try Manifest(chunkSize: chunk, entries: entries).validate(), what) {
                XCTAssertTrue("\($0)".contains("twice"), "refused, but not for the name: \($0)")
            }
            let hand = try Hand(Manifest(chunkSize: chunk, entries: entries), from: mallory, to: victim)
            XCTAssertNotNil(hand.refusal, what)
            try ended()
            assertContained(before, snapshot(), what)
            hand.hangUp()
        }
    }

    /// Links: one that stays inside its drop is made as it is; one that leaves it is not made;
    /// and nothing is ever written through one.
    func testLinksOutOfTheDropAreNotMade() throws {
        let real = bytes(100, seed: 1)
        let out = ["P/abs": documents.path, "P/root": "/", "P/climb": "../../../Documents", "P/top": "..", "P/sub/far": "../../..",
                   "P/sub/sneaky": "deep/../../../..", "P/sub/back": "../sub/../../../Documents", "Loose": "P/real.txt"]
        // ("~" is a name like any other: nothing here expands it.)
        let kept = ["P/in": "real.txt", "P/sub/up": "../real.txt", "P/sub/self": ".", "P/sub/top": "..", "P/dot": "./sub/./up", "P/tilde": "~/Documents"]
        var entries: [Manifest.Entry] = [.init(path: "P", kind: .directory, mode: 0o755), .init(path: "P/real.txt", kind: .file, size: 100),
                                         .init(path: "P/sub", kind: .directory, mode: 0o755)]
        for (path, link) in out.merging(kept, uniquingKeysWith: { a, _ in a }).sorted(by: { $0.key < $1.key }) {
            entries.append(.init(path: path, kind: .symlink, link: link))
        }
        let manifest = Manifest(chunkSize: chunk, entries: entries)
        let before = snapshot()
        let hand = try Hand(manifest, from: mallory, to: victim)
        XCTAssertTrue(hand.planned, hand.refusal ?? "")
        XCTAssertEqual(try deliver(hand, ["P/real.txt": real]).type, FrameType.complete.rawValue)
        let session = try ended()
        XCTAssertEqual(session.state, .completed)
        let after = snapshot()
        assertContained(before, after, allowing: [allowed(manifest, from: mallory, contents: ["P/real.txt": real])])
        for (path, link) in kept { XCTAssertEqual(after[Self.inside + "/" + path]?.target, link, path) }
        for path in out.keys { XCTAssertNil(after[Self.inside + "/" + path], "\(path) was made, and points out of the drop") }
        XCTAssertEqual(session.stats.skippedLinks, out.count)
    }

    /// What is already in a partial folder (left by an earlier attempt, or put there by
    /// someone else) must be exactly what the manifest says, or the drop ends there: a link, a
    /// folder, a file with a second name, a pipe, where the manifest has something else. Each
    /// stands in for a way out of the tree, and each points at something outside the destination.
    func testWhatIsAlreadyInThePartialFolderMustBeWhatTheManifestSays() throws {
        let fm = FileManager.default
        let secret = documents.appendingPathComponent("secret.txt"), large = documents.appendingPathComponent("large.bin")
        var pipes: [Int32] = []
        defer { for fd in pipes { close(fd) } }
        // What is planted where: (the entry it stands in for, how it is planted).
        let plants: [(name: String, at: String, plant: (URL) throws -> Void)] = [
            ("a link where a folder belongs", "sub", { try fm.createSymbolicLink(atPath: $0.path, withDestinationPath: self.documents.path) }),
            ("a file where a folder belongs", "sub", { try Data("x".utf8).write(to: $0) }),
            ("a pipe where a folder belongs", "sub", { XCTAssertEqual(mkfifo($0.path, 0o600), 0) }),
            ("a link where a file belongs", "sub/a.bin", { try fm.createSymbolicLink(atPath: $0.path, withDestinationPath: large.path) }),
            ("a folder where a file belongs", "sub/a.bin", { try fm.createDirectory(at: $0, withIntermediateDirectories: false) }),
            ("a file with a second name where a file belongs", "sub/a.bin", { try fm.linkItem(at: large, to: $0) }),
            ("a pipe where a file belongs", "sub/a.bin", { url in
                XCTAssertEqual(mkfifo(url.path, 0o600), 0)
                // Someone is reading it, so that opening it for writing does not wait (see the notes on what is left).
                pipes.append(open(url.path, O_RDONLY | O_NONBLOCK))
            }),
            ("a link where an empty file belongs", "sub/empty", { try fm.createSymbolicLink(atPath: $0.path, withDestinationPath: secret.path) }),
            ("a file with a second name where an empty file belongs", "sub/empty", { try fm.linkItem(at: secret, to: $0) }),
            ("a link to somewhere else where a link belongs", "sub/in", { try fm.createSymbolicLink(atPath: $0.path, withDestinationPath: self.documents.path) }),
            ("a folder where a link belongs", "sub/in", { try fm.createDirectory(at: $0, withIntermediateDirectories: false) }),
            ("a file where a link belongs", "sub/in", { try Data("x".utf8).write(to: $0) }),
            ("the top-level folder is a link", "", { url in
                try fm.removeItem(at: url)
                try fm.createSymbolicLink(atPath: url.path, withDestinationPath: self.documents.path)
            }),
        ]
        for (i, plant) in plants.enumerated() {
            let top = "P\(i)", a = bytes(chunk + 10, seed: 3)
            let manifest = Manifest(chunkSize: chunk, entries: [
                .init(path: top, kind: .directory, mode: 0o755), .init(path: "\(top)/sub", kind: .directory, mode: 0o755),
                .init(path: "\(top)/sub/a.bin", kind: .file, size: Int64(a.count), mode: 0o644), .init(path: "\(top)/sub/empty", kind: .file, size: 0),
                .init(path: "\(top)/sub/in", kind: .symlink, link: "a.bin"),
            ])
            let allow = allowed(manifest, from: mallory)
            // The partial folder as an earlier attempt would have left it, with one thing in it that is not the manifest's.
            let items = dst.appendingPathComponent(allow.partial).appendingPathComponent("items")
            try fm.createDirectory(at: items.appendingPathComponent(top), withIntermediateDirectories: true)
            if plant.at.contains("/") { try fm.createDirectory(at: items.appendingPathComponent("\(top)/sub"), withIntermediateDirectories: true) }
            try plant.plant(items.appendingPathComponent(plant.at.isEmpty ? top : "\(top)/\(plant.at)"))

            let before = snapshot()
            let hand = try Hand(manifest, from: mallory, to: victim)
            if hand.planned {
                // Only the file with bytes to come is still unopened: its first chunk is where the drop meets what is there.
                try hand.stream(hand.chunks(of: 2, a))
            }
            let session = try ended()
            guard case .failed(let why) = session.state else { XCTFail("\(plant.name): the drop went on, \(session.state)"); continue }
            XCTAssertTrue(why.contains("refused") || why.contains("Cannot create"), "\(plant.name): \(why)")
            assertContained(before, snapshot(), allowing: [allow], plant.name)
            hand.hangUp()
        }
        XCTAssertEqual(try Data(contentsOf: secret), Data("secret".utf8))
        XCTAssertEqual(try Data(contentsOf: large), Data(repeating: 0x5A, count: chunk * 4))
    }

    /// Records under the drop's own keys for what its manifest does not have: a folder, a
    /// link, a file that is empty, a file that is not there, a chunk past the end, a length
    /// that is not the chunk's. None is written. Then two honest ones far apart in a large
    /// file, which are: the file is as long as the manifest says and no longer.
    func testRecordsForWhatTheManifestDoesNotHaveAreNotWritten() throws {
        let big = 4 << 20, f = bytes(chunk * 2 + 100, seed: 9)
        let manifest = Manifest(chunkSize: chunk, entries: [
            .init(path: "d", kind: .directory), .init(path: "d/f.bin", kind: .file, size: Int64(f.count)), .init(path: "d/empty", kind: .file, size: 0),
            .init(path: "d/link", kind: .symlink, link: "f.bin"), .init(path: "d/big.bin", kind: .file, size: Int64(big)),
        ])
        let before = snapshot()
        let hand = try Hand(manifest, from: mallory, to: victim)
        XCTAssertTrue(hand.planned, hand.refusal ?? "")
        let session = try XCTUnwrap(victim.offers.withLock { $0.last })
        let full = UInt32(chunk), bigChunks = UInt32(big / chunk)
        // (file, chunk, the length it claims, the bytes that follow)
        let hostile: [(UInt32, UInt32, UInt32, Int)] = [
            (0, 0, full, chunk), (0, 0, 0, 0),                                   // the folder
            (3, 0, 5, 5), (3, 0, full, chunk),                                   // the link
            (2, 0, 0, 0), (2, 0, 1, 1), (2, 0, full, chunk),                     // the empty file
            (5, 0, full, chunk), (0x7FFF_FFFF, 0, full, chunk), (0xFFFF_FFFE, 0, full, chunk), (0xFFFF_FFFF, 1, 0, 0), (0xFFFF_FFFF, 0, 1, 1),
            (1, 3, full, chunk), (1, 3, 100, 100), (1, 0xFFFF_FFFF, full, chunk), (1, 0x8000_0000, full, chunk),   // past the end of f.bin
            (1, 2, full, chunk), (1, 2, 99, 99), (1, 2, 101, 101), (1, 0, full - 1, chunk - 1), (1, 0, full + 1, chunk + 1), (1, 0, 0, 0),
            (1, 0, 0xFFFF_FFFF, chunk), (1, 0, 0x8000_0000, chunk),
            (4, bigChunks, full, chunk), (4, bigChunks - 1, full + 1, chunk + 1), (4, 0xFFFF_FFFF, full, chunk),
        ]
        for (file, c, length, count) in hostile {
            var (s, cipher) = try hand.attach()
            let record = try Hand.record(&cipher, file: file, chunk: c, length: length, bytes: Data(repeating: 0xEE, count: count))
            try? record.withUnsafeBytes { try s.writeAll($0.baseAddress!, record.count) }
            XCTAssertTrue(until(5) { s.waitReadable(milliseconds: 0) }, "the connection that carried (\(file), \(c), \(length)) was not closed")
            s.shutdown()
        }
        XCTAssertEqual(session.stats.chunks, 0, "one of them was written")
        XCTAssertFalse(session.state.isFinal, "and none of them ended the drop")
        // The last chunk of each file, and nothing before it.
        try hand.stream(hand.chunks(of: 4, Data(repeating: 0x42, count: big), only: [Int(bigChunks) - 1]) + hand.chunks(of: 1, f, only: [2]))
        XCTAssertEqual(session.stats.chunks, 2)
        let after = snapshot()
        assertContained(before, after, allowing: [allowed(manifest, from: mallory)])
        let items = "\(Self.inside)/\(allowed(manifest, from: mallory).partial)/items/"
        XCTAssertEqual(after[items + "d/big.bin"]?.size, Int64(big))
        XCTAssertEqual(after[items + "d/f.bin"]?.size, Int64(f.count))
        XCTAssertEqual(after[items + "d/empty"]?.size, 0)
        hand.hangUp()
        try ended()
    }

    // MARK: (b) Somebody on this Mac, between two steps of a drop

    /// A folder of the partial tree is moved aside and a link to somewhere else put in its
    /// place, between two data connections. The next file that needs the folder finds it is
    /// not one: the drop ends, and nothing is written where the link points.
    func testAFolderSwappedForALinkMidDropIsNotWrittenThrough() throws {
        let a = bytes(chunk * 2, seed: 1), b = bytes(500, seed: 2), c = bytes(500, seed: 3)
        let manifest = Manifest(chunkSize: chunk, entries: [
            .init(path: "P", kind: .directory), .init(path: "P/sub", kind: .directory), .init(path: "P/sub/a.bin", kind: .file, size: Int64(a.count)),
            .init(path: "P/sub/b.bin", kind: .file, size: Int64(b.count)), .init(path: "P/c.bin", kind: .file, size: Int64(c.count)),
        ])
        let allow = allowed(manifest, from: mallory)
        let hand = try Hand(manifest, from: mallory, to: victim)
        XCTAssertTrue(hand.planned, hand.refusal ?? "")
        try hand.stream(hand.chunks(of: 2, a, only: [0]))

        let items = dst.appendingPathComponent(allow.partial).appendingPathComponent("items")
        try FileManager.default.moveItem(at: items.appendingPathComponent("P/sub"), to: items.appendingPathComponent("P/aside"))
        try FileManager.default.createSymbolicLink(atPath: items.appendingPathComponent("P/sub").path, withDestinationPath: documents.path)
        let before = snapshot()
        // A file in another folder first, so that the receiver has to find `P/sub` again.
        try hand.stream(hand.chunks(of: 4, c) + hand.chunks(of: 2, a, only: [1]) + hand.chunks(of: 3, b))
        let session = try ended()
        guard case .failed(let why) = session.state else { return XCTFail("the drop went on: \(session.state)") }
        XCTAssertTrue(why.contains("refused"), why)
        assertContained(before, snapshot(), allowing: [allow])
        hand.hangUp()
    }

    /// The same folder is moved right out of the destination while the receiver has it open.
    /// This is what is NOT prevented: the receiver holds the folder, not its name, and what it
    /// writes next goes where the folder went. What is held to: nothing but that folder, which
    /// the drop made and the local actor moved, is touched outside the destination.
    func testAFolderMovedAwayWhileOpenTakesOnlyItselfOutside() throws {
        let a = bytes(chunk * 2, seed: 1), b = bytes(500, seed: 2)
        let manifest = Manifest(chunkSize: chunk, entries: [
            .init(path: "P", kind: .directory), .init(path: "P/sub", kind: .directory), .init(path: "P/sub/a.bin", kind: .file, size: Int64(a.count)),
            .init(path: "P/sub/b.bin", kind: .file, size: Int64(b.count)),
        ])
        let allow = allowed(manifest, from: mallory)
        let hand = try Hand(manifest, from: mallory, to: victim)
        XCTAssertTrue(hand.planned, hand.refusal ?? "")
        let session = try XCTUnwrap(victim.offers.withLock { $0.last })
        // One connection, kept open: the receiver has `P/sub` and `a.bin` in hand when the folder goes.
        var (s, cipher) = try hand.attach()
        var record = try Hand.record(&cipher, file: 2, chunk: 0, bytes: Data(a.prefix(chunk)))
        try record.withUnsafeBytes { try s.writeAll($0.baseAddress!, record.count) }
        XCTAssertTrue(until(5) { session.stats.chunks == 1 })

        let items = dst.appendingPathComponent(allow.partial).appendingPathComponent("items")
        try FileManager.default.moveItem(at: items.appendingPathComponent("P/sub"), to: documents.appendingPathComponent("moved"))
        let before = snapshot()
        record = try Hand.record(&cipher, file: 2, chunk: 1, bytes: Data(a.suffix(chunk))) + Hand.record(&cipher, file: 3, chunk: 0, bytes: b)
            + RecordHeader.sealEnd(&cipher)
        try record.withUnsafeBytes { try s.writeAll($0.baseAddress!, record.count) }
        XCTAssertTrue(until(5) { s.waitReadable(milliseconds: 0) })
        _ = try? hand.done()
        try ended()
        assertContained(before, snapshot(), allowing: [allow], ignoring: ["home/Documents/moved"])
        hand.hangUp()
    }

    // MARK: (c) A drop picked up again after its partial folder was changed

    /// Sends part of a drop by hand and goes away; the receiver gives up on it and leaves the partial folder.
    func interrupted(_ manifest: Manifest, sending records: (Hand) throws -> [(file: UInt32, chunk: UInt32, bytes: Data)]) throws -> URL {
        let hand = try Hand(manifest, from: mallory, to: victim)
        XCTAssertTrue(hand.planned, hand.refusal ?? "")
        try hand.stream(try records(hand))
        hand.hangUp()
        try ended()
        return dst.appendingPathComponent(allowed(manifest, from: mallory).partial)
    }

    /// A ledger record for every chunk of every entry, and some for what does not exist.
    func ledgerClaimingEverything(_ manifest: Manifest) -> Data {
        var out = Data()
        for file in 0..<(manifest.entries.count + 2) {
            for c in 0..<(file < manifest.entries.count ? max(1, manifest.chunkCount(file)) + 1 : 2) { out += Crypto.be32(UInt32(file)) + Crypto.be32(UInt32(c)) }
        }
        return out + Data([1, 2, 3, 4, 5])   // and a torn record at the end
    }

    /// A ledger that claims chunks that are not on the disk: a file that was deleted, one cut
    /// short, records for entries that are folders or do not exist. A resume takes the
    /// ledger's word only for chunks whose file is there and long enough; the rest are sent
    /// again, and what arrives is what was sent.
    func testAResumeDoesNotTakeTheLedgersWordForChunksThatAreNotThere() throws {
        let contents = ["P/a.bin": bytes(chunk * 3 + 7, seed: 1), "P/b.bin": bytes(chunk * 2, seed: 2), "P/c.bin": bytes(100, seed: 3)]
        let manifest = Manifest(chunkSize: chunk, entries: [
            .init(path: "P", kind: .directory), .init(path: "P/a.bin", kind: .file, size: Int64(contents["P/a.bin"]!.count)),
            .init(path: "P/b.bin", kind: .file, size: Int64(contents["P/b.bin"]!.count)), .init(path: "P/c.bin", kind: .file, size: 100),
            .init(path: "P/empty", kind: .file, size: 0),
        ])
        let allow = allowed(manifest, from: mallory, contents: contents)
        let before = snapshot()
        let partial = try interrupted(manifest) { $0.chunks(of: 1, contents["P/a.bin"]!) + $0.chunks(of: 2, contents["P/b.bin"]!) }
        assertContained(before, snapshot(), allowing: [allow], "after the first attempt")

        try FileManager.default.removeItem(at: partial.appendingPathComponent("items/P/a.bin"))
        XCTAssertEqual(truncate(partial.appendingPathComponent("items/P/b.bin").path, off_t(chunk + 1)), 0)
        try ledgerClaimingEverything(manifest).write(to: partial.appendingPathComponent("ledger"))

        let hand = try Hand(manifest, from: mallory, to: victim)
        let plan = try decode(Plan.self, from: hand.reply.body)
        XCTAssertEqual(plan.completeFiles, [], "a file was taken for complete on the ledger's word")
        XCTAssertEqual(plan.partialFiles.map(\.file), [2])
        XCTAssertEqual(plan.partialFiles.first?.chunks, [0], "the chunk that is wholly there, and not the one that was cut")
        XCTAssertEqual(try deliver(hand, contents).type, FrameType.complete.rawValue)
        XCTAssertEqual(try ended().state, .completed)
        assertContained(before, snapshot(), allowing: [allow])
        XCTAssertEqual(try Data(contentsOf: dst.appendingPathComponent("P/a.bin")), contents["P/a.bin"])
    }

    /// The ledger says a file is complete, and where the file was there is now a link to a
    /// file elsewhere that is long enough, or a folder. The ledger's word is not taken for
    /// either (neither is an ordinary file), the chunks are asked for again, and writing them
    /// is refused: the drop ends with nothing changed at the other end of the link.
    func testAResumeIsRefusedWhereAFileOfTheDropHasBecomeALinkOrAFolder() throws {
        let fm = FileManager.default
        let swaps: [(URL) throws -> Void] = [
            { try fm.createSymbolicLink(atPath: $0.path, withDestinationPath: self.documents.appendingPathComponent("large.bin").path) },
            { try fm.createDirectory(at: $0, withIntermediateDirectories: false) },
        ]
        for (i, swap) in swaps.enumerated() {
            let a = bytes(chunk * 2, seed: 1)
            let manifest = Manifest(chunkSize: chunk, entries: [.init(path: "Q\(i)", kind: .directory), .init(path: "Q\(i)/a.bin", kind: .file, size: Int64(a.count))])
            let allow = allowed(manifest, from: mallory)
            let partial = try interrupted(manifest) { $0.chunks(of: 1, a) }
            try fm.removeItem(at: partial.appendingPathComponent("items/Q\(i)/a.bin"))
            try swap(partial.appendingPathComponent("items/Q\(i)/a.bin"))
            try ledgerClaimingEverything(manifest).write(to: partial.appendingPathComponent("ledger"))

            let before = snapshot()
            let hand = try Hand(manifest, from: mallory, to: victim)
            XCTAssertEqual(try decode(Plan.self, from: hand.reply.body).completeFiles, [], "the ledger was believed about something that is not a file")
            try hand.stream(hand.chunks(of: 1, a))
            guard case .failed = try ended().state else { return XCTFail("the drop went on") }
            assertContained(before, snapshot(), allowing: [allow])
            hand.hangUp()
        }
    }

    // MARK: Every way a drop ends

    /// Declined, refused, abandoned by the sender, cancelled by the person here, ended because
    /// trust in the sender was withdrawn: nothing is in the destination but, at most, a partial
    /// folder holding what the manifest names; and nothing is put in place.
    func testHoweverADropEndsOnlyItsPartialFolderIsLeft() throws {
        let a = bytes(chunk * 3, seed: 1)
        func manifest(_ top: String) -> Manifest {
            Manifest(chunkSize: chunk, entries: [.init(path: top, kind: .directory), .init(path: "\(top)/a.bin", kind: .file, size: Int64(a.count)),
                                                 .init(path: "\(top)/in", kind: .symlink, link: "a.bin"), .init(path: "\(top)/empty", kind: .file, size: 0)])
        }
        let before = snapshot()
        var allowing: [Allowed] = []
        let dst = dst

        // Declined: not so much as a partial folder.
        victim.listener.onOffer = { $0.decline("No thanks") }
        XCTAssertThrowsError(try Hand(manifest("Declined"), from: mallory, to: victim))
        assertContained(before, snapshot(), "declined")
        victim.listener.onOffer = { [weak victim] s in
            victim?.offers.withLock { $0.append(s) }
            s.accept(destination: dst)
        }

        // Accepted, and then the manifest is not what was offered.
        var hand = try Hand(manifest("Other"), from: mallory, to: victim, items: ["Something else"])
        XCTAssertTrue(hand.refusal?.contains("not what was offered") ?? false, hand.refusal ?? "no refusal")
        try ended()
        assertContained(before, snapshot(), "not what was offered")

        // The sender goes away part of the way through.
        allowing.append(allowed(manifest("Abandoned"), from: mallory))
        _ = try interrupted(manifest("Abandoned")) { $0.chunks(of: 1, a, only: [0, 2]) }
        assertContained(before, snapshot(), allowing: allowing, "abandoned")

        // The person here cancels.
        allowing.append(allowed(manifest("Cancelled"), from: mallory))
        hand = try Hand(manifest("Cancelled"), from: mallory, to: victim)
        try hand.stream(hand.chunks(of: 1, a, only: [1]))
        try XCTUnwrap(victim.offers.withLock { $0.last }).cancel()
        XCTAssertEqual(try ended().state, .cancelled)
        assertContained(before, snapshot(), allowing: allowing, "cancelled")

        // Everything arrives, and trust in the sender is withdrawn before it says so: nothing is put in place.
        allowing.append(allowed(manifest("Withdrawn"), from: mallory))
        hand = try Hand(manifest("Withdrawn"), from: mallory, to: victim)
        try hand.stream(hand.chunks(of: 1, a))
        victim.trust.forget(mallory.key)
        _ = try? hand.done()
        guard case .failed = try ended().state else { return XCTFail("the drop went on after trust was withdrawn") }
        let after = snapshot()
        assertContained(before, after, allowing: allowing, "withdrawn")
        for top in ["Declined", "Other", "Abandoned", "Cancelled", "Withdrawn"] { XCTAssertNil(after["\(Self.inside)/\(top)"], "\(top) was put in place") }
    }

    // MARK: (d) Putting a drop in place

    /// The destination already has every name the drop brings, as a file, a folder (full and
    /// empty), a link, under another spelling. Each stays exactly as it was and the newcomer
    /// gets a "keep both" name, counting past the ones already taken.
    func testANameThatIsTakenIsKeptAndTheNewcomerNumbered() throws {
        let fm = FileManager.default
        try Data("old".utf8).write(to: dst.appendingPathComponent("report.pdf"))
        try Data("old 2".utf8).write(to: dst.appendingPathComponent("report 2.pdf"))
        try fm.createDirectory(at: dst.appendingPathComponent("Photos/2019"), withIntermediateDirectories: true)
        try fm.createDirectory(at: dst.appendingPathComponent("Empty"), withIntermediateDirectories: true)
        try fm.createSymbolicLink(atPath: dst.appendingPathComponent("Docs").path, withDestinationPath: documents.path)
        try Data("old".utf8).write(to: dst.appendingPathComponent("README.md"))
        try Data("a file".utf8).write(to: dst.appendingPathComponent("Folder"))
        var contents = ["report.pdf": bytes(900, seed: 1), "Photos": bytes(10, seed: 2), "Docs/x.txt": bytes(20, seed: 3), "readme.md": bytes(30, seed: 4),
                        "Mine/kept.txt": bytes(40, seed: 5), "mine.txt": bytes(50, seed: 6)]
        contents["Folder/in.txt"] = bytes(60, seed: 7)
        let manifest = Manifest(chunkSize: chunk, entries: [
            .init(path: "report.pdf", kind: .file, size: 900), .init(path: "Photos", kind: .file, size: 10),          // a file where a folder is
            .init(path: "Empty", kind: .directory), .init(path: "Docs", kind: .directory), .init(path: "Docs/x.txt", kind: .file, size: 20),
            .init(path: "readme.md", kind: .file, size: 30), .init(path: "Mine", kind: .directory), .init(path: "Mine/kept.txt", kind: .file, size: 40),
            .init(path: "mine.txt", kind: .file, size: 50), .init(path: "Folder", kind: .directory), .init(path: "Folder/in.txt", kind: .file, size: 60),
        ])
        let before = snapshot()
        let hand = try Hand(manifest, from: mallory, to: victim)
        let reply = try deliver(hand, contents)
        XCTAssertEqual(reply.type, FrameType.complete.rawValue)
        XCTAssertEqual(try ended().state, .completed)
        let after = snapshot()
        assertContained(before, after, allowing: [allowed(manifest, from: mallory, contents: contents)])
        let saved = try decode(Complete.self, from: reply.body).saved
        XCTAssertEqual(saved, ["report 3.pdf", "Photos 2", "Empty 2", "Docs 2", foldsCase ? "readme 2.md" : "readme.md", "Mine 2", "mine 2.txt", "Folder 2"])
        for name in saved { XCTAssertNotNil(after["\(Self.inside)/\(name)"], "\(name) is said to be saved and is not there") }
    }
}

// MARK: - The partial folder itself

extension ContainmentTests {
    /// The partial folder is a link to a folder elsewhere, put there before the drop (its
    /// name is no secret to someone who saw an earlier attempt's). As found, the whole drop
    /// was built where the link pointed: `SafeTree` opened `<partial>/items` refusing a link
    /// at `items` only, and the ledger went by its path.
    func testAPartialFolderThatIsALinkIsNotBuiltIn() throws {
        let a = bytes(chunk + 10, seed: 1)
        let manifest = Manifest(chunkSize: chunk, entries: [.init(path: "P", kind: .directory), .init(path: "P/a.bin", kind: .file, size: Int64(a.count))])
        let allow = allowed(manifest, from: mallory)
        try FileManager.default.createSymbolicLink(atPath: dst.appendingPathComponent(allow.partial).path, withDestinationPath: agents.path)
        let before = snapshot()
        let hand = try Hand(manifest, from: mallory, to: victim)
        XCTAssertTrue(hand.refusal?.contains("refused") ?? false, "the drop was taken into a folder that is a link: \(hand.refusal ?? "a plan")")
        if hand.planned { _ = try? deliver(hand, ["P/a.bin": a]) }
        try ended()
        let after = snapshot()
        // Nothing but, for now, one empty folder where the link points: see below.
        assertContained(before, after, ignoring: ["home/Library/LaunchAgents"])
        // Nothing at all behind the link: the tree makes the partial folder and `items` itself,
        // following nothing. (`ReceiveSession.conduct` used to make `items` by path first, and
        // one empty folder was left where the link pointed.)
        XCTAssertEqual(after.keys.filter { $0.hasPrefix("home/Library/LaunchAgents/") }.sorted(), [])
        assertContained(before, after)
        hand.hangUp()
    }

    /// `SafeTree` by itself: it makes its root and the folder that holds it, and goes through
    /// a link for neither.
    func testATreeIsNeverOpenedThroughALink() throws {
        let fm = FileManager.default
        // Nothing there yet: both are made.
        let fresh = dst.appendingPathComponent("Fresh.partial/items")
        XCTAssertNoThrow(try SafeTree(root: fresh))
        var isDirectory: ObjCBool = false
        XCTAssertTrue(fm.fileExists(atPath: fresh.path, isDirectory: &isDirectory) && isDirectory.boolValue)
        // The folder that holds the root is a link (to a folder that has an `items` in it, even).
        try fm.createDirectory(at: documents.appendingPathComponent("items"), withIntermediateDirectories: false)
        try fm.createSymbolicLink(atPath: dst.appendingPathComponent("Linked.partial").path, withDestinationPath: documents.path)
        // The root is a link.
        try fm.createDirectory(at: dst.appendingPathComponent("Real.partial"), withIntermediateDirectories: false)
        try fm.createSymbolicLink(atPath: dst.appendingPathComponent("Real.partial/items").path, withDestinationPath: documents.path)
        // The folder is a link to nowhere, and a file.
        try fm.createSymbolicLink(atPath: dst.appendingPathComponent("Dangling.partial").path, withDestinationPath: agents.appendingPathComponent("made").path)
        try Data("x".utf8).write(to: dst.appendingPathComponent("File.partial"))
        let before = snapshot()
        for name in ["Linked", "Real", "Dangling", "File"] {
            XCTAssertThrowsError(try SafeTree(root: dst.appendingPathComponent("\(name).partial/items")), name)
        }
        let after = snapshot()
        XCTAssertEqual(before, after, "refusing a tree made or changed something")
    }

    /// Between two attempts the ledger is changed for a link to a file elsewhere, a link to a
    /// file that is not there, a second name for a file elsewhere, a folder, a pipe. As found,
    /// the ledger went by its path: it was read, emptied and rewritten through a link (the
    /// file at the other end lost its contents), a link to nowhere had its file made, and a
    /// pipe was waited on for ever.
    func testALedgerThatIsNotTheDropsOwnOrdinaryFileIsRefused() throws {
        let fm = FileManager.default
        let swaps: [(String, (URL) throws -> Void)] = [
            ("a link to a file elsewhere", { try fm.createSymbolicLink(atPath: $0.path, withDestinationPath: self.documents.appendingPathComponent("secret.txt").path) }),
            ("a link to a file that is not there", { try fm.createSymbolicLink(atPath: $0.path, withDestinationPath: self.agents.appendingPathComponent("made.plist").path) }),
            ("a second name for a file elsewhere", { try fm.linkItem(at: self.documents.appendingPathComponent("large.bin"), to: $0) }),
            ("a folder", { try fm.createDirectory(at: $0, withIntermediateDirectories: false) }),
            ("a pipe", { XCTAssertEqual(mkfifo($0.path, 0o600), 0) }),
        ]
        for (i, (what, swap)) in swaps.enumerated() {
            let a = bytes(chunk * 2, seed: 1)
            let manifest = Manifest(chunkSize: chunk, entries: [.init(path: "L\(i)", kind: .directory), .init(path: "L\(i)/a.bin", kind: .file, size: Int64(a.count))])
            let partial = try interrupted(manifest) { $0.chunks(of: 1, a, only: [0]) }
            try fm.removeItem(at: partial.appendingPathComponent("ledger"))
            try swap(partial.appendingPathComponent("ledger"))
            let before = snapshot()
            let hand = try Hand(manifest, from: mallory, to: victim)
            XCTAssertNotNil(hand.refusal, "\(what): the drop went on")
            if hand.planned { _ = try? deliver(hand, ["L\(i)/a.bin": a]) }
            try ended()
            assertContained(before, snapshot(), allowing: [allowed(manifest, from: mallory)], what)
            hand.hangUp()
        }
        XCTAssertEqual(try Data(contentsOf: documents.appendingPathComponent("secret.txt")), Data("secret".utf8))
    }
}

// MARK: - Putting a drop in place: a name is asked for by taking it

extension ContainmentTests {
    /// Another Mac the victim has paired with.
    func paired(_ name: String) throws -> TestMac {
        let trust = Trust.inMemory()
        trust.adopt(victim.trust, as: "victim")
        victim.trust.adopt(trust, as: name)
        return try TestMac(name, trust: trust)
    }

    /// The destination has a link to nowhere under the name the drop brings. As found, the
    /// name was taken for free (`fileExists` follows a link, and this one leads nowhere) and
    /// `rename` then replaced the link.
    func testALinkToNowhereUnderTheNameIsKept() throws {
        let fm = FileManager.default
        try fm.createSymbolicLink(atPath: dst.appendingPathComponent("note.txt").path, withDestinationPath: "/nonexistent/elsewhere")
        try fm.createSymbolicLink(atPath: dst.appendingPathComponent("Album").path, withDestinationPath: "not-there")
        let contents = ["note.txt": bytes(50, seed: 1), "Album/a.jpg": bytes(60, seed: 2)]
        let manifest = Manifest(chunkSize: chunk, entries: [.init(path: "note.txt", kind: .file, size: 50), .init(path: "Album", kind: .directory),
                                                            .init(path: "Album/a.jpg", kind: .file, size: 60)])
        let before = snapshot()
        let reply = try deliver(try Hand(manifest, from: mallory, to: victim), contents)
        XCTAssertEqual(try ended().state, .completed)
        assertContained(before, snapshot(), allowing: [allowed(manifest, from: mallory, contents: contents)])
        XCTAssertEqual(try decode(Complete.self, from: reply.body).saved, ["note 2.txt", "Album 2"])
    }

    /// Two drops from two Macs bring the same names (files, a folder with something in it, an
    /// empty folder) and both finish at the same moment. Each name is there twice afterwards,
    /// once from each. As found, both could see a name free and both `rename` onto it: the
    /// second replaced the first one's file (and its empty folder), and failed on its full one.
    func testTwoDropsFinishingAtOnceUnderTheSameNamesBothArrive() throws {
        let holly = try paired("holly")
        let rounds = 6, files = 48
        let before = snapshot()
        var allowing: [Allowed] = [], expected: [(name: String, isDirectory: Bool, hashes: Set<String>)] = []
        for round in 0..<rounds {
            var hands: [Hand] = [], sent: [[String: Data]] = []
            for (who, mac) in [mallory!, holly].enumerated() {
                var entries: [Manifest.Entry] = [], contents: [String: Data] = [:]
                // The second Mac lists the same names the other way round: an item is put in
                // place in the manifest's order, so somewhere in the middle the two reach for
                // the same name at the same time.
                for f in who == 0 ? Array(0..<files) : Array((0..<files).reversed()) {
                    contents["r\(round)-f\(f).bin"] = bytes(200 + f, seed: UInt8(who * 100 + f))
                    entries.append(.init(path: "r\(round)-f\(f).bin", kind: .file, size: Int64(200 + f)))
                }
                contents["r\(round)-Folder/in.txt"] = bytes(300, seed: UInt8(who + 7))
                let folders: [Manifest.Entry] = [.init(path: "r\(round)-Folder", kind: .directory), .init(path: "r\(round)-Folder/in.txt", kind: .file, size: 300),
                                                 .init(path: "r\(round)-Empty", kind: .directory)]
                entries.insert(contentsOf: folders, at: files / 2)
                let manifest = Manifest(chunkSize: chunk, entries: entries)
                let hand = try Hand(manifest, from: mac, to: victim)
                XCTAssertTrue(hand.planned, hand.refusal ?? "")
                // Everything but the last word.
                try hand.stream(manifest.entries.enumerated().filter { $0.element.kind == .file }.flatMap { hand.chunks(of: $0.offset, contents[$0.element.path]!) })
                hands.append(hand)
                sent.append(contents)
                allowing.append(allowed(manifest, from: mac, contents: contents))
            }
            for name in sent[0].keys.sorted() where !name.contains("/") { expected.append((name, false, [Self.sha(sent[0][name]!), Self.sha(sent[1][name]!)])) }
            expected += [("r\(round)-Folder", true, []), ("r\(round)-Empty", true, [])]

            let go = DispatchSemaphore(value: 0), over = DispatchGroup()
            let replies = Locked<[UInt8]>([])
            for hand in hands {
                over.enter()
                Thread.detachNewThread {
                    go.wait()
                    let reply = try? hand.done()
                    replies.withLock { $0.append(reply?.type ?? 0) }
                    over.leave()
                }
            }
            go.signal()
            go.signal()
            over.wait()
            XCTAssertEqual(replies.withLock { $0 }, [FrameType.complete.rawValue, FrameType.complete.rawValue], "round \(round): one of the two was not put in place")
            XCTAssertTrue(until(15) { victim.offers.withLock { $0.allSatisfy { $0.state.isFinal } } })
            for hand in hands { hand.hangUp() }
        }
        let after = snapshot()
        assertContained(before, after, allowing: allowing)
        var lost = 0
        for (name, isDirectory, hashes) in expected {
            let second = Naming.unique(name, isDirectory: isDirectory) { $0 == name }
            guard let one = after["\(Self.inside)/\(name)"], let other = after["\(Self.inside)/\(second)"] else { lost += 1; continue }
            if !isDirectory, Set([one.hash, other.hash]) != hashes { lost += 1 }
        }
        XCTAssertEqual(lost, 0, "of \(expected.count) names brought twice, \(lost) are not there twice, once from each Mac")
    }

    /// While a drop is arriving, its `items` folder is moved aside and a link to a folder
    /// elsewhere put in its place; that folder has things of its own under the names the
    /// drop brings. As found, the drop was put in place by path (`…/items/Taxes`), through the
    /// link: the other folder's `Taxes` and `secret.txt` were moved into the destination, and
    /// what had actually arrived was deleted with the partial folder.
    func testAnItemsFolderSwappedForALinkBringsNothingInFromOutside() throws {
        let contents = ["Taxes/a.bin": bytes(chunk + 5, seed: 1), "secret.txt": bytes(40, seed: 2)]
        let manifest = Manifest(chunkSize: chunk, entries: [.init(path: "Taxes", kind: .directory), .init(path: "Taxes/a.bin", kind: .file, size: Int64(chunk + 5)),
                                                            .init(path: "secret.txt", kind: .file, size: 40)])
        let allow = allowed(manifest, from: mallory, contents: contents)
        let hand = try Hand(manifest, from: mallory, to: victim)
        XCTAssertTrue(hand.planned, hand.refusal ?? "")
        let partial = dst.appendingPathComponent(allow.partial)
        try FileManager.default.moveItem(at: partial.appendingPathComponent("items"), to: partial.appendingPathComponent("aside"))
        try FileManager.default.createSymbolicLink(atPath: partial.appendingPathComponent("items").path, withDestinationPath: documents.path)
        let before = snapshot()
        XCTAssertEqual(try deliver(hand, contents).type, FrameType.complete.rawValue)
        XCTAssertEqual(try ended().state, .completed)
        // (The partial folder is the local actor's own doing here, and goes with the drop.)
        assertContained(before, snapshot(), allowing: [allow], ignoring: ["\(Self.inside)/\(allow.partial)"])
        XCTAssertEqual(try Data(contentsOf: dst.appendingPathComponent("Taxes/a.bin")), contents["Taxes/a.bin"], "what was put in place is what arrived")
    }

    /// While a drop is arriving, its partial folder is moved aside and a folder the person
    /// already had is given its name. The drop is put in place from the folder it was built
    /// in; what now has that folder's name is not the drop's to clear away.
    func testWhatStandsWhereThePartialFolderWasIsNotClearedAway() throws {
        let contents = ["P/a.bin": bytes(chunk + 5, seed: 1)]
        let manifest = Manifest(chunkSize: chunk, entries: [.init(path: "P", kind: .directory), .init(path: "P/a.bin", kind: .file, size: Int64(chunk + 5))])
        let allow = allowed(manifest, from: mallory, contents: contents)
        let hand = try Hand(manifest, from: mallory, to: victim)
        XCTAssertTrue(hand.planned, hand.refusal ?? "")
        let partial = dst.appendingPathComponent(allow.partial)
        try FileManager.default.moveItem(at: partial, to: dst.appendingPathComponent("aside"))
        try FileManager.default.moveItem(at: dst.appendingPathComponent("Mine"), to: partial)
        let before = snapshot()
        _ = try? deliver(hand, contents)
        try ended()
        let after = snapshot()
        assertContained(before, after, allowing: [allow], ignoring: ["\(Self.inside)/aside"])
        XCTAssertEqual(after["\(Self.inside)/\(allow.partial)/kept.txt"]?.hash, Self.sha(Data("kept".utf8)), "the person's own file went with the partial folder's name")
    }

    /// A destination that can be written to and not read (a drop box): a drop still lands in it.
    func testADestinationThatCannotBeReadStillTakesADrop() throws {
        let contents = ["note.txt": bytes(50, seed: 1)]
        let manifest = Manifest(chunkSize: chunk, entries: [.init(path: "note.txt", kind: .file, size: 50)])
        let before = snapshot()
        chmod(dst.path, 0o300)
        defer { chmod(dst.path, 0o755) }
        let reply = try deliver(try Hand(manifest, from: mallory, to: victim), contents)
        XCTAssertEqual(reply.type, FrameType.complete.rawValue, (try? decode(Reason.self, from: reply.body).message) ?? "")
        XCTAssertEqual(try ended().state, .completed)
        chmod(dst.path, 0o755)
        assertContained(before, snapshot(), allowing: [allowed(manifest, from: mallory, contents: contents)])
    }
}

// MARK: - Modes, times and the quarantine mark go on what the manifest says is there

extension ContainmentTests {
    /// Between two attempts a file of the drop is changed for a second name for a file
    /// elsewhere that is long enough, and the ledger made to say it all arrived. Nothing is
    /// left to send, so the file is never opened for writing (which would refuse it). As
    /// found, the drop then set its mode, its time and the quarantine mark by name, on the
    /// file elsewhere, and moved the second name into the destination as if it had arrived.
    func testAFileThatBecameASecondNameForAFileElsewhereIsNotFinished() throws {
        let a = bytes(chunk * 2, seed: 1)
        let manifest = Manifest(chunkSize: chunk, entries: [.init(path: "P", kind: .directory, mode: 0o755),
                                                            .init(path: "P/a.bin", kind: .file, size: Int64(a.count), mtime: 1_000_000, mode: 0o777)])
        let partial = try interrupted(manifest) { $0.chunks(of: 1, a) }
        try FileManager.default.removeItem(at: partial.appendingPathComponent("items/P/a.bin"))
        try FileManager.default.linkItem(at: documents.appendingPathComponent("large.bin"), to: partial.appendingPathComponent("items/P/a.bin"))
        try ledgerClaimingEverything(manifest).write(to: partial.appendingPathComponent("ledger"))
        let before = snapshot()
        let hand = try Hand(manifest, from: mallory, to: victim)
        // (That the ledger is believed about a file that is there and long enough is not this test's business.)
        XCTAssertEqual(try decode(Plan.self, from: hand.reply.body).completeFiles, [1])
        let reply = try hand.done()
        XCTAssertEqual(reply.type, FrameType.error.rawValue, "the drop was put in place")
        XCTAssertNotEqual(try ended().state, .completed)
        assertContained(before, snapshot(), allowing: [allowed(manifest, from: mallory)])
        hand.hangUp()
    }

    /// The same of `SafeTree` by itself: asked to finish a name that is not what the manifest
    /// has there, it refuses and changes nothing, in the tree or out of it.
    func testFinishingRefusesWhatIsNotWhatTheManifestHasThere() throws {
        let fm = FileManager.default
        let root = dst.appendingPathComponent("T.partial/items")
        let tree = try SafeTree(root: root)
        try tree.makeDirectory("folder")
        close(try tree.openFile("file"))
        try fm.linkItem(at: documents.appendingPathComponent("secret.txt"), to: root.appendingPathComponent("second-name"))
        try fm.createSymbolicLink(atPath: root.appendingPathComponent("link").path, withDestinationPath: documents.appendingPathComponent("secret.txt").path)
        try fm.createSymbolicLink(atPath: root.appendingPathComponent("folder-link").path, withDestinationPath: documents.path)
        XCTAssertEqual(mkfifo(root.appendingPathComponent("pipe").path, 0o600), 0)
        let held = open(root.appendingPathComponent("pipe").path, O_RDWR)   // so that opening it to look does not wait
        defer { close(held) }
        let before = snapshot()
        for (name, directory) in [("second-name", false), ("link", false), ("folder-link", true), ("folder-link", false), ("pipe", false), ("folder", false),
                                  ("file", true), ("nothing", false), ("nothing", true), ("link/x", false), ("folder-link/secret.txt", false)] {
            XCTAssertThrowsError(try tree.finish(name, directory: directory, mtime: 86400, mode: 0o777, quarantine: Array("0081;0;test;".utf8)), "\(name) as a \(directory ? "folder" : "file")")
        }
        XCTAssertEqual(before, snapshot(), "refusing to finish something changed it, or what it leads to")
        // And what is what the manifest says gets all three.
        try tree.finish("file", mtime: 86400, mode: 0o640, quarantine: Array("0081;0;test;".utf8))
        try tree.finish("folder", directory: true, mtime: 86400, mode: 0o750, quarantine: Array("0081;0;test;".utf8))
        let after = snapshot()
        for (name, mode) in [("file", UInt16(0o640)), ("folder", 0o750)] {
            let item = try XCTUnwrap(after["\(Self.inside)/T.partial/items/\(name)"])
            XCTAssertEqual(item.mode, mode)
            XCTAssertEqual(item.mtime, "86400.0")
            XCTAssertEqual(item.xattrs, ["com.apple.quarantine"])
        }
    }
}

// MARK: - Two entries of a manifest are never one thing on disk

extension ContainmentTests {
    /// Pairs of names that are two as text, and to `Manifest.validate` (which folds case and
    /// how accents are composed), and that this Mac's APFS takes for one: it folds case in
    /// full (ß is ss, the long s is s, a ligature is its letters, final sigma is sigma).
    static let alike = [("Maße", "Masse"), ("Wei\u{17F}", "Weis"), ("o\u{FB01}ce", "ofice"), ("\u{3C2}", "\u{3C3}"), ("\u{B5}", "\u{3BC}"), ("\u{3D1}", "\u{3B8}")]

    /// Whether the volume the tests run on takes `a` and `b` for one name.
    func folds(_ a: String, _ b: String) -> Bool {
        let probe = src.appendingPathComponent("fold-probe")
        try? FileManager.default.createDirectory(at: probe, withIntermediateDirectories: false)
        defer { try? FileManager.default.removeItem(at: probe) }
        FileManager.default.createFile(atPath: probe.appendingPathComponent(a).path, contents: nil)
        var st = stat()
        return lstat(probe.appendingPathComponent(b).path, &st) == 0
    }

    /// A drop holding `d/Maße.txt` and `d/Masse.txt`: two files where it came from, two
    /// entries in its manifest, two names to `validate`, and one name on this disk. As found,
    /// the second was opened as the first (an ordinary file that was already there), the
    /// chunks of both were written into it, the ledger called both complete, and the drop was
    /// put in place and reported complete with one file holding the wrong bytes: nobody
    /// attacking, just a folder from a volume that tells the two apart. The text of a manifest
    /// cannot be made to match every disk, so the disk is what refuses it.
    func testTwoNamesThatAreOneOnThisDiskDoNotBecomeOneFile() throws {
        try XCTSkipUnless(folds("Maße", "Masse"), "needs a volume that takes ß and ss for one name (a Mac's own does); this one keeps them apart, and both files would rightly arrive")
        let contents = ["d/Maße.txt": bytes(chunk * 2, seed: 1), "d/Masse.txt": bytes(chunk * 2, seed: 2)]
        let manifest = Manifest(chunkSize: chunk, entries: [.init(path: "d", kind: .directory), .init(path: "d/Maße.txt", kind: .file, size: Int64(chunk * 2)),
                                                            .init(path: "d/Masse.txt", kind: .file, size: Int64(chunk * 2))])
        XCTAssertNoThrow(try manifest.validate(), "(if the text refuses it now, this test is about the disk and needs another pair)")
        let before = snapshot()
        let hand = try Hand(manifest, from: mallory, to: victim)
        XCTAssertTrue(hand.planned, hand.refusal ?? "")
        let reply = try? deliver(hand, contents)
        XCTAssertNotEqual(reply?.type, FrameType.complete.rawValue, "the drop was put in place")
        let session = try ended()
        guard case .failed(let why) = session.state else { XCTFail("the drop ended \(session.state)"); return assertContained(before, snapshot(), allowing: [allowed(manifest, from: mallory, contents: contents)]) }
        XCTAssertTrue(why.contains("one name on this disk"), why)
        let after = snapshot()
        assertContained(before, after, allowing: [allowed(manifest, from: mallory, contents: contents)])
        XCTAssertNil(after["\(Self.inside)/d"], "nothing of it is in place")
        // And the one file there is in the partial folder holds the first one's bytes, not a mixture.
        let partial = dst.appendingPathComponent(allowed(manifest, from: mallory).partial)
        XCTAssertEqual(try Data(contentsOf: partial.appendingPathComponent("items/d/Maße.txt")), contents["d/Maße.txt"])
        hand.hangUp()
    }

    /// The same for folders (two that are one would pour their files together), and for a
    /// folder and a file. Refused before any data is asked for.
    func testTwoFoldersThatAreOneOnThisDiskAreRefused() throws {
        try XCTSkipUnless(folds("Maße", "Masse"), "needs a volume that takes ß and ss for one name (a Mac's own does)")
        let before = snapshot()
        var allowing: [Allowed] = []
        for (i, second) in [Manifest.Entry(path: "t/Strasse", kind: .directory), .init(path: "t/Strasse", kind: .file, size: 0)].enumerated() {
            var entries: [Manifest.Entry] = [.init(path: "t", kind: .directory), .init(path: "t/Straße", kind: .directory), .init(path: "t/Straße/x.txt", kind: .file, size: 10), second]
            if second.kind == .directory { entries.append(.init(path: "t/Strasse/x.txt", kind: .file, size: 10)) }
            entries = entries.map { var e = $0; e.path = "T\(i)" + e.path.dropFirst(1); return e }
            let manifest = Manifest(chunkSize: chunk, entries: entries)
            XCTAssertNoThrow(try manifest.validate())
            allowing.append(allowed(manifest, from: mallory))
            let hand = try Hand(manifest, from: mallory, to: victim)
            XCTAssertNotNil(hand.refusal, "two entries that are one name were taken")
            try ended()
            assertContained(before, snapshot(), allowing: allowing)
            hand.hangUp()
        }
    }

    /// `SafeTree` by itself, with no `validate` before it: every pair this disk takes for one
    /// name, in case, in composition and beyond, as files, folders and links; and at the end
    /// of a drop whose files were never opened in this run (a resume the ledger called complete).
    func testTheTreeRefusesASecondEntryForOneThingOnDisk() throws {
        try XCTSkipUnless(foldsCase, "needs a volume that takes names differing in case for one (a Mac's own does); on this one each pair is two files, rightly")
        let pairs = ([("readme", "README"), ("Caf\u{E9}", "Cafe\u{301}")] + Self.alike).filter { folds($0.0, $0.1) }
        XCTAssertGreaterThanOrEqual(pairs.count, 2)
        if pairs.count < 2 + Self.alike.count { print("ContainmentTests: this volume keeps \(2 + Self.alike.count - pairs.count) of the pairs apart; those were not tried") }
        let root = dst.appendingPathComponent("T.partial/items")
        let tree = try SafeTree(root: root)
        for (a, b) in pairs {
            close(try tree.openFile("f-" + a))
            XCTAssertNoThrow(close(try tree.openFile("f-" + a)), "the same entry again is the same entry")
            XCTAssertThrowsError(try tree.openFile("f-" + b), "\(a) / \(b) as files")
            try tree.makeDirectory("d-" + a)
            XCTAssertNoThrow(try tree.makeDirectory("d-" + a))
            XCTAssertThrowsError(try tree.makeDirectory("d-" + b), "\(a) / \(b) as folders")
            try tree.makeSymlink("l-" + a, to: "f-" + a)
            XCTAssertNoThrow(try tree.makeSymlink("l-" + a, to: "f-" + a))
            XCTAssertThrowsError(try tree.makeSymlink("l-" + b, to: "f-" + a), "\(a) / \(b) as links")
        }
        // A new run over the same tree, as a resume is: nothing is opened, everything is finished.
        let again = try SafeTree(root: root)
        for (a, b) in pairs {
            XCTAssertNoThrow(try again.finish("f-" + a, mtime: 0, mode: 0o644))
            XCTAssertThrowsError(try again.finish("f-" + b, mtime: 0, mode: 0o644), "\(a) / \(b) at the end of a drop")
            XCTAssertNoThrow(try again.finish("d-" + a, directory: true, mtime: 0, mode: 0o755))
            XCTAssertThrowsError(try again.finish("d-" + b, directory: true, mtime: 0, mode: 0o755))
        }
        XCTAssertEqual(try FileManager.default.contentsOfDirectory(atPath: root.path).count, pairs.count * 3, "one thing for each first name and nothing for the second")
    }
}

// MARK: - The tree by itself, asked for paths no manifest may hold

extension ContainmentTests {
    /// `Manifest.validate` refuses a path that climbs, stands still, is empty in part or holds
    /// a NUL, before a drop begins. `SafeTree` is the other gate, and was not one for these:
    /// it walked whatever it was given, and ".." is a real folder that no symlink check
    /// minds. Asked directly, as found, it made `escape` beside the tree and in the
    /// destination, opened `Documents/secret.txt` for writing by climbing to it, and set the
    /// mode of the partial folder and of the destination. Every operation, every such path.
    func testTheTreeRefusesAPathThatClimbsOrStandsStillOrNamesNothing() throws {
        let long = String(repeating: "n", count: 256)
        let root = dst.appendingPathComponent("T.partial/items")
        let tree = try SafeTree(root: root)
        try tree.makeDirectory("ok")
        close(try tree.openFile("ok/file"))
        let paths = ["..", "../escape", "../../escape", "../ledger", "ok/..", "ok/../..", "ok/../../escape", "ok/../../../../Documents/secret.txt",
                     "ok/../../../../Documents", "ok/../../../Mine/kept.txt", ".", "./escape", "ok/.", "ok/./file", "", "ok//file", "ok/", "/", "/escape",
                     "//", root.path + "/ok/file", documents.appendingPathComponent("secret.txt").path, "nul\0byte", "ok/nul\0/x", "ok/file\0", "ok\0/file",
                     long, "ok/" + long, long + "/x"]
        let before = snapshot()
        for path in paths {
            let what = path.debugDescription
            XCTAssertThrowsError(try { close(try tree.openFile(path)) }(), "openFile \(what)")
            XCTAssertThrowsError(try tree.makeDirectory(path), "makeDirectory \(what)")
            XCTAssertThrowsError(try tree.makeSymlink(path, to: "ok"), "makeSymlink \(what)")
            XCTAssertThrowsError(try tree.finish(path, mtime: 86400, mode: 0o777), "finish \(what)")
            XCTAssertThrowsError(try tree.finish(path, directory: true, mtime: 86400, mode: 0o777), "finish \(what) as a folder")
            XCTAssertNil(tree.fileSize(path), "fileSize \(what)")
            XCTAssertEqual(before, snapshot(), "an operation on \(what) changed something")
        }
        for name in ["..", ".", "", "a/b", "../x", "nul\0"] {
            XCTAssertThrowsError(try tree.openBeside(name), "openBeside \(name.debugDescription)")
            XCTAssertThrowsError(try tree.place("ok", in: -1, as: name), "place as \(name.debugDescription)")
            XCTAssertThrowsError(try tree.place(name, in: -1, as: "ok"), "place \(name.debugDescription)")
        }
        XCTAssertEqual(before, snapshot())
        // Names with dots in them that are names: three dots, a leading dot, a colon, a backslash.
        for path in ["...", "ok/.hidden", "ok/..two", "ok/a:b", "ok/a\\..\\b", "ok/ ", "ok/~"] { XCTAssertNoThrow(close(try tree.openFile(path)), path) }
        XCTAssertEqual(Set(try FileManager.default.contentsOfDirectory(atPath: root.appendingPathComponent("ok").path)), [".hidden", "..two", "a:b", "a\\..\\b", " ", "~", "file"])
    }
}

// MARK: - A partial folder is nothing a drop can bring

extension ContainmentTests {
    /// Holly is about to send `Report`. Mallory can work out what her drop's partial folder
    /// will be called here (the name is the manifest's key under her public key, which any Mac
    /// on the network may ask her for; the manifest is no secret to someone who sent her the
    /// folder, times and all). So Mallory sends, first, a folder of that name: a tree with
    /// its own bytes in it and a ledger saying every chunk has arrived. As found, that folder
    /// was put in the destination like any other, Holly's drop took it for its own earlier
    /// attempt, asked for nothing, and put Mallory's bytes in place as hers, reported complete.
    func testADropCannotBringAnotherDropsPartialFolder() throws {
        let holly = try paired("holly")
        let honest = bytes(chunk * 2 + 9, seed: 1), forged = bytes(chunk * 2 + 9, seed: 66)
        try FileManager.default.createDirectory(at: src.appendingPathComponent("Report"), withIntermediateDirectories: false)
        try honest.write(to: src.appendingPathComponent("Report/q3.bin"))
        let hers = Manifest(chunkSize: chunk, entries: [.init(path: "Report", kind: .directory, mtime: 1_700_000_000, mode: 0o755),
                                                       .init(path: "Report/q3.bin", kind: .file, size: Int64(honest.count), mtime: 1_700_000_000, mode: 0o644)])
        let hersAllowed = allowed(hers, from: holly, contents: ["Report/q3.bin": honest])

        let top = hersAllowed.partial
        var ledger = Data()
        for c in 0..<hers.chunkCount(1) { ledger += Crypto.be32(1) + Crypto.be32(UInt32(c)) }
        let planted = ["\(top)/items/Report/q3.bin": forged, "\(top)/ledger": ledger]
        let his = Manifest(chunkSize: chunk, entries: [
            .init(path: top, kind: .directory), .init(path: "\(top)/items", kind: .directory), .init(path: "\(top)/items/Report", kind: .directory),
            .init(path: "\(top)/items/Report/q3.bin", kind: .file, size: Int64(forged.count)), .init(path: "\(top)/ledger", kind: .file, size: Int64(ledger.count)),
        ])
        let before = snapshot()
        let first = try Hand(his, from: mallory, to: victim)
        XCTAssertNotNil(first.refusal, "a drop was taken that brings something named as a partial folder is")
        if first.planned { _ = try? deliver(first, planted) }
        try ended()
        first.hangUp()

        // Holly's own app sends her drop: it sends what it is asked for and no more.
        let s = SendSession(urls: [], host: "127.0.0.1", port: victim.port, peerName: "victim", identity: holly.identity, trust: holly.trust, streams: 2, chunkSize: chunk,
                            prescanned: ScannedDrop(manifest: hers, sources: [src.appendingPathComponent("Report").path, src.appendingPathComponent("Report/q3.bin").path]))
        s.start()
        XCTAssertTrue(until(20) { s.state.isFinal })
        XCTAssertEqual(s.state, .completed)
        XCTAssertEqual(s.progress.resumedBytes, 0, "her drop was told that bytes she never sent were already there")
        try ended()
        assertContained(before, snapshot(), allowing: [hersAllowed, allowed(his, from: mallory, contents: planted)])
        XCTAssertEqual(try Data(contentsOf: dst.appendingPathComponent("Report/q3.bin")), honest, "what arrived as Holly's drop is not what she sent")
    }

    /// The rule as text: no part of a path ends as a partial folder's name does, in any
    /// spelling a Mac's disk takes for it (capitals, and the long s, which it folds to s).
    func testNoEntryMayBeNamedAsAPartialFolderIs() {
        let key = String(repeating: "0a", count: 16)
        func refused(_ entries: [Manifest.Entry]) -> Bool { (try? Manifest(chunkSize: chunk, entries: entries).validate()) == nil }
        for name in ["Report.\(key).nimbusdrop-partial", "x.nimbusdrop-partial", "X.NIMBUSDROP-PARTIAL", "x.Nimbusdrop-Partial", "x.nimbu\u{17F}drop-partial", ".nimbusdrop-partial"] {
            XCTAssertTrue(refused([.init(path: name, kind: .directory)]), "\(name) as a folder")
            XCTAssertTrue(refused([.init(path: name, kind: .file, size: 1)]), "\(name) as a file")
            XCTAssertTrue(refused([.init(path: name, kind: .symlink, link: "x")]), "\(name) as a link")
            XCTAssertTrue(refused([.init(path: "d", kind: .directory), .init(path: "d/\(name)", kind: .directory)]), "\(name) inside a folder")
            if folds(name, name.lowercased().replacingOccurrences(of: "\u{17F}", with: "s")) == false { XCTFail("this volume keeps \(name) apart from the plain spelling; the rule is wider than it need be here") }
        }
        // Names that only look near it are names.
        for name in ["nimbusdrop-partial", "x.nimbusdrop-partial.txt", "x.nimbusdrop-partial ", "x.nimbusdrop-partia", "x.nimbusdrop-partiaI", "x-nimbusdrop-partial", "partial"] {
            XCTAssertFalse(refused([.init(path: name, kind: .directory)]), name)
        }
    }
}

// MARK: - The ledger's count

extension ContainmentTests {
    /// `validate` lets a file have as many chunks as 32 bits can number; the ledger counted
    /// the chunks a file still lacks in 31, clamped. A file of more than 2^31 chunks (8 TB and
    /// up at the smallest chunk) would have been called complete with chunks still missing,
    /// and put in place short. Nobody can send two billion chunks in a test: what is checked
    /// is the count the ledger starts from.
    func testAFileOfMoreChunksThanThirtyOneBitsCountIsCountedInFull() throws {
        let chunks = Int(Int32.max) + 6
        let manifest = Manifest(chunkSize: 4096, entries: [.init(path: "huge.bin", kind: .file, size: Int64(chunks) * 4096 - 100), .init(path: "small.bin", kind: .file, size: 5000)])
        XCTAssertNoThrow(try manifest.validate())
        XCTAssertEqual(manifest.chunkCount(0), chunks)
        let partial = dst.appendingPathComponent("T.partial")
        let ledger = try Ledger(url: partial.appendingPathComponent("ledger"), manifest: manifest, tree: try SafeTree(root: partial.appendingPathComponent("items")))
        XCTAssertEqual(ledger.missingChunks, chunks + 2, "the ledger starts \(chunks + 2 - ledger.missingChunks) chunks short: it would call the file complete that many early")
        XCTAssertFalse(ledger.isComplete)
    }
}

// MARK: - The tree by itself, against things that are not what they are asked to be

extension ContainmentTests {
    /// Each operation of `SafeTree`, asked for a name that something of another kind has: a
    /// link (to a folder, to a file, to nowhere), a file with a second name elsewhere, a pipe,
    /// a folder, a file. It refuses, and nothing changes at the name or at what it leads to.
    func testTheTreeTakesNothingForWhatItIsNot() throws {
        let fm = FileManager.default
        let root = dst.appendingPathComponent("T.partial/items")
        let tree = try SafeTree(root: root)
        try tree.makeDirectory("folder")
        close(try tree.openFile("file"))
        try tree.makeSymlink("link", to: "file")
        try fm.createSymbolicLink(atPath: root.appendingPathComponent("to-folder").path, withDestinationPath: documents.path)
        try fm.createSymbolicLink(atPath: root.appendingPathComponent("to-file").path, withDestinationPath: documents.appendingPathComponent("secret.txt").path)
        try fm.createSymbolicLink(atPath: root.appendingPathComponent("to-nowhere").path, withDestinationPath: agents.appendingPathComponent("made.plist").path)
        try fm.linkItem(at: documents.appendingPathComponent("large.bin"), to: root.appendingPathComponent("second-name"))
        XCTAssertEqual(mkfifo(root.appendingPathComponent("pipe").path, 0o600), 0)
        let held = open(root.appendingPathComponent("pipe").path, O_RDWR)   // both ends, so that nothing waits on it
        defer { close(held) }
        let before = snapshot()

        for name in ["to-folder", "to-file", "to-nowhere", "second-name", "pipe", "file", "link"] {
            XCTAssertThrowsError(try tree.makeDirectory(name), "\(name) taken for a folder")
        }
        for name in ["to-folder", "to-file", "to-nowhere", "second-name", "pipe", "folder", "link"] {
            XCTAssertThrowsError(try { close(try tree.openFile(name)) }(), "\(name) opened as a file")
        }
        for name in ["to-folder", "to-file", "to-nowhere", "second-name", "pipe", "folder", "file"] {
            XCTAssertThrowsError(try tree.makeSymlink(name, to: "file"), "\(name) taken for the link to file")
        }
        XCTAssertThrowsError(try tree.makeSymlink("link", to: "folder"), "a link that is there must be the same link")
        for name in ["to-folder/new", "to-folder/secret.txt", "to-file/x", "file/x", "pipe/x", "second-name/x", "link/x", "to-nowhere/x"] {
            XCTAssertThrowsError(try { close(try tree.openFile(name)) }(), "\(name): written through something that is not a folder of the tree")
            XCTAssertThrowsError(try tree.makeDirectory(name), name)
            XCTAssertNil(tree.fileSize(name), name)
        }
        for name in ["to-file", "to-folder", "to-nowhere", "pipe", "folder", "link"] { XCTAssertNil(tree.fileSize(name), "\(name) measured as a file") }
        XCTAssertEqual(before, snapshot(), "something was made or changed by a refusal")
        // The same again is a resume, and is taken.
        XCTAssertNoThrow(try tree.makeDirectory("folder"))
        XCTAssertNoThrow(close(try tree.openFile("file")))
        XCTAssertNoThrow(try tree.makeSymlink("link", to: "file"))
        XCTAssertEqual(before, snapshot())
    }

    /// A pipe where a file belongs, with nobody reading it. The drop does not write to it and
    /// is not put in place. What is NOT held: opening a pipe to write waits for a reader, so
    /// the receiver waits (holding the tree, so every other connection of the drop waits too)
    /// until somebody opens the other end, here the test after a moment. Somebody local can
    /// stall a drop this way; they can also just delete its partial folder.
    func testAPipeWhereAFileBelongsIsNotWrittenTo() throws {
        let a = bytes(chunk, seed: 1)
        let manifest = Manifest(chunkSize: chunk, entries: [.init(path: "P", kind: .directory), .init(path: "P/a.bin", kind: .file, size: Int64(a.count))])
        let allow = allowed(manifest, from: mallory)
        let pipe = dst.appendingPathComponent(allow.partial).appendingPathComponent("items/P/a.bin")
        try FileManager.default.createDirectory(at: pipe.deletingLastPathComponent(), withIntermediateDirectories: true)
        XCTAssertEqual(mkfifo(pipe.path, 0o600), 0)
        let before = snapshot()
        let hand = try Hand(manifest, from: mallory, to: victim)
        XCTAssertTrue(hand.planned, hand.refusal ?? "")
        let session = try XCTUnwrap(victim.offers.withLock { $0.last })
        var (s, cipher) = try hand.attach()
        let record = try Hand.record(&cipher, file: 1, chunk: 0, bytes: a)
        try record.withUnsafeBytes { try s.writeAll($0.baseAddress!, record.count) }
        let waited = !until(1) { session.state.isFinal }
        let reader = open(pipe.path, O_RDONLY | O_NONBLOCK)
        defer { close(reader) }
        guard case .failed(let why) = try ended().state else { return XCTFail("the drop went on") }
        XCTAssertTrue(why.contains("refused"), why)
        var byte: UInt8 = 0
        XCTAssertLessThanOrEqual(read(reader, &byte, 1), 0, "something was written into the pipe")
        assertContained(before, snapshot(), allowing: [allow])
        if waited { print("ContainmentTests: the receiver waited on a pipe put where a file belongs until its other end was opened (not held: see docs/security/filesystem-containment.md)") }
        s.shutdown()
        hand.hangUp()
    }

    /// Putting a drop in place on a volume that cannot refuse-and-move in one step (exFAT and
    /// MS-DOS volumes answer ENOTSUP), which no test can make for itself. Skipped unless
    /// NIMBUS_CONTAINMENT_VOLUME names a folder on one, for example a disk image:
    ///
    ///     hdiutil create -size 40m -fs ExFAT -volname NDTEST /tmp/nd.dmg
    ///     hdiutil attach -nobrowse -mountpoint /tmp/nd-volume /tmp/nd.dmg
    ///     NIMBUS_CONTAINMENT_VOLUME=/tmp/nd-volume swift test --filter testPlacingOnAVolumeThatCannotMoveWithoutReplacing
    func testPlacingOnAVolumeThatCannotMoveWithoutReplacing() throws {
        guard let volume = ProcessInfo.processInfo.environment["NIMBUS_CONTAINMENT_VOLUME"] else {
            throw XCTSkip("needs a folder on a volume without RENAME_EXCL (exFAT, MS-DOS); set NIMBUS_CONTAINMENT_VOLUME to one")
        }
        let fm = FileManager.default
        let folder = URL(fileURLWithPath: volume).appendingPathComponent("containment-\(UUID().uuidString)")
        try fm.createDirectory(at: folder, withIntermediateDirectories: false)
        defer { try? fm.removeItem(at: folder) }
        let tree = try SafeTree(root: folder.appendingPathComponent("T.partial/items"))
        for name in ["a.txt", "b.txt", "c.txt"] {
            let fd = try tree.openFile(name)
            _ = name.withCString { write(fd, $0, strlen($0)) }
            close(fd)
        }
        try Data("was here".utf8).write(to: folder.appendingPathComponent("a.txt"))
        let into = open(folder.path, O_EXEC | O_DIRECTORY)
        defer { close(into) }
        XCTAssertFalse(try tree.place("a.txt", in: into, as: "a.txt"), "a name that is taken")
        XCTAssertEqual(try String(contentsOf: folder.appendingPathComponent("a.txt"), encoding: .utf8), "was here", "and what has it is as it was")
        XCTAssertTrue(try tree.place("a.txt", in: into, as: "a 2.txt"))
        XCTAssertEqual(try String(contentsOf: folder.appendingPathComponent("a 2.txt"), encoding: .utf8), "a.txt")
        XCTAssertTrue(try tree.place("b.txt", in: into, as: "b.txt"), "a name that is free")
        XCTAssertFalse(try tree.place("c.txt", in: into, as: "B.TXT") && !fm.fileExists(atPath: folder.appendingPathComponent("b.txt").path), "nothing is replaced under another spelling of its name")
        XCTAssertEqual(try String(contentsOf: folder.appendingPathComponent("b.txt"), encoding: .utf8), "b.txt")
    }
}
