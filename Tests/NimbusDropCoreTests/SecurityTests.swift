// Copyright (C) 2026 Niels Joubert
// SPDX-License-Identifier: GPL-3.0-or-later
import Foundation
import XCTest
@testable import NimbusDropCore

/// What a hostile sender can do to a receiver that accepts its drop. Every test here is an
/// attack that was thought through against the real code; the ones marked "worked" did.
final class SecurityTests: XCTestCase {
    var root: URL!
    let attacker = Identity(name: "attacker", id: "attacker-id")
    let chunk = 16 * 1024

    override func setUpWithError() throws {
        root = FileManager.default.temporaryDirectory.appendingPathComponent("nimbusdrop-security-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: root.appendingPathComponent("home/Downloads"), withIntermediateDirectories: true)
        try FileManager.default.createDirectory(at: root.appendingPathComponent("home/Library/LaunchAgents"), withIntermediateDirectories: true)
        Tuning.reconnectSeconds = 1
    }

    override func tearDownWithError() throws {
        Tuning.reconnectSeconds = 60
        try? FileManager.default.removeItem(at: root)
    }

    /// The victim: accepts whatever is offered, into its Downloads.
    func victim() throws -> DropListener {
        let downloads = self.downloads
        let l = try DropListener(identity: Identity(name: "victim", id: "victim-id"), preferredPort: 0)
        l.onOffer = { $0.accept(destination: downloads) }
        l.start()
        return l
    }

    var downloads: URL { root.appendingPathComponent("home/Downloads") }
    var launchAgents: URL { root.appendingPathComponent("home/Library/LaunchAgents") }

    func wait(_ t: Transfer) {
        let deadline = Date().addingTimeInterval(20)
        while !t.state.isFinal, Date() < deadline { Thread.sleep(forTimeInterval: 0.01) }
    }

    /// Sends a hand-made manifest: what a modified sender would do.
    func send(_ entries: [Manifest.Entry], payloadFor path: String, to l: DropListener) throws -> SendSession {
        let payload = root.appendingPathComponent("payload")
        try Data("<plist>run this at login</plist>".utf8).write(to: payload)
        let scanned = ScannedDrop(manifest: Manifest(chunkSize: chunk, entries: entries),
                                  sources: entries.map { $0.path == path ? payload.path : "/dev/null" })
        let s = SendSession(urls: [], host: "127.0.0.1", port: l.port, peerName: "victim", identity: attacker,
                            chunkSize: chunk, prescanned: scanned)
        s.start()
        wait(s)
        Thread.sleep(forTimeInterval: 0.3)
        return s
    }

    func testASymlinkAndAFolderThatDifferOnlyInCaseDoNotWriteOutsideTheDrop() throws {
        // On a case-insensitive disk (the default on a Mac), "Photos/x" and "Photos/X" are one
        // name. The manifest calls one a symlink out of the drop and the other a folder, and
        // puts a file "in the folder". Each path is unique and has a folder for a parent, as
        // the manifest tells it.
        let l = try victim()
        defer { l.stop() }
        let size = Int64("<plist>run this at login</plist>".utf8.count)
        _ = try send([
            .init(path: "Photos", kind: .directory, mode: 0o755),
            // From Downloads/<partial>/items/Photos/ up to the home folder, then down.
            .init(path: "Photos/x", kind: .symlink, link: "../../../../Library/LaunchAgents"),
            .init(path: "Photos/X", kind: .directory, mode: 0o755),
            .init(path: "Photos/X/evil.plist", kind: .file, size: size, mode: 0o644),
        ], payloadFor: "Photos/X/evil.plist", to: l)
        XCTAssertEqual(try FileManager.default.contentsOfDirectory(atPath: launchAgents.path), [],
                       "a file was written into LaunchAgents, outside the folder the drop was saved to")
    }

    func testAPartialFolderWithASymlinkPlantedInItIsRefused() throws {
        // The second way to the same end: an earlier drop (or anything else) leaves a symlink in
        // a partial folder where a later drop expects a folder. Nothing about the later
        // manifest is wrong as text; the disk is.
        let l = try victim()
        defer { l.stop() }
        let size = Int64("<plist>run this at login</plist>".utf8.count)
        let entries: [Manifest.Entry] = [
            .init(path: "Photos", kind: .directory, mode: 0o755),
            .init(path: "Photos/sub", kind: .directory, mode: 0o755),
            .init(path: "Photos/sub/evil.plist", kind: .file, size: size, mode: 0o644),
        ]
        let key = Manifest(chunkSize: chunk, entries: entries).key(senderID: attacker.id)
        let items = downloads.appendingPathComponent("Photos.\(key.prefix(32)).nimbusdrop-partial/items")
        try FileManager.default.createDirectory(at: items.appendingPathComponent("Photos"), withIntermediateDirectories: true)
        try FileManager.default.createSymbolicLink(atPath: items.appendingPathComponent("Photos/sub").path, withDestinationPath: launchAgents.path)
        let s = try send(entries, payloadFor: "Photos/sub/evil.plist", to: l)
        guard case .failed(let why) = s.state else { return XCTFail("the drop went through: \(s.state)") }
        XCTAssertTrue(why.contains("refused"), why)
        XCTAssertEqual(try FileManager.default.contentsOfDirectory(atPath: launchAgents.path), [])
    }

    func testFileOperationsDoNotLeaveTheTree() throws {
        // SafeTree on its own, against a folder with every trap in it.
        let fm = FileManager.default
        let inside = root.appendingPathComponent("tree"), outside = root.appendingPathComponent("outside")
        try fm.createDirectory(at: inside.appendingPathComponent("real"), withIntermediateDirectories: true)
        try fm.createDirectory(at: outside, withIntermediateDirectories: true)
        try Data("secret".utf8).write(to: outside.appendingPathComponent("victim.txt"))
        try fm.createSymbolicLink(atPath: inside.appendingPathComponent("trap").path, withDestinationPath: outside.path)
        try fm.createSymbolicLink(atPath: inside.appendingPathComponent("filetrap").path, withDestinationPath: outside.appendingPathComponent("victim.txt").path)
        try fm.linkItem(at: outside.appendingPathComponent("victim.txt"), to: inside.appendingPathComponent("hardlink"))
        let tree = try SafeTree(root: inside)

        XCTAssertThrowsError(try tree.makeDirectory("trap"), "a symlink is not a folder, whatever it points to")
        XCTAssertThrowsError(try tree.makeDirectory("TRAP"), "nor under another spelling of its name")
        XCTAssertThrowsError(try tree.openFile("trap/new.txt"), "no writing through a symlinked folder")
        XCTAssertThrowsError(try tree.openFile("filetrap"), "no writing through a symlink to a file")
        XCTAssertThrowsError(try tree.openFile("hardlink"), "no writing into a file that is also somewhere else")
        XCTAssertThrowsError(try tree.makeSymlink("real", to: "elsewhere"), "a folder is not a link")
        XCTAssertThrowsError(try tree.makeSymlink("trap", to: "somewhere/else"), "a link that is there must be the same link")
        XCTAssertNoThrow(try tree.makeSymlink("trap", to: outside.path), "the same link again is a resume")
        XCTAssertNoThrow(try tree.makeDirectory("real"), "a real folder again is a resume")
        XCTAssertNil(tree.fileSize("trap/victim.txt"), "nor is anything measured through a symlink")
        tree.finish("filetrap", mtime: 0, mode: 0o777)

        XCTAssertEqual(try fm.contentsOfDirectory(atPath: outside.path), ["victim.txt"], "nothing was made outside")
        XCTAssertEqual(try String(contentsOf: outside.appendingPathComponent("victim.txt"), encoding: .utf8), "secret")
        let mode = try fm.attributesOfItem(atPath: outside.appendingPathComponent("victim.txt").path)[.posixPermissions] as? Int
        XCTAssertEqual(mode, 0o644, "and nothing outside had its permissions changed")
        close(try tree.openFile("real/ok.txt"))
        XCTAssertTrue(fm.fileExists(atPath: inside.appendingPathComponent("real/ok.txt").path), "an honest path works")
    }

    func testNamesTheDiskTakesForOneAreRefusedAsText() {
        func bad(_ entries: [Manifest.Entry], _ why: String, line: UInt = #line) {
            XCTAssertThrowsError(try Manifest(chunkSize: chunk, entries: entries).validate(), why, line: line)
        }
        bad([.init(path: "a", kind: .directory), .init(path: "a/x", kind: .symlink, link: "/tmp"), .init(path: "a/X", kind: .directory)], "case")
        bad([.init(path: "Caf\u{E9}", kind: .file), .init(path: "Cafe\u{301}", kind: .file)], "an accent composed two ways")
        bad([.init(path: "a", kind: .symlink, link: "/tmp"), .init(path: "A", kind: .directory), .init(path: "A/f", kind: .file)], "at the top level")
    }

    func testHostileNumbersAreRefusedNotCrashedOn() {
        // Each of these used to reach arithmetic that traps (a crash is a denial of service).
        func bad(_ e: Manifest.Entry, line: UInt = #line) {
            XCTAssertThrowsError(try Manifest(chunkSize: chunk, entries: [e]).validate(), line: line)
        }
        bad(.init(path: "f", kind: .file, size: .max))
        bad(.init(path: "f", kind: .file, size: -1))
        bad(.init(path: "f", kind: .file, size: 1, mtime: 1e300))
        bad(.init(path: "f", kind: .file, size: 1, mtime: -.infinity))
        bad(.init(path: "f", kind: .file, size: 1, mtime: .nan))
        bad(.init(path: "l", kind: .symlink, link: String(repeating: "a", count: 5000)))
        XCTAssertThrowsError(try Manifest(chunkSize: 1 << 40, entries: [.init(path: "f", kind: .file)]).validate())
        // The largest sizes that are let through do not overflow the sums done with them.
        let big = Manifest(chunkSize: 4096, entries: (0..<4).map { .init(path: "f\($0)", kind: .file, size: Manifest.maxFileSize) })
        XCTAssertNoThrow(try big.validate())
        XCTAssertEqual(big.totalBytes, 4 << 50)
        XCTAssertEqual(big.chunkCount(0), 1 << 38)
    }

    // MARK: A raw connection: what is on the wire, without the app's sender

    func connect(_ l: DropListener) throws -> Socket { try Socket.connect(host: "127.0.0.1", port: l.port) }

    func testWhatArrivesMustBeWhatWasOffered() throws {
        // The person agrees to "1 file, 5 bytes". The manifest then describes something else.
        let l = try victim()
        defer { l.stop() }
        func attempt(_ manifest: Manifest) throws -> String {
            let s = try connect(l)
            try s.send(.offer, Offer(version: protocolVersion, minor: 0, app: "x", senderName: "attacker", senderID: "a",
                                     items: ["note.txt"], fileCount: 1, totalBytes: 5))
            XCTAssertEqual(try s.readFrame().type, .accept)
            try s.send(.manifest, manifest)
            let reply = try s.readFrame()
            XCTAssertEqual(reply.type, .error)
            return try decode(Reason.self, from: reply.body).message
        }
        for manifest in [
            Manifest(chunkSize: chunk, entries: [.init(path: "note.txt", kind: .file, size: 5_000_000_000)]),          // far bigger
            Manifest(chunkSize: chunk, entries: [.init(path: "note.txt", kind: .file, size: 5), .init(path: "more.app", kind: .file, size: 0)]),   // something extra
            Manifest(chunkSize: chunk, entries: [.init(path: "Install.command", kind: .file, size: 5)]),               // another name
        ] {
            XCTAssertTrue(try attempt(manifest).contains("not what was offered"))
        }
        Thread.sleep(forTimeInterval: 0.2)
        XCTAssertEqual(try FileManager.default.contentsOfDirectory(atPath: downloads.path), [], "and nothing was written")
    }

    func testAStrangerCannotMakeThisMacSetHalfAGigabyteAside() throws {
        // A frame header promising 400 MB, from a connection that has not been let in.
        let l = try victim()
        defer { l.stop() }
        let s = try connect(l)
        var length = UInt32(400 << 20).bigEndian
        var crc = withUnsafeBytes(of: &length) { checksum($0.baseAddress!, 4) }.bigEndian
        var head = Data()
        withUnsafeBytes(of: &length) { head.append(contentsOf: $0) }
        withUnsafeBytes(of: &crc) { head.append(contentsOf: $0) }
        try head.withUnsafeBytes { try s.writeAll($0.baseAddress!, 8) }
        // The receiver does not wait for the 400 MB: it closes at the header.
        s.setReadTimeout(3)
        var byte: UInt8 = 0
        XCTAssertThrowsError(try s.readExactly(&byte, 1)) { XCTAssertTrue("\($0)".contains("closed"), "\($0)") }
    }

    func testAConnectionThatNeverSaysWhatItIsIsClosed() throws {
        Tuning.strangerSeconds = 1
        defer { Tuning.strangerSeconds = 10 }
        let l = try victim()
        defer { l.stop() }
        let s = try connect(l)
        // One byte, then silence: not "no data", so a per-read timeout alone would wait for ever.
        var b: UInt8 = 0
        try s.writeAll(&b, 1)
        s.setReadTimeout(4)
        let started = Date()
        XCTAssertThrowsError(try s.readExactly(&b, 1))
        XCTAssertLessThan(Date().timeIntervalSince(started), 3)
    }

    func testOffersCannotBuryThePersonInQuestions() throws {
        // Twenty offers from one address. Two questions are asked; the rest are declined unseen.
        let asked = Box(0)
        let l = try DropListener(identity: Identity(name: "victim", id: "victim-id"), preferredPort: 0)
        l.onOffer = { _ in asked.value += 1 }   // never answers
        l.start()
        defer { l.stop() }
        var sockets: [Socket] = [], declined = 0
        for i in 0..<20 {
            let s = try connect(l)
            try s.send(.offer, Offer(version: protocolVersion, minor: 0, app: "x", senderName: "attacker", senderID: "a\(i)",
                                     items: ["f"], fileCount: 1, totalBytes: 1))
            sockets.append(s)
        }
        Thread.sleep(forTimeInterval: 0.5)
        for s in sockets where s.waitReadable(milliseconds: 50) {
            if let f = try? s.readFrame(), f.type == .decline { declined += 1 }
        }
        XCTAssertEqual(asked.value, Tuning.pendingOffersPerAddress)
        XCTAssertEqual(declined, 20 - Tuning.pendingOffersPerAddress)
    }

    func testNamesFromAnotherMachineCannotForgeLinesOrFloodAPanel() throws {
        XCTAssertEqual(Sanitize.label("dads-imac\n2026-11-22 ERROR  something false"), "dads-imac 2026-11-22 ERROR  something false")
        XCTAssertEqual(Sanitize.label("a\u{2028}b\rc\0d\u{1B}[31m"), "a b c d [31m")
        XCTAssertEqual(Sanitize.label(String(repeating: "x", count: 500), limit: 64).count, 65)
        let seen = Box<ReceiveSession?>(nil)
        let l = try DropListener(identity: Identity(name: "victim", id: "victim-id"), preferredPort: 0)
        l.onOffer = { seen.value = $0 }
        l.start()
        defer { l.stop() }
        let s = try connect(l)
        try s.send(.offer, Offer(version: protocolVersion, minor: 0, app: "x", senderName: "macbookairm4\n\n(trusted)" + String(repeating: "!", count: 300),
                                 senderID: "a", items: ["holiday\nphotos"], fileCount: 1, totalBytes: 1))
        Thread.sleep(forTimeInterval: 0.3)
        let r = try XCTUnwrap(seen.value)
        XCTAssertFalse(r.peerName.contains("\n"))
        XCTAssertLessThanOrEqual(r.peerName.count, 65)
        XCTAssertEqual(r.items, ["holiday photos"])
        XCTAssertEqual(r.peerAddress, "127.0.0.1", "the address is the connection's, not the sender's say-so")
    }
}
