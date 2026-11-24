// Copyright (C) 2026 Niels Joubert
// SPDX-License-Identifier: GPL-3.0-or-later
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

/// What a hostile sender can do to a receiver that accepts its drop. Every test here is an
/// attack that was thought through against the real code; the ones marked "worked" did.
final class SecurityTests: XCTestCase {
    var root: URL!
    let attacker = Identity(name: "attacker", id: "attacker-id")
    let chunk = 16 * 1024
    /// The attacker is a Mac the victim has paired with: these are attacks by a peer that is
    /// who it says it is and means harm, which pairing does nothing to prevent.
    var attackerTrust: Trust!
    var victimTrust: Trust!

    override func setUpWithError() throws {
        root = FileManager.default.temporaryDirectory.appendingPathComponent("nimbusdrop-security-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: root.appendingPathComponent("home/Downloads"), withIntermediateDirectories: true)
        try FileManager.default.createDirectory(at: root.appendingPathComponent("home/Library/LaunchAgents"), withIntermediateDirectories: true)
        Tuning.reconnectSeconds = 1
        (attackerTrust, victimTrust) = Trust.paired("attacker", "victim")
    }

    override func tearDownWithError() throws {
        Tuning.reconnectSeconds = 60
        try? FileManager.default.removeItem(at: root)
    }

    /// The victim: accepts whatever is offered, into its Downloads.
    func victim() throws -> DropListener {
        let downloads = self.downloads
        let l = try DropListener(identity: Identity(name: "victim", id: "victim-id"), trust: victimTrust, preferredPort: 0)
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
        let s = SendSession(urls: [], host: "127.0.0.1", port: l.port, peerName: "victim", identity: attacker, trust: attackerTrust,
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
        let key = Manifest(chunkSize: chunk, entries: entries).key(senderID: attackerTrust.publicKey.raw.map { String(format: "%02x", $0) }.joined())
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
        let big = Manifest(chunkSize: 1 << 20, entries: (0..<4).map { .init(path: "f\($0)", kind: .file, size: Manifest.maxFileSize) })
        XCTAssertNoThrow(try big.validate())
        XCTAssertEqual(big.totalBytes, 4 << 50)
        XCTAssertEqual(big.chunkCount(0), 1 << 30)
        // A chunk is named on the wire by 32 bits: a file of more chunks than that is refused,
        // not sent with numbers that wrap.
        XCTAssertThrowsError(try Manifest(chunkSize: 4096, entries: [.init(path: "f", kind: .file, size: Manifest.maxFileSize)]).validate())
        XCTAssertNoThrow(try Manifest(chunkSize: 4096, entries: [.init(path: "f", kind: .file, size: 4096 * Int64(UInt32.max) - 1)]).validate())
    }

    // MARK: A raw connection: what is on the wire, without the app's sender

    func connect(_ l: DropListener) throws -> Socket { try Socket.connect(host: "127.0.0.1", port: l.port) }

    /// The attacker's own hand on the protocol: a proved, paired channel on which it may send
    /// whatever it likes.
    func dial(_ l: DropListener, name: String = "attacker") throws -> Channel {
        try Channel.dial(host: "127.0.0.1", port: l.port, trust: attackerTrust, name: name, purpose: .drop).channel
    }

    func testWhatArrivesMustBeWhatWasOffered() throws {
        // The person agrees to "1 file, 5 bytes". The manifest then describes something else.
        let l = try victim()
        defer { l.stop() }
        func attempt(_ manifest: Manifest) throws -> String {
            let s = try dial(l)
            try s.send(.offer, Offer(items: ["note.txt"], fileCount: 1, totalBytes: 5))
            XCTAssertEqual(try s.read().type, .accept)
            try s.send(.manifest, manifest)
            let reply = try s.read()
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
        // Before a key is proved nothing longer than a kilobyte is read: a handshake frame
        // promising 60,000 bytes is refused at its length.
        let l = try victim()
        defer { l.stop() }
        let s = try connect(l)
        let opening = Opening.mine()
        try opening.withUnsafeBytes { try s.writeAll($0.baseAddress!, opening.count) }
        let n: UInt16 = 60000
        let head = Data([UInt8(n >> 8), UInt8(n & 0xff), UInt8(~n >> 8), UInt8(~n & 0xff)])
        try head.withUnsafeBytes { try s.writeAll($0.baseAddress!, 4) }
        s.setReadTimeout(3)
        var reply = [UInt8](repeating: 0, count: opening.count)
        try reply.withUnsafeMutableBytes { try s.readExactly($0.baseAddress!, opening.count) }   // its own opening, sent before it read ours
        var byte: UInt8 = 0
        XCTAssertThrowsError(try s.readExactly(&byte, 1)) { XCTAssertTrue("\($0)".contains("closed"), "\($0)") }
    }

    func testAPairedMacCannotMakeThisMacSetHalfAGigabyteAsideEither() throws {
        // After a handshake and before an accept, a message is one fragment. One that announces
        // 400 MB is refused on its first fragment, with nothing set aside.
        let asked = Box(0)
        let l = try DropListener(identity: Identity(name: "victim", id: "victim-id"), trust: victimTrust, preferredPort: 0)
        l.onOffer = { _ in asked.value += 1 }
        l.start()
        defer { l.stop() }
        let s = try dial(l)
        // (The victim hangs up at the first fragment, so the rest of the sending may fail.)
        try? s.send(.offer, Offer(items: [String(repeating: "x", count: 200_000)], fileCount: 1, totalBytes: 1))
        s.socket.setReadTimeout(3)
        XCTAssertThrowsError(try s.read())
        XCTAssertEqual(asked.value, 0)

        // And after an accept, the manifest may be as large as the offer said the drop was, no
        // larger: "1 file" does not buy a 300,000-entry manifest.
        l.onOffer = { $0.accept(destination: self.downloads) }
        let t = try dial(l)
        try t.send(.offer, Offer(items: ["a"], fileCount: 1, totalBytes: 1))
        XCTAssertEqual(try t.read().type, .accept)
        try? t.send(.manifest, Manifest(chunkSize: chunk, entries: (0..<20_000).map { .init(path: "f\($0)", kind: .file, size: 0) }))
        t.socket.setReadTimeout(3)
        let reply = try? t.read()
        XCTAssertTrue(reply == nil || reply!.type == .error, "refused, or the connection closed")
        XCTAssertEqual(try FileManager.default.contentsOfDirectory(atPath: downloads.path), [])
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
        // A dozen offers from one Mac. Two questions are asked; the rest are declined unseen.
        let asked = Box(0)
        let l = try DropListener(identity: Identity(name: "victim", id: "victim-id"), trust: victimTrust, preferredPort: 0)
        l.onOffer = { _ in asked.value += 1 }   // never answers
        l.start()
        defer { l.stop() }
        var channels: [Channel] = [], declined = 0
        for _ in 0..<12 {
            let s = try dial(l)
            try s.send(.offer, Offer(items: ["f"], fileCount: 1, totalBytes: 1))
            channels.append(s)
        }
        Thread.sleep(forTimeInterval: 0.5)
        for s in channels where s.socket.waitReadable(milliseconds: 50) {
            if let f = try? s.read(), f.type == .decline { declined += 1 }
        }
        XCTAssertEqual(asked.value, Tuning.pendingOffersPerAddress)
        XCTAssertEqual(declined, 12 - Tuning.pendingOffersPerAddress)
    }

    func testNamesFromAnotherMachineCannotForgeLinesOrFloodAPanel() throws {
        XCTAssertEqual(Sanitize.label("dads-imac\n2026-11-22 ERROR  something false"), "dads-imac 2026-11-22 ERROR  something false")
        XCTAssertEqual(Sanitize.label("a\u{2028}b\rc\0d\u{1B}[31m"), "a b c d [31m")
        XCTAssertEqual(Sanitize.label(String(repeating: "x", count: 500), limit: 64).count, 65)
        let seen = Box<ReceiveSession?>(nil)
        let l = try DropListener(identity: Identity(name: "victim", id: "victim-id"), trust: victimTrust, preferredPort: 0)
        l.onOffer = { seen.value = $0 }
        l.start()
        defer { l.stop() }
        let s = try dial(l, name: "macbookairm4\n\n(trusted)" + String(repeating: "!", count: 300))
        try s.send(.offer, Offer(items: ["holiday\nphotos"], fileCount: 1, totalBytes: 1))
        Thread.sleep(forTimeInterval: 0.3)
        let r = try XCTUnwrap(seen.value)
        XCTAssertEqual(r.peerName, "attacker", "the name shown is the one given to that Mac here, whatever it calls itself today")
        XCTAssertFalse(victimTrust.known[0].announced.contains { $0.contains("\n") }, "and what it calls itself is cleaned before it is kept")
        XCTAssertEqual(r.items, ["holiday photos"])
        XCTAssertEqual(r.peerAddress, "127.0.0.1", "the address is the connection's, not the sender's say-so")
    }

    // MARK: What a drop leaves behind

    func testWhatIsReceivedIsQuarantinedAsADownloadIs() throws {
        // An app or a script in a drop must get Gatekeeper's question when first run, as one
        // from AirDrop or a browser does; that is what this mark is.
        let fm = FileManager.default
        let src = root.appendingPathComponent("src/Tools")
        try fm.createDirectory(at: src.appendingPathComponent("Run.app/Contents/MacOS"), withIntermediateDirectories: true)
        try Data("#!/bin/sh\n".utf8).write(to: src.appendingPathComponent("Run.app/Contents/MacOS/Run"))
        try Data("#!/bin/sh\n".utf8).write(to: src.appendingPathComponent("install.command"))
        try fm.setAttributes([.posixPermissions: 0o755], ofItemAtPath: src.appendingPathComponent("install.command").path)
        let l = try victim()
        defer { l.stop() }
        let s = SendSession(urls: [src], host: "127.0.0.1", port: l.port, peerName: "victim", identity: attacker, trust: attackerTrust, chunkSize: chunk)
        s.start()
        wait(s)
        XCTAssertEqual(s.state, .completed)
        func mark(_ path: String) -> String? {
            var buffer = [UInt8](repeating: 0, count: 256)
            let n = getxattr(downloads.appendingPathComponent(path).path, "com.apple.quarantine", &buffer, buffer.count, 0, XATTR_NOFOLLOW)
            return n > 0 ? String(decoding: buffer.prefix(n), as: UTF8.self) : nil
        }
        for path in ["Tools", "Tools/install.command", "Tools/Run.app", "Tools/Run.app/Contents/MacOS/Run"] {
            let value = try XCTUnwrap(mark(path), "\(path) is not quarantined")
            XCTAssertTrue(value.hasPrefix("0081;") || value.hasPrefix("0083;"), value)
            XCTAssertTrue(value.contains("Nimbus"), value)
        }
        XCTAssertEqual(try fm.attributesOfItem(atPath: downloads.appendingPathComponent("Tools/install.command").path)[.posixPermissions] as? Int, 0o755,
                       "it is still the executable it was; macOS asks before running it")
    }

    func testLinksThatPointOutOfTheDropAreLeftOut() throws {
        let fm = FileManager.default
        let src = root.appendingPathComponent("src/Project")
        try fm.createDirectory(at: src.appendingPathComponent("lib/deep"), withIntermediateDirectories: true)
        try Data("x".utf8).write(to: src.appendingPathComponent("lib/real.txt"))
        for (name, target) in [("inside", "lib/real.txt"), ("lib/deep/up", "../real.txt"), ("lib/deep/top", "../../lib"),
                               ("absolute", "/etc/hosts"), ("climbs", "../../../Library"), ("lib/deep/too-far", "../../../x"),
                               ("sneaky", "lib/../../.."), ("home", "/Users")] {
            try fm.createSymbolicLink(atPath: src.appendingPathComponent(name).path, withDestinationPath: target)
        }
        let seen = Box<ReceiveSession?>(nil)
        let downloads = self.downloads
        let l = try DropListener(identity: Identity(name: "victim", id: "victim-id"), trust: victimTrust, preferredPort: 0)
        l.onOffer = { seen.value = $0; $0.accept(destination: downloads) }
        l.start()
        defer { l.stop() }
        let s = SendSession(urls: [src], host: "127.0.0.1", port: l.port, peerName: "victim", identity: attacker, trust: attackerTrust, chunkSize: chunk)
        s.start()
        wait(s)
        XCTAssertEqual(s.state, .completed, "the drop itself is fine; only the links are left out")
        let got = downloads.appendingPathComponent("Project")
        func link(_ name: String) -> String? { try? fm.destinationOfSymbolicLink(atPath: got.appendingPathComponent(name).path) }
        XCTAssertEqual(link("inside"), "lib/real.txt")
        XCTAssertEqual(link("lib/deep/up"), "../real.txt")
        XCTAssertEqual(link("lib/deep/top"), "../../lib", "as far up as the drop's own top is still inside")
        for name in ["absolute", "climbs", "lib/deep/too-far", "sneaky", "home"] {
            XCTAssertNil(link(name), "\(name) points outside and was recreated")
            XCTAssertFalse(fm.fileExists(atPath: got.appendingPathComponent(name).path))
        }
        let r = try XCTUnwrap(seen.value)
        wait(r)
        XCTAssertEqual(r.stats.skippedLinks, 5, "and the receiver can say how many")
    }

    func testWhichLinksStayInside() {
        func inside(_ path: String, _ link: String) -> Bool { Manifest.linkStaysInside(path: path, link: link) }
        XCTAssertTrue(inside("Photos/a", "b.jpg"))
        XCTAssertTrue(inside("Photos/sub/a", "../b.jpg"))
        XCTAssertTrue(inside("App.app/Contents/Frameworks/X.framework/X", "Versions/Current/X"))
        XCTAssertTrue(inside("Photos/sub/a", "./x/./y"))
        XCTAssertFalse(inside("Photos/a", "../elsewhere"), "out of the top-level item")
        XCTAssertFalse(inside("Photos/sub/a", "../../elsewhere"))
        XCTAssertFalse(inside("Photos/a", "/Users/someone/.ssh"))
        XCTAssertFalse(inside("Photos/a", "sub/../../.."), "'..' after a name: refused rather than resolved")
        XCTAssertFalse(inside("link", "anything"), "a top-level item that is itself a link has nothing to stay inside")
        XCTAssertFalse(inside("Photos/a", ""))
    }

    // MARK: Who may connect

    func testWhichAddressesAreOnThisNetwork() {
        let home = [LocalNetwork.Net(address: [192, 168, 1, 107], mask: [255, 255, 255, 0]),
                    LocalNetwork.Net(address: [10, 8, 0, 2], mask: [255, 255, 255, 255]),          // a point-to-point VPN
                    LocalNetwork.Net(address: LocalNetwork.parse("2001:db8:1:2::10")!, mask: [UInt8](repeating: 0xFF, count: 8) + [UInt8](repeating: 0, count: 8))]
        func local(_ a: String) -> Bool { LocalNetwork.isLocal(a, among: home) }
        XCTAssertTrue(local("192.168.1.143"), "the same subnet")
        XCTAssertTrue(local("127.0.0.1"), "this Mac")
        XCTAssertTrue(local("::1"))
        XCTAssertTrue(local("fe80::1c2b:3aff:fe4d:5e6f%en0"), "a link-local neighbour")
        XCTAssertTrue(local("169.254.10.20"))
        XCTAssertTrue(local("2001:db8:1:2::99"), "the same IPv6 prefix")
        XCTAssertFalse(local("192.168.2.143"), "the subnet next door")
        XCTAssertFalse(local("8.8.8.8"))
        XCTAssertFalse(local("10.8.0.9"), "another end of the VPN: the mask covers one address")
        XCTAssertFalse(local("2001:db8:1:3::99"))
        XCTAssertFalse(local("not an address"))
        XCTAssertFalse(LocalNetwork.isLocal("192.168.1.143", among: [.init(address: [0, 0, 0, 0], mask: [0, 0, 0, 0])]), "an empty mask matches nothing, not everything")
        XCTAssertFalse(LocalNetwork.current().isEmpty, "this Mac has at least its loopback")
    }

    func testAnAddressThatIsNotLocalIsTurnedAwayUnread() throws {
        let asked = Box(0)
        let l = try DropListener(identity: Identity(name: "victim", id: "victim-id"), trust: victimTrust, preferredPort: 0)
        l.onOffer = { _ in asked.value += 1 }
        l.allows = { _ in false }   // as if 127.0.0.1 were somewhere far away
        l.start()
        defer { l.stop() }
        XCTAssertTrue(l.localOnly, "the default")
        let s = try connect(l)
        let opening = Opening.mine()
        try? opening.withUnsafeBytes { try s.writeAll($0.baseAddress!, opening.count) }
        s.setReadTimeout(3)
        var b: UInt8 = 0
        XCTAssertThrowsError(try s.readExactly(&b, 1), "the connection was closed, not answered")
        XCTAssertEqual(asked.value, 0, "and nobody was asked anything")
        XCTAssertThrowsError(try Probe.identify(host: "127.0.0.1", port: l.port, timeout: 2), "not even who it is")
    }

    // MARK: The uninstaller

    /// The uninstaller deletes folders. It deletes only what is exactly a partial folder of
    /// this app's, by name, and only where a drop was saved; never anything else there.
    func testTheUninstallerRemovesOnlyWhatIsTheApps() throws {
        let fm = FileManager.default
        let home = root.appendingPathComponent("home"), downloads = home.appendingPathComponent("Downloads"), other = home.appendingPathComponent("Elsewhere")
        let key = String(repeating: "0a", count: 16)
        for dir in [downloads, other] {
            for name in ["Photos.\(key).nimbusdrop-partial", "Photos", "Notes.nimbusdrop-partial", "x.\(key.dropLast()).nimbusdrop-partial", "y.\(key.uppercased()).nimbusdrop-partial"] {
                try fm.createDirectory(at: dir.appendingPathComponent(name), withIntermediateDirectories: true)
            }
            try Data().write(to: dir.appendingPathComponent("file.\(key).nimbusdrop-partial"))   // a file of that name is not ours
        }
        let found = Leftovers.partials(near: [other.appendingPathComponent("Christmas").path], also: [downloads])
        XCTAssertEqual(Set(found.map(\.path)), [downloads.appendingPathComponent("Photos.\(key).nimbusdrop-partial").path, other.appendingPathComponent("Photos.\(key).nimbusdrop-partial").path])
        XCTAssertEqual(Leftovers.partials(near: [], also: [home.appendingPathComponent("not-there")]), [])

        // What is kept under Library is named by the bundle, and a development copy does not
        // claim the released app's files or the command line's identities.
        let release = Leftovers.library(bundleID: "com.njoubert.nimbusdrop", bundleName: "Nimbus Drop", home: home).map { $0.path.replacingOccurrences(of: home.path, with: "~") }
        let dev = Leftovers.library(bundleID: "com.njoubert.nimbusdrop.dev", bundleName: "Nimbus Drop Dev", home: home).map { $0.path.replacingOccurrences(of: home.path, with: "~") }
        XCTAssertTrue(release.contains("~/Library/Application Support/com.njoubert.nimbusdrop"))
        XCTAssertTrue(release.contains("~/Library/Application Support/com.njoubert.nimbusdrop.cli"))
        XCTAssertTrue(release.contains("~/Library/Logs/Nimbus Drop"))
        XCTAssertTrue(release.contains("~/Library/Preferences/com.njoubert.nimbusdrop.plist"))
        XCTAssertTrue(dev.contains("~/Library/Logs/Nimbus Drop Dev"))
        XCTAssertTrue(dev.allSatisfy { $0.contains("nimbusdrop.dev") || $0.hasSuffix("/Nimbus Drop Dev") }, "\(dev)")
        XCTAssertTrue((release + dev).allSatisfy { $0.hasPrefix("~/Library/") && $0.split(separator: "/").count >= 4 }, "never a whole Library folder")
        XCTAssertEqual(Leftovers.serviceKey(bundleID: "com.njoubert.nimbusdrop", bundleName: "Nimbus Drop"), "com.njoubert.nimbusdrop - Nimbus Drop To… - dropService")
    }
}
