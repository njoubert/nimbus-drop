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

/// What the review of the code against the plan found (Phase 5, 2026-11-23, at d1863b8;
/// docs/plans/protocol3-code-review.md), as tests. Each of the first group failed on the code
/// as reviewed; the finding it belongs to is named in its comment. The second group is one
/// test for each guard the review could remove without any test noticing; `scripts/mutate.py`
/// removes them again. `testFuzz…`: malformed input thrown at the parsers (a trap in the
/// listener would take the test process down with it).
final class ReviewTests: XCTestCase {
    var root: URL!
    let chunk = 16 * 1024
    let day = 86400.0

    override func setUpWithError() throws {
        root = FileManager.default.temporaryDirectory.appendingPathComponent("nimbusdrop-review-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: root.appendingPathComponent("dst"), withIntermediateDirectories: true)
        Tuning.reconnectSeconds = 2
        // Both ends of every test are at one address, and the fuzzers arrive faster than one
        // address may.
        Tuning.arrivalsPerAddress = 500
    }

    override func tearDownWithError() throws {
        Tuning.reconnectSeconds = 60
        Tuning.pairQuietSeconds = 10
        Tuning.pairQuietLongest = 600
        Tuning.strangerSeconds = 10
        Tuning.attachSeconds = 5
        Tuning.connectRetrySeconds = 30
        Tuning.strangers = 64
        Tuning.strangersPerAddress = 8
        Tuning.arrivalsPerSecond = 500
        Tuning.arrivalsPerAddress = 200
        Tuning.unattachedPerAddress = 4
        Tuning.pairedWaiting = 8
        Tuning.unattachedPerDrop = 16
        Tuning.streamsPerDrop = 64
        Tuning.pairSeconds = 120
        DropKeys.streamBytes = 1 << 38
        try? FileManager.default.removeItem(at: root)
    }

    var dst: URL { root.appendingPathComponent("dst") }

    func file(_ name: String, bytes: Int) throws -> URL {
        let url = root.appendingPathComponent(name)
        try Data((0..<bytes).map { UInt8(truncatingIfNeeded: $0 &* 31) }).write(to: url)
        return url
    }

    func pairedMacs() throws -> (TestMac, TestMac) {
        let (a, b) = Trust.paired("sender", "receiver")
        let sender = try TestMac("sender", trust: a), receiver = try TestMac("receiver", trust: b)
        let dst = dst
        receiver.listener.onOffer = { [weak receiver] s in
            receiver?.offers.withLock { $0.append(s) }
            s.accept(destination: dst)
        }
        return (sender, receiver)
    }

    func send(_ urls: [URL], from: TestMac, to: TestMac, port: UInt16? = nil, expect: PublicKey? = nil, name: String? = nil) -> SendSession {
        let s = SendSession(urls: urls, host: "127.0.0.1", port: port ?? to.port, peerName: name ?? to.identity.name, identity: from.identity, trust: from.trust,
                            expect: expect, streams: 4, chunkSize: chunk)
        s.start()
        return s
    }

    func wait(_ t: Transfer, _ seconds: Double = 20) { _ = until(seconds) { t.state.isFinal } }

    // MARK: Findings, as failing tests

    /// F2. P16 / Key expiry: "After its end date a key is refused ... and cannot be paired
    /// again; the record of it is kept as a tombstone when the rest of its entry is dropped."
    /// A key on the pair-again list is dropped at its end with no tombstone, and is New again.
    func testAKeyThatRunsOutOnThePairAgainListStaysRefused() throws {
        let clock = FakeClock()
        let trust = Trust.inMemory(clock: clock, lifetime: day)
        let theirs = KeyPair().publicKey
        try trust.store(pairing: theirs, announced: "air", method: "codes", remaining: 10 * day)
        clock.pass(2 * day)
        trust.tick()   // this Mac's own key ran out and was replaced: `theirs` waits to be paired again
        guard case .renew = trust.standing(of: theirs) else { return XCTFail("\(trust.standing(of: theirs))") }
        clock.pass(10 * day)
        trust.tick()   // and now the deadline recorded for `theirs` has passed
        XCTAssertFalse(trust.standing(of: theirs).mayPair, "a key past the deadline recorded for it is \(trust.standing(of: theirs)): it can be paired as a new Mac, for a fresh 90 days, and using it raises no alarm")
        XCTAssertTrue(trust.tombstones.contains { $0.key == theirs })
    }

    /// F2, the same after Reset Identity (every Known Mac goes to the pair-again list).
    func testAKeyThatRunsOutAfterAResetStaysRefused() throws {
        let clock = FakeClock()
        let trust = Trust.inMemory(clock: clock)
        let theirs = KeyPair().publicKey
        try trust.store(pairing: theirs, announced: "air", method: "codes", remaining: 10 * day)
        _ = trust.beginReset()
        trust.completeReset(told: [])
        clock.pass(11 * day)
        trust.tick()
        XCTAssertFalse(trust.standing(of: theirs).mayPair, "\(trust.standing(of: theirs))")
    }

    /// F3. Key expiry says a calendar set forward "costs a renewal". In the code it costs every
    /// pairing for good: each peer's key, still good on its own Mac, is tombstoned here, and
    /// stays refused after the calendar is put right. Each of those Macs has to Reset Identity.
    func testACalendarSetForwardOnceCostsARenewalAndNoMore() throws {
        let clock = FakeClock()
        let trust = Trust.inMemory(clock: clock)
        let theirs = KeyPair().publicKey
        try trust.store(pairing: theirs, announced: "air", method: "codes", remaining: 80 * day)
        clock.setCalendar(by: 100 * day)    // a forged time server, for one tick
        trust.tick()
        clock.setCalendar(by: -100 * day)   // and the calendar is right again
        trust.tick()
        guard case .renew = trust.standing(of: theirs) else {
            return XCTFail("the other Mac's key has 80 days left by every honest clock, and is \(trust.standing(of: theirs)) here: it should be waiting to be paired again")
        }
        XCTAssertTrue(trust.tombstones.isEmpty)
        // And pairing it again gives a pairing that holds, with the end its key always had.
        try trust.store(pairing: theirs, announced: "air", method: "codes", remaining: 80 * day)
        XCTAssertTrue(trust.standing(of: theirs).isPaired)
        clock.pass(81 * day)
        XCTAssertFalse(trust.standing(of: theirs).mayPair, "its key has now run out by the count kept here, and that is for good")
    }

    /// F5. Pairing: "One pairing at a time on each Mac, in either role. A request arriving
    /// meanwhile is answered busy." A stranger's request is put on screen beside this Mac's own
    /// pairing in progress.
    func testNoRequestIsShownWhileThisMacIsItselfPairing() throws {
        let a = try TestMac("a"), b = try TestMac("b"), stranger = try TestMac("b")
        let mine = a.pair(with: b)   // b's person has not answered yet
        XCTAssertTrue(until { mine.state == .asking })
        let theirs = stranger.pair(with: a)
        _ = until(3) { theirs.state.isFinal || !a.requests.withLock { $0.isEmpty } }
        XCTAssertTrue(a.requests.withLock { $0.isEmpty }, "a request from a stranger calling itself “b” was shown while this Mac's person was in the middle of pairing with b")
        mine.cancel()
        theirs.cancel()
    }

    /// F6. Admission: an offer waits "until answered or withdrawn; the sender's key ending
    /// withdraws it". P16: no Mac begins a drop with a key after the deadline it recorded.
    func testAnOfferStillWaitingWhenItsKeyEndsIsWithdrawn() throws {
        let clock = FakeClock()
        let a = Trust.inMemory(clock: clock), b = Trust.inMemory(clock: clock)
        try a.store(pairing: b.publicKey, announced: "receiver", method: "codes", remaining: 90 * day)
        try b.store(pairing: a.publicKey, announced: "sender", method: "codes", remaining: 3600)
        let sender = try TestMac("sender", trust: a), receiver = try TestMac("receiver", trust: b)
        let s = send([try file("late.txt", bytes: 10)], from: sender, to: receiver)
        XCTAssertTrue(until { receiver.offers.withLock { $0.count == 1 } })
        clock.pass(3700, calendar: 0)   // the sender's key runs out with the question still on screen
        b.tick()
        Thread.sleep(forTimeInterval: 0.3)
        let offer = receiver.offers.withLock { $0[0] }
        XCTAssertTrue(offer.state.isFinal, "the offer is still waiting (\(offer.state)) after the key that made it ran out")
        offer.accept(destination: dst)
        wait(s, 10)
        XCTAssertNotEqual(s.state, .completed)
        XCTAssertFalse(FileManager.default.fileExists(atPath: dst.appendingPathComponent("late.txt").path), "a drop began, and was delivered, under a key past its deadline")
    }

    /// F7. Withdrawing trust runs with the trust store's lock held, and for a sender it says a
    /// last word on the control connection first (`SendSession.fail`). A paired Mac that has
    /// stopped reading that connection, and then retires its own key, leaves the store locked
    /// for good: no handshake, no tile, no window that asks who a key is ever gets an answer.
    func testAPairedMacCannotLockTheTrustStoreByRetiringItselfMidDrop() throws {
        let a = Trust.inMemory(), k = Trust.inMemory()
        a.adopt(k, as: "hostile"); k.adopt(a, as: "victim")
        let victim = try TestMac("victim", trust: a)
        // The hostile Mac as a receiver: takes the offer, says yes, and never reads again.
        let (fd, port) = try Socket.listen(port: 0)
        defer { close(fd) }
        let taken = Locked<Channel?>(nil)
        Thread.detachNewThread {
            let client = accept(fd, nil, nil)
            guard client >= 0 else { return }
            let socket = Socket(fd: client)
            guard (try? Opening.readKind(socket)) == Opening.control, let c = try? Channel.respond(socket, keys: k.keyPair),
                  (try? c.read()) != nil,
                  (try? c.send(.hello, SecureHello(minor: 0, app: "x", name: "hostile", remaining: 90 * 86400, paired: true, purpose: nil))) != nil,
                  (try? c.read()) != nil, (try? c.send(.accept, Empty())) != nil else { return }
            taken.withLock { $0 = c }
        }
        // A drop whose manifest is more than the two socket buffers hold (a folder of 400,000 files).
        let entries = [Manifest.Entry(path: "Photos", kind: .directory)]
            + (0..<400_000).map { Manifest.Entry(path: "Photos/file-with-a-name-of-ordinary-length-\($0).jpeg", kind: .file, size: 0) }
        let scanned = ScannedDrop(manifest: Manifest(chunkSize: chunk, entries: entries), sources: entries.map { _ in "/dev/null" })
        let s = SendSession(urls: [], host: "127.0.0.1", port: port, peerName: "hostile", identity: victim.identity, trust: a, expect: k.publicKey,
                            chunkSize: chunk, prescanned: scanned)
        s.start()
        XCTAssertTrue(until { taken.withLock { $0 != nil } })
        Thread.sleep(forTimeInterval: 1.5)   // the manifest is on its way and going nowhere
        XCTAssertFalse(s.state.isFinal)
        // Now it retires its own key, as any paired key may.
        Thread.detachNewThread {
            guard let (c, _) = try? Channel.dial(host: "127.0.0.1", port: victim.port, trust: k, name: "hostile", purpose: .retire) else { return }
            try? c.send(.retire, Empty())
            _ = try? c.read()
        }
        Thread.sleep(forTimeInterval: 1.5)
        let answered = Locked(false)
        Thread.detachNewThread { _ = a.standing(of: KeyPair().publicKey); answered.withLock { $0 = true } }
        XCTAssertTrue(until(5) { answered.withLock { $0 } }, "the trust store has not answered a question in 5 s: its lock is held by a thread writing to a socket nobody reads")
        XCTAssertTrue(until(5) { s.state.isFinal }, "and the drop to it has ended, without waiting to say goodbye to a Mac that is not listening")
        XCTAssertFalse(a.standing(of: k.publicKey).mayPair, "the retirement was carried out")
        taken.withLock { $0?.socket.shutdown() }   // let everything go
        _ = until(5) { answered.withLock { $0 } }
    }

    /// F6, the other half: nobody looked at the clock between the key's end and the click.
    func testAYesToAnOfferWhoseKeyHasSinceEndedStartsNothing() throws {
        let clock = FakeClock()
        let a = Trust.inMemory(clock: clock), b = Trust.inMemory(clock: clock)
        try a.store(pairing: b.publicKey, announced: "receiver", method: "codes", remaining: 90 * day)
        try b.store(pairing: a.publicKey, announced: "sender", method: "codes", remaining: 3600)
        let sender = try TestMac("sender", trust: a), receiver = try TestMac("receiver", trust: b)
        let s = send([try file("late.txt", bytes: 10)], from: sender, to: receiver)
        XCTAssertTrue(until { receiver.offers.withLock { $0.count == 1 } })
        clock.pass(3700, calendar: 0)
        receiver.offers.withLock { $0[0] }.accept(destination: dst)
        wait(s, 10)
        XCTAssertNotEqual(s.state, .completed)
        XCTAssertFalse(FileManager.default.fileExists(atPath: dst.appendingPathComponent("late.txt").path))
    }

    /// F7, the rule behind it: nothing that ends a session runs while the trust store is
    /// locked. A session being ended asks the store a question from another thread, as a
    /// handshake in progress or a window would; it must get its answer.
    func testEndingASessionDoesNotHoldTheTrustStore() throws {
        final class Asks: Transfer, @unchecked Sendable {
            let trust: Trust
            let answered = Locked(false)
            init(_ trust: Trust) {
                self.trust = trust
                super.init(direction: .send, state: .transferring, peerName: "x", peerAddress: "x")
            }
            override func withdrawn(_ error: DropError) {
                let done = DispatchSemaphore(value: 0)
                Thread.detachNewThread { [self] in _ = trust.standing(of: KeyPair().publicKey); answered.withLock { $0 = true }; done.signal() }
                _ = done.wait(timeout: .now() + 2)
                super.withdrawn(error)
            }
        }
        let trust = Trust.inMemory()
        let key = KeyPair().publicKey
        try trust.store(pairing: key, announced: "air", method: "codes", remaining: day)
        let session = Asks(trust)
        trust.track(session, key: key)
        trust.forget(key)
        XCTAssertTrue(session.state.isFinal, "ended before Forget returned")
        XCTAssertTrue(session.answered.withLock { $0 }, "the store was locked while the session was being ended")
    }

    /// F4. `--send NAME` means the Known Mac this identity calls NAME, and the drop is aimed at
    /// that Mac's key. A paired Mac that announces another's name is not that Mac.
    func testASendByNameIsAimedAtTheKeyOfTheMacThisOneCallsThat() throws {
        let a = Trust.inMemory(), b = Trust.inMemory(), c = Trust.inMemory()
        a.adopt(b, as: "air"); b.adopt(a, as: "pro")
        a.adopt(c, as: "mini"); c.adopt(a, as: "pro")
        let sender = try TestMac("pro", trust: a), air = try TestMac("air", trust: b), mini = try TestMac("air", trust: c)   // the mini announces itself as "air"
        let dst = dst
        mini.listener.onOffer = { $0.accept(destination: dst) }
        _ = air
        let meant = try XCTUnwrap(a.knownMac(called: "air"))
        XCTAssertEqual(meant.key, b.publicKey)
        XCTAssertEqual(a.knownMac(called: "AIR")?.key, b.publicKey)
        XCTAssertEqual(a.knownMac(called: c.publicKey.tag)?.name, "mini")
        XCTAssertNil(a.knownMac(called: "someone-else"))
        // The mini's record is the one found under "air": the drop does not go to it.
        let s = send([try file("for-the-air.txt", bytes: 10)], from: sender, to: mini, expect: meant.key, name: "air")
        wait(s, 10)
        XCTAssertNotEqual(s.state, .completed, "sent to “air”; delivered to the Mac this one knows as “mini”")
        XCTAssertTrue(s.wrongIdentity)
        XCTAssertFalse(FileManager.default.fileExists(atPath: dst.appendingPathComponent("for-the-air.txt").path))
    }

    /// Forget at the receiver while a drop is running (the owner, 2026-11-23): the sender
    /// lost its connections and spent its whole minute "trying to get it back" from a Mac
    /// that would never take it. The Mac says so at the first attempt, and the drop ends there.
    func testADropEndsAtOnceWhenTheReceiverForgetsThePairingMidDrop() throws {
        Tuning.reconnectSeconds = 30
        let (sender, receiver) = try pairedMacs()
        let s = send([try file("big.bin", bytes: 300 << 20)], from: sender, to: receiver)
        XCTAssertTrue(until { s.state == .transferring })
        Thread.sleep(forTimeInterval: 0.05)
        receiver.trust.forget(sender.key)
        XCTAssertTrue(until(8) { s.state.isFinal }, "still \(s.state), with half a minute of reconnecting ahead of it")
        XCTAssertNotEqual(s.state, .completed)
        XCTAssertTrue(s.needsPairing, "\(s.state)")
        guard case .renew = sender.trust.standing(of: receiver.key) else { return XCTFail("the tile would go on saying Paired: \(sender.trust.standing(of: receiver.key))") }
    }

    /// Forget tells the other Mac when it can be reached (the owner, 2026-11-23: the forgotten
    /// Mac went on showing "Paired" until its next drop failed). What it is told is something
    /// only the forgetting Mac's own key can say, and only about itself.
    func testForgetTellsTheOtherMacAndNobodyElseCanSayItForIt() throws {
        // (A pairing only seconds old is not ended by such a hello; these have been paired a while.)
        Tuning.strangerSeconds = 0.5
        let (sender, receiver) = try pairedMacs()
        Thread.sleep(forTimeInterval: 0.6)
        let third = Trust.inMemory()
        third.adopt(receiver.trust, as: "receiver"); receiver.trust.adopt(third, as: "third")
        // A stranger, and another paired Mac, each say "not paired": it is about themselves only.
        _ = try? Channel.dial(host: "127.0.0.1", port: receiver.port, trust: Trust.inMemory(), name: "sender", purpose: nil, paired: false)
        XCTAssertTrue(receiver.trust.standing(of: sender.key).isPaired)
        XCTAssertTrue(receiver.trust.standing(of: third.publicKey).isPaired)
        // A drop is waiting from the Mac that is about to forget; it goes with the pairing.
        receiver.listener.onOffer = { [weak receiver] s in receiver?.offers.withLock { $0.append(s) } }
        let s = send([try file("a.bin", bytes: chunk)], from: sender, to: receiver)
        XCTAssertTrue(until { receiver.offers.withLock { $0.count } == 1 })
        XCTAssertTrue(sender.trust.forget(receiver.key, telling: (host: "127.0.0.1", port: receiver.port), identity: sender.identity))
        guard case .renew = receiver.trust.standing(of: sender.key) else { return XCTFail("the forgotten Mac still has \(receiver.trust.standing(of: sender.key))") }
        XCTAssertTrue(until(3) { receiver.offers.withLock { $0[0] }.state.isFinal && s.state.isFinal })
        XCTAssertTrue(receiver.trust.standing(of: third.publicKey).isPaired, "and nobody else's pairing was touched")
        XCTAssertTrue(receiver.trust.tombstones.isEmpty, "forgotten is not retired: the two can pair again")
        // Nowhere to reach it: forgotten here all the same.
        XCTAssertFalse(third.forget(receiver.key, telling: nil, identity: sender.identity))
        XCTAssertFalse(third.standing(of: receiver.key).isPaired)
    }

    // MARK: Guards no test noticed the absence of

    /// A drop begun by hand, as far as the receiver's first plan, so that what follows can be
    /// anything at all under the right keys.
    struct HandDrop {
        let peer: RawPeer
        let keys: DropKeys
        let manifest: Manifest
        let port: UInt16
        var conn: UInt64 = 0

        /// Opens a data connection and proves it belongs to the drop.
        mutating func attach() throws -> (Socket, CipherState) {
            conn += 1
            let s = try Socket.connect(host: "127.0.0.1", port: port)
            s.setReadTimeout(2)
            try Opening.data.withUnsafeBytes { try s.writeAll($0.baseAddress!, 5) }
            var challenge = Data(count: 16)
            try challenge.withUnsafeMutableBytes { try s.readExactly($0.baseAddress!, 16) }
            let message = keys.sessionID + Crypto.be64(conn) + keys.attachTag(conn: conn, challenge: challenge)
            try message.withUnsafeBytes { try s.writeAll($0.baseAddress!, message.count) }
            return (s, keys.stream(conn))
        }

        /// An honest record for `chunk` of file 0.
        func record(_ cipher: inout CipherState, chunk: Int) throws -> Data {
            let length = manifest.chunkLength(file: 0, chunk: chunk)
            let header = RecordHeader(file: 0, chunk: UInt32(chunk), length: UInt32(length)).bytes
            return try cipher.seal(header) + cipher.seal(Data(repeating: 7, count: length), ad: header)
        }
    }

    func handDrop(from sender: TestMac, to receiver: TestMac, bytes: Int) throws -> HandDrop {
        let manifest = Manifest(chunkSize: chunk, entries: [.init(path: "f.bin", kind: .file, size: Int64(bytes))])
        let p = try RawPeer(port: receiver.port, keys: sender.trust.keyPair)
        try p.hello(.drop)
        try p.json(.offer, Offer(items: ["f.bin"], fileCount: 1, totalBytes: manifest.totalBytes))
        guard try p.read().type == FrameType.accept.rawValue else { throw DropError("not accepted") }
        try p.json(.manifest, manifest)
        guard try p.read().type == FrameType.plan.rawValue else { throw DropError("no plan") }
        return HandDrop(peer: p, keys: DropKeys(master: p.master), manifest: manifest, port: receiver.port)
    }

    /// Whether the other end has closed `s` (as opposed to holding it open in silence).
    func closed(_ s: Socket, within seconds: Double = 1) -> Bool {
        until(seconds) { s.waitReadable(milliseconds: 0) }
    }

    func testTheEndOfADataConnectionIsExactlyTheEndMarker() throws {
        let (sender, receiver) = try pairedMacs()
        var drop = try handDrop(from: sender, to: receiver, bytes: chunk * 3)
        let session = try XCTUnwrap(receiver.offers.withLock { $0.first })
        // The real one ends a connection with nothing counted against it.
        var (s, cipher) = try drop.attach()
        var end = try RecordHeader.sealEnd(&cipher)
        try end.withUnsafeBytes { try s.writeAll($0.baseAddress!, end.count) }
        XCTAssertTrue(closed(s))
        XCTAssertEqual(session.stats.damagedChunks, 0)
        // One that names a chunk, or a length, is not an end: it is damage.
        for (c, l) in [(UInt32(1), UInt32(0)), (0, 1)] {
            (s, cipher) = try drop.attach()
            end = try cipher.seal(RecordHeader(file: RecordHeader.endMarker, chunk: c, length: l).bytes)
            try end.withUnsafeBytes { try s.writeAll($0.baseAddress!, end.count) }
            XCTAssertTrue(closed(s))
        }
        XCTAssertTrue(until(3) { session.stats.damagedChunks == 2 }, "\(session.stats.damagedChunks)")
        drop.peer.socket.shutdown()
    }

    /// Divergence 10: the receiver holds a stream key to its byte budget too, not only the sender.
    func testAStreamKeyIsHeldToItsBytesByTheReceiverToo() throws {
        DropKeys.streamBytes = Int64(chunk * 2)
        let (sender, receiver) = try pairedMacs()
        var drop = try handDrop(from: sender, to: receiver, bytes: chunk * 4)
        let session = try XCTUnwrap(receiver.offers.withLock { $0.first })
        var (s, cipher) = try drop.attach()
        for c in 0..<3 {
            let record = try drop.record(&cipher, chunk: c)
            try? record.withUnsafeBytes { try s.writeAll($0.baseAddress!, record.count) }
        }
        XCTAssertTrue(closed(s, within: 3), "the third chunk under one key is more than the key may carry")
        XCTAssertEqual(session.stats.chunks, 2)
        XCTAssertEqual(session.stats.damagedChunks, 1)
        drop.peer.socket.shutdown()
    }

    func testNoMoreDataConnectionsThanADropMayHave() throws {
        Tuning.streamsPerDrop = 3
        let (sender, receiver) = try pairedMacs()
        var drop = try handDrop(from: sender, to: receiver, bytes: chunk * 3)
        var held: [Socket] = []
        for _ in 0..<3 { held.append(try drop.attach().0) }
        Thread.sleep(forTimeInterval: 0.3)
        let extra = try drop.attach().0
        XCTAssertTrue(closed(extra), "a fourth, proved like the others, is closed: three is what this drop may have")
        for s in held { XCTAssertFalse(s.waitReadable(milliseconds: 0), "and the three are left alone") }
        drop.peer.socket.shutdown()
    }

/// How many of `sockets` the other end is still holding open.
    func open(_ sockets: [Socket]) -> Int { sockets.filter { !$0.waitReadable(milliseconds: 0) }.count }

    func knock(_ port: UInt16) throws -> (socket: Socket, challenged: Bool) {
        let s = try Socket.connect(host: "127.0.0.1", port: port)
        s.setReadTimeout(2)
        try Opening.data.withUnsafeBytes { try s.writeAll($0.baseAddress!, 5) }
        var challenge = Data(count: 16)
        return (s, (try? challenge.withUnsafeMutableBytes { try s.readExactly($0.baseAddress!, 16) }) != nil)
    }

    /// F1. 64 connections that say nothing used to keep every paired Mac out: the pool was
    /// full and the newcomer was refused. Now the one that has waited longest gives way.
    /// Once with the limit that one address has (the attacker pushes out only its own), once
    /// as if they came from many addresses (the whole pool is full).
    func testSilentConnectionsDoNotKeepAPairedMacOut() throws {
        for perAddress in [8, 64] {
            Tuning.strangersPerAddress = perAddress
            let (sender, receiver) = try pairedMacs()
            var held: [Socket] = []
            for _ in 0..<Tuning.strangers { held.append(try Socket.connect(host: "127.0.0.1", port: receiver.port)) }
            Thread.sleep(forTimeInterval: 0.5)
            XCTAssertLessThanOrEqual(open(held), perAddress)
            let s = send([try file("a-\(perAddress).bin", bytes: chunk * 4)], from: sender, to: receiver)
            wait(s, 8)
            XCTAssertEqual(s.state, .completed, "with \(perAddress) places an address: silent connections kept a paired Mac out")
            Thread.sleep(forTimeInterval: 1.1)   // the next round's arrivals are counted afresh
        }
    }

    /// F1, the second pool: strangers that say "NDATA" and nothing more do not keep a drop's
    /// own data connections from proving themselves.
    func testStrangersCannotTakeTheDataConnectionSlotsOfADrop() throws {
        for perAddress in [4, 16] {
            Tuning.unattachedPerAddress = perAddress
            let (sender, receiver) = try pairedMacs()
            var drop = try handDrop(from: sender, to: receiver, bytes: chunk * 3)
            var held: [Socket] = []
            for _ in 0..<Tuning.unattachedPerDrop { held.append(try knock(receiver.port).socket) }
            XCTAssertLessThanOrEqual(open(held), perAddress)
            let (real, _) = try drop.attach()
            XCTAssertFalse(real.waitReadable(milliseconds: 300), "the drop's own data connection was closed")
            drop.peer.socket.shutdown()
        }
    }

    /// The pools are still pools: never more unproved connections than the limit, however
    /// many arrive. The newest are the ones that stay.
    func testConnectionsThatHaveProvedNoKeyAreCounted() throws {
        Tuning.strangers = 8
        Tuning.strangersPerAddress = 100
        let (_, receiver) = try pairedMacs()
        var held: [Socket] = []
        for _ in 0..<12 { held.append(try Socket.connect(host: "127.0.0.1", port: receiver.port)); Thread.sleep(forTimeInterval: 0.02) }
        Thread.sleep(forTimeInterval: 0.3)
        XCTAssertEqual(open(held), 8, "twelve arrived and the pool holds eight")
        XCTAssertEqual(open(Array(held.suffix(8))), 8, "the eight that arrived last")
    }

    func testOneAddressHoldsOnlySoManyPlaces() throws {
        Tuning.strangersPerAddress = 3
        let (_, receiver) = try pairedMacs()
        var held: [Socket] = []
        for _ in 0..<10 { held.append(try Socket.connect(host: "127.0.0.1", port: receiver.port)); Thread.sleep(forTimeInterval: 0.02) }
        Thread.sleep(forTimeInterval: 0.3)
        XCTAssertEqual(open(held), 3, "ten arrived from one address, which may hold three places of the 64")
        XCTAssertEqual(open(Array(held.suffix(3))), 3)
    }

    func testDataConnectionsThatHaveProvedNothingAreCounted() throws {
        let (sender, receiver) = try pairedMacs()
        let drop = try handDrop(from: sender, to: receiver, bytes: chunk * 3)
        for (whole, perAddress) in [(4, 100), (16, 2)] {
            Tuning.unattachedPerDrop = whole
            Tuning.unattachedPerAddress = perAddress
            var held: [Socket] = []
            for _ in 0..<8 {
                let k = try knock(receiver.port)
                XCTAssertTrue(k.challenged)
                held.append(k.socket)
            }
            Thread.sleep(forTimeInterval: 0.3)
            XCTAssertEqual(open(held), min(whole, perAddress), "eight arrived; the drop has \(whole) places for connections that have proved nothing, \(perAddress) an address")
            XCTAssertEqual(open(Array(held.suffix(min(whole, perAddress)))), min(whole, perAddress), "the newest")
            for s in held { s.shutdown() }
            Thread.sleep(forTimeInterval: 0.2)
        }
        drop.peer.socket.shutdown()
    }

    func testArrivalsAreRationed() throws {
        Tuning.strangersPerAddress = 64
        for (all, perAddress) in [(10, 500), (500, 10)] {
            Tuning.arrivalsPerSecond = all
            Tuning.arrivalsPerAddress = perAddress
            let (_, receiver) = try pairedMacs()
            var held: [Socket] = []
            for _ in 0..<30 { held.append(try Socket.connect(host: "127.0.0.1", port: receiver.port)) }
            Thread.sleep(forTimeInterval: 0.5)
            let taken = open(held)
            XCTAssertLessThanOrEqual(taken, 10, "thirty arrived within a second and \(taken) were taken (\(all) a second in all, \(perAddress) from one address)")
            XCTAssertGreaterThan(taken, 0)
        }
    }

    /// A paired key is in a counted class too, from its handshake until it says what it came for.
    func testAPairedKeyIsCountedUntilItSaysWhatItWants() throws {
        Tuning.pairedWaiting = 3
        let (sender, receiver) = try pairedMacs()
        var held: [Channel] = []
        for _ in 0..<3 { held.append(try Channel.dial(host: "127.0.0.1", port: receiver.port, trust: sender.trust, name: "sender", purpose: .drop).channel) }
        XCTAssertThrowsError(try Channel.dial(host: "127.0.0.1", port: receiver.port, trust: sender.trust, name: "sender", purpose: .drop),
                             "a fourth connection from a paired key that has asked for nothing was answered")
        for c in held { c.socket.shutdown() }
        Thread.sleep(forTimeInterval: 0.3)
        let s = send([try file("a.bin", bytes: chunk * 4)], from: sender, to: receiver)
        wait(s)
        XCTAssertEqual(s.state, .completed, "and it is not held against the key once they are gone")
    }

    // MARK: The pause after a refused request (F9)

    /// Puts `mac` into its pause: a stranger asks, and the person there says no.
    func pause(_ mac: TestMac) throws {
        mac.onRequest = { $0.refuse() }
        let p = try TestMac("nobody").pair(with: mac)
        XCTAssertTrue(until(5) { p.state.isFinal })
        mac.onRequest = nil
    }

    /// F9. One stranger keeps the pause running on both Macs. Two people can still pair, by
    /// trying once from each side: the first try is turned away with the seconds left, and the
    /// request that then comes back the other way is one this Mac's person asked for.
    func testAStrangerCannotKeepTwoPeopleFromPairing() throws {
        Tuning.pairQuietSeconds = 60
        let a = try TestMac("a"), b = try TestMac("b"), c = try TestMac("c")
        try pause(a)
        try pause(b)
        let first = a.pair(with: b)
        XCTAssertTrue(until(5) { first.state.isFinal })
        XCTAssertFalse(first.isPaired)
        let seconds = try XCTUnwrap(first.pausedFor, "b did not say it is paused: \(first.state)")
        XCTAssertTrue(seconds > 0 && seconds <= 60)
        // Anyone a's person did not ask is still turned away by a's own pause.
        let other = c.pair(with: a)
        XCTAssertTrue(until(5) { other.state.isFinal })
        XCTAssertEqual(a.requests.withLock { $0.count }, 1, "only the stranger's, from before")
        // Now from b, as a's tile says to.
        a.onRequest = { $0.proceed() }
        let second = b.pair(with: a)
        let theirs = try XCTUnwrap(second.code(), "\(second.state)")
        let request = try XCTUnwrap(a.requests.withLock { $0.last })
        let mine = try XCTUnwrap(request.code())
        second.submit(mine)
        request.submit(theirs)
        XCTAssertTrue(until(5) { second.isPaired && request.isPaired })
    }

    /// F9. A Mac that is on record here (to be paired again) is not a stranger: nobody else
    /// can prove its key, and the pause does not apply to its request.
    func testThePauseDoesNotApplyToAMacThatIsToBePairedAgain() throws {
        Tuning.pairQuietSeconds = 60
        let a = try TestMac("a"), b = try TestMac("b")
        a.trust.adopt(b.trust, as: "b")
        _ = a.trust.beginReset()
        a.trust.completeReset(told: [])
        guard case .renew = a.trust.standing(of: b.key) else { return XCTFail("\(a.trust.standing(of: b.key))") }
        try pause(a)
        let p = b.pair(with: a)
        XCTAssertTrue(until(5) { a.requests.withLock { $0.count } == 2 }, "the request of a Mac it knows was not shown: \(p.state)")
        p.cancel()
    }

    /// The seconds in a `busy` are a number from another machine: held to what a pause can be.
    func testAPauseOfAnyLengthIsHeldToTenMinutes() throws {
        let a = try TestMac("a")
        let (fd, port) = try Socket.listen(port: 0)
        defer { close(fd) }
        let keys = KeyPair()
        Thread.detachNewThread {
            let client = accept(fd, nil, nil)
            guard client >= 0 else { return }
            let socket = Socket(fd: client)
            socket.setReadTimeout(3)
            guard (try? Opening.readKind(socket)) == Opening.control, let c = try? Channel.respond(socket, keys: keys), (try? c.read()) != nil,
                  (try? c.send(.hello, SecureHello(minor: 0, app: "x", name: "liar", remaining: 1, paired: false, purpose: nil))) != nil,
                  (try? c.read()) != nil else { return }
            try? c.send(.busy, body: Data(#"{"message":"later","pause":1e300}"#.utf8))
            Thread.sleep(forTimeInterval: 0.5)
            socket.shutdown()
        }
        let p = PairingSession(host: "127.0.0.1", port: port, peerName: "liar", identity: a.identity, trust: a.trust)
        XCTAssertTrue(until(5) { p.state.isFinal })
        XCTAssertEqual(p.pausedFor, 600)
    }

        /// A finished drop's answer names its files. It is said again only to the Mac that sent the
    /// drop, on proof that it holds the drop's keys; and not at all once trust in that Mac has
    /// been withdrawn, even if it is paired again afterwards.
    func testAFinishedDropsAnswerIsOnlyForItsSenderAndGoesWhenTrustDoes() throws {
        let (sender, receiver) = try pairedMacs()
        let third = Trust.inMemory()
        third.adopt(receiver.trust, as: "receiver"); receiver.trust.adopt(third, as: "third")
        let manifest = Manifest(chunkSize: chunk, entries: [.init(path: "secret-name.txt", kind: .file, size: 0)])
        let p = try RawPeer(port: receiver.port, keys: sender.trust.keyPair)
        try p.hello(.drop)
        try p.json(.offer, Offer(items: ["secret-name.txt"], fileCount: 1, totalBytes: 0))
        XCTAssertEqual(try p.read().type, FrameType.accept.rawValue)
        try p.json(.manifest, manifest)
        XCTAssertEqual(try p.read().type, FrameType.plan.rawValue)
        try p.json(.done, Done(streams: 0, resent: 0))
        XCTAssertEqual(try p.read().type, FrameType.complete.rawValue)
        let keys = DropKeys(master: p.master)

        /// What comes back to a resume of that drop from `who`, with a true proof or a made-up one.
        func ask(_ who: KeyPair, honest: Bool) -> [UInt8] {
            guard let q = try? RawPeer(port: receiver.port, keys: who), (try? q.hello(.resume)) != nil else { return [] }
            defer { q.socket.shutdown() }
            let proof = honest ? DropKeys.resumeProof(keys.resumeKey, "resume", h: q.h) : Crypto.random(32)
            guard (try? q.json(.resume, Resume(session: keys.sessionID, proof: proof))) != nil else { return [] }
            var got: [UInt8] = []
            while let m = try? q.read() { got.append(m.type) }
            return got
        }
        XCTAssertEqual(ask(third.keyPair, honest: false), [], "another paired Mac that names the session learns nothing")
        XCTAssertEqual(ask(sender.trust.keyPair, honest: false), [], "nor does the sender's key without the drop's")
        XCTAssertEqual(ask(sender.trust.keyPair, honest: true), [FrameType.resumed.rawValue, FrameType.complete.rawValue], "the sender, proved, is told again")
        // Forgotten, then paired again: what the old pairing left behind is gone.
        receiver.trust.forget(sender.key)
        receiver.trust.adopt(sender.trust, as: "sender")
        XCTAssertEqual(ask(sender.trust.keyPair, honest: true), [], "the answer and its key went when the trust did")
    }

    /// Both ends must hold the pairing. A sender that says it does not have this Mac paired
    /// (it forgot it) is not taken at its key's word.
    func testAnOfferFromAMacThatSaysItIsNotPairedIsNotShown() throws {
        let (sender, receiver) = try pairedMacs()
        let p = try RawPeer(port: receiver.port, keys: sender.trust.keyPair)
        try p.hello(.drop, paired: false)
        try? p.json(.offer, Offer(items: ["a"], fileCount: 1, totalBytes: 5))
        XCTAssertNil(try? p.read(), "no answer: the connection is closed")
        XCTAssertTrue(receiver.offers.withLock { $0.isEmpty })
    }

    /// P9 with no expected key: this Mac's key is not shown to a Mac that proves a key it is
    /// not paired with. The handshake's third message is what would show it.
    func testASenderDoesNotShowItsKeyToAMacItIsNotPairedWith() throws {
        let (sender, _) = try pairedMacs()
        let (fd, port) = try Socket.listen(port: 0)
        defer { close(fd) }
        let learned = Locked<PublicKey?>(nil), over = Locked(false)
        Thread.detachNewThread {
            let client = accept(fd, nil, nil)
            guard client >= 0 else { return }
            let socket = Socket(fd: client)
            socket.setReadTimeout(3)
            if (try? Opening.readKind(socket)) == Opening.control, let c = try? Channel.respond(socket, keys: KeyPair()) { learned.withLock { $0 = c.remote } }
            over.withLock { $0 = true }
            socket.shutdown()
        }
        let s = SendSession(urls: [try file("a.txt", bytes: 10)], host: "127.0.0.1", port: port, peerName: "stranger", identity: sender.identity, trust: sender.trust,
                            expect: nil, chunkSize: chunk)
        s.start()
        wait(s, 10)
        XCTAssertTrue(s.needsPairing)
        XCTAssertTrue(until(5) { over.withLock { $0 } })
        XCTAssertNil(learned.withLock { $0 }, "the Mac that answered is not paired, and has learned which key was asking")
    }

    /// Divergence 1: a handshake message carries the handshake and nothing else.
    func testAHandshakeMessageWithAPayloadEndsTheConnection() throws {
        let (_, receiver) = try pairedMacs()
        func second(payload: Data) throws -> Data {
            let socket = try Socket.connect(host: "127.0.0.1", port: receiver.port)
            defer { socket.shutdown() }
            socket.setReadTimeout(2)
            let mine = Opening.mine()
            try mine.withUnsafeBytes { try socket.writeAll($0.baseAddress!, mine.count) }
            _ = try Opening.readKind(socket)
            let theirs = try Opening.readRest(socket)
            let noise = Noise(initiator: true, prologue: Channel.prologue(initiator: mine, responder: theirs.bytes), s: KeyPair())
            try Channel.write(socket, try noise.write(payload: payload))
            return try Channel.read(socket, limit: 1024)
        }
        XCTAssertNoThrow(try second(payload: Data()))
        XCTAssertThrowsError(try second(payload: Data("hello".utf8)), "a first message with something in it was answered")
    }

    func testTheCodesRunOutOfTime() throws {
        Tuning.pairSeconds = 1
        let a = try TestMac("a"), b = try TestMac("b")
        b.onRequest = { $0.proceed() }
        let mine = a.pair(with: b)
        XCTAssertNotNil(mine.code(), "\(mine.state)")
        // Nobody types anything.
        XCTAssertTrue(until(6) { mine.state.isFinal }, "the codes are still up: \(mine.state)")
        XCTAssertFalse(mine.isPaired)
        let theirs = try XCTUnwrap(b.requests.withLock { $0.first })
        XCTAssertTrue(until(6) { theirs.state.isFinal })
        XCTAssertTrue(a.trust.known.isEmpty && b.trust.known.isEmpty)
    }

    /// A key that has run out is still on the list of Known Macs (as run out), and may not be
    /// paired again. Its request is not shown, and the notice names it as this Mac knows it
    /// (divergence 19), not as the caller calls itself.
    func testARequestToPairFromAKeyThatHasRunOutIsNotShown() throws {
        let clock = FakeClock()
        let a = Trust.inMemory(clock: clock), b = Trust.inMemory()
        try a.store(pairing: b.publicKey, announced: "air", method: "codes", remaining: 3600)
        clock.pass(7200)
        guard case .expired = a.standing(of: b.publicKey) else { return XCTFail("\(a.standing(of: b.publicKey))") }
        let mac = try TestMac("pro", trust: a), old = try TestMac("something-else", trust: b)
        let p = old.pair(with: mac)
        XCTAssertTrue(until(5) { p.state.isFinal })
        XCTAssertFalse(p.isPaired)
        XCTAssertTrue(mac.requests.withLock { $0.isEmpty }, "a request from a key that has run out reached the person")
        XCTAssertEqual(mac.refusedIdentities.withLock { $0 }, ["air"])
    }

    /// Divergence 18: withdrawing trust in a key also stops a pairing this Mac's own person
    /// had begun with it.
    func testWithdrawingTrustStopsAPairingThisMacBeganWithThatKey() throws {
        let a = try TestMac("a"), b = try TestMac("b")
        let mine = a.pair(with: b)   // b's person has not answered
        XCTAssertTrue(until { mine.state == .asking })
        a.trust.retire(b.key)
        XCTAssertTrue(until(3) { mine.state.isFinal }, "\(mine.state)")
        XCTAssertFalse(mine.isPaired)
    }

    // MARK: Fuzzing

    /// An initiator driven by hand below the level of `Channel`, so that what is sealed can be
    /// anything at all.
    final class RawPeer {
        let socket: Socket
        var out: CipherState
        var back: CipherState
        let master: Data
        let h: Data

        init(port: UInt16, keys: KeyPair) throws {
            let socket = try Socket.connect(host: "127.0.0.1", port: port)
            self.socket = socket
            socket.setReadTimeout(2)
            let mine = Opening.mine()
            try mine.withUnsafeBytes { try socket.writeAll($0.baseAddress!, mine.count) }
            guard try Opening.readKind(socket) == Opening.control else { throw DropError("not NDROP") }
            let theirs = try Opening.readRest(socket)
            let noise = Noise(initiator: true, prologue: Channel.prologue(initiator: mine, responder: theirs.bytes), s: keys)
            try Channel.write(socket, try noise.write())
            _ = try noise.read(try Channel.read(socket, limit: 1024))
            try Channel.write(socket, try noise.write())
            h = noise.h
            (out, back, master) = try noise.split()
        }

        func plain(_ p: Data) throws { try Channel.write(socket, try out.seal(p)) }

        func message(_ type: UInt8, _ body: Data, more: UInt8 = 0, total: UInt32? = nil) throws {
            try plain(Data([type, more]) + Crypto.be32(total ?? UInt32(body.count)) + body)
        }

        func json<T: Encodable>(_ type: FrameType, _ value: T) throws { try message(type.rawValue, try JSONEncoder().encode(value)) }

        func hello(_ purpose: Purpose?, paired: Bool = true) throws {
            try json(.hello, SecureHello(minor: 0, app: "fuzz", name: "fuzz", remaining: 90 * 86400, paired: paired, purpose: purpose))
            _ = try read()
        }

        func read() throws -> (type: UInt8, body: Data) {
            let first = try back.open(try Channel.read(socket))
            guard first.count >= 6 else { throw DropError("short") }
            var body = Data(first.dropFirst(6)), more = first[1] & 1 == 1
            while more {
                let next = try back.open(try Channel.read(socket))
                body.append(next.dropFirst(2))
                more = next[1] & 1 == 1
            }
            return (first[0], body)
        }
    }

    /// Bytes before any key is proved: openings, frame headers, handshake messages.
    func testFuzzOpeningsAndHandshakeFrames() throws {
        Tuning.strangerSeconds = 1
        let (sender, receiver) = try pairedMacs()
        var rng = SystemRandomNumberGenerator()
        func frame(_ body: Data, lie: Bool = false) -> Data {
            let n = UInt16(body.count), c = lie ? n : ~n
            return Data([UInt8(n >> 8), UInt8(n & 0xff), UInt8(c >> 8), UInt8(c & 0xff)]) + body
        }
        let sizes = [0, 1, 15, 16, 31, 32, 33, 47, 48, 63, 64, 79, 80, 95, 96, 97, 112, 500, 1023, 1024, 1025, 4000, 65535]
        for i in 0..<600 {
            guard let s = try? Socket.connect(host: "127.0.0.1", port: receiver.port) else { continue }
            s.setReadTimeout(1)
            var bytes = Data()
            switch i % 6 {
            case 0: bytes = Crypto.random(Int.random(in: 0...64, using: &rng))
            case 1: bytes = Opening.control + Data([UInt8.random(in: 0...255, using: &rng)]) + Crypto.random(Int.random(in: 0...20, using: &rng))
            case 2: bytes = Opening.mine() + frame(Crypto.random(sizes[i / 6 % sizes.count]), lie: i % 12 == 2)
            case 3: bytes = Opening.data + Crypto.random(Int.random(in: 0...80, using: &rng))
            case 4:
                // A whole first message, then a third of every awkward length.
                bytes = Opening.mine() + frame(Crypto.random(32) + Crypto.random(i % 24 == 4 ? 0 : 200))
                try? bytes.withUnsafeBytes { try s.writeAll($0.baseAddress!, bytes.count) }
                _ = try? Opening.readKind(s)
                _ = try? Opening.readRest(s)
                _ = try? Channel.read(s, limit: 2048)
                bytes = frame(Crypto.random(sizes[i / 6 % sizes.count]))
            default:
                // A low-order point and a non-canonical one as the ephemeral key.
                var e = Data(count: 32)
                if i % 12 == 5 { e = Data(repeating: 0xff, count: 32) }
                bytes = Opening.mine() + frame(e)
            }
            try? bytes.withUnsafeBytes { try s.writeAll($0.baseAddress!, bytes.count) }
            if i % 3 == 0 { var b: UInt8 = 0; _ = try? s.readExactly(&b, 1) }
            s.shutdown()
            if i % 50 == 49 { Thread.sleep(forTimeInterval: 0.15) }   // stay under the arrival rate
        }
        Thread.sleep(forTimeInterval: 1.5)
        let s = send([try file("after.bin", bytes: chunk * 3)], from: sender, to: receiver)
        wait(s)
        XCTAssertEqual(s.state, .completed, "after the junk the listener is alive and none of its slots leaked")
    }

    /// Sealed control messages from a key nobody paired, and from a paired one: fragments that
    /// lie about themselves, JSON that is not what it should be.
    func testFuzzSealedMessagesAndFragments() throws {
        Tuning.strangerSeconds = 2
        Tuning.pairQuietSeconds = 0.001
        Tuning.pairQuietLongest = 0.001
        let (sender, receiver) = try pairedMacs()
        receiver.onRequest = { $0.proceed() }
        var rng = SystemRandomNumberGenerator()
        let deep = Data(String(repeating: "[", count: 15000).utf8)
        let jsons: [Data] = [
            Data(), Data("{}".utf8), Data("null".utf8), Data("[]".utf8), deep, Crypto.random(200),
            Data(#"{"minor":1e999,"app":"x","name":"x","remaining":1,"paired":true,"purpose":"drop"}"#.utf8),
            Data(#"{"minor":99999999999999999999999999,"app":"x","name":"x","remaining":-1e308,"paired":true,"purpose":"pair"}"#.utf8),
            Data(#"{"minor":0,"app":"x","name":"x","remaining":1,"paired":true,"purpose":"nonsense"}"#.utf8),
            Data(#"{"minor":0,"app":7,"name":["x"],"remaining":"soon","paired":1}"#.utf8),
            Data(#"{"minor":0,"app":"x","name":"\u0000‮\n\r","remaining":0,"paired":true,"purpose":"pair"}"#.utf8),
            Data(#"{"minor":0,"app":"x","name":""#.utf8) + Data(repeating: 0x41, count: 15000) + Data(#"","remaining":0,"paired":true,"purpose":"verify"}"#.utf8),   // (true: from the paired key, false is a Forget, which is not what this test is about)
            Data(#"{"items":[],"fileCount":-9223372036854775808,"totalBytes":-9223372036854775808}"#.utf8),
            Data(#"{"items":["a"],"fileCount":9223372036854775807,"totalBytes":9223372036854775807}"#.utf8),
            Data(#"{"session":"AAAA","proof":"AAAA"}"#.utf8), Data(#"{"value":"AAAA"}"#.utf8), Data(#"{"streams":-1}"#.utf8),
        ]
        let types: [UInt8] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 48, 49, 50, 255]
        for i in 0..<500 {
            // Odd rounds as the paired sender, even ones as a fresh key.
            guard let p = try? RawPeer(port: receiver.port, keys: i % 2 == 1 ? sender.trust.keyPair : KeyPair()) else { continue }
            let body = jsons[Int.random(in: 0..<jsons.count, using: &rng)]
            let type = types[Int.random(in: 0..<types.count, using: &rng)]
            do {
                switch i % 10 {
                case 0: try p.plain(Crypto.random(Int.random(in: 0...5, using: &rng)))                       // too short to be a message
                case 1: try p.message(type, body)                                                             // any type, any body, first
                case 2: try p.message(FrameType.hello.rawValue, body, more: 1, total: UInt32.max)             // announces 4 GB
                case 3: try p.message(FrameType.hello.rawValue, body, more: 0, total: UInt32(body.count) + 7) // promises more, says done
                case 4: try p.message(FrameType.hello.rawValue, body, more: 1)                                // done, says more
                case 5:
                    // A first fragment, then continuations that are empty, of another type, too long.
                    try p.message(FrameType.hello.rawValue, Data("{".utf8), more: 1, total: 4000)
                    for _ in 0..<20 { try p.plain(Data([FrameType.hello.rawValue, 1])) }
                    try p.plain(Data([type, 1]) + Crypto.random(100))
                    try p.plain(Data([FrameType.hello.rawValue, 0]) + Crypto.random(5000))
                case 6:
                    // A proper hello, then whatever comes to mind where the purpose's first message belongs.
                    // (The paired sender always says it is paired: saying otherwise is a Forget.)
                    try p.hello([Purpose.drop, .pair, .verify, .resume, .retire][i / 10 % 5], paired: i % 2 == 1 || i % 20 < 10)
                    try p.message(type, body)
                    try p.message(type, body, more: 1, total: UInt32.random(in: 0...UInt32.max, using: &rng))
                case 7:
                    // A pairing that goes wrong at every step in turn.
                    try p.hello(i % 20 < 10 ? .pair : .verify)
                    try p.json(.pairRequest, Empty())
                    let go = try p.read()
                    guard go.type == FrameType.pairGo.rawValue else { break }
                    let step = i / 10 % 6
                    if step == 0 { try p.message(type, body) }
                    if step >= 1 { try p.json(.commit, PairValue(value: Crypto.random(step == 1 ? 31 : 32))) }
                    if step >= 2 { _ = try p.read() }
                    if step == 2 { try p.message(type, body) }
                    if step == 3 { try p.json(.reveal, PairValue(value: Crypto.random(32))) }
                    if step >= 4 { try p.json(.paired, Empty()); try p.message(type, body) }
                case 8:
                    // A drop (taken, when the key is paired), then a manifest that is something else.
                    try p.hello(.drop)
                    try p.json(.offer, Offer(items: ["a"], fileCount: Int.random(in: 0...3, using: &rng), totalBytes: 5))
                    guard try p.read().type == FrameType.accept.rawValue else { break }
                    if i % 20 < 10 { try p.message(FrameType.manifest.rawValue, body) } else {
                        try p.message(FrameType.manifest.rawValue, Data(#"{"chunkSize":4096,"entries":[{"p":"a","k":0,"s":5,"m":0,"o":420}"#.utf8), more: 1, total: 60000)
                        try p.plain(Data([FrameType.manifest.rawValue, 1]) + Data(repeating: 0x20, count: 61000))
                    }
                default:
                    try p.hello(nil)
                    try p.message(type, body)
                }
                _ = try? p.read()
            } catch {}
            p.socket.shutdown()
            if i % 40 == 39 { Thread.sleep(forTimeInterval: 0.2) }
        }
        XCTAssertEqual(receiver.trust.known.count, 1, "nothing was paired by any of it")
        XCTAssertTrue(receiver.trust.standing(of: sender.key).isPaired, "and the pairing there was is still there")
        Thread.sleep(forTimeInterval: 2.5)
        let s = send([try file("after.bin", bytes: chunk * 3)], from: sender, to: receiver)
        wait(s)
        XCTAssertEqual(s.state, .completed)
    }

    /// A paired sender that means harm, after its drop is accepted: manifests with hostile
    /// numbers, then records sealed under the right keys that describe what the manifest does
    /// not have. Nothing may trap, and nothing may be written outside what was described.
    func testFuzzRecordsFromAPairedSenderThatMeansHarm() throws {
        Tuning.attachSeconds = 1
        let (sender, receiver) = try pairedMacs()
        let entries: [Manifest.Entry] = [
            .init(path: "d", kind: .directory), .init(path: "d/f.bin", kind: .file, size: Int64(chunk * 2 + 100)),
            .init(path: "d/empty", kind: .file, size: 0), .init(path: "d/link", kind: .symlink, link: "f.bin"),
        ]
        let manifest = Manifest(chunkSize: chunk, entries: entries)
        let p = try RawPeer(port: receiver.port, keys: sender.trust.keyPair)
        try p.hello(.drop)
        try p.json(.offer, Offer(items: ["d"], fileCount: 2, totalBytes: manifest.totalBytes))
        XCTAssertEqual(try p.read().type, FrameType.accept.rawValue)
        try p.json(.manifest, manifest)
        XCTAssertEqual(try p.read().type, FrameType.plan.rawValue)
        let keys = DropKeys(master: p.master)
        var conn: UInt64 = 0

        func attach() throws -> (Socket, CipherState) {
            conn += 1
            let s = try Socket.connect(host: "127.0.0.1", port: receiver.port)
            s.setReadTimeout(2)
            try Opening.data.withUnsafeBytes { try s.writeAll($0.baseAddress!, 5) }
            var challenge = Data(count: 16)
            try challenge.withUnsafeMutableBytes { try s.readExactly($0.baseAddress!, 16) }
            let message = keys.sessionID + Crypto.be64(conn) + keys.attachTag(conn: conn, challenge: challenge)
            try message.withUnsafeBytes { try s.writeAll($0.baseAddress!, message.count) }
            return (s, keys.stream(conn))
        }
        let files: [UInt32] = [0, 1, 2, 3, 4, 5, 0x7fffffff, 0x80000000, 0xfffffffe, 0xffffffff]
        let chunks: [UInt32] = [0, 1, 2, 3, 0x7fffffff, 0x80000000, 0xffffffff]
        let lengths: [UInt32] = [0, 1, 100, UInt32(chunk) - 1, UInt32(chunk), UInt32(chunk) + 1, 1 << 20, 0x7fffffff, 0x80000000, 0xffffffff]
        var sent = 0
        for f in files { for c in chunks { for l in lengths {
            // The one honest combination per chunk is left out: this is about the others.
            if f == 1, c <= 2, Int(l) == manifest.chunkLength(file: 1, chunk: Int(c)) { continue }
            guard var (s, cipher) = try? attach() else { XCTFail("could not attach connection \(conn)"); return }
            let header = RecordHeader(file: f, chunk: c, length: l).bytes
            var record = try cipher.seal(header)
            // What follows is as long as it says, up to a point; the receiver should not get as far as reading it.
            record += try cipher.seal(Data(count: Int(min(l, 70000))), ad: header)
            try? record.withUnsafeBytes { try s.writeAll($0.baseAddress!, record.count) }
            s.shutdown()
            sent += 1
            Thread.sleep(forTimeInterval: 0.004)   // under the listener's 500 arrivals a second
        } } }
        let session = try XCTUnwrap(receiver.offers.withLock { $0.first })
        XCTAssertTrue(until(20) { session.stats.connectionFailures >= sent - 70 }, "\(session.stats.connectionFailures) of \(sent) refused")   // the end markers (file 0xffffffff, chunk 0, length 0) are not failures
        XCTAssertEqual(session.stats.chunks, 0, "none of them was written")
        XCTAssertFalse(session.state.isFinal, "and none of them ended the drop")
        let partial = try FileManager.default.contentsOfDirectory(atPath: dst.path)
        XCTAssertEqual(partial.count, 1)
        let size = (try? FileManager.default.attributesOfItem(atPath: dst.appendingPathComponent(partial[0]).appendingPathComponent("items/d/f.bin").path))?[.size] as? Int
        XCTAssertTrue(size == nil || size == 0, "nothing reached the file: \(String(describing: size))")
        p.socket.shutdown()
    }
}
