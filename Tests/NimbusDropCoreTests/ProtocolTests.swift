// Copyright (C) 2026 Niels Joubert
// SPDX-License-Identifier: GPL-3.0-or-later
import Foundation
import XCTest
@testable import NimbusDropCore

/// Protocol 3 against the people it was designed against: an impostor, a thief of an old key,
/// someone replaying what they recorded, someone flooding, and a paired Mac that is retired
/// while its drop is still running. Each test is one of the findings of the two reviews of the
/// plan (docs/plans), as an attack.
final class ProtocolTests: XCTestCase {
    var root: URL!
    let chunk = 16 * 1024

    override func setUpWithError() throws {
        root = FileManager.default.temporaryDirectory.appendingPathComponent("nimbusdrop-protocol-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: root.appendingPathComponent("dst"), withIntermediateDirectories: true)
        Tuning.reconnectSeconds = 2
        Tuning.pairQuietSeconds = 0.2
    }

    override func tearDownWithError() throws {
        Tuning.reconnectSeconds = 60
        Tuning.pairQuietSeconds = 10
        Tuning.unpaired = 8
        Tuning.strangers = 64
        Tuning.arrivalsPerSecond = 500
        Tuning.strangerSeconds = 10
        Tuning.attachSeconds = 5
        DropKeys.streamBytes = 1 << 38
        try? FileManager.default.removeItem(at: root)
    }

    var dst: URL { root.appendingPathComponent("dst") }

    func file(_ name: String, bytes: Int) throws -> URL {
        let url = root.appendingPathComponent(name)
        var data = Data(count: bytes)
        data.withUnsafeMutableBytes { (raw: UnsafeMutableRawBufferPointer) in for i in 0..<bytes { raw[i] = UInt8(truncatingIfNeeded: i &* 31 &+ i / 251) } }
        try data.write(to: url)
        return url
    }

    /// Two Macs that have paired, the second accepting what it is offered.
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

    func send(_ urls: [URL], from: TestMac, to: TestMac, port: UInt16? = nil, expect: PublicKey? = nil, streams: Int = 4) -> SendSession {
        let s = SendSession(urls: urls, host: "127.0.0.1", port: port ?? to.port, peerName: to.identity.name, identity: from.identity, trust: from.trust,
                            expect: expect, streams: streams, chunkSize: chunk)
        s.start()
        return s
    }

    func wait(_ t: Transfer, _ seconds: Double = 20) { _ = until(seconds) { t.state.isFinal } }

    // MARK: Who is at the other end

    func testNothingIsSentToAMacThatIsNotPaired() throws {
        let a = try TestMac("a"), b = try TestMac("b")
        let s = send([try file("secret-plans.txt", bytes: 100)], from: a, to: b)
        wait(s)
        guard case .failed = s.state else { return XCTFail("\(s.state)") }
        XCTAssertTrue(s.needsPairing, "the app is told why, so that it can offer to pair")
        XCTAssertTrue(b.offers.withLock { $0.isEmpty }, "nobody was asked anything")
        XCTAssertEqual(try FileManager.default.contentsOfDirectory(atPath: dst.path), [])
    }

    func testAPairingHeldByOneSideOnlyIsNotEnough() throws {
        // The last message of a pairing can be lost: one Mac stored it and the other did not.
        // The next handshake shows it, and nothing is offered.
        let (sender, receiver) = try pairedMacs()
        receiver.trust.forget(sender.key)
        let s = send([try file("a.txt", bytes: 100)], from: sender, to: receiver)
        wait(s)
        guard case .failed(let why) = s.state else { return XCTFail("\(s.state)") }
        XCTAssertTrue(s.needsPairing)
        XCTAssertTrue(why.contains("no longer has this Mac paired"), why)
        XCTAssertTrue(receiver.offers.withLock { $0.isEmpty })
    }

    func testAnImpostorAtThePairedMacsAddressLearnsNothing() throws {
        // Someone has taken over the address of the Mac this drop is meant for. The sender asks
        // whoever is there to prove the key it expects, before saying anything about itself.
        let (sender, receiver) = try pairedMacs()
        let impostor = try TestMac("receiver")
        let lines = Locked<[String]>([])
        DropLog.sink = { _, line in lines.withLock { $0.append(line) } }
        defer { DropLog.sink = nil }
        let s = send([try file("secret-plans.txt", bytes: 100)], from: sender, to: receiver, port: impostor.port, expect: receiver.key)
        wait(s)
        guard case .failed(let why) = s.state else { return XCTFail("\(s.state)") }
        XCTAssertTrue(s.wrongIdentity)
        XCTAssertTrue(why.contains("Nothing was sent"), why)
        Thread.sleep(forTimeInterval: 0.3)
        XCTAssertTrue(impostor.offers.withLock { $0.isEmpty } && impostor.requests.withLock { $0.isEmpty })
        let log = lines.withLock { $0 }.joined(separator: "\n")
        XCTAssertFalse(log.contains(sender.key.tag + ")") && log.contains("asks to pair"), "the impostor never learned who was calling")
        XCTAssertFalse(log.contains("secret-plans") && log.contains("offer from"), "nor what was being sent")
    }

    func testAnOpeningAlteredOnTheWayBreaksTheHandshake() throws {
        // The lists of protocol majors are sent in the clear and bound into the handshake. This
        // sender says it speaks 3 and 4; someone on the path strips the 4, as they would to keep
        // two Macs on an older protocol. Both ends are honest; they hashed different openings.
        let (sender, receiver) = try pairedMacs()
        Opening.majors = [3, 4]
        defer { Opening.majors = [UInt8(protocolVersion)] }
        let relay = try Socket.listen(port: 0)
        defer { close(relay.fd) }
        Thread.detachNewThread {
            let client = accept(relay.fd, nil, nil)
            guard client >= 0, let server = try? Socket.connect(host: "127.0.0.1", port: receiver.port) else { return }
            let near = Socket(fd: client)
            func pump(_ from: Socket, _ to: Socket, rewrite: Bool) {
                var first = rewrite
                var buffer = [UInt8](repeating: 0, count: 4096)
                while true {
                    let n = read(from.fd, &buffer, buffer.count)
                    guard n > 0 else { to.shutdown(); return }
                    // "NDROP" 02 03 04 becomes "NDROP" 02 03 03: the 4 is gone.
                    if first, n >= 8, buffer[5] == 2, buffer[7] == 4 { buffer[7] = 3; first = false }
                    guard (try? buffer.withUnsafeBytes { try to.writeAll($0.baseAddress!, n) }) != nil else { return }
                }
            }
            Thread.detachNewThread { pump(server, near, rewrite: false) }
            pump(near, server, rewrite: true)
        }
        let s = send([try file("a.txt", bytes: 10)], from: sender, to: receiver, port: relay.port, expect: receiver.key)
        wait(s)
        guard case .failed(let why) = s.state else { return XCTFail("\(s.state)") }
        XCTAssertTrue(why.contains("could not prove"), why)
        XCTAssertTrue(receiver.offers.withLock { $0.isEmpty })
        // The same relay with nothing to strip changes nothing, so it was the stripping.
        Opening.majors = [UInt8(protocolVersion)]
    }

    /// One Mac forgets the other. The one that was forgotten finds out at its next drop, and
    /// from then on shows the Mac as one to pair again, not as paired.
    func testAMacThatWasForgottenStopsCallingItPaired() throws {
        let (a, b) = try pairedMacs()
        b.trust.forget(a.key)
        XCTAssertTrue(a.trust.standing(of: b.key).isPaired, "nothing has told it yet")
        let s = send([try file("after.txt", bytes: 100)], from: a, to: b)
        wait(s)
        XCTAssertTrue(s.needsPairing, "\(s.state)")
        XCTAssertTrue(b.offers.withLock { $0.isEmpty })
        guard case .renew(let r) = a.trust.standing(of: b.key) else { return XCTFail("\(a.trust.standing(of: b.key))") }
        XCTAssertEqual(r.key, b.key)
        XCTAssertTrue(a.trust.known.isEmpty, "it is not listed as paired")
        XCTAssertTrue(a.trust.standing(of: b.key).mayPair, "and it can be paired again, by two people, like any other")
    }

    func testAStrangerWhoClaimsToBePairedIsNotBelieved() throws {
        // A modified copy with a key nobody paired says "paired: yes" in its hello and sends an
        // offer anyway. What a Mac says about itself is not what this Mac knows about it.
        let (_, receiver) = try pairedMacs()
        let (c, hello) = try Channel.dial(host: "127.0.0.1", port: receiver.port, trust: Trust.inMemory(), name: "sender", purpose: .drop, paired: true)
        XCTAssertFalse(hello.paired, "and it is told so")
        try? c.send(.offer, Offer(items: ["a"], fileCount: 1, totalBytes: 1))
        c.socket.setReadTimeout(2)
        XCTAssertNil(try? c.read())
        XCTAssertTrue(receiver.offers.withLock { $0.isEmpty })
    }

    // MARK: Data connections

    func testADropOfManyChunksArrivesOverSeveralConnections() throws {
        let (sender, receiver) = try pairedMacs()
        let src = try file("big.bin", bytes: chunk * 60 + 77)
        let s = send([src], from: sender, to: receiver)
        wait(s)
        XCTAssertEqual(s.state, .completed)
        XCTAssertEqual(try Data(contentsOf: dst.appendingPathComponent("big.bin")), try Data(contentsOf: src))
    }

    func testNobodyButTheSenderCanAttachADataConnection() throws {
        // The session id of a drop is not a secret (it crosses the wire). Knowing it buys nothing.
        Tuning.attachSeconds = 1
        let (sender, receiver) = try pairedMacs()
        // A hand-driven sender, so that the drop sits open while it is attacked.
        let (c, _) = try Channel.dial(host: "127.0.0.1", port: receiver.port, trust: sender.trust, name: "sender", purpose: .drop)
        let manifest = Manifest(chunkSize: chunk, entries: [.init(path: "f.bin", kind: .file, size: Int64(chunk * 3))])
        try c.send(.offer, Offer(items: ["f.bin"], fileCount: 1, totalBytes: manifest.totalBytes))
        XCTAssertEqual(try c.read().type, .accept)
        try c.send(.manifest, manifest)
        XCTAssertEqual(try c.read().type, .plan)
        let keys = DropKeys(master: c.master)

        /// Opens a data connection and answers the challenge with `tag`; true if it was let in
        /// (the receiver keeps reading instead of hanging up).
        func attach(session: Data, conn: UInt64, tag: (Data) -> Data) throws -> (Socket, Data)? {
            let s = try Socket.connect(host: "127.0.0.1", port: receiver.port)
            s.setReadTimeout(3)
            try Opening.data.withUnsafeBytes { try s.writeAll($0.baseAddress!, 5) }
            var challenge = Data(count: 16)
            try challenge.withUnsafeMutableBytes { try s.readExactly($0.baseAddress!, 16) }
            let message = session + Crypto.be64(conn) + tag(challenge)
            try message.withUnsafeBytes { try s.writeAll($0.baseAddress!, message.count) }
            // Let in: nothing comes back and nothing closes. Refused: the connection closes.
            return s.waitReadable(milliseconds: 400) ? nil : (s, challenge)
        }

        // A stranger who knows the session id and guesses the rest.
        XCTAssertNil(try attach(session: keys.sessionID, conn: 1) { _ in Crypto.random(16) })
        // The real thing, which records what it sent.
        var recorded = Data(), usedChallenge = Data()
        let real = try XCTUnwrap(try attach(session: keys.sessionID, conn: 1) { ch in
            usedChallenge = ch
            recorded = keys.attachTag(conn: 1, challenge: ch)
            return recorded
        })
        XCTAssertEqual(real.1, usedChallenge)
        // The recording played back on another connection: the challenge there is another one.
        XCTAssertNil(try attach(session: keys.sessionID, conn: 1) { _ in recorded })
        // A recording that never arrived (its connection was cut on the way), played back first
        // under a number nobody has used: it answers some other connection's challenge.
        let elsewhere = keys.attachTag(conn: 2, challenge: Crypto.random(16))
        XCTAssertNil(try attach(session: keys.sessionID, conn: 2) { _ in elsewhere })
        // The right key, but a number that has been taken: each is used once.
        XCTAssertNil(try attach(session: keys.sessionID, conn: 1) { keys.attachTag(conn: 1, challenge: $0) })
        // A session that does not exist.
        XCTAssertNil(try attach(session: Crypto.random(16), conn: 1) { keys.attachTag(conn: 1, challenge: $0) })
        // None of that has ended the drop: the real connection now delivers a chunk.
        var cipher = keys.stream(1)
        let header = RecordHeader(file: 0, chunk: 0, length: UInt32(chunk)).bytes
        let payload = Data(repeating: 7, count: chunk)
        let record = try cipher.seal(header) + (try cipher.seal(payload, ad: header))
        try record.withUnsafeBytes { try real.0.writeAll($0.baseAddress!, record.count) }
        let session = try XCTUnwrap(receiver.offers.withLock { $0.first })
        XCTAssertTrue(until { session.stats.chunks == 1 }, "the chunk was taken")
        XCTAssertFalse(session.state.isFinal)
        c.socket.shutdown()
        real.0.shutdown()
    }

    func testJunkOnDataConnectionsDoesNotEndADrop() throws {
        // Draft 2 of the plan ended a drop after three records that failed to open. Anyone who
        // had seen a session id could then stop a drop. Now a failed record costs a connection.
        let (sender, receiver) = try pairedMacs()
        let src = try file("big.bin", bytes: chunk * 3000)
        let s = send([src], from: sender, to: receiver, streams: 2)
        // Junk for as long as the drop lasts, from before it starts moving: a test that waited
        // to see it moving first missed the moment on a slower Mac (CI, 2026-11-23).
        let port = receiver.port
        let thrown = Locked(0)
        Thread.detachNewThread {
            while !s.state.isFinal {
                if let junk = try? Socket.connect(host: "127.0.0.1", port: port) {
                    let bytes = Opening.data + Crypto.random(200)
                    try? bytes.withUnsafeBytes { try junk.writeAll($0.baseAddress!, bytes.count) }
                    thrown.withLock { $0 += 1 }
                }
                Thread.sleep(forTimeInterval: 0.005)
            }
        }
        wait(s, 60)
        XCTAssertEqual(s.state, .completed)
        XCTAssertGreaterThan(thrown.withLock { $0 }, 3, "junk was thrown at it")
        XCTAssertEqual(try Data(contentsOf: dst.appendingPathComponent("big.bin")), try Data(contentsOf: src))
    }

    func testAStreamKeyThatHasCarriedItsFillIsReplacedByANewConnection() throws {
        // A key seals only so much; then the sender moves to a new connection, and so a new key.
        DropKeys.streamBytes = Int64(chunk * 5)
        let (sender, receiver) = try pairedMacs()
        let src = try file("big.bin", bytes: chunk * 50)
        let s = send([src], from: sender, to: receiver, streams: 2)
        wait(s)
        XCTAssertEqual(s.state, .completed)
        XCTAssertEqual(try Data(contentsOf: dst.appendingPathComponent("big.bin")), try Data(contentsOf: src))
        XCTAssertEqual(s.stats.connectionFailures, 0, "moving to a new key is not a failure")
        XCTAssertEqual(s.stats.retransmittedChunks, 0)
    }

    func testAManifestTooLargeForOneMessageArrivesInFragments() throws {
        // 3,000 files make a manifest of a few hundred kilobytes: several Noise messages.
        let (sender, receiver) = try pairedMacs()
        let dir = root.appendingPathComponent("Many")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        for i in 0..<3000 { try Data("file \(i)".utf8).write(to: dir.appendingPathComponent("a-rather-long-file-name-to-fill-the-manifest-\(i).txt")) }
        let s = send([dir], from: sender, to: receiver)
        wait(s, 60)
        XCTAssertEqual(s.state, .completed)
        XCTAssertEqual(try FileManager.default.contentsOfDirectory(atPath: dst.appendingPathComponent("Many").path).count, 3000)
    }

    // MARK: Picking a drop up again

    func testOnlyTheSameDropsSenderCanResumeIt() throws {
        let (sender, receiver) = try pairedMacs()
        let third = try TestMac("third")
        receiver.trust.adopt(third.trust, as: "third")
        third.trust.adopt(receiver.trust, as: "receiver")
        let (c, _) = try Channel.dial(host: "127.0.0.1", port: receiver.port, trust: sender.trust, name: "sender", purpose: .drop)
        let manifest = Manifest(chunkSize: chunk, entries: [.init(path: "f.bin", kind: .file, size: Int64(chunk * 3))])
        try c.send(.offer, Offer(items: ["f.bin"], fileCount: 1, totalBytes: manifest.totalBytes))
        XCTAssertEqual(try c.read().type, .accept)
        try c.send(.manifest, manifest)
        XCTAssertEqual(try c.read().type, .plan)
        let keys = DropKeys(master: c.master)

        func resume(as trust: Trust, proof: (Channel) -> Data) throws -> FrameType? {
            let (r, _) = try Channel.dial(host: "127.0.0.1", port: receiver.port, trust: trust, name: "x", purpose: .resume)
            try r.send(.resume, Resume(session: keys.sessionID, proof: proof(r)))
            r.socket.setReadTimeout(2)
            return (try? r.read())?.type
        }
        // Another paired Mac that knows the session id (and even the right proof, somehow):
        // the drop belongs to the key that began it.
        XCTAssertNil(try resume(as: third.trust) { DropKeys.resumeProof(keys.resumeKey, "resume", h: $0.h) })
        // The sender itself with a proof made for another connection.
        XCTAssertNil(try resume(as: sender.trust) { _ in DropKeys.resumeProof(keys.resumeKey, "resume", h: Crypto.random(32)) })
        // The sender itself, properly.
        XCTAssertEqual(try resume(as: sender.trust) { DropKeys.resumeProof(keys.resumeKey, "resume", h: $0.h) }, .resumed)
        c.socket.shutdown()
    }

    // MARK: Withdrawing trust

    func testRetiringAKeyEndsItsDropBeforeAnythingIsPutInPlace() throws {
        // A thief with a copied key starts a drop; the owner resets. From the moment the
        // retirement is acknowledged nothing that key authenticated may deliver.
        let (sender, receiver) = try pairedMacs()
        let src = try file("big.bin", bytes: chunk * 3000)
        let s = send([src], from: sender, to: receiver, streams: 1)
        XCTAssertTrue(until { s.progress.doneBytes > Int64(chunk * 20) })
        let r = try XCTUnwrap(receiver.offers.withLock { $0.first })
        receiver.trust.retire(sender.key)
        XCTAssertTrue(until { r.state.isFinal && s.state.isFinal })
        guard case .failed(let why) = r.state else { return XCTFail("\(r.state)") }
        XCTAssertTrue(why.contains("no longer trusted"), why)
        XCTAssertNotEqual(s.state, .completed)
        Thread.sleep(forTimeInterval: 0.5)
        XCTAssertFalse(FileManager.default.fileExists(atPath: dst.appendingPathComponent("big.bin").path), "nothing was put in place")
        // And the key cannot come back for it: not a new drop, not a resume, not a pairing.
        let again = send([src], from: sender, to: receiver)
        wait(again)
        XCTAssertNotEqual(again.state, .completed)
        XCTAssertFalse(FileManager.default.fileExists(atPath: dst.appendingPathComponent("big.bin").path))
        XCTAssertEqual(receiver.refusedIdentities.withLock { $0 }, ["sender"])
    }

    func testAnOfferWaitingForAnAnswerIsWithdrawnWhenItsKeyIsRetired() throws {
        let (sender, receiver) = try pairedMacs()
        let withdrawn = Locked(0)
        receiver.listener.onOffer = { [weak receiver] s in
            s.onWithdrawn = { withdrawn.withLock { $0 += 1 } }
            receiver?.offers.withLock { $0.append(s) }   // and never answers
        }
        let s = send([try file("a.txt", bytes: 10)], from: sender, to: receiver)
        XCTAssertTrue(until { !receiver.offers.withLock { $0 }.isEmpty })
        let r = receiver.offers.withLock { $0[0] }
        receiver.trust.retire(sender.key)
        XCTAssertTrue(until { r.state.isFinal })
        XCTAssertTrue(until { withdrawn.withLock { $0 } == 1 }, "the panel is taken away")
        // An answer clicked after that is too late.
        r.accept(destination: dst)
        Thread.sleep(forTimeInterval: 0.4)
        XCTAssertEqual(try FileManager.default.contentsOfDirectory(atPath: dst.path), [])
        wait(s)
        XCTAssertNotEqual(s.state, .completed)
    }

    func testResetTellsThePairedMacsAndTheOldKeyIsRefusedFromThenOn() throws {
        let (sender, receiver) = try pairedMacs()
        let away = try TestMac("away")
        sender.trust.adopt(away.trust, as: "away")
        away.trust.adopt(sender.trust, as: "sender")
        let old = sender.trust.keyPair
        let ports = [receiver.key: receiver.port]   // "away" cannot be found
        let list = sender.trust.reset(identity: sender.identity, reach: { ports[$0].map { ("127.0.0.1", $0) } }, seconds: 3)
        XCTAssertNotEqual(sender.key, old.publicKey)
        XCTAssertEqual(list.first { $0.key == receiver.key }?.told, true)
        XCTAssertEqual(list.first { $0.key == away.key }?.told, false, "and the list says which Mac still trusts the old identity")
        guard case .retired = receiver.trust.standing(of: old.publicKey) else { return XCTFail("\(receiver.trust.standing(of: old.publicKey))") }
        XCTAssertTrue(away.trust.standing(of: old.publicKey).isPaired, "the one that was not reached still trusts it, as the list says")

        // The thief, holding the old key, calls the Mac that was told: refused, and said.
        let socket = try Socket.connect(host: "127.0.0.1", port: receiver.port)
        socket.setReadTimeout(3)
        let channel = try Channel.initiate(socket, keys: old, expect: nil)
        try? channel.send(.hello, SecureHello(minor: 0, app: "x", name: "sender", remaining: 1000, paired: true, purpose: .drop))
        XCTAssertThrowsError(try channel.read(), "hung up on")
        XCTAssertTrue(until { receiver.refusedIdentities.withLock { $0 } == ["sender"] })
        // The new key is nobody yet: it was vouched for by nothing.
        XCTAssertEqual(receiver.trust.standing(of: sender.key), .unknown)
    }

    func testARetireNoticeRetiresOnlyTheKeyThatProvedIt() throws {
        let (sender, receiver) = try pairedMacs()
        let third = try TestMac("third")
        receiver.trust.adopt(third.trust, as: "third")
        // A Mac nobody has paired cannot retire anything.
        let stranger = Trust.inMemory()
        let (c, _) = try Channel.dial(host: "127.0.0.1", port: receiver.port, trust: stranger, name: "x", purpose: .retire, paired: true)
        try? c.send(.retire, Empty())
        c.socket.setReadTimeout(2)
        XCTAssertNil(try? c.read())
        XCTAssertTrue(receiver.trust.standing(of: sender.key).isPaired)
        XCTAssertTrue(receiver.trust.standing(of: third.key).isPaired)
        // A paired Mac retires itself, and nobody else.
        let (d, _) = try Channel.dial(host: "127.0.0.1", port: receiver.port, trust: sender.trust, name: "sender", purpose: .retire)
        try d.send(.retire, Empty())
        XCTAssertEqual(try d.read().type, .retired)
        guard case .retired = receiver.trust.standing(of: sender.key) else { return XCTFail("\(receiver.trust.standing(of: sender.key))") }
        XCTAssertTrue(receiver.trust.standing(of: third.key).isPaired, "one notice, one key")
    }

    // MARK: What a stranger may cost

    func testCompletingAHandshakeWithAFreshKeyEarnsNothing() throws {
        // Anyone can make a key and complete a handshake. Fifty of them do, and hold on.
        Tuning.unpaired = 4
        Tuning.strangerSeconds = 2
        let (sender, receiver) = try pairedMacs()
        var held: [Channel] = []
        for _ in 0..<50 {
            if let c = try? Channel.dial(host: "127.0.0.1", port: receiver.port, trust: Trust.inMemory(), name: "flood", purpose: .pair).channel { held.append(c) }
        }
        // At most four got as far as an answer; the rest were closed at once.
        XCTAssertLessThanOrEqual(held.count, 4)
        XCTAssertTrue(receiver.requests.withLock { $0.isEmpty }, "and nobody was asked anything: none of them even asked yet")
        // Meanwhile a paired Mac sends a drop as if nothing were happening.
        let src = try file("a.bin", bytes: chunk * 10)
        let s = send([src], from: sender, to: receiver)
        wait(s)
        XCTAssertEqual(s.state, .completed)
        // And the ones that hold on are closed when their time is up, whatever they do.
        Thread.sleep(forTimeInterval: 2.5)
        for c in held {
            c.socket.setReadTimeout(1)
            XCTAssertThrowsError(try c.read())
        }
        let after = try Channel.dial(host: "127.0.0.1", port: receiver.port, trust: Trust.inMemory(), name: "later", purpose: .pair)
        after.channel.socket.shutdown()
    }

    func testADataConnectionWithNoDropInProgressIsClosedAtOnce() throws {
        let (_, receiver) = try pairedMacs()
        let s = try Socket.connect(host: "127.0.0.1", port: receiver.port)
        try Opening.data.withUnsafeBytes { try s.writeAll($0.baseAddress!, 5) }
        s.setReadTimeout(2)
        var b: UInt8 = 0
        XCTAssertThrowsError(try s.readExactly(&b, 1), "no challenge, no wait: there is nothing it could belong to")
    }

    func testAKeyThatHasRunOutCannotStartADrop() throws {
        let clock = FakeClock()
        let a = Trust.inMemory(clock: clock), b = Trust.inMemory(clock: clock)
        try a.store(pairing: b.publicKey, announced: "receiver", method: "codes", remaining: 90 * 86400)
        try b.store(pairing: a.publicKey, announced: "sender", method: "codes", remaining: 3600)   // the sender's key has an hour left
        let sender = try TestMac("sender", trust: a), receiver = try TestMac("receiver", trust: b)
        let dst = dst
        receiver.listener.onOffer = { $0.accept(destination: dst) }
        let first = send([try file("a.txt", bytes: 10)], from: sender, to: receiver)
        wait(first)
        XCTAssertEqual(first.state, .completed)
        clock.pass(3700, calendar: 0)   // an hour of elapsed time, with the calendar held still
        let second = send([try file("b.txt", bytes: 10)], from: sender, to: receiver)
        wait(second)
        XCTAssertNotEqual(second.state, .completed)
        XCTAssertTrue(second.needsPairing)
        XCTAssertFalse(FileManager.default.fileExists(atPath: dst.appendingPathComponent("b.txt").path))
    }
}
