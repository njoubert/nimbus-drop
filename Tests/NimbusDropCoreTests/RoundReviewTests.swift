// Copyright (C) 2026 Niels Joubert
// SPDX-License-Identifier: GPL-3.0-or-later
import Darwin
import Foundation
import XCTest
@testable import NimbusBase
@testable import NimbusCrypto
@testable import NimbusDropCore
@testable import NimbusNet
@testable import NimbusSafeStorageCore
@testable import NimbusSecurityCore
@testable import NimbusTransferCore

/// What a review of the two sessions around the round machines found (2026-11-24), as attacks.
/// Each failed before its fix and has a line in `scripts/mutate.py`.
final class RoundReviewTests: XCTestCase {
    var root: URL!

    override func setUpWithError() throws {
        root = FileManager.default.temporaryDirectory.appendingPathComponent("nimbusdrop-round-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: root.appendingPathComponent("dst"), withIntermediateDirectories: true)
    }

    override func tearDownWithError() throws {
        Tuning.manifestSeconds = 60
        try? FileManager.default.removeItem(at: root)
    }

    /// An accepted drop is given room for its manifest out of a budget all drops share, in
    /// proportion to the files its offer claimed, and the next accepted drop waits when there
    /// is none left. Until 2026-11-24 nothing bounded how long the manifest could take to
    /// come: two offers that each claimed enough files to take half the budget, accepted, and
    /// then silent, held it for good, and every drop accepted after them waited for room that
    /// never came, with no word to anyone. A sender that was accepted has so long to be silent.
    func testAnAcceptedOfferThatSendsNoManifestDoesNotHoldUpEveryOtherDrop() throws {
        Tuning.manifestSeconds = 1
        let (a, b) = Trust.paired("greedy", "receiver")
        let honest = Trust.inMemory()
        honest.adopt(b, as: "receiver"); b.adopt(honest, as: "honest")
        let receiver = try TestMac("receiver", trust: b)
        let dst = root.appendingPathComponent("dst")
        receiver.listener.onOffer = { [weak receiver] s in
            receiver?.offers.withLock { $0.append(s) }
            s.accept(destination: dst)
        }
        // Two offers of 300,000 files: room for 512 MB of manifest each, which is all there is.
        var silent: [Channel] = []
        for _ in 0..<2 {
            let (channel, _) = try Channel.dial(host: "127.0.0.1", port: receiver.port, trust: a, name: "greedy", purpose: .drop)
            channel.socket.setReadTimeout(20)
            try channel.send(.offer, Offer(items: ["everything"], fileCount: 300_000, totalBytes: 1))
            XCTAssertEqual(try channel.read().type, .accept)
            silent.append(channel)
        }
        // An honest drop from another Mac, accepted while those two say nothing.
        let source = root.appendingPathComponent("small.txt")
        try Data(repeating: 7, count: 1000).write(to: source)
        let s = SendSession(urls: [source], host: "127.0.0.1", port: receiver.port, peerName: "receiver", identity: Identity(name: "honest", id: UUID().uuidString),
                            trust: honest, expect: b.publicKey)
        s.start()
        XCTAssertTrue(until(15) { s.state.isFinal }, "still \(s.state): the drop is waiting for room that two silent senders hold")
        XCTAssertEqual(s.state, .completed)
        // The two that sent nothing were given up, and told why.
        for channel in silent {
            let last = try? channel.read()
            XCTAssertEqual(last?.type, .error)
            let why = last.flatMap { try? decode(Reason.self, from: $0.body).message } ?? ""
            XCTAssertTrue(why.contains("did not send"), why)
        }
        let greedy = receiver.offers.withLock { $0 }.filter { $0.offeredFiles == 300_000 }
        XCTAssertEqual(greedy.count, 2)
        for session in greedy { XCTAssertTrue(until(5) { session.state.isFinal }, "\(session.state)") }
        s.cancel()
        for session in receiver.offers.withLock({ $0 }) { session.cancel() }
    }

    /// A paired receiver that means harm, made by hand: it takes a drop as far as its first
    /// plan, lets the round's data connection in and never reads it (so the round does not
    /// end), and then says "plan" ten thousand times. The sender reads the conversation on a
    /// thread of its own, so that a reason for stopping is heard in the middle of a round; it
    /// kept everything that thread read until the drop's own thread came for it, without
    /// limit. An honest receiver says one thing for each thing it is asked. More waiting unread
    /// than that can ever be is not a conversation being kept to, and ends the drop.
    func testAReceiverCannotFillASendersMemoryWithMessagesNobodyAskedFor() throws {
        let (a, b) = Trust.paired("sender", "receiver")
        let (fd, port) = try Socket.listen(port: 0)
        defer { close(fd) }
        let flood = 10_000
        let roundBegan = DispatchSemaphore(value: 0), over = DispatchSemaphore(value: 0)
        let sent = Locked(0)
        Thread.detachNewThread {
            defer { over.signal() }
            func next() -> Socket? {
                let client = accept(fd, nil, nil)
                guard client >= 0 else { return nil }
                let s = Socket(fd: client)
                s.setReadTimeout(10)
                return s
            }
            guard let socket = next(), (try? Opening.readKind(socket)) == Opening.control,
                  let channel = try? Channel.respond(socket, keys: b.keyPair), let hello = try? channel.read(), hello.type == .hello else { return }
            try? channel.send(.hello, SecureHello(minor: protocolMinor, app: "test", name: "receiver", remaining: b.remaining, paired: true, purpose: nil))
            guard let offer = try? channel.read(), offer.type == .offer else { return }
            try? channel.send(.accept, Empty())
            channel.limit = 1 << 20
            guard let manifest = try? channel.read(), manifest.type == .manifest else { return }
            let nothing = Plan(completeFiles: [], partialFiles: [])
            try? channel.send(.plan, nothing)
            // The round's data connection: let in (the challenge is all the sender waits for),
            // then left unread, so that the sender's stream stands still with chunks to send.
            guard let data = next(), (try? Opening.readKind(data)) == Opening.data else { return }
            let challenge = Crypto.random(16)
            try? challenge.withUnsafeBytes { try data.writeAll($0.baseAddress!, 16) }
            roundBegan.signal()
            for _ in 0..<flood {
                guard (try? channel.send(.plan, nothing)) != nil else { break }
                sent.withLock { $0 += 1 }
            }
            // Held open until the sender hangs up, or the test is over.
            _ = try? channel.read()
            data.shutdown()
            socket.shutdown()
        }
        // More than a socket will take without a reader, so the round cannot finish.
        let source = root.appendingPathComponent("big.bin")
        try Data(count: 64 << 20).write(to: source)
        let s = SendSession(urls: [source], host: "127.0.0.1", port: port, peerName: "receiver", identity: Identity(name: "sender", id: UUID().uuidString),
                            trust: a, expect: b.publicKey, streams: 1)
        s.start()
        XCTAssertEqual(roundBegan.wait(timeout: .now() + 20), .success)
        var most = 0
        let ended = until(10) { most = max(most, s.unread); return s.state.isFinal }
        XCTAssertLessThanOrEqual(most, 2, "the sender held \(most) messages nobody had asked for (the receiver wrote \(sent.withLock { $0 }))")
        XCTAssertTrue(ended, "still \(s.state), with \(s.unread) messages unread")
        guard case .failed(let why) = s.state else { return XCTFail("\(s.state)") }
        XCTAssertTrue(why.contains("Unexpected"), why)
        s.cancel()
        XCTAssertEqual(over.wait(timeout: .now() + 20), .success)
    }
}
