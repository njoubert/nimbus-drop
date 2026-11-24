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

    override func tearDownWithError() throws { try? FileManager.default.removeItem(at: root) }

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
