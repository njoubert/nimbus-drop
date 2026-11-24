// Copyright (C) 2026 Niels Joubert
// SPDX-License-Identifier: GPL-3.0-or-later
import Darwin
import Foundation
import XCTest
@testable import NimbusBase
@testable import NimbusCrypto
@testable import NimbusDropCore
@testable import NimbusNet
@testable import NimbusSecurityCore
@testable import NimbusTransferCore

/// What the formal models (formal/) found in the code, as attacks. Each test failed before its
/// fix and has a line in `scripts/mutate.py`.
final class ModelFindingsTests: XCTestCase {
    var root: URL!

    override func setUpWithError() throws {
        root = FileManager.default.temporaryDirectory.appendingPathComponent("nimbusdrop-model-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: root.appendingPathComponent("dst"), withIntermediateDirectories: true)
    }

    override func tearDownWithError() throws { try? FileManager.default.removeItem(at: root) }

    // MARK: TrustWithdraw.tla, NothingOutlivesTheWithdrawal

    /// A session asks "is this key paired?" at the start of its handshake and registers with
    /// the trust store at the end of it. The other Mac decides how long that takes: here it
    /// proves its key, takes this Mac's hello, and then says nothing. Meanwhile the person
    /// chooses Forget. The withdrawal ends every session of that key, and finds none: this one
    /// is not registered yet. Then the other Mac answers, and until 2026-11-24 the drop went
    /// ahead: the offer (file names, sizes) and, on an accept, every byte, to a Mac that had
    /// just been forgotten. For a retired key it is worse: whoever holds the old key gets the drop.
    func testADropDoesNotBeginUnderAPairingThatEndedDuringItsHandshake() throws {
        let (a, b) = Trust.paired("sender", "receiver")
        let (fd, port) = try Socket.listen(port: 0)
        defer { close(fd) }
        let helloArrived = DispatchSemaphore(value: 0), forgotten = DispatchSemaphore(value: 0), over = DispatchSemaphore(value: 0)
        let offered = Locked<Offer?>(nil)
        Thread.detachNewThread {
            defer { over.signal() }
            let client = accept(fd, nil, nil)
            guard client >= 0 else { return }
            let socket = Socket(fd: client)
            socket.setReadTimeout(5)
            guard (try? Opening.readKind(socket)) == Opening.control, let channel = try? Channel.respond(socket, keys: b.keyPair),
                  let first = try? channel.read(), first.type == .hello else { return }
            helloArrived.signal()
            // The other Mac takes its time; the person at the sender chooses Forget meanwhile.
            _ = forgotten.wait(timeout: .now() + 5)
            try? channel.send(.hello, SecureHello(minor: protocolMinor, app: "test", name: "receiver", remaining: b.remaining, paired: true, purpose: nil))
            socket.setReadTimeout(2)
            if let next = try? channel.read(), next.type == .offer { offered.withLock { $0 = try? decode(Offer.self, from: next.body) } }
            socket.shutdown()
        }
        let source = root.appendingPathComponent("secret-plans.txt")
        try Data(repeating: 7, count: 1000).write(to: source)
        let s = SendSession(urls: [source], host: "127.0.0.1", port: port, peerName: "receiver", identity: Identity(name: "sender", id: UUID().uuidString),
                            trust: a, expect: b.publicKey)
        s.start()
        XCTAssertEqual(helloArrived.wait(timeout: .now() + 10), .success)
        a.forget(b.publicKey)
        forgotten.signal()
        XCTAssertEqual(over.wait(timeout: .now() + 10), .success)
        XCTAssertTrue(until(10) { s.state.isFinal })
        XCTAssertNil(offered.withLock { $0 }, "an offer was made to a Mac that had been forgotten before the drop began")
        guard case .failed = s.state else { return XCTFail("\(s.state)") }
    }

    /// The same gap at the Mac that receives: a paired Mac proves its key and says hello, and
    /// is forgotten here before its offer arrives. Nothing from it is shown to anyone.
    func testAnOfferIsNotShownUnderAPairingThatEndedDuringItsHandshake() throws {
        let (a, b) = Trust.paired("sender", "receiver")
        let receiver = try TestMac("receiver", trust: b)
        let (channel, hello) = try Channel.dial(host: "127.0.0.1", port: receiver.port, trust: a, name: "sender", purpose: .drop)
        XCTAssertTrue(hello.paired)
        // The listener has asked who this key is, and answered. Now the person there chooses Forget.
        b.forget(a.publicKey)
        try channel.send(.offer, Offer(items: ["surprise.app"], fileCount: 1, totalBytes: 5))
        channel.socket.setReadTimeout(3)
        let answer = try? channel.read()
        XCTAssertNotEqual(answer?.type, .accept)
        XCTAssertFalse(until(1) { !receiver.offers.withLock { $0.isEmpty } }, "an offer from a Mac that had just been forgotten was put in front of the person")
    }

    /// The rule by itself, at the trust store: asking about a key and registering a session
    /// under it are one decision. What was registered before a withdrawal is ended by it; what
    /// comes to register after it is ended there and then.
    func testRegisteringASessionUnderAKeyThatWasWithdrawnEndsIt() throws {
        final class Session: TrustedSession, @unchecked Sendable {
            let ended = Locked(false)
            var isFinal: Bool { ended.withLock { $0 } }
            var isWaitingForAccept: Bool { false }
            func log(_ message: @autoclosure () -> String, _ level: LogLevel) {}
            func withdrawn(_ error: DropError) { ended.withLock { $0 = true } }
        }
        let (a, b) = Trust.paired()
        let paired = Session(), gone = Session()
        a.track(paired, key: b.publicKey)
        XCTAssertFalse(paired.isFinal)
        a.forget(b.publicKey)
        XCTAssertTrue(paired.isFinal, "a withdrawal ends what was registered")
        a.track(gone, key: b.publicKey)
        XCTAssertTrue(gone.isFinal, "and what registers after it")
    }
}
