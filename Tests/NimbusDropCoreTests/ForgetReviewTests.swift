// Copyright (C) 2026 Niels Joubert
// SPDX-License-Identifier: GPL-3.0-or-later
import Darwin
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

/// What the review of "Forget tells the other Mac" (at e1bc42a, 2026-11-23) found, as tests.
/// Each asserts what should hold and fails on the code as reviewed.
final class ForgetReviewTests: XCTestCase {
    var root: URL!
    let chunk = 16 * 1024

    override func setUpWithError() throws {
        root = FileManager.default.temporaryDirectory.appendingPathComponent("nimbusdrop-forget-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: root.appendingPathComponent("dst"), withIntermediateDirectories: true)
        Tuning.reconnectSeconds = 5
        Tuning.arrivalsPerAddress = 500
    }

    override func tearDownWithError() throws {
        Tuning.reconnectSeconds = 60
        Tuning.arrivalsPerAddress = 200
        try? FileManager.default.removeItem(at: root)
    }

    var dst: URL { root.appendingPathComponent("dst") }

    /// Someone on the path, as far as a test needs one: carries every connection to `target`,
    /// slowly if asked, counts what it carried towards the target, and cuts everything on cue.
    final class Relay: @unchecked Sendable {
        let port: UInt16
        private let fd: Int32
        private let target: UInt16
        private let lock = NSLock()
        private var pairs: [(Int32, Int32)] = []
        private var _carried = 0
        private var _pause: useconds_t = 0
        private var stopped = false

        init(to target: UInt16) throws {
            self.target = target
            (fd, port) = try Socket.listen(port: 0)
            Thread.detachNewThread { [self] in
                while !lock.withLock({ stopped }) {
                    var p = pollfd(fd: fd, events: Int16(POLLIN), revents: 0)
                    guard poll(&p, 1, 100) > 0 else { continue }
                    let client = accept(fd, nil, nil)
                    guard client >= 0 else { continue }
                    guard let out = try? Socket.connect(host: "127.0.0.1", port: target, timeout: 2) else { close(client); continue }
                    let server = dup(out.fd)
                    lock.withLock { pairs.append((client, server)) }
                    Thread.detachNewThread { [self] in pump(client, server, count: true) }
                    Thread.detachNewThread { [self] in pump(server, client, count: false) }
                }
            }
        }

        deinit { lock.withLock { stopped = true }; close(fd) }

        var carried: Int { lock.withLock { _carried } }
        /// Microseconds to wait after each piece carried towards the target.
        var pause: useconds_t {
            get { lock.withLock { _pause } }
            set { lock.withLock { _pause = newValue } }
        }

        private func pump(_ from: Int32, _ to: Int32, count: Bool) {
            var buffer = [UInt8](repeating: 0, count: 32 << 10)
            var one: Int32 = 1
            setsockopt(to, SOL_SOCKET, SO_NOSIGPIPE, &one, socklen_t(MemoryLayout<Int32>.size))
            while true {
                let n = read(from, &buffer, buffer.count)
                guard n > 0 else { break }
                var sent = 0
                while sent < n {
                    let w = buffer.withUnsafeBytes { write(to, $0.baseAddress! + sent, n - sent) }
                    guard w > 0 else { break }
                    sent += w
                }
                guard sent == n else { break }
                if count {
                    lock.withLock { _carried += n }
                    let p = pause
                    if p > 0 { usleep(p) }
                }
            }
            Darwin.shutdown(from, SHUT_RDWR)
            Darwin.shutdown(to, SHUT_RDWR)
        }

        /// Every connection that is open now is cut; new ones are carried as before.
        func cut() {
            let all = lock.withLock { () -> [(Int32, Int32)] in defer { pairs = [] }; return pairs }
            for (a, b) in all { Darwin.shutdown(a, SHUT_RDWR); Darwin.shutdown(b, SHUT_RDWR) }
        }
    }

    // MARK: 1. A reconnect within the grace is answered "not paired", and the sender believes it

    /// The plan (Key expiry, P16): "A session already running ends within the stated grace":
    /// a drop that is running when its keys reach their end may finish. The receiver honours
    /// that on a reconnect (`DropListener.serve`, purpose `resume`, standing `.expired`), and
    /// e1bc42a made it not take the sender's truthful `paired: false` for a Forget. But the
    /// receiver's own hello on that reconnect also says `paired: false` (its record of the
    /// sender's key has run out too, at the same moment the sender's key did), and the sender
    /// (`SendSession.reconnect`) takes THAT for a Forget and ends the drop: "… no longer has
    /// this Mac paired; pair again". `testADropFinishesOnTheKeyItStartedWith` (chaos) passes
    /// only because the receiver's clock in it never moves, which no real pair of Macs matches:
    /// the sender's key and the receiver's record of it end together.
    ///
    /// Anyone who can cut one TCP connection at the right time (or a Wi-Fi blip) turns the
    /// grace into an ended drop and a "pair again" alert.
    func testADropInItsGraceSurvivesAReconnectWhenBothSidesHaveSeenTheKeyRunOut() throws {
        let clock = FakeClock()
        // One clock for both Macs: time passes for both, as it does.
        let a = Trust.inMemory(clock: clock, lifetime: 3600), b = Trust.inMemory(clock: clock)
        a.adopt(b, as: "receiver")
        b.adopt(a, as: "sender")   // good for the hour the sender's key has left
        let sender = try TestMac("sender", trust: a), receiver = try TestMac("receiver", trust: b)
        let dst = dst
        receiver.listener.onOffer = { $0.accept(destination: dst) }
        let relay = try Relay(to: receiver.port)
        relay.pause = 20_000

        let url = root.appendingPathComponent("big.bin")
        var bytes = Data()
        let piece = Crypto.random(1 << 20)
        for _ in 0..<24 { bytes.append(piece) }
        try bytes.write(to: url)

        let began = a.publicKey
        let s = SendSession(urls: [url], host: "127.0.0.1", port: relay.port, peerName: "receiver", identity: sender.identity, trust: a,
                            expect: b.publicKey, streams: 4, chunkSize: chunk)
        s.start()
        XCTAssertTrue(until(20) { relay.carried > 4 << 20 || s.state.isFinal }, "the drop never got going")
        XCTAssertFalse(s.state.isFinal, "the drop was over before the link could be cut: \(s.state)")
        // The hour is up, for both of them. Then the link drops for a moment.
        clock.pass(4000)
        XCTAssertNotEqual(a.publicKey, began, "the sender's key was replaced on schedule")
        guard case .expired = b.standing(of: began) else { return XCTFail("the receiver's record of that key should have run out too: \(b.standing(of: began))") }
        relay.pause = 0
        relay.cut()

        _ = until(40) { s.state.isFinal }
        XCTAssertFalse(s.needsPairing, "the sender took the receiver's hello on a reconnect for a Forget")
        XCTAssertEqual(s.state, .completed, "a drop that was running when its key ran out did not finish within the grace")
        XCTAssertEqual(try? Data(contentsOf: dst.appendingPathComponent("big.bin")), bytes)
    }

    // MARK: 2. The notice has no deadline of its own

    /// `Trust.forget(_:telling:identity:seconds:)` says the other Mac "is reached (for at most
    /// `seconds`)". `seconds` is the connect timeout and the timeout of each single read, and
    /// nothing bounds the whole: whatever answers at the address the tile pointed to (an
    /// address is a label; it need not be the Mac that was forgotten, and it need prove
    /// nothing) can feed the opening and the handshake a byte at a time and hold the thread,
    /// the socket and, on the command line, `--forget` itself: about 1,050 reads before a key
    /// has to be proved (52 minutes at the default 3 s), and 65,535 more for a relay that lets
    /// the real Mac prove it.
    func testTellingAForgottenMacTakesNoLongerThanItSays() throws {
        let (a, b) = Trust.paired()
        // Something at the address: it says it is Nimbus Drop, slowly, and never proves a key.
        let (fd, port) = try Socket.listen(port: 0)
        defer { close(fd) }
        let done = Locked(false)
        Thread.detachNewThread {
            let client = accept(fd, nil, nil)
            guard client >= 0 else { return }
            var one: Int32 = 1
            setsockopt(client, SOL_SOCKET, SO_NOSIGPIPE, &one, socklen_t(MemoryLayout<Int32>.size))
            // The opening, the header of a 1,000-byte handshake message, and some of it.
            let bytes = Opening.mine() + Data([0x03, 0xe8, 0xfc, 0x17]) + Data(repeating: 0, count: 5)
            for byte in bytes {
                if done.withLock({ $0 }) { break }
                var b = byte
                guard write(client, &b, 1) == 1 else { break }
                usleep(500_000)
            }
            close(client)
        }
        let seconds = 1.0
        let started = Date()
        let told = a.forget(b.publicKey, telling: (host: "127.0.0.1", port: port), identity: Identity(name: "sender", id: UUID().uuidString), seconds: seconds)
        let took = Date().timeIntervalSince(started)
        done.withLock { $0 = true }
        XCTAssertFalse(told)
        XCTAssertFalse(a.standing(of: b.publicKey).isPaired, "forgotten here whatever the other end does")
        XCTAssertLessThan(took, 3 * seconds, "told to take at most \(seconds) s, the notice was held for \(took) s by an address that proved nothing")
    }

    // MARK: 3. A hello that predates a pairing

    /// A `paired: false` that was true when it was sealed (a probe during the pairing, a Forget
    /// followed at once by pairing again) can arrive just after the pairing is stored. It is
    /// not taken for a Forget while the pairing is only seconds old; afterwards it is.
    func testAHelloFromBeforeAPairingDoesNotEndIt() throws {
        let clock = FakeClock()
        let a = Trust.inMemory(clock: clock), b = Trust.inMemory(clock: clock)
        a.adopt(b, as: "receiver"); b.adopt(a, as: "sender")
        let receiver = try TestMac("receiver", trust: b)
        _ = try? Channel.dial(host: "127.0.0.1", port: receiver.port, trust: a, name: "sender", purpose: nil, paired: false)
        XCTAssertTrue(b.standing(of: a.publicKey).isPaired, "a pairing made a moment ago was ended by a hello that may predate it")
        clock.pass(Tuning.strangerSeconds + 1)
        _ = try? Channel.dial(host: "127.0.0.1", port: receiver.port, trust: a, name: "sender", purpose: nil, paired: false)
        guard case .renew = b.standing(of: a.publicKey) else { return XCTFail("\(b.standing(of: a.publicKey))") }
    }
}
