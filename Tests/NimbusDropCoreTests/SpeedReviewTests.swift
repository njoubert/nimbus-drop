// Copyright (C) 2026 Niels Joubert
// SPDX-License-Identifier: GPL-3.0-or-later
import Darwin
import Foundation
import XCTest
@testable import NimbusDropCore

/// What the review of the speed test (protocol 3.1, at 7a746c9, 2026-11-23) found, as tests.
/// Each asserts what should hold and failed on the code as reviewed (which also asked nobody:
/// here the person at the Mac that is asked says yes, and what follows must still hold). The attacker throughout is
/// a paired Mac that means harm: it holds the right keys and speaks the protocol by hand.
final class SpeedReviewTests: XCTestCase {
    typealias RawPeer = ReviewTests.RawPeer

    override func setUp() { Tuning.arrivalsPerAddress = 500; Tuning.speedPauseSeconds = 0 }
    override func tearDown() { Tuning.arrivalsPerAddress = 200; Tuning.speedPauseSeconds = 10 }

    func pairedMacs() throws -> (TestMac, TestMac) {
        let (a, b) = Trust.paired("tester", "asked")
        let asked = try TestMac("asked", trust: b)
        asked.listener.onSpeedTest = { $0.accept() }
        return (try TestMac("tester", trust: a), asked)
    }

    /// Asks for a speed test by hand. The answer's type is `speedGo` or `busy`.
    func ask(_ from: TestMac, _ to: TestMac, seconds: Double = 1, streams: Int = 1) throws -> (peer: RawPeer, answer: UInt8) {
        let p = try RawPeer(port: to.port, keys: from.trust.keyPair)
        try p.hello(.speed)
        try p.json(.speed, SpeedAsk(seconds: seconds, streams: streams))
        return (p, try p.read().type)
    }

    /// Opens a data connection and proves it belongs to the test, as a drop's are attached.
    func attach(_ keys: DropKeys, _ conn: UInt64, port: UInt16) throws -> Socket {
        let s = try Socket.connect(host: "127.0.0.1", port: port)
        s.setReadTimeout(2)
        try Opening.data.withUnsafeBytes { try s.writeAll($0.baseAddress!, 5) }
        var challenge = Data(count: 16)
        try challenge.withUnsafeMutableBytes { try s.readExactly($0.baseAddress!, 16) }
        let message = keys.sessionID + Crypto.be64(conn) + keys.attachTag(conn: conn, challenge: challenge)
        try message.withUnsafeBytes { try s.writeAll($0.baseAddress!, message.count) }
        // Let the listener take it out of the pool of unattached connections before the next.
        Thread.sleep(forTimeInterval: 0.01)
        return s
    }

    /// Whether the other end has closed `s`. Only for a connection the other end never writes on.
    func closed(_ s: Socket, within seconds: Double = 1) -> Bool {
        until(seconds) { s.waitReadable(milliseconds: 0) }
    }

    // MARK: F1. Data connections outlive a speed test that completed

    /// A test that ends well closes nothing but its control connection: `Transfer.finish`
    /// shuts the tracked sockets only when the state is not `.completed`, and the absolute
    /// deadline guards the control socket alone. A tester that attaches its "up" connections,
    /// walks the conversation to its end and never sends an end marker leaves one thread, one
    /// descriptor and one 4 MiB buffer per connection behind at the Mac that was asked; a byte
    /// now and then (inside the read timeout of seconds + 10) keeps each for as long as it likes.
    func testADataConnectionDoesNotOutliveItsSpeedTest() throws {
        let (a, b) = try pairedMacs()
        let seen = Locked<[Transfer]>([])
        b.listener.onSpeedTest = { t in seen.withLock { $0.append(t) }; t.accept() }
        let (p, answer) = try ask(a, b)
        XCTAssertEqual(answer, FrameType.speedGo.rawValue)
        p.socket.setReadTimeout(8)
        let keys = DropKeys(master: p.master)
        try p.json(.speedUpDone, Empty())
        XCTAssertEqual(try p.read().type, FrameType.speedCount.rawValue)
        // After the count, so that the Mac that was asked does not even wait three seconds for it.
        let s = try attach(keys, 1, port: b.port)
        XCTAssertFalse(s.waitReadable(milliseconds: 300), "the connection was not taken")
        try p.json(.speedDown, Empty())
        XCTAssertEqual(try p.read().type, FrameType.speedDone.rawValue)
        try p.json(.speedCount, SpeedCount(bytes: 0, seconds: 1))
        XCTAssertTrue(until(5) { seen.withLock { $0.first?.state } == .completed })
        // The control connection has been closed; the test is over at the Mac that was asked.
        XCTAssertTrue(closed(p.socket, within: 2))
        XCTAssertTrue(closed(s, within: 2), "a data connection was still open two seconds after its speed test completed")
        // And it stays for as long as a byte arrives now and then: well past seconds + 10.
        let start = Date()
        while Date().timeIntervalSince(start) < 13 {
            var byte: UInt8 = 0
            try? s.writeAll(&byte, 1)
            Thread.sleep(forTimeInterval: 2)
        }
        XCTAssertTrue(s.waitReadable(milliseconds: 0), "a data connection was still open fifteen seconds after its one-second speed test completed")
    }

    /// The same, counted: tests back to back, each leaving its connections behind. What one
    /// paired Mac holds open at another is then not "one test, 2 × 32 connections" but as many
    /// as it cares to open (a GUI app has 256 descriptors; `accept` failing for want of one
    /// leaves the listener deaf to everybody).
    func testFinishedSpeedTestsDoNotAccumulateConnections() throws {
        let (a, b) = try pairedMacs()
        let seen = Locked<[Transfer]>([])
        b.listener.onSpeedTest = { t in seen.withLock { $0.append(t) }; t.accept() }
        var left: [Socket] = []
        let tests = 6, each = 8
        for _ in 0..<tests {
            let (p, answer) = try ask(a, b, streams: each)
            XCTAssertEqual(answer, FrameType.speedGo.rawValue)
            let keys = DropKeys(master: p.master)
            try p.json(.speedUpDone, Empty())
            _ = try p.read()
            for conn in 1...each { left.append(try attach(keys, UInt64(conn), port: b.port)) }
            try p.json(.speedDown, Empty())
            _ = try p.read()
            try p.json(.speedCount, SpeedCount(bytes: 0, seconds: 1))
            XCTAssertTrue(closed(p.socket, within: 3))
        }
        XCTAssertTrue(until(5) { seen.withLock { $0.count == tests && $0.allSatisfy { $0.state == .completed } } })
        Thread.sleep(forTimeInterval: 1)
        let open = left.filter { !$0.waitReadable(milliseconds: 0) }.count
        XCTAssertEqual(open, 0, "\(open) data connections of \(tests) finished speed tests are still open at the Mac that was asked")
    }

    /// The other direction. A tester that attaches a "down" connection and never reads it
    /// leaves the thread that writes to it blocked in `writev`; the conversation goes on
    /// without it after seconds + 10 and completes, and nothing ever closes that socket. The
    /// thread, its 4 MiB of random bytes and the 4 MiB record it sealed stay until the tester
    /// reads or goes away. Shown here by what arrives when the tester does read, long after:
    /// the rest of the stream and a properly sealed end marker, from a thread that was there
    /// all along. Had the socket been closed with the test, the stream would stop mid-record.
    func testADownConnectionNobodyReadsDoesNotOutliveItsSpeedTest() throws {
        let (a, b) = try pairedMacs()
        let seen = Locked<[Transfer]>([])
        b.listener.onSpeedTest = { t in seen.withLock { $0.append(t) }; t.accept() }
        let (p, answer) = try ask(a, b)
        XCTAssertEqual(answer, FrameType.speedGo.rawValue)
        p.socket.setReadTimeout(20)
        let keys = DropKeys(master: p.master)
        let s = try attach(keys, 2, port: b.port)
        try p.json(.speedUpDone, Empty())
        XCTAssertEqual(try p.read().type, FrameType.speedCount.rawValue)
        try p.json(.speedDown, Empty())
        // The Mac that was asked waits seconds + 10 for its writer, then carries on without it.
        XCTAssertEqual(try p.read().type, FrameType.speedDone.rawValue)
        try p.json(.speedCount, SpeedCount(bytes: 0, seconds: 1))
        XCTAssertTrue(until(5) { seen.withLock { $0.first?.state } == .completed })
        Thread.sleep(forTimeInterval: lingerBeforeReading)
        var cipher = keys.stream(2)
        s.setReadTimeout(5)
        let meter = SpeedWire.Meter()
        XCTAssertThrowsError(try SpeedWire.receive(s, cipher: &cipher, meter: meter, over: { false }),
                             "a thread at the Mac that was asked was still writing to a data connection \(Int(lingerBeforeReading)) s after its speed test completed (it sent \(meter.bytes >> 20) MiB and an end marker)")
    }

    /// How long the tester leaves the down connection unread after the test has completed.
    /// (Set SPEED_REVIEW_LINGER=45 to see that TCP's own limits do not end it either.)
    var lingerBeforeReading: Double { ProcessInfo.processInfo.environment["SPEED_REVIEW_LINGER"].flatMap(Double.init) ?? 3 }

    // MARK: F2. "One at a time" does not hold

    /// `served` frees the Mac for the next test before the first has left `serve`, and the
    /// first's `defer { speedTesting = false }` then clears the flag again when it does leave,
    /// under whichever test holds it by then. A tester that does not send its last count keeps
    /// the first test in `serve` for three seconds: a second starts in that time (as designed),
    /// the first leaves, and a third is let in beside the second. Repeated, every three
    /// seconds adds another test, each good for 2 × 30 + 20 seconds and 64 connections.
    func testOneSpeedTestAtATimeHoldsWhileAnEarlierOneLingers() throws {
        let (a, b) = try pairedMacs()
        // The first, to its last word but one: the Mac that was asked now waits 3 s for a count.
        let (first, answer) = try ask(a, b)
        XCTAssertEqual(answer, FrameType.speedGo.rawValue)
        try first.json(.speedUpDone, Empty())
        XCTAssertEqual(try first.read().type, FrameType.speedCount.rawValue)
        try first.json(.speedDown, Empty())
        XCTAssertEqual(try first.read().type, FrameType.speedDone.rawValue)
        // The second: thirty seconds each way, and it stays where it is.
        var second: RawPeer?
        XCTAssertTrue(until(6) {
            if second != nil { return true }
            guard let (p, answer) = try? ask(a, b, seconds: 30), answer == FrameType.speedGo.rawValue else { return false }
            second = p
            return true
        }, "the Mac was never free for a second test")
        // The first one's three seconds run out and it leaves.
        XCTAssertTrue(closed(first.socket, within: 5))
        Thread.sleep(forTimeInterval: 0.3)
        XCTAssertFalse(second!.socket.waitReadable(milliseconds: 0), "the second test is still open")
        let (third, verdict) = try ask(a, b, seconds: 30)
        XCTAssertEqual(verdict, FrameType.busy.rawValue, "a third speed test was let in while the second was still running")
        second?.socket.shutdown()
        third.socket.shutdown()
    }

    // MARK: F3. Nothing between one test and the next

    /// PROPOSED, not in the plan: some pause, per key, between one speed test and the next.
    /// As built there is none, and a test need carry nothing: a paired Mac can have hundreds a
    /// second served, each a row in the other Mac's window for a minute and four lines in its
    /// log; or one after another at thirty seconds each way, for ever, with the Mac held awake
    /// throughout (`AppModel.refresh` takes the sleep hold for any row that is not final).
    /// The bound asserted here (no more than three served to one key in two seconds) is generous.
    func testAPairedMacIsNotServedSpeedTestsWithoutPause() throws {
        Tuning.speedPauseSeconds = 10
        let (a, b) = try pairedMacs()
        let seen = Locked<[Transfer]>([])
        b.listener.onSpeedTest = { t in seen.withLock { $0.append(t) }; t.accept() }
        let start = Date()
        var served = 0
        while Date().timeIntervalSince(start) < 2 {
            guard let (p, answer) = try? ask(a, b), answer == FrameType.speedGo.rawValue else { continue }
            try? p.json(.speedUpDone, Empty())
            _ = try? p.read()
            try? p.json(.speedDown, Empty())
            _ = try? p.read()
            try? p.json(.speedCount, SpeedCount(bytes: 0, seconds: 1))
            served += 1
        }
        print("speed tests served to one key in two seconds: \(served); rows handed to the window: \(seen.withLock { $0.count })")
        XCTAssertLessThanOrEqual(served, 3, "\(served) speed tests were served to one paired Mac in two seconds, with no pause between them")
    }

    // MARK: F4. The Mac that asks has no limit of its own

    /// A Mac that answers a speed test and then reads nothing: paired, and either hostile or
    /// merely stopped (a suspended process answers TCP's keepalives all the same).
    final class Silent: @unchecked Sendable {
        let port: UInt16
        private let fd: Int32
        private let lock = NSLock()
        private var held: [Socket] = []
        private var channels: [Channel] = []
        private var stopped = false

        init(as mac: Trust) throws {
            (fd, port) = try Socket.listen(port: 0)
            Thread.detachNewThread { [self] in
                while !lock.withLock({ stopped }) {
                    var p = pollfd(fd: fd, events: Int16(POLLIN), revents: 0)
                    guard poll(&p, 1, 100) > 0 else { continue }
                    let client = accept(fd, nil, nil)
                    guard client >= 0 else { continue }
                    let socket = Socket(fd: client)
                    lock.withLock { held.append(socket) }
                    Thread.detachNewThread { [self] in serve(socket, mac) }
                }
            }
        }

        deinit { stop() }

        func stop() {
            let all = lock.withLock { () -> [Socket] in
                if !stopped { stopped = true; close(fd) }
                return held
            }
            for s in all { s.shutdown() }
        }

        private func serve(_ socket: Socket, _ mac: Trust) {
            socket.setReadTimeout(5)
            guard let kind = try? Opening.readKind(socket) else { return }
            if kind == Opening.data {
                // Taken, and then never read.
                let challenge = Crypto.random(16)
                var message = Data(count: 40)
                try? challenge.withUnsafeBytes { try socket.writeAll($0.baseAddress!, 16) }
                try? message.withUnsafeMutableBytes { try socket.readExactly($0.baseAddress!, 40) }
                return
            }
            guard let channel = try? Channel.respond(socket, keys: mac.keyPair), (try? channel.read())?.type == .hello else { return }
            lock.withLock { channels.append(channel) }
            try? channel.send(.hello, SecureHello(minor: protocolMinor, app: "silent", name: "asked", remaining: mac.remaining, paired: true, purpose: nil))
            guard let frame = try? channel.read(), frame.type == .speed, let ask = try? decode(SpeedAsk.self, from: frame.body) else { return }
            try? channel.send(.speedGo, ask)
            // And nothing more is said.
        }
    }

    /// The Mac that is asked keeps an absolute limit of 2 × seconds + 20. The Mac that asks
    /// keeps none: its senders block in `writev` against a Mac that reads nothing, `run` waits
    /// for them without limit, and no watchdog is started. The row says "Measuring…" (and the
    /// Mac is held awake) until its person cancels; `--speed` on the command line never returns.
    func testTheMacThatAsksGivesUpOnAMacThatStopsReading() throws {
        let (mine, theirs) = Trust.paired("tester", "asked")
        let tester = try TestMac("tester", trust: mine)
        let silent = try Silent(as: theirs)
        defer { silent.stop() }
        let t = SpeedTest(host: "127.0.0.1", port: silent.port, peerName: "asked", identity: tester.identity, trust: mine, expect: theirs.publicKey,
                          seconds: 1, streams: 1)
        t.start()
        XCTAssertTrue(until(10) { t.state == .transferring })
        // The limit the Mac that is asked would keep for a one-second test.
        XCTAssertTrue(until(22) { t.state.isFinal }, "a one-second speed test was still \(t.state) after 22 s against a Mac that stopped reading")
        t.cancel()
    }

    // MARK: F5. The count the tester sends back is shown as it comes

    /// The Mac that was asked shows "↑ … to <tester>" from the tester's own count. The bytes
    /// are held to what was sent; the seconds only to being positive, so the rate shown at the
    /// Mac that was asked is whatever the tester likes, infinity included.
    func testTheAskedMacDoesNotShowARateNoLinkCouldCarry() throws {
        let (a, b) = try pairedMacs()
        let seen = Locked<[Transfer]>([])
        b.listener.onSpeedTest = { t in seen.withLock { $0.append(t) }; t.accept() }
        let (p, answer) = try ask(a, b)
        XCTAssertEqual(answer, FrameType.speedGo.rawValue)
        p.socket.setReadTimeout(15)
        let keys = DropKeys(master: p.master)
        let s = try attach(keys, 2, port: b.port)
        try p.json(.speedUpDone, Empty())
        XCTAssertEqual(try p.read().type, FrameType.speedCount.rawValue)
        try p.json(.speedDown, Empty())
        var cipher = keys.stream(2)
        s.setReadTimeout(10)
        try SpeedWire.receive(s, cipher: &cipher, meter: SpeedWire.Meter(), over: { false })
        let done = try p.read()
        XCTAssertEqual(done.type, FrameType.speedDone.rawValue)
        let sent = try JSONDecoder().decode(SpeedCount.self, from: done.body).bytes
        XCTAssertGreaterThan(sent, 0)
        try p.json(.speedCount, SpeedCount(bytes: sent, seconds: .leastNonzeroMagnitude))
        XCTAssertTrue(until(5) { seen.withLock { $0.first?.state } == .completed })
        let shown = try XCTUnwrap(seen.withLock { $0.first?.speedResult })
        // A hundred times what the fastest Mac moves through memory is not a measurement.
        XCTAssertLessThan(shown.upRate, 1e12, "the Mac that was asked shows \(Format.bitRate(shown.upRate)) on the tester's word")
    }
}
