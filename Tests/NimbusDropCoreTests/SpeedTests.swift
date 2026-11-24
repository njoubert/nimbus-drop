// Copyright (C) 2026 Niels Joubert
// SPDX-License-Identifier: GPL-3.0-or-later
import Foundation
import XCTest
@testable import NimbusDropCore

/// The speed test (the plan's Addendum B): what it measures, who may ask for one, and what
/// the Mac that is asked will and will not do for it.
final class SpeedTests: XCTestCase {
    typealias RawPeer = ReviewTests.RawPeer

    override func setUp() { Tuning.arrivalsPerAddress = 500; Tuning.speedPauseSeconds = 0 }
    override func tearDown() { Tuning.arrivalsPerAddress = 200; Tuning.speedPauseSeconds = 10 }

    func pairedMacs() throws -> (TestMac, TestMac) {
        let (a, b) = Trust.paired("tester", "asked")
        let asked = try TestMac("asked", trust: b)
        // The person at the Mac that is asked says yes, unless a test says otherwise.
        asked.listener.onSpeedTest = { $0.accept() }
        return (try TestMac("tester", trust: a), asked)
    }

    /// The tenet: nothing one Mac has another do happens without a yes from the person there.
    /// A speed test asks, and until the answer is yes nothing runs: no data connection is
    /// taken, nothing is sent, nothing is counted. (As first built it started at once.)
    func testNothingRunsUntilThePersonAtTheOtherMacSaysYes() throws {
        let (a, b) = try pairedMacs()
        let asked = Locked<[SpeedResponder]>([])
        b.listener.onSpeedTest = { r in asked.withLock { $0.append(r) } }
        let t = test(a, b)
        XCTAssertTrue(until(5) { asked.withLock { $0.count } == 1 })
        Thread.sleep(forTimeInterval: 1.5)
        XCTAssertEqual(t.state, .waitingForAccept, "the test went ahead with nobody having said yes")
        XCTAssertEqual(t.progress.doneBytes, 0)
        let question = asked.withLock { $0[0] }
        XCTAssertEqual(question.state, .waitingForAccept)
        XCTAssertEqual(question.secondsEachWay, 1)
        // A data connection that tries its luck meanwhile finds nothing to attach to.
        let s = try Socket.connect(host: "127.0.0.1", port: b.port)
        try Opening.data.withUnsafeBytes { try s.writeAll($0.baseAddress!, 5) }
        XCTAssertTrue(until(2) { s.waitReadable(milliseconds: 0) }, "a data connection was taken before the yes")
        // Yes: now it runs.
        question.accept()
        XCTAssertTrue(until(15) { t.state.isFinal })
        XCTAssertEqual(t.state, .completed)
        XCTAssertGreaterThan(t.result.upBytes, 0)
    }

    func testNoMeansNoAndNobodyToAskMeansNo() throws {
        let (a, b) = try pairedMacs()
        b.listener.onSpeedTest = { $0.decline() }
        var t = test(a, b)
        XCTAssertTrue(until(5) { t.state.isFinal })
        guard case .declined = t.state else { return XCTFail("\(t.state)") }
        XCTAssertEqual(t.result.upBytes, 0)
        // Nobody listening for the question (receiving from the command line with no terminal, say).
        b.listener.onSpeedTest = nil
        t = test(a, b)
        XCTAssertTrue(until(5) { t.state.isFinal })
        guard case .declined = t.state else { return XCTFail("\(t.state)") }
        // And a no does not hold the Mac: the next question is put.
        b.listener.onSpeedTest = { $0.accept() }
        t = test(a, b)
        XCTAssertTrue(until(15) { t.state.isFinal })
        XCTAssertEqual(t.state, .completed)
    }

    func testAQuestionIsTakenAwayWhenTheAskerGivesUp() throws {
        let (a, b) = try pairedMacs()
        let asked = Locked<[SpeedResponder]>([]), withdrawn = Locked(0)
        b.listener.onSpeedTest = { r in
            r.onWithdrawn = { withdrawn.withLock { $0 += 1 } }
            asked.withLock { $0.append(r) }
        }
        let t = test(a, b)
        XCTAssertTrue(until(5) { asked.withLock { $0.count } == 1 })
        t.cancel()
        XCTAssertTrue(until(5) { withdrawn.withLock { $0 } == 1 }, "the question stayed up after the Mac that asked had gone")
        let question = asked.withLock { $0[0] }
        XCTAssertTrue(question.state.isFinal)
        question.accept()   // a click that came too late does nothing
        Thread.sleep(forTimeInterval: 0.3)
        XCTAssertNotEqual(question.state, .transferring)
        // Forgetting the Mac that asks takes its question away too.
        let second = test(a, b)
        XCTAssertTrue(until(5) { asked.withLock { $0.count } == 2 })
        b.trust.forget(a.key)
        XCTAssertTrue(until(5) { withdrawn.withLock { $0 } == 2 })
        XCTAssertTrue(until(5) { second.state.isFinal })
        XCTAssertNotEqual(second.state, .completed)
    }

    func test(_ from: TestMac, _ to: TestMac, seconds: Double = 1, streams: Int = 4, expect: PublicKey? = nil) -> SpeedTest {
        let t = SpeedTest(host: "127.0.0.1", port: to.port, peerName: to.identity.name, identity: from.identity, trust: from.trust, expect: expect ?? to.key,
                          seconds: seconds, streams: streams)
        t.start()
        return t
    }

    func testItMeasuresBothDirectionsAndWritesNothing() throws {
        let (a, b) = try pairedMacs()
        let seen = Locked<[Transfer]>([])
        b.listener.onSpeedTest = { t in seen.withLock { $0.append(t) }; t.accept() }
        let t = test(a, b)
        XCTAssertTrue(until(15) { t.state.isFinal })
        XCTAssertEqual(t.state, .completed)
        let r = t.result
        XCTAssertEqual(r.streams, 4)
        XCTAssertGreaterThan(r.upBytes, 50 << 20, "\(r)")
        XCTAssertGreaterThan(r.downBytes, 50 << 20, "\(r)")
        // Each direction ran for about the second that was asked for, as its receiver counted it.
        XCTAssertTrue((0.5...3).contains(r.upSeconds) && (0.5...3).contains(r.downSeconds), "\(r)")
        XCTAssertGreaterThan(r.upRate, 0)
        XCTAssertGreaterThan(r.downRate, 0)
        XCTAssertEqual(seen.withLock { $0.count }, 1, "asked once")
        XCTAssertTrue(until(5) { seen.withLock { $0[0].state } == .completed })
        // Both Macs show the same two figures, each from its own side.
        let theirs = try XCTUnwrap(seen.withLock { $0[0].speedResult })
        XCTAssertEqual(theirs.downBytes, r.upBytes)
        XCTAssertEqual(theirs.upBytes, r.downBytes)
        XCTAssertEqual(theirs.upSeconds, r.downSeconds, accuracy: 0.001)
        XCTAssertEqual(t.speedResult, r)
        XCTAssertEqual(t.linkInterface, "lo0")
        // And the Mac is free for another.
        let again = test(a, b, streams: 1)
        XCTAssertTrue(until(15) { again.state.isFinal })
        XCTAssertEqual(again.state, .completed)
    }

    func testOnlyAPairedMacMayAsk() throws {
        let (a, b) = try pairedMacs()
        let stranger = try TestMac("stranger")
        // From this side: nothing is said to a Mac that is not paired.
        let t = test(stranger, b)
        XCTAssertTrue(until(10) { t.state.isFinal })
        XCTAssertTrue(t.needsPairing, "\(t.state)")
        // From a key nobody paired, speaking the protocol by hand and claiming to be paired.
        let p = try RawPeer(port: b.port, keys: KeyPair())
        try p.hello(.speed, paired: true)
        try? p.json(.speed, SpeedAsk(seconds: 1, streams: 1))
        XCTAssertNil(try? p.read(), "a stranger's speed test was answered")
        // And a paired key that says it is not paired is not served either.
        let q = try RawPeer(port: b.port, keys: a.trust.keyPair)
        Tuning.strangerSeconds = 30   // (so that saying so is not taken for a Forget in this test: the pairing is seconds old)
        defer { Tuning.strangerSeconds = 10 }
        try q.hello(.speed, paired: false)
        try? q.json(.speed, SpeedAsk(seconds: 1, streams: 1))
        XCTAssertNil(try? q.read())
    }

    func testOneAtATimeAndNoMoreThanAMacGives() throws {
        let (a, b) = try pairedMacs()
        // Ask for an hour on a thousand connections: thirty seconds and thirty-two are granted.
        let p = try RawPeer(port: b.port, keys: a.trust.keyPair)
        try p.hello(.speed)
        try p.json(.speed, SpeedAsk(seconds: 3600, streams: 1000))
        let go = try p.read()
        XCTAssertEqual(go.type, FrameType.speedGo.rawValue)
        let granted = try JSONDecoder().decode(SpeedAsk.self, from: go.body)
        XCTAssertEqual(granted.seconds, 30)
        XCTAssertEqual(granted.streams, 32)
        // While that one is open, another is told the Mac is busy.
        let second = test(a, b)
        XCTAssertTrue(until(10) { second.state.isFinal })
        guard case .failed(let why) = second.state else { return XCTFail("\(second.state)") }
        XCTAssertTrue(why.contains("another speed test"), why)
        p.socket.shutdown()
        // And when it is gone, the next is taken.
        Thread.sleep(forTimeInterval: 0.5)
        let third = test(a, b)
        XCTAssertTrue(until(15) { third.state.isFinal })
        XCTAssertEqual(third.state, .completed)
    }

    /// A paired Mac that means harm, with the right keys: connections beyond what was granted,
    /// and records that are not a speed test's.
    func testConnectionsAndRecordsAreHeldToWhatASpeedTestIs() throws {
        let (a, b) = try pairedMacs()
        let p = try RawPeer(port: b.port, keys: a.trust.keyPair)
        try p.hello(.speed)
        try p.json(.speed, SpeedAsk(seconds: 2, streams: 2))
        XCTAssertEqual(try p.read().type, FrameType.speedGo.rawValue)
        let keys = DropKeys(master: p.master)
        func attach(_ conn: UInt64) throws -> (Socket, CipherState)? {
            let s = try Socket.connect(host: "127.0.0.1", port: b.port)
            s.setReadTimeout(2)
            try Opening.data.withUnsafeBytes { try s.writeAll($0.baseAddress!, 5) }
            var challenge = Data(count: 16)
            try challenge.withUnsafeMutableBytes { try s.readExactly($0.baseAddress!, 16) }
            let message = keys.sessionID + Crypto.be64(conn) + keys.attachTag(conn: conn, challenge: challenge)
            try message.withUnsafeBytes { try s.writeAll($0.baseAddress!, message.count) }
            // Refused connections are closed; one that was taken stays open and silent.
            return s.waitReadable(milliseconds: 400) ? nil : (s, keys.stream(conn))
        }
        XCTAssertNil(try attach(5), "two connections each way were granted: numbers 1 to 4")
        XCTAssertNil(try attach(0))
        var (s, cipher) = try XCTUnwrap(try attach(1))
        XCTAssertNil(try attach(1), "a number is taken once")
        // A record for a file (there are none), and one longer than a chunk: each closes its connection.
        var header = RecordHeader(file: 1, chunk: 0, length: 16).bytes
        var record = try cipher.seal(header) + cipher.seal(Data(count: 16), ad: header)
        try record.withUnsafeBytes { try s.writeAll($0.baseAddress!, record.count) }
        XCTAssertTrue(until(2) { s.waitReadable(milliseconds: 0) }, "a record that names a file was taken")
        (s, cipher) = try XCTUnwrap(try attach(2))
        header = RecordHeader(file: 0, chunk: 0, length: UInt32(SpeedWire.chunk + 1)).bytes
        record = try cipher.seal(header)
        try record.withUnsafeBytes { try s.writeAll($0.baseAddress!, record.count) }
        XCTAssertTrue(until(2) { s.waitReadable(milliseconds: 0) }, "a record longer than a chunk was taken")
        // A down connection says nothing until it is asked to.
        let (d, _) = try XCTUnwrap(try attach(3))
        XCTAssertFalse(d.waitReadable(milliseconds: 500))
        try p.json(.speedUpDone, Empty())
        let count = try p.read()
        XCTAssertEqual(count.type, FrameType.speedCount.rawValue)
        XCTAssertEqual(try JSONDecoder().decode(SpeedCount.self, from: count.body).bytes, 0, "nothing that was sent counted")
        p.socket.shutdown()
    }

    func testWithdrawingTrustEndsASpeedTest() throws {
        let (a, b) = try pairedMacs()
        let t = test(a, b, seconds: 20)
        XCTAssertTrue(until(10) { t.state == .transferring && t.progress.doneBytes > 0 })
        b.trust.forget(a.key)
        XCTAssertTrue(until(5) { t.state.isFinal }, "the test ran on after the Mac that was asked forgot the one asking")
        XCTAssertNotEqual(t.state, .completed)
    }
}
