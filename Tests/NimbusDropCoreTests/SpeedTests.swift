// Copyright (C) 2026 Niels Joubert
// SPDX-License-Identifier: GPL-3.0-or-later
import Foundation
import XCTest
@testable import NimbusDropCore

/// The speed test (the plan's Addendum B): what it measures, who may ask for one, and what
/// the Mac that is asked will and will not do for it.
final class SpeedTests: XCTestCase {
    typealias RawPeer = ReviewTests.RawPeer

    override func setUp() { Tuning.arrivalsPerAddress = 500 }
    override func tearDown() { Tuning.arrivalsPerAddress = 200 }

    func pairedMacs() throws -> (TestMac, TestMac) {
        let (a, b) = Trust.paired("tester", "asked")
        return (try TestMac("tester", trust: a), try TestMac("asked", trust: b))
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
        b.listener.onSpeedTest = { t in seen.withLock { $0.append(t) } }
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
        XCTAssertTrue(b.offers.withLock { $0.isEmpty }, "nobody was asked anything")
        XCTAssertEqual(seen.withLock { $0.count }, 1, "and the Mac that was asked knows it happened")
        XCTAssertTrue(until(3) { seen.withLock { $0[0].state } == .completed })
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
