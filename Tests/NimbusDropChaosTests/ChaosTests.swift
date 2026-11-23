// Copyright (C) 2026 Niels Joubert
// SPDX-License-Identifier: GPL-3.0-or-later
import Foundation
import NimbusDropChaos
import XCTest
@testable import NimbusDropCore

/// Whole drops sent through `ChaosProxy`: a real sender, a real receiver, and a network between
/// them that turns bad on cue. Every test ends on one of two acceptable outcomes and checks
/// which: the drop arrived and is byte-for-byte what was sent, or it stopped cleanly, nothing
/// half-made is in the destination, and sending again finishes it. Wrong bytes in the
/// destination is the one outcome that must never happen.
final class ChaosTests: XCTestCase {
    var root: URL!
    var listener: DropListener!
    var proxy: ChaosProxy!
    var received = Box<[ReceiveSession]>([])
    let sender = Identity(name: "sender", id: "sender-id")
    /// Small chunks, so a few megabytes are hundreds of chunks across the connections.
    let chunk = 64 << 10

    override func setUpWithError() throws {
        root = FileManager.default.temporaryDirectory.appendingPathComponent("nimbusdrop-chaos-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: root.appendingPathComponent("dst"), withIntermediateDirectories: true)
        // The engine's patience, shortened: a minute of stall becomes a second and a half.
        Tuning.stallSeconds = 1.5
        Tuning.connectRetrySeconds = 3
        Tuning.connectTimeout = 2
        Tuning.settleSeconds = 0.5
        Tuning.reconnectSeconds = 3
        let dst = self.dst
        let received = self.received
        listener = try DropListener(identity: Identity(name: "receiver", id: "receiver-id"), preferredPort: 0)
        listener.onOffer = { session in
            received.value += [session]
            session.accept(destination: dst)
        }
        listener.start()
        proxy = try ChaosProxy(targetPort: listener.port, seed: 7)
        proxy.start()
    }

    override func tearDownWithError() throws {
        proxy.stop()
        listener.stop()
        Tuning.stallSeconds = 60
        Tuning.connectRetrySeconds = 30
        Tuning.connectTimeout = 10
        Tuning.settleSeconds = 1
        Tuning.reconnectSeconds = 60
        Tuning.idleRounds = 5
        try? FileManager.default.removeItem(at: root)
    }

    // MARK: Helpers

    var dst: URL { root.appendingPathComponent("dst") }

    func bytes(_ count: Int, seed: UInt64) -> Data {
        var state = seed &* 6364136223846793005 &+ 1442695040888963407
        var data = Data(count: count)
        data.withUnsafeMutableBytes { (raw: UnsafeMutableRawBufferPointer) in
            for i in 0..<count {
                state = state &* 6364136223846793005 &+ 1442695040888963407
                raw[i] = UInt8(truncatingIfNeeded: state >> 33)
            }
        }
        return data
    }

    /// A folder of `megabytes`: one file with most of it, a spread of photo-sized ones, small ones.
    @discardableResult
    func makeTree(megabytes: Int = 8) throws -> URL {
        let dir = root.appendingPathComponent("src/Photos")
        try FileManager.default.createDirectory(at: dir.appendingPathComponent("small"), withIntermediateDirectories: true)
        let total = megabytes << 20
        try bytes(total / 2 + 777, seed: 1).write(to: dir.appendingPathComponent("movie.bin"))
        for i in 0..<8 { try bytes(total / 16, seed: UInt64(10 + i)).write(to: dir.appendingPathComponent("IMG_\(i).raw")) }
        for i in 0..<30 { try bytes(300 + i * 91, seed: UInt64(100 + i)).write(to: dir.appendingPathComponent("small/note\(i).txt")) }
        try Data().write(to: dir.appendingPathComponent("small/empty"))
        return dir
    }

    /// Sends through the proxy.
    func send(_ url: URL, streams: Int = 4) -> SendSession {
        let s = SendSession(urls: [url], host: "127.0.0.1", port: proxy.port, peerName: "receiver", identity: sender,
                            streams: streams, chunkSize: chunk)
        s.start()
        return s
    }

    @discardableResult
    func wait(_ t: Transfer, timeout: TimeInterval = 60, file: StaticString = #filePath, line: UInt = #line) -> TimeInterval {
        let start = Date()
        while !t.state.isFinal, Date().timeIntervalSince(start) < timeout { Thread.sleep(forTimeInterval: 0.01) }
        XCTAssertTrue(t.state.isFinal, "still \(t.state) after \(Int(timeout)) s", file: file, line: line)
        return Date().timeIntervalSince(start)
    }

    func snapshot(_ dir: URL) throws -> [String: String] {
        var out: [String: String] = [:]
        let e = FileManager.default.enumerator(atPath: dir.path)!
        while let rel = e.nextObject() as? String {
            var isDir: ObjCBool = false
            FileManager.default.fileExists(atPath: dir.path + "/" + rel, isDirectory: &isDir)
            out[rel] = isDir.boolValue ? "dir" : "\(try Data(contentsOf: dir.appendingPathComponent(rel)).hashValue)"
        }
        return out
    }

    /// The drop is in the destination, identical, and nothing else is.
    func assertArrived(_ src: URL, file: StaticString = #filePath, line: UInt = #line) throws {
        XCTAssertEqual(try FileManager.default.contentsOfDirectory(atPath: dst.path), ["Photos"], "what is in the destination", file: file, line: line)
        XCTAssertEqual(try snapshot(dst.appendingPathComponent("Photos")), try snapshot(src), "the copy differs from the original", file: file, line: line)
    }

    /// Nothing finished is in the destination: only the partial folder, if anything.
    func assertNothingFinished(file: StaticString = #filePath, line: UInt = #line) throws {
        let left = try FileManager.default.contentsOfDirectory(atPath: dst.path)
        XCTAssertTrue(left.allSatisfy { $0.hasSuffix(".nimbusdrop-partial") }, "found \(left)", file: file, line: line)
    }

    /// The receiver's side of the last drop, once it has ended too.
    func receiverSide(file: StaticString = #filePath, line: UInt = #line) throws -> ReceiveSession {
        let r = try XCTUnwrap(received.value.last, file: file, line: line)
        wait(r, file: file, line: line)
        return r
    }

    /// A clean network again, and the same drop sent a second time: it must finish, and reuse
    /// what the first attempt delivered.
    func assertResendFinishes(_ src: URL, expectReuse: Bool = true, file: StaticString = #filePath, line: UInt = #line) throws {
        proxy.set { $0 = ChaosProxy.Conditions() }
        Thread.sleep(forTimeInterval: 0.3)
        let again = send(src)
        wait(again, file: file, line: line)
        XCTAssertEqual(again.state, .completed, file: file, line: line)
        if expectReuse { XCTAssertGreaterThan(again.progress.resumedBytes, 0, "the second attempt reused nothing", file: file, line: line) }
        try assertArrived(src, file: file, line: line)
    }

    // MARK: The harness itself

    func testACleanProxyChangesNothing() throws {
        let src = try makeTree()
        let s = send(src)
        wait(s)
        XCTAssertEqual(s.state, .completed)
        XCTAssertEqual(s.stats, TransferStats(rounds: 1, connectionFailures: 0, damagedChunks: 0))
        XCTAssertEqual(proxy.stats.connections, 5, "one control connection and four for data")
        XCTAssertGreaterThan(proxy.stats.bytesToTarget, 8 << 20)
        try assertArrived(src)
    }

    // MARK: Bandwidth

    func testANarrowLinkIsSlowNotBroken() throws {
        // With a generous limit on standing still, slow must not be mistaken for stalled.
        Tuning.stallSeconds = 15
        let src = try makeTree(megabytes: 4)
        proxy.set { $0.bytesPerSecond = 2 << 20 }
        let s = send(src)
        let took = wait(s)
        XCTAssertEqual(s.state, .completed)
        XCTAssertGreaterThan(took, 1.5, "4 MB through 2 MB/s cannot take under about two seconds")
        XCTAssertEqual(s.stats.connectionFailures, 0, "a slow connection is not a stalled one")
        try assertArrived(src)
    }

    func testBandwidthFallingOffACliffMidDrop() throws {
        Tuning.stallSeconds = 15
        let src = try makeTree(megabytes: 8)
        // Unlimited, then at 3 MB the link collapses to 1 % of a gigabit-ish pace, then recovers.
        proxy.whenForwarded(bytes: 3 << 20) { $0.set { $0.bytesPerSecond = 600 << 10 } }
        proxy.whenForwarded(bytes: 5 << 20) { $0.set { $0.bytesPerSecond = nil } }
        let s = send(src)
        let took = wait(s)
        XCTAssertEqual(s.state, .completed)
        XCTAssertGreaterThan(took, 2.5, "2 MB at 600 KB/s is more than three seconds")
        XCTAssertEqual(s.stats.connectionFailures, 0)
        XCTAssertEqual(try receiverSide().stats.damagedChunks, 0)
        try assertArrived(src)
    }

    func testALinkTooSlowForOneConnectionIsWornDownNotGivenUpOn() throws {
        // 100 KB/s across four connections: each moves a 64 KB chunk in well over the 1.5 s
        // the tests allow a connection to stand still, so connections are closed as stalled
        // again and again. The drop still has to arrive, round by round.
        Tuning.idleRounds = 50
        let src = try makeTree(megabytes: 1)
        proxy.whenForwarded(bytes: 300 << 10) { $0.set { $0.bytesPerSecond = 100 << 10 } }
        proxy.whenForwarded(bytes: 700 << 10) { $0.set { $0.bytesPerSecond = nil } }
        let s = send(src)
        wait(s, timeout: 120)
        XCTAssertEqual(s.state, .completed)
        try assertArrived(src)
    }

    // MARK: Loss

    func testLossRisingSuddenlyMidDrop() throws {
        let src = try makeTree(megabytes: 6)
        // 2 % of segments, each costing 20 ms, from the 2 MB mark: about a fifth of the pace.
        proxy.whenForwarded(bytes: 2 << 20) { $0.set { $0.loss = 0.02; $0.lossPenalty = 0.02 } }
        let s = send(src)
        wait(s)
        XCTAssertEqual(s.state, .completed)
        XCTAssertGreaterThan(proxy.stats.segmentsLost, 20)
        try assertArrived(src)
    }

    func testHeavyLossFromTheStart() throws {
        let src = try makeTree(megabytes: 2)
        proxy.set { $0.loss = 0.1; $0.lossPenalty = 0.01 }
        let s = send(src)
        wait(s)
        XCTAssertEqual(s.state, .completed)
        try assertArrived(src)
    }

    // MARK: Connections dropping

    func testOneDataConnectionDropsAndTheDropCarriesOn() throws {
        let src = try makeTree()
        proxy.set { $0.bytesPerSecond = 6 << 20 }   // slow enough that the kill lands mid-drop
        proxy.whenForwarded(bytes: 2 << 20) { $0.killOneData() }
        let s = send(src)
        wait(s)
        XCTAssertEqual(s.state, .completed, "one lost connection must not cost the drop")
        XCTAssertEqual(proxy.stats.connectionsKilled, 1)
        XCTAssertEqual(received.value.count, 1, "the person was asked once, not again")
        XCTAssertGreaterThanOrEqual(try receiverSide().stats.connectionFailures, 1)
        try assertArrived(src)
    }

    func testEveryDataConnectionDropsAndNewOnesFinishTheJob() throws {
        let src = try makeTree()
        proxy.set { $0.bytesPerSecond = 6 << 20 }
        proxy.whenForwarded(bytes: 2 << 20) { $0.kill(.data) }
        proxy.whenForwarded(bytes: 5 << 20) { $0.kill(.data) }
        let s = send(src)
        wait(s)
        XCTAssertEqual(s.state, .completed)
        XCTAssertGreaterThanOrEqual(s.stats.rounds, 2, "the missing chunks went out in a later round")
        XCTAssertEqual(received.value.count, 1)
        try assertArrived(src)
    }

    func testConnectionsDroppingOverAndOver() throws {
        let src = try makeTree()
        proxy.set { $0.bytesPerSecond = 8 << 20 }
        for mark in stride(from: 1, to: 9, by: 1) { proxy.whenForwarded(bytes: Int64(mark) << 20) { $0.killOneData() } }
        let s = send(src)
        wait(s)
        XCTAssertEqual(s.state, .completed)
        XCTAssertGreaterThanOrEqual(proxy.stats.connectionsKilled, 4)
        try assertArrived(src)
    }

    func testTheControlConnectionDropsAndIsWonBack() throws {
        // Large enough that the cut lands while most of it has not left the sender.
        let src = try makeTree(megabytes: 48)
        proxy.set { $0.bytesPerSecond = 6 << 20 }
        proxy.whenForwarded(bytes: 2 << 20) { p in
            p.kill(.control)
            p.set { $0.bytesPerSecond = nil }
        }
        let s = send(src)
        wait(s)
        XCTAssertEqual(s.state, .completed, "losing the conversation's connection is not losing the drop")
        XCTAssertEqual(s.stats.reconnects, 1)
        XCTAssertEqual(received.value.count, 1, "the person was asked once, not again")
        XCTAssertEqual(try receiverSide().stats.reconnects, 1)
        try assertArrived(src)
    }

    func testEverythingDropsForAMomentAndTheDropCarriesOn() throws {
        // What a Mac changing Wi-Fi networks and coming back looks like: every connection dies,
        // for a second and a half nothing can be opened, then it can.
        let src = try makeTree(megabytes: 48)
        proxy.set { $0.bytesPerSecond = 6 << 20 }
        proxy.whenForwarded(bytes: 2 << 20) { p in
            p.set { $0.refuseNew = true; $0.bytesPerSecond = nil }
            p.kill(.all)
            p.after(seconds: 1.5) { $0.set { $0.refuseNew = false } }
        }
        let s = send(src)
        wait(s)
        XCTAssertEqual(s.state, .completed)
        XCTAssertGreaterThanOrEqual(s.stats.reconnects, 1)
        XCTAssertGreaterThan(proxy.stats.connectionsRefused, 0, "it was turned away while the link was down")
        XCTAssertEqual(received.value.count, 1)
        try assertArrived(src)
    }

    func testTheReceiverGivesTheConversationUpButTheSenderOnlyFindsOutAtTheEnd() throws {
        // The owner's test with 0.2.0 on 2026-11-22: a cable out for a while. The receiver timed
        // its control connection out; the sender's survived as far as the sender could tell,
        // its data connections were replaced, and 5 GB went across while the receiver's window
        // still said "lost the connection, waiting". The sender learned its control connection
        // was dead only on writing "done", and then reconnected in half a second.
        //
        // Here: the control connection dies on the receiver's side only. The drop must carry
        // on, must say it is moving while it moves, and must end with one reconnect.
        let lines = Box<[String]>([])
        DropLog.sink = { line in lines.value += [line] }
        defer { DropLog.sink = nil }
        Tuning.reconnectSeconds = 2   // far less than the rest of the drop takes
        let src = try makeTree(megabytes: 48)
        proxy.set { $0.bytesPerSecond = 6 << 20 }
        proxy.whenForwarded(bytes: 2 << 20) { $0.killFarSide(.control) }
        let s = send(src)
        wait(s)
        XCTAssertEqual(s.state, .completed)
        XCTAssertEqual(s.stats.reconnects, 1, "the sender reconnected once, when it had something to say")
        XCTAssertEqual(received.value.count, 1, "the person was asked once")
        let r = try receiverSide()
        XCTAssertEqual(r.state, .completed, "the receiver did not give the drop up while data was still arriving")
        try assertArrived(src)

        // The receiver's story, in order: lost, moving again (before the sender is back), back.
        let story = lines.value.filter { $0.contains(" recv] ") }
        func index(_ text: String, after: Int = -1) -> Int? { story.indices.first { $0 > after && story[$0].contains(text) } }
        let lost = try XCTUnwrap(index("lost the control connection"), story.joined(separator: "\n"))
        let moving = try XCTUnwrap(index("] transferring", after: lost), "it never said it was receiving again:\n" + story.joined(separator: "\n"))
        let back = try XCTUnwrap(index("the sender is back", after: lost), story.joined(separator: "\n"))
        XCTAssertLessThan(moving, back, "it showed itself as moving while the conversation was still missing")
    }

    func testTheReceiverComesBackAtAnotherAddress() throws {
        // The old way in goes away for good; the receiver is reachable somewhere else, and the
        // sender is told where when it asks.
        let src = try makeTree(megabytes: 48)
        let elsewhere = try ChaosProxy(targetPort: listener.port, seed: 9)
        elsewhere.start()
        defer { elsewhere.stop() }
        proxy.set { $0.bytesPerSecond = 6 << 20 }
        proxy.whenForwarded(bytes: 2 << 20) { p in
            p.set { $0.refuseNew = true }
            p.kill(.all)
        }
        let s = SendSession(urls: [src], host: "127.0.0.1", port: proxy.port, peerName: "receiver", identity: sender,
                            streams: 4, chunkSize: chunk)
        let asked = Box(0)
        let newPort = elsewhere.port
        s.relocate = { asked.value += 1; return ("127.0.0.1", newPort) }
        s.start()
        wait(s)
        XCTAssertEqual(s.state, .completed)
        XCTAssertGreaterThanOrEqual(asked.value, 1, "the sender asked where the receiver is now")
        XCTAssertGreaterThan(elsewhere.stats.bytesToTarget, 40 << 20, "and the rest went the new way")
        XCTAssertEqual(received.value.count, 1)
        try assertArrived(src)
    }

    func testALinkThatStaysDownEndsTheDropCleanlyAndItResumes() throws {
        let src = try makeTree(megabytes: 48)
        proxy.set { $0.bytesPerSecond = 6 << 20 }
        proxy.whenForwarded(bytes: 2 << 20) { p in
            p.set { $0.refuseNew = true }
            p.kill(.all)
        }
        let s = send(src)
        let took = wait(s)
        guard case .failed(let why) = s.state else { return XCTFail("expected the drop to stop, got \(s.state)") }
        XCTAssertTrue(why.contains("could not get it back"), why)
        XCTAssertGreaterThan(took, 3, "it kept trying for the whole window")
        XCTAssertLessThan(took, 15)
        let r = try receiverSide()
        guard case .failed = r.state else { return XCTFail("the receiver carried on: \(r.state)") }
        try assertNothingFinished()
        try assertResendFinishes(src)
    }

    func testNewConnectionsRefusedBrieflyAreRetried() throws {
        let src = try makeTree()
        proxy.set { $0.bytesPerSecond = 6 << 20 }
        // Every data connection dies and for a second none can be opened; the control
        // connection lives, so the sender keeps trying rather than giving up.
        proxy.whenForwarded(bytes: 2 << 20) { p in
            p.set { $0.refuseNew = true }
            p.kill(.data)
            p.after(seconds: 1) { $0.set { $0.refuseNew = false } }
        }
        let s = send(src)
        wait(s)
        XCTAssertEqual(s.state, .completed)
        XCTAssertGreaterThan(proxy.stats.connectionsRefused, 0)
        try assertArrived(src)
    }

    // MARK: Stalls

    func testAShortStallIsWaitedOut() throws {
        let src = try makeTree()
        proxy.set { $0.bytesPerSecond = 6 << 20 }
        proxy.whenForwarded(bytes: 2 << 20) { p in
            p.set { $0.blackhole = true }
            p.after(seconds: 0.7) { $0.set { $0.blackhole = false } }   // under the 1.5 s allowed
        }
        let s = send(src)
        wait(s)
        XCTAssertEqual(s.state, .completed)
        try assertArrived(src)
    }

    func testALinkThatSwallowsEverythingIsGivenUpOnNotWaitedForForever() throws {
        let src = try makeTree()
        proxy.set { $0.bytesPerSecond = 6 << 20 }
        proxy.whenForwarded(bytes: 2 << 20) { $0.set { $0.blackhole = true } }
        let s = send(src)
        // Nothing is ever closed, and nothing gets across to say so: only each side's own watch
        // can end this. Silence is first taken for a lost connection; reconnecting gets no
        // answer either; then the drop is given up.
        let took = wait(s, timeout: 90)
        guard case .failed(let why) = s.state else { return XCTFail("expected the drop to be given up, got \(s.state)") }
        XCTAssertTrue(why.contains("could not get it back"), why)
        XCTAssertLessThan(took, 60)
        let r = try receiverSide()
        guard case .failed = r.state else { return XCTFail("the receiver is still waiting: \(r.state)") }
        try assertNothingFinished()
        proxy.kill(.all)
        try assertResendFinishes(src)
    }

    func testTheNetworkGoesSilentThenComesBack() throws {
        // A Mac that walks out of Wi-Fi range and back, or changes networks and returns: for a
        // while nothing gets through in either direction and nothing is closed. Long enough
        // here that both sides notice the silence and start trying to get the drop back; then
        // the link returns, and they must find each other again without anybody being asked.
        Tuning.reconnectSeconds = 20
        let src = try makeTree(megabytes: 48)
        proxy.set { $0.bytesPerSecond = 6 << 20 }
        proxy.whenForwarded(bytes: 2 << 20) { p in
            p.set { $0.blackhole = true; $0.bytesPerSecond = nil }
            p.after(seconds: 7) { $0.set { $0.blackhole = false } }
        }
        let s = send(src)
        wait(s, timeout: 90)
        XCTAssertEqual(s.state, .completed)
        XCTAssertGreaterThanOrEqual(s.stats.reconnects, 1)
        XCTAssertEqual(received.value.count, 1, "the person was asked once, not again")
        try assertArrived(src)
    }

    func testTheNetworkComesBackAndEveryOldConnectionIsReset() throws {
        // What the owner saw on 2026-11-22 sending to a Mac that changed Wi-Fi networks: the
        // drop sat waiting while the other Mac was away, and the moment it came back the old
        // connections were reset ("connection reset by peer") and 0.1.0 ended the drop there.
        // Silence, then every connection that was open is cut as the link returns.
        Tuning.reconnectSeconds = 20
        let src = try makeTree(megabytes: 48)
        proxy.set { $0.bytesPerSecond = 6 << 20 }
        proxy.whenForwarded(bytes: 2 << 20) { p in
            p.set { $0.blackhole = true; $0.bytesPerSecond = nil }
            p.after(seconds: 2) { q in
                q.kill(.all)
                q.set { $0.blackhole = false }
            }
        }
        let s = send(src)
        wait(s, timeout: 90)
        XCTAssertEqual(s.state, .completed)
        XCTAssertGreaterThanOrEqual(s.stats.reconnects, 1)
        XCTAssertEqual(received.value.count, 1)
        try assertArrived(src)
    }

    func testTheAnswerThatItAllArrivedIsLostAndAskedForAgain() throws {
        // Everything is across and the receiver is finishing when the conversation's connection
        // dies: its "complete" never arrives. The sender reconnects and is told again, instead
        // of reporting a failure for a drop that landed.
        let src = try makeTree(megabytes: 2)
        proxy.whenForwarded(bytes: Int64(2 << 20) + 20_000) { $0.kill(.control) }
        let s = send(src)
        wait(s)
        XCTAssertEqual(s.state, .completed)
        XCTAssertEqual(s.stats.reconnects, 1, "the sender came back to ask")
        XCTAssertEqual(try receiverSide().state, .completed)
        XCTAssertEqual(received.value.count, 1)
        try assertArrived(src)
    }

    func testOneConnectionStallsAndIsReplaced() throws {
        // The proxy cannot stall one connection alone, but the engine can be shown the same
        // thing: a long blackhole that ends. Connections that stood still past the limit are
        // closed by the sender and their chunks go out again once bytes move.
        let src = try makeTree()
        proxy.set { $0.bytesPerSecond = 6 << 20 }
        proxy.whenForwarded(bytes: 2 << 20) { p in
            p.set { $0.blackhole = true }
            p.after(seconds: 2.5) { $0.set { $0.blackhole = false } }   // past the 1.5 s allowed
        }
        let s = send(src)
        wait(s)
        XCTAssertEqual(s.state, .completed)
        try assertArrived(src)
    }

    // MARK: Corruption

    func testFlippedBitsInTheDataAreCaughtAndTheChunksSentAgain() throws {
        let src = try makeTree()
        proxy.set { $0.corruptEvery = 1 << 20; $0.corruptScope = .data }
        let s = send(src)
        wait(s)
        XCTAssertEqual(s.state, .completed)
        XCTAssertGreaterThanOrEqual(proxy.stats.bitsFlipped, 4, "the proxy did damage")
        let r = try receiverSide()
        XCTAssertGreaterThanOrEqual(r.stats.damagedChunks, 1, "and the receiver saw it")
        XCTAssertGreaterThanOrEqual(s.stats.rounds, 2)
        try assertArrived(src)   // the proof: despite the damage, every byte is right
    }

    func testALinkThatDamagesNearlyEverythingStopsWithoutWritingWrongBytes() throws {
        Tuning.idleRounds = 3
        let src = try makeTree(megabytes: 2)
        proxy.set { $0.corruptEvery = 2000; $0.corruptScope = .data }   // several flips in every chunk
        let s = send(src)
        wait(s)
        guard case .failed(let why) = s.state else { return XCTFail("expected the drop to be given up, got \(s.state)") }
        XCTAssertTrue(why.contains("incomplete"), why)
        try assertNothingFinished()
        try assertResendFinishes(src, expectReuse: false)
    }

    func testAChunkRedirectedByOneFlippedBitIsNotWritten() throws {
        // The dangerous flip is not in the data but in the 16 bytes before it. On one connection
        // the chunks go out in manifest order: the folder is entry 0, IMG_0…IMG_7 are entries
        // 1…8 (one 64 KB chunk each, with a 1 MB tree), then movie.bin's nine chunks.
        //
        //  - Turn IMG_2's file index (3) into 1: IMG_2's bytes, intact, aimed at IMG_0, which
        //    is already written. A checksum over the data alone would pass them.
        //  - Turn movie.bin chunk 5's index into 4: the same, inside one file.
        let attach = 61, framed = 16 + chunk   // the attach frame, then header + chunk each
        for (name, offset, bit) in [("file index", attach + 2 * framed + 3, 1),
                                    ("chunk index", attach + 8 * framed + 5 * framed + 7, 0)] {
            try? FileManager.default.removeItem(at: dst)
            try FileManager.default.createDirectory(at: dst, withIntermediateDirectories: true)
            try? FileManager.default.removeItem(at: root.appendingPathComponent("src"))
            let src = try makeTree(megabytes: 1)
            XCTAssertEqual(try Data(contentsOf: src.appendingPathComponent("IMG_0.raw")).count, chunk, "the layout this test counts on")
            proxy.plantFlip(connection: proxy.stats.connections + 1, offset: Int64(offset), bit: bit)
            let s = send(src, streams: 1)
            wait(s)
            XCTAssertEqual(s.state, .completed, name)
            XCTAssertEqual(try receiverSide().stats.damagedChunks, 1, "\(name): the flip was seen for what it was")
            try assertArrived(src)
        }
    }

    func testABitFlippedInAChunkHeaderDoesNotPutBytesInTheWrongPlace() throws {
        // A data connection begins with its attach frame (about 70 bytes), then 16-byte chunk
        // headers. One flip at each offset through the first header and into the chunk: the
        // file index, the chunk index, the length, the checksum itself.
        for offset in stride(from: 60, to: 110, by: 3) {
            try? FileManager.default.removeItem(at: dst)
            try FileManager.default.createDirectory(at: dst, withIntermediateDirectories: true)
            try? FileManager.default.removeItem(at: root.appendingPathComponent("src"))
            let src = try makeTree(megabytes: 1)
            let first = proxy.stats.connections
            proxy.plantFlip(connection: first + 1, offset: Int64(offset))
            let s = send(src)
            wait(s)
            XCTAssertEqual(s.state, .completed, "offset \(offset)")
            try assertArrived(src)
        }
    }

    func testFlippedBitsInTheConversationNeverYieldAWrongDrop() throws {
        // The control connection carries the offer, the manifest (names, sizes) and the plan.
        // One flipped bit at a time, at every stride through it: the drop may stop, it may not
        // arrive altered.
        var completed = 0, stopped = 0
        for offset in stride(from: 3, to: 5200, by: 131) {
            try? FileManager.default.removeItem(at: dst)
            try FileManager.default.createDirectory(at: dst, withIntermediateDirectories: true)
            try? FileManager.default.removeItem(at: root.appendingPathComponent("src"))
            let src = try makeTree(megabytes: 1)
            proxy.plantFlip(connection: proxy.stats.connections, offset: Int64(offset))
            let s = send(src)
            wait(s)
            if s.state == .completed {
                completed += 1
                try assertArrived(src)
            } else {
                stopped += 1
                if let r = received.value.last { wait(r) }
                try assertNothingFinished()
            }
            proxy.kill(.all)
        }
        XCTAssertGreaterThan(stopped, 10, "flips inside the conversation were caught (\(completed) runs had the flip land past its end)")
    }

    func testRandomDamageEverywhereOverManySeeds() throws {
        // Everything at once, differently each time: bits flipped on every connection, the
        // conversation included. Whatever happens, no wrong byte reaches the destination.
        var outcomes: [String: Int] = [:]
        for seed in 1...12 {
            proxy.stop()
            proxy = try ChaosProxy(targetPort: listener.port, seed: UInt64(seed))
            proxy.start()
            try? FileManager.default.removeItem(at: dst)
            try FileManager.default.createDirectory(at: dst, withIntermediateDirectories: true)
            let src = try makeTree(megabytes: 2)
            proxy.set { $0.corruptEvery = 150_000 + seed * 40_000; $0.corruptScope = .all }
            let s = send(src)
            wait(s)
            if s.state == .completed {
                outcomes["arrived", default: 0] += 1
                try assertArrived(src)
            } else {
                outcomes["stopped", default: 0] += 1
                if let r = received.value.last { wait(r) }
                try assertNothingFinished()
            }
        }
        XCTAssertEqual(outcomes.values.reduce(0, +), 12, "\(outcomes)")
    }

    // MARK: Everything at once

    func testAThoroughlyBadNetwork() throws {
        Tuning.idleRounds = 20
        let src = try makeTree(megabytes: 8)
        proxy.set { $0.bytesPerSecond = 5 << 20; $0.loss = 0.01; $0.lossPenalty = 0.01; $0.corruptEvery = 2 << 20 }
        proxy.whenForwarded(bytes: 2 << 20) { $0.killOneData() }
        proxy.whenForwarded(bytes: 4 << 20) { $0.set { $0.bytesPerSecond = 1 << 20 } }
        proxy.whenForwarded(bytes: 5 << 20) { p in p.set { $0.bytesPerSecond = 8 << 20 }; p.kill(.data) }
        let s = send(src)
        wait(s, timeout: 120)
        XCTAssertEqual(s.state, .completed)
        XCTAssertEqual(received.value.count, 1)
        try assertArrived(src)
    }
}

final class Box<T>: @unchecked Sendable {
    private let lock = NSLock()
    private var _value: T
    init(_ value: T) { _value = value }
    var value: T {
        get { lock.withLock { _value } }
        set { lock.withLock { _value = newValue } }
    }
}
