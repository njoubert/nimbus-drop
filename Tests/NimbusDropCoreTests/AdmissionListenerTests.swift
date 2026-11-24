// Copyright (C) 2026 Niels Joubert
// SPDX-License-Identifier: GPL-3.0-or-later
import Foundation
import XCTest
@testable import NimbusBase
@testable import NimbusCrypto
@testable import NimbusDropCore
@testable import NimbusNet
@testable import NimbusSecurityCore
@testable import NimbusTransferCore

/// The listener and `Admission`. Which connection has a place is decided in `Admission`
/// (NimbusCrypto: `AdmissionTests` attacks it by itself, and TLC holds it equal to
/// formal/tla/Admission.tla). What is left to the listener is to tell it each thing that
/// happens to a connection and to close what it says to close. The tests of the review
/// (`ReviewTests`, which this extends for its Macs and its hand-made drops) already notice
/// most of that going missing; these are the reports no earlier test would miss, and what
/// the model of admission found. `scripts/mutate.py` takes each away again.
extension ReviewTests {
    /// A data connection that has proved its drop is the drop's own from then on. Were the
    /// listener not to say so, it would go on holding a place among the connections that have
    /// proved nothing, and the drop's next connections would close its first ones.
    func testAnAttachedDataConnectionIsNotClosedToMakeRoomForTheNext() throws {
        Tuning.unattachedPerAddress = 2
        let (sender, receiver) = try pairedMacs()
        var drop = try handDrop(from: sender, to: receiver, bytes: chunk * 3)
        var held: [Socket] = []
        for _ in 0..<6 {
            held.append(try drop.attach().0)
            Thread.sleep(forTimeInterval: 0.05)
        }
        Thread.sleep(forTimeInterval: 0.3)
        XCTAssertEqual(open(held), 6, "six of a drop's data connections, one after another, where two that have proved nothing may wait")
        drop.peer.socket.shutdown()
    }

    /// A paired key is counted from its handshake until it has said what it came for, and no
    /// longer: a Mac whose offer is waiting for an answer can still open a connection.
    func testAPairedKeyThatHasSaidWhatItCameForIsNoLongerCounted() throws {
        Tuning.pairedWaiting = 1
        let (a, b) = Trust.paired("sender", "receiver")
        let sender = try TestMac("sender", trust: a), receiver = try TestMac("receiver", trust: b)
        // Nobody answers the offer: its connection stays, having said what it came for.
        let waiting = send([try file("a.bin", bytes: chunk)], from: sender, to: receiver)
        XCTAssertTrue(until(5) { receiver.offers.withLock { $0.count } == 1 })
        let second = try Channel.dial(host: "127.0.0.1", port: receiver.port, trust: sender.trust, name: "sender", purpose: .drop)
        XCTAssertTrue(second.hello.paired, "a second connection from a Mac whose offer is waiting was turned away")
        second.channel.socket.shutdown()
        waiting.cancel()
    }

    /// Found by the model of admission (formal/tla/AdmissionSystem.tla, UnattachedWithinItsLimit),
    /// 2026-11-24. Data connections that have not yet proved their drop have so many places for
    /// each drop in progress. When a drop ended, the connections waiting on the places it had
    /// given were left where they were: more of them than the listener says it holds, and with
    /// no drop left, connections with nothing they could ever attach to, each for as long as it
    /// is given to attach. Now the ones that have waited longest are closed with the drop.
    func testDataConnectionsWaitingWhenADropEndsAreClosed() throws {
        Tuning.unattachedPerDrop = 3
        Tuning.unattachedPerAddress = 100
        Tuning.attachSeconds = 30
        let (sender, receiver) = try pairedMacs()
        let first = try handDrop(from: sender, to: receiver, bytes: chunk * 3)
        let second = try handDrop(from: sender, to: receiver, bytes: chunk * 4)
        var held: [Socket] = []
        for _ in 0..<6 {
            let k = try knock(receiver.port)
            XCTAssertTrue(k.challenged)
            held.append(k.socket)
        }
        Thread.sleep(forTimeInterval: 0.3)
        XCTAssertEqual(open(held), 6, "two drops in progress: six places")
        let drops = receiver.offers.withLock { $0 }
        XCTAssertEqual(drops.count, 2)
        drops[0].cancel()
        XCTAssertTrue(until(3) { self.open(held) == 3 }, "one drop ended, and \(open(held)) connections that have proved nothing are still held, where three may be")
        XCTAssertEqual(open(Array(held.suffix(3))), 3, "the three that have waited longest gave way")
        drops[1].cancel()
        XCTAssertTrue(until(3) { self.open(held) == 0 }, "no drop is in progress, and \(open(held)) data connections are still held")
        first.peer.socket.shutdown()
        second.peer.socket.shutdown()
    }

    /// A drop of nothing, finished by hand as its sender; and the sender asking again whether
    /// it arrived, with the drop's own proof: what comes back.
    func finishedDrop(from sender: TestMac, to receiver: TestMac) throws -> () -> [UInt8] {
        let manifest = Manifest(chunkSize: chunk, entries: [.init(path: "note.txt", kind: .file, size: 0)])
        let p = try RawPeer(port: receiver.port, keys: sender.trust.keyPair)
        try p.hello(.drop)
        try p.json(.offer, Offer(items: ["note.txt"], fileCount: 1, totalBytes: 0))
        guard try p.read().type == FrameType.accept.rawValue else { throw DropError("not accepted") }
        try p.json(.manifest, manifest)
        guard try p.read().type == FrameType.plan.rawValue else { throw DropError("no plan") }
        try p.json(.done, Done(streams: 0, resent: 0))
        guard try p.read().type == FrameType.complete.rawValue else { throw DropError("not complete") }
        let keys = DropKeys(master: p.master), port = receiver.port, pair = sender.trust.keyPair
        return {
            guard let q = try? RawPeer(port: port, keys: pair), (try? q.hello(.resume)) != nil else { return [] }
            defer { q.socket.shutdown() }
            guard (try? q.json(.resume, Resume(session: keys.sessionID, proof: DropKeys.resumeProof(keys.resumeKey, "resume", h: q.h)))) != nil else { return [] }
            var got: [UInt8] = []
            while let m = try? q.read() { got.append(m.type) }
            return got
        }
    }

    /// Reported by an independent review (2026-11-24), and shown by these two tests before it
    /// was put right. A finished drop's answer is kept "for five minutes", with the drop's
    /// resume key, for a sender that lost its connection before it heard. The five minutes
    /// were looked at only when ANOTHER drop finished. So, first: a sender that asked long
    /// after was still answered. Now the age is checked when someone asks. (The time is
    /// shortened after the drop has finished, so that nothing but that check can be what
    /// refuses.)
    func testAFinishedDropIsNotAnsweredForAfterItsTime() throws {
        defer { Tuning.completedSeconds = 300 }
        let (sender, receiver) = try pairedMacs()
        let ask = try finishedDrop(from: sender, to: receiver)
        XCTAssertEqual(ask(), [FrameType.resumed.rawValue, FrameType.complete.rawValue], "within its time the sender is told again")
        Tuning.completedSeconds = 0.3
        Thread.sleep(forTimeInterval: 0.6)
        XCTAssertEqual(ask(), [], "the sender was answered after the time the answer is kept for")
    }

    /// And second: on a Mac that received nothing else, the answer and the resume key stayed
    /// in memory until the app was quit. Now both are gone when their time is up, whether or
    /// not anyone asks.
    func testAFinishedDropsKeyIsForgottenWhenItsTimeIsUp() throws {
        Tuning.completedSeconds = 1
        defer { Tuning.completedSeconds = 300 }
        let (sender, receiver) = try pairedMacs()
        _ = try finishedDrop(from: sender, to: receiver)
        XCTAssertEqual(receiver.listener.remembered, 1)
        XCTAssertTrue(until(6) { receiver.listener.remembered == 0 }, "its time is up and nobody has asked: the answer and the drop's resume key are still kept")
    }

    /// Reported by an independent review (2026-11-24); the model of admission had it down as a
    /// limit ("keys nobody paired, holding on, keep the next one out"), and this test showed it
    /// through the listener before anything was changed. It is F1 in the one pool F1's fix did
    /// not reach. Anyone can make a key and complete a handshake. One host did it as many times
    /// as there are places for keys nobody has paired, said nothing more, and came back as
    /// each connection's ten seconds ran out. Every other key that is not paired at the moment
    /// (a new Mac, one whose pairing has run out, one this Mac's own person has just asked to
    /// pair with) was then closed before its hello was read. Every pairing ends within ninety
    /// days, so in time one host could stop two Macs from ever pairing again.
    ///
    /// Now such a key takes its place as a stranger does: the one that has waited longest
    /// without asking for anything gives way. Once with the share one address has (the host
    /// pushes out only its own), once as if they came from many addresses (the pool is full).
    func testKeysNobodyPairedThatSayNothingDoNotKeepAMacFromAskingToPair() throws {
        defer { Tuning.unpairedPerAddress = 2 }
        for perAddress in [2, 100] {
            Tuning.unpairedPerAddress = perAddress
            let victim = try TestMac("victim"), newcomer = try TestMac("newcomer")
            victim.onRequest = { $0.refuse() }
            var held: [Channel] = []
            for _ in 0..<Tuning.unpaired + 2 {
                held.append(try Channel.dial(host: "127.0.0.1", port: victim.port, trust: Trust.inMemory(), name: "flood", purpose: .pair).channel)
            }
            Thread.sleep(forTimeInterval: 0.3)
            XCTAssertEqual(open(held.map(\.socket)), min(perAddress, Tuning.unpaired), "the ones that gave way were closed, and the newest hold the places")
            let asking = newcomer.pair(with: victim)
            XCTAssertTrue(until(4) { !victim.requests.withLock { $0 }.isEmpty },
                          "connections that proved fresh keys and then said nothing kept a Mac from asking to pair (\(perAddress) places an address): \(asking.state)")
            for c in held { c.socket.shutdown() }
            Thread.sleep(forTimeInterval: 1.1)   // the next round's arrivals are counted afresh
        }
    }

    /// What does not give way: a connection whose request to pair has been read. It may be in
    /// front of a person for minutes, and is not closed to make room for anyone. With every
    /// place so held, a newcomer with a fresh key is the one turned away, as before.
    func testARequestToPairThatHasBeenReadIsNotClosedToMakeRoom() throws {
        Tuning.unpaired = 1
        Tuning.unpairedPerAddress = 100
        defer { Tuning.unpaired = 8; Tuning.unpairedPerAddress = 2 }
        let victim = try TestMac("victim"), asker = try TestMac("asker")
        let asking = asker.pair(with: victim)   // nobody answers: the request stays on screen
        XCTAssertTrue(until(4) { !victim.requests.withLock { $0 }.isEmpty })
        for _ in 0..<6 {
            XCTAssertThrowsError(try Channel.dial(host: "127.0.0.1", port: victim.port, trust: Trust.inMemory(), name: "flood", purpose: .pair),
                                 "a stranger's fresh key was answered where the one place is held by a request that has been read")
        }
        XCTAssertFalse(asking.state.isFinal, "the request on screen was closed to make room for a stranger: \(asking.state)")
        XCTAssertFalse(victim.requests.withLock { $0 }.first?.state.isFinal ?? true)
        asking.cancel()
    }

    /// Found on the way to the model of admission (2026-11-24). The rate is so many arrivals in
    /// a second, and the listener read the second off the calendar: set back, the calendar left
    /// the arrivals of the moment counted until it came round to them again, and with the rate
    /// full nobody was let in for as long. A test cannot set this Mac's calendar, so this holds
    /// the listener to WHICH clock it reads: the one that counts from boot and cannot be set,
    /// as the lifetimes of keys are counted. (What a clock that goes back does to the machine
    /// is `AdmissionTests.testAnArrivalFromLaterThanNowIsForgotten`.)
    func testArrivalsAreTimedOnTheClockThatCannotBeSet() {
        let read = DropListener.elapsed()
        XCTAssertEqual(read, SystemClock().continuous, accuracy: 5)
        XCTAssertGreaterThan(abs(read - Date().timeIntervalSinceReferenceDate), 86400, "that is the calendar")
        XCTAssertGreaterThan(abs(read - Date().timeIntervalSince1970), 86400, "and so is that")
    }
}
