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
