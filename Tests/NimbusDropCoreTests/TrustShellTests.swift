// Copyright (C) 2026 Niels Joubert
// SPDX-License-Identifier: GPL-3.0-or-later
import Foundation
import XCTest
@testable import NimbusBase
@testable import NimbusCrypto
@testable import NimbusDropCore
@testable import NimbusSecurityCore

/// `Trust`, the class: the lock, the disk and the order in which what `TrustCore` decides is
/// carried out. The core is held equal to its specification; this part is not, so it is
/// tested here against the things `formal/tla/TrustWithdraw.tla` says of it: written before
/// anything is ended, nothing ended with the store locked, registration and withdrawal as
/// one decision under threads that race, a disk that refuses, a restart.
final class TrustShellTests: XCTestCase {
    let day = 86400.0

    /// Everything that happens, in the order it happens, from whatever thread.
    final class Journal: @unchecked Sendable {
        private let lock = NSLock()
        private var lines: [String] = []
        func note(_ line: String) { lock.withLock { lines.append(line) } }
        var all: [String] { lock.withLock { lines } }
    }

    /// A disk that says what it was asked, and can be made to refuse.
    final class Disk: TrustStorage, @unchecked Sendable {
        let journal: Journal
        private let lock = NSLock()
        private var data: Data?
        var full = false
        init(_ journal: Journal) { self.journal = journal }
        func load() throws -> Data? { lock.withLock { data } }
        func save(_ data: Data) throws {
            try lock.withLock {
                if full { journal.note("save refused"); throw DropError("No space left on device") }
                self.data = data
                journal.note("saved")
            }
        }
        func setAside(_ label: String) { lock.withLock { data = nil } }
    }

    /// A session as the trust store knows one.
    final class Session: TrustedSession, @unchecked Sendable {
        let name: String
        let journal: Journal
        weak var store: Trust?
        private let lock = NSLock()
        private var ended = false
        var waiting = false
        /// What the store answered when this session, being ended, asked it a question: that it
        /// could be asked at all is what "not with the store locked" means for another thread.
        var askedWhileEnding: KeyStanding?
        init(_ name: String, _ journal: Journal) { self.name = name; self.journal = journal }
        var isFinal: Bool { lock.withLock { ended } }
        var isWaitingForAccept: Bool { lock.withLock { waiting && !ended } }
        func log(_ message: @autoclosure () -> String, _ level: LogLevel) {}
        func withdrawn(_ error: DropError) {
            journal.note("ended \(name)")
            // From another thread, as a socket's reader would: it must not find the store locked.
            if let store {
                let asked = DispatchSemaphore(value: 0)
                Thread.detachNewThread { [self] in
                    let answer = store.standing(of: PublicKey.madeUp())
                    lock.withLock { askedWhileEnding = answer }
                    asked.signal()
                }
                if asked.wait(timeout: .now() + 5) == .timedOut { journal.note("LOCKED while ending \(name)") }
            }
            lock.withLock { ended = true }
        }
    }

    func store(_ journal: Journal, clock: TrustClock = SystemClock()) throws -> (Trust, Disk) {
        let disk = Disk(journal)
        return (try Trust(storage: disk, clock: clock), disk)
    }

    /// The order every withdrawal takes: the file, then the sessions, then the listeners.
    func testAWithdrawalIsWrittenThenItsSessionsAreEndedThenTheListenersAreTold() throws {
        let journal = Journal()
        let (trust, _) = try store(journal)
        let key = PublicKey.madeUp()
        try trust.store(pairing: key, announced: "air", method: "codes", remaining: 30 * day)
        let a = Session("a", journal), b = Session("b", journal)
        a.store = trust; b.store = trust
        trust.track(a, key: key)
        trust.track(b, key: key)
        trust.onWithdrawn { _ in journal.note("told") }
        let before = journal.all.count
        trust.retire(key)
        let after = Array(journal.all[before...])
        XCTAssertEqual(after.first, "saved", "\(after)")
        XCTAssertEqual(Set(after.dropFirst().prefix(2)), ["ended a", "ended b"], "\(after)")
        XCTAssertEqual(after.last, "told", "\(after)")
        XCTAssertFalse(after.contains { $0.hasPrefix("LOCKED") }, "a session was ended with the trust store locked")
        XCTAssertEqual(a.askedWhileEnding, .unknown)
        XCTAssertTrue(a.isFinal && b.isFinal)
    }

    /// Registration and withdrawal, raced: whatever the order, when both calls have returned
    /// the session is over. (The finding of `TrustWithdraw.tla`, at the class, under threads.)
    func testASessionRacingAWithdrawalIsAlwaysEnded() throws {
        let journal = Journal()
        let (trust, _) = try store(journal)
        var endedByTrack = 0, endedByWithdrawal = 0
        for round in 0..<400 {
            let key = PublicKey.madeUp()
            try trust.store(pairing: key, announced: "mac \(round)", method: "codes", remaining: 30 * day)
            let session = Session("s\(round)", Journal())
            let go = DispatchSemaphore(value: 0), done = DispatchGroup()
            for work in [{ trust.track(session, key: key) }, { round % 2 == 0 ? trust.forget(key) : trust.retire(key) }] {
                done.enter()
                Thread.detachNewThread {
                    go.wait()
                    work()
                    done.leave()
                }
            }
            go.signal(); go.signal()
            XCTAssertEqual(done.wait(timeout: .now() + 10), .success)
            XCTAssertTrue(session.isFinal, "round \(round): the session outlived the withdrawal of the key that authenticated it")
            XCTAssertFalse(trust.standing(of: key).isPaired)
            if session.journal.all == ["ended s\(round)"] { endedByTrack += 1; endedByWithdrawal += 1 }
        }
        XCTAssertEqual(endedByTrack, 400)
        XCTAssertEqual(endedByWithdrawal, 400)
    }

    /// A withdrawal that could not be written is in force, is said to be unsaved, is not
    /// acknowledged, and is undone by a restart: which is why nothing is acknowledged without
    /// `commit`. Written, it survives one.
    func testAWithdrawalThatWasNotWrittenIsInForceUnsavedAndUndoneByARestart() throws {
        let journal = Journal()
        let clock = FakeClock()
        let (trust, disk) = try store(journal, clock: clock)
        let key = PublicKey.madeUp()
        try trust.store(pairing: key, announced: "air", method: "codes", remaining: 30 * day)
        disk.full = true
        trust.retire(key)
        XCTAssertFalse(trust.standing(of: key).isPaired, "in force here at once")
        XCTAssertTrue(trust.unsaved)
        XCTAssertThrowsError(try trust.commit(), "nothing may be acknowledged to the other Mac")
        // The app dies and is started again: the file never heard of the withdrawal.
        let restarted = try Trust(storage: disk, clock: clock)
        XCTAssertTrue(restarted.standing(of: key).isPaired, "(the limit this test states: an unsaved withdrawal does not survive a restart)")
        // With the disk taking writes again, the retry holds, and then a restart keeps it.
        disk.full = false
        clock.pass(31)
        trust.tick()
        XCTAssertFalse(trust.unsaved)
        XCTAssertNoThrow(try trust.commit())
        let again = try Trust(storage: disk, clock: clock)
        guard case .retired = again.standing(of: key) else { return XCTFail("\(again.standing(of: key))") }
        XCTAssertThrowsError(try again.store(pairing: key, announced: "air", method: "codes", remaining: 30 * day))
    }

    /// The same notice twice, or a retire after a forget: one tombstone, nothing ended twice,
    /// and the key stays refused.
    func testTheSameWithdrawalTwiceIsOneWithdrawal() throws {
        let journal = Journal()
        let (trust, _) = try store(journal)
        let key = PublicKey.madeUp()
        try trust.store(pairing: key, announced: "air", method: "codes", remaining: 30 * day)
        let s = Session("s", journal)
        trust.track(s, key: key)
        trust.retire(key)
        trust.retire(key)
        trust.forget(key)
        trust.retire(key, reason: "replaced")
        XCTAssertEqual(journal.all.filter { $0 == "ended s" }.count, 1)
        XCTAssertEqual(trust.tombstones.filter { $0.key == key }.count, 1)
        guard case .retired = trust.standing(of: key) else { return XCTFail("\(trust.standing(of: key))") }
    }

    /// A session that is still waiting for a person's yes when its key runs out is withdrawn;
    /// one that has begun may finish, until its day of grace is over. At the class, with a clock.
    func testWhatAKeyRunningOutEndsAndWhen() throws {
        let journal = Journal(), clock = FakeClock()
        let (trust, _) = try store(journal, clock: clock)
        let key = PublicKey.madeUp()
        try trust.store(pairing: key, announced: "air", method: "codes", remaining: 3600)
        let waiting = Session("waiting", journal), running = Session("running", journal)
        waiting.waiting = true
        trust.track(waiting, key: key)
        trust.track(running, key: key)
        clock.pass(3700, calendar: 0)
        trust.tick()
        XCTAssertTrue(waiting.isFinal, "the offer outlived the pairing it was made under")
        XCTAssertFalse(running.isFinal, "a drop that had begun may finish")
        clock.pass(day - 200, calendar: 0)
        trust.tick()
        XCTAssertFalse(running.isFinal)
        clock.pass(400, calendar: 0)
        trust.tick()
        XCTAssertTrue(running.isFinal, "a drop ran on past the day allowed after its key's end")
    }
}
