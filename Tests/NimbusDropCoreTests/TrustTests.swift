// Copyright (C) 2026 Niels Joubert
// SPDX-License-Identifier: GPL-3.0-or-later
import CryptoKit
import Foundation
import XCTest
@testable import NimbusDropCore

/// A clock the tests set: the boot it claims, its continuous time and its calendar.
final class FakeClock: TrustClock, @unchecked Sendable {
    private let lock = NSLock()
    private var _boot = "boot-1"
    private var _continuous = 1000.0
    private var _wall = Date(timeIntervalSince1970: 1_800_000_000)

    var bootSession: String { lock.withLock { _boot } }
    var continuous: Double { lock.withLock { _continuous } }
    var wall: Date { lock.withLock { _wall } }

    /// Time passes, on both clocks.
    func pass(_ seconds: Double) { lock.withLock { _continuous += seconds; _wall += seconds } }
    /// Time passes, but the calendar is held where it was (or set back): a forged time server.
    func pass(_ seconds: Double, calendar: Double) { lock.withLock { _continuous += seconds; _wall += calendar } }
    /// The calendar alone jumps.
    func setCalendar(by seconds: Double) { lock.withLock { _wall += seconds } }
    /// The Mac was off for `off` seconds by the calendar and has been up for `up` since.
    func reboot(off: Double, up: Double) { lock.withLock { _boot = UUID().uuidString; _continuous = up; _wall += off + up } }
}

/// The trust store: who is trusted, for how long, and what survives what.
final class TrustTests: XCTestCase {
    let day = 86400.0

    func pairing(_ trust: Trust, with key: PublicKey = KeyPair().publicKey, name: String = "air", remaining: Double = 90 * 86400) throws -> PublicKey {
        try trust.store(pairing: key, announced: name, method: "codes", remaining: remaining)
        return key
    }

    // MARK: Keys end

    func testAKeyEndsOnItsDate() throws {
        let clock = FakeClock()
        let trust = Trust.inMemory(clock: clock)
        let key = try pairing(trust, remaining: 30 * day)
        XCTAssertTrue(trust.standing(of: key).isPaired)
        clock.pass(30 * day - 10)
        XCTAssertTrue(trust.standing(of: key).isPaired)
        clock.pass(20)
        guard case .expired = trust.standing(of: key) else { return XCTFail("\(trust.standing(of: key))") }
        XCTAssertFalse(trust.standing(of: key).mayPair, "a key that has run out cannot be paired again")
        XCTAssertThrowsError(try trust.store(pairing: key, announced: "air", method: "codes", remaining: 90 * day))
    }

    func testACalendarHeldStillDoesNotKeepAKeyAlive() throws {
        // The counterexample of the second review: a clock that cannot go back can still be
        // stopped. Time the Mac is on is counted whatever the calendar says.
        let clock = FakeClock()
        let trust = Trust.inMemory(clock: clock)
        let key = try pairing(trust, remaining: 30 * day)
        clock.pass(31 * day, calendar: 0)
        guard case .expired = trust.standing(of: key) else { return XCTFail("a frozen calendar kept the key alive") }
    }

    func testACalendarSetBackAgainAndAgainDoesNotKeepAKeyAlive() throws {
        let clock = FakeClock()
        let trust = Trust.inMemory(clock: clock)
        let key = try pairing(trust, remaining: 30 * day)
        for _ in 0..<40 { clock.pass(day, calendar: -3 * day) }
        guard case .expired = trust.standing(of: key) else { return XCTFail("rollback kept the key alive") }
    }

    /// The calendar is a second way for a pairing to end sooner, and no more than that: a date
    /// reached on the calendar alone ends the pairing (the Mac is to be paired again), and does
    /// not refuse the key for good. Until the review of 2026-11-23 (F3) it did, and a calendar
    /// set forward once cost every pairing permanently.
    func testACalendarSetForwardEndsThePairingEarlyAndNotTheKey() throws {
        let clock = FakeClock()
        let trust = Trust.inMemory(clock: clock)
        let key = try pairing(trust, remaining: 30 * day)
        clock.setCalendar(by: 31 * day)
        guard case .renew = trust.standing(of: key) else { return XCTFail("\(trust.standing(of: key))") }
        XCTAssertFalse(trust.standing(of: trust.publicKey) != .mine)
        XCTAssertTrue(trust.known.isEmpty)
        XCTAssertTrue(trust.tombstones.isEmpty, "only the time counted here refuses a key for good")
        // Put right again, it is still a Mac to pair again, not a paired one.
        clock.setCalendar(by: -31 * day)
        guard case .renew = trust.standing(of: key) else { return XCTFail("\(trust.standing(of: key))") }
        // And the count kept here still ends its key when it was always going to.
        clock.pass(31 * day)
        XCTAssertFalse(trust.standing(of: key).mayPair)
    }

    func testTimeIsCountedAcrossARestartAndAReboot() throws {
        let clock = FakeClock()
        let storage = MemoryStorage()
        var trust = try Trust(storage: storage, clock: clock)
        let key = try pairing(trust, remaining: 30 * day)
        // The app is quit for ten days in the same boot: the continuous clock still counted.
        clock.pass(10 * day, calendar: 0)
        trust = try Trust(storage: storage, clock: clock)
        XCTAssertTrue(trust.standing(of: key).isPaired)
        XCTAssertEqual(trust.known.first?.key, key, "what was stored is read back")
        // Off for fifteen days by the calendar, up for an hour: both are counted.
        clock.reboot(off: 15 * day, up: 3600)
        trust = try Trust(storage: storage, clock: clock)
        XCTAssertTrue(trust.standing(of: key).isPaired, "25 days and an hour so far")
        // A reboot whose calendar claims no time passed while off: the time since boot counts.
        clock.reboot(off: -10 * day, up: 6 * day)
        trust = try Trust(storage: storage, clock: clock)
        guard case .expired = trust.standing(of: key) else { return XCTFail("31 days counted, and the key lives") }
    }

    func testAStatedLifetimeIsHeldToNinetyDaysAndNeverMovedLater() throws {
        let clock = FakeClock()
        let trust = Trust.inMemory(clock: clock)
        let key = try pairing(trust, remaining: 10_000 * day)   // a modified copy claiming for ever
        clock.pass(89 * day)
        XCTAssertTrue(trust.standing(of: key).isPaired)
        clock.pass(2 * day)
        // (This Mac's own key ran out at the same moment, so the entry is a tombstone by now.)
        XCTAssertFalse(trust.standing(of: key).isPaired, "a key outlived ninety days")
        XCTAssertFalse(trust.standing(of: key).mayPair)

        let other = try pairing(trust, name: "studio", remaining: 5 * day)
        clock.pass(day)
        // Pairing the same key again cannot buy it more time than it first had.
        try trust.store(pairing: other, announced: "studio", method: "codes", remaining: 90 * day)
        clock.pass(4 * day + 10)
        guard case .expired = trust.standing(of: other) else { return XCTFail("a renewal moved a key's end later") }
    }

    func testThisMacsOwnKeyIsReplacedAtItsEnd() throws {
        let clock = FakeClock()
        let trust = Trust.inMemory(clock: clock, lifetime: 7 * day)
        let first = trust.publicKey
        let key = try pairing(trust)
        clock.pass(7 * day + 1)
        XCTAssertNotEqual(trust.publicKey, first, "a new key, by itself")
        XCTAssertTrue(trust.known.isEmpty, "and its pairings stopped, with nobody asked anything")
        guard case .renew(let r) = trust.standing(of: key) else { return XCTFail("\(trust.standing(of: key))") }
        XCTAssertEqual(r.name, "air", "remembered, so that pairing again can say it is the same Mac")
        XCTAssertNil(r.told, "this was an expiry, not a reset")
        XCTAssertTrue(trust.standing(of: key).mayPair)
        try trust.store(pairing: key, announced: "air-renamed", method: "codes", remaining: 50 * day)
        XCTAssertEqual(trust.known.first?.name, "air", "and it keeps the name it had here")
    }

    func testAShorterLifetimeTakesEffectAtOnce() throws {
        let clock = FakeClock()
        let trust = Trust.inMemory(clock: clock)
        let first = trust.publicKey
        clock.pass(2 * day)
        trust.setLifetime(3600)
        XCTAssertNotEqual(trust.publicKey, first, "the key was already older than an hour")
        XCTAssertLessThanOrEqual(trust.remaining, 3600)
        XCTAssertEqual(Trust.lifetimes.max(), 90 * day, "there is no 'never'")
        trust.setLifetime(1e12)
        XCTAssertEqual(trust.lifetime, 3600, "and no way to ask for one")
    }

    // MARK: Withdrawing trust

    func testARetiredKeyIsRefusedForGoodAndForgettingDoesNotUndoThat() throws {
        let trust = Trust.inMemory()
        let key = try pairing(trust)
        trust.retire(key)
        guard case .retired(let t) = trust.standing(of: key) else { return XCTFail("\(trust.standing(of: key))") }
        XCTAssertEqual(t.name, "air")
        XCTAssertFalse(trust.standing(of: key).mayPair)
        XCTAssertThrowsError(try trust.store(pairing: key, announced: "air", method: "codes", remaining: day))
        trust.forget(key)
        guard case .retired = trust.standing(of: key) else { return XCTFail("forgetting brought a retired key back") }
    }

    func testForgettingRemovesThePairingAndNothingMore() throws {
        let trust = Trust.inMemory()
        let key = try pairing(trust)
        trust.forget(key)
        XCTAssertEqual(trust.standing(of: key), .unknown)
        XCTAssertTrue(trust.standing(of: key).mayPair, "it can be paired again, by two people, like any key")
    }

    func testPairingAReplacementRetiresWhatItReplaces() throws {
        let trust = Trust.inMemory()
        let old = try pairing(trust, name: "macstudio")
        let new = KeyPair().publicKey
        try trust.store(pairing: new, announced: "macstudio", method: "codes", remaining: day, replacing: old)
        guard case .retired(let t) = trust.standing(of: old) else { return XCTFail("\(trust.standing(of: old))") }
        XCTAssertEqual(t.reason, "replaced")
        XCTAssertEqual(trust.known.map(\.name), ["macstudio"], "one Mac of that name, the new one")
        XCTAssertEqual(trust.known.first?.key, new)
    }

    func testTwoKnownMacsNeverShareAName() throws {
        let trust = Trust.inMemory()
        _ = try pairing(trust, name: "MacBook Pro")
        _ = try pairing(trust, name: "MacBook Pro")
        XCTAssertEqual(trust.known.map(\.name), ["MacBook Pro", "MacBook Pro 2"])
    }

    func testResetMovesEveryoneToPairAgainMarkedWithWhetherTheyWereTold() throws {
        let trust = Trust.inMemory()
        let told = try pairing(trust, name: "air"), missed = try pairing(trust, name: "imac")
        let before = trust.publicKey
        let (old, peers) = trust.beginReset()
        XCTAssertEqual(old.publicKey, before)
        XCTAssertEqual(Set(peers.map(\.key)), [told, missed])
        trust.completeReset(told: [told])
        XCTAssertNotEqual(trust.publicKey, before)
        XCTAssertTrue(trust.known.isEmpty)
        XCTAssertEqual(trust.again.first { $0.key == told }?.told, true)
        XCTAssertEqual(trust.again.first { $0.key == missed }?.told, false, "the one that still trusts the old identity is named")
    }

    func testASessionMayOutliveItsKeyButNotForLong() throws {
        let clock = FakeClock()
        let trust = Trust.inMemory(clock: clock, lifetime: 3600)
        let key = try pairing(trust, remaining: 600)
        let session = Transfer(direction: .send, state: .transferring, peerName: "air", peerAddress: "x")
        trust.track(session, key: key)
        clock.pass(700)
        trust.tick()
        XCTAssertFalse(session.state.isFinal, "its key ran out, and it may finish")
        clock.pass(3600)
        trust.tick()
        guard case .failed(let why) = session.state else { return XCTFail("a session ran on past its grace: \(session.state)") }
        XCTAssertTrue(why.contains("ran out"), why)
    }

    func testWithdrawingTrustEndsWhatTheKeyHadAuthenticated() throws {
        let trust = Trust.inMemory()
        let key = try pairing(trust), other = try pairing(trust, name: "imac")
        let mine = Transfer(direction: .receive, state: .transferring, peerName: "air", peerAddress: "x")
        let theirs = Transfer(direction: .receive, state: .transferring, peerName: "imac", peerAddress: "y")
        trust.track(mine, key: key)
        trust.track(theirs, key: other)
        var told: [PublicKey] = []
        trust.onWithdrawn { told.append($0) }
        trust.retire(key)
        guard case .failed = mine.state else { return XCTFail("\(mine.state)") }
        XCTAssertFalse(theirs.state.isFinal, "a retirement touches one key")
        XCTAssertEqual(told, [key])
    }

    // MARK: Names

    func testNamesAreComparedAsAPersonReadsThem() {
        for other in ["MacStudio", "macstudio-2", "macstudio (3)", "ｍａｃｓｔｕｄｉｏ", "mac studio", "MACSTUDIO.local", "mäcstudio"] {
            XCTAssertEqual(Trust.fold(other), Trust.fold("macstudio"), other)
        }
        XCTAssertNotEqual(Trust.fold("macstudio"), Trust.fold("macbook"))
    }

    func testAnUnknownKeyUnderAKnownNameIsNoticed() throws {
        let clock = FakeClock()
        let trust = Trust.inMemory(clock: clock)
        let real = try pairing(trust, name: "macstudio", remaining: 10 * day)
        let stranger = KeyPair().publicKey
        let clash = try XCTUnwrap(trust.nameClash("MacStudio-2", key: stranger))
        XCTAssertEqual(clash.key, real)
        XCTAssertFalse(clash.expected, "the real one's key is still good: this is a surprise")
        XCTAssertNil(trust.nameClash("macstudio", key: real), "a Mac does not clash with itself")
        XCTAssertNil(trust.nameClash("somebody else", key: stranger))
        XCTAssertTrue(trust.standing(of: real).isPaired, "and the Mac that is known is untouched by it")
        clock.pass(11 * day)
        XCTAssertEqual(trust.nameClash("macstudio", key: stranger)?.expected, true, "after its end date a new key under that name is expected")
    }

    // MARK: Keys as bytes

    func testAKeyHasOneEncoding() {
        let key = KeyPair().publicKey
        var flipped = [UInt8](key.raw)
        flipped[31] |= 0x80
        XCTAssertNil(PublicKey(Data(flipped)), "the top bit is ignored by X25519, so it is refused here")
        var big = [UInt8](repeating: 0xff, count: 32)
        big[31] = 0x7f
        big[0] = 0xed
        XCTAssertNil(PublicKey(Data(big)), "the field prime itself")
        big[0] = 0xec
        XCTAssertNotNil(PublicKey(Data(big)), "one below it")
        XCTAssertNil(PublicKey(Data(count: 31)))
        XCTAssertThrowsError(try JSONDecoder().decode(PublicKey.self, from: try JSONEncoder().encode(Data(flipped))), "nor is one read back from a file")
    }

    func testTagsAndIdentityNumbersHaveTheirShape() {
        let key = KeyPair().publicKey
        XCTAssertTrue(key.tag.wholeMatch(of: #/[0-9A-HJKMNP-TV-Z]{4}(-[0-9A-HJKMNP-TV-Z]{4}){3}/#) != nil, key.tag)
        XCTAssertTrue(key.identityNumber.wholeMatch(of: #/[0-9]{30}/#) != nil)
        XCTAssertEqual(key.identityNumber, key.identityNumber)
        XCTAssertNotEqual(key.identityNumber, KeyPair().publicKey.identityNumber)
        XCTAssertEqual(PublicKey.digits(" 30517 84926\n11370-65208 "), "30517849261137065208")
        XCTAssertEqual(PublicKey.grouped("3051784926"), "30517 84926")
    }

    func testALowOrderKeyAgreesWithNobody() {
        XCTAssertThrowsError(try KeyPair().agree(with: Data(count: 32)), "all zeros: a key of order one")
    }

    // MARK: The file

    /// A Forget that could not be written is in force, is known to be unsaved, and is written
    /// as soon as the disk takes it; it is not left to be undone by the next launch.
    func testAWithdrawalThatCouldNotBeWrittenIsTriedAgainUntilItHolds() throws {
        let storage = MemoryStorage(), clock = FakeClock()
        let trust = try Trust(storage: storage, clock: clock)
        let key = try pairing(trust)
        let changes = Locked(0)
        trust.onChange = { changes.withLock { $0 += 1 } }
        storage.failSaves = true
        trust.forget(key)
        XCTAssertFalse(trust.standing(of: key).isPaired, "forgotten here and now, written or not")
        XCTAssertTrue(trust.unsaved)
        XCTAssertTrue(try Trust(storage: storage, clock: clock).standing(of: key).isPaired, "the hazard: on the disk it is still paired")
        clock.pass(60)
        trust.tick()
        XCTAssertTrue(trust.unsaved, "the disk is still full")
        storage.failSaves = false
        let before = changes.withLock { $0 }
        clock.pass(60)
        trust.tick()
        XCTAssertFalse(trust.unsaved)
        XCTAssertGreaterThan(changes.withLock { $0 }, before, "and whoever is showing a warning hears of it")
        XCTAssertFalse(try Trust(storage: storage, clock: clock).standing(of: key).isPaired, "a restart no longer brings it back")
    }

    func testAnUnreadableTrustFileIsNeverQuietlyReplaced() throws {
        let storage = MemoryStorage()
        let trust = try Trust(storage: storage)
        let key = try pairing(trust)
        trust.retire(key)
        let good = try XCTUnwrap(storage.stored)

        // Damage: kept, and the app is told; nothing is regenerated.
        try storage.save(Data("not a trust file".utf8))
        XCTAssertThrowsError(try Trust(storage: storage)) { XCTAssertEqual($0 as? TrustFault, .damaged) }
        XCTAssertEqual(storage.stored, Data("not a trust file".utf8))

        // The enclave unavailable for now: the same.
        try storage.save(good)
        storage.fault = .unavailable("busy")
        XCTAssertThrowsError(try Trust(storage: storage)) { XCTAssertEqual($0 as? TrustFault, .unavailable("busy")) }
        storage.fault = nil
        XCTAssertEqual(storage.stored, good)
        guard case .retired = try Trust(storage: storage).standing(of: key) else { return XCTFail("the retirement did not survive") }

        // Files from another Mac: set aside, a new identity, and a note of it.
        storage.fault = .foreign
        let fresh = try Trust(storage: storage)
        XCTAssertEqual(fresh.startNote, "foreign")
        XCTAssertNotEqual(fresh.publicKey, trust.publicKey)

        // Starting fresh after damage is somebody's explicit choice.
        try storage.save(Data("damaged".utf8))
        XCTAssertEqual(try Trust.startFresh(storage: storage).standing(of: key), .unknown, "and it does lose the record, which is why it asks")
    }

    func testTheStoredFileOpensOnlyWithItsOwnDeviceKey() throws {
        try XCTSkipUnless(SecureEnclave.isAvailable, "no Secure Enclave here (a virtual machine)")
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("nimbusdrop-trust-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: dir) }
        let storage = EnclaveStorage(folder: dir)
        XCTAssertNil(try storage.load(), "a first run")
        let trust = try Trust(storage: storage)
        let key = try pairing(trust)
        // Another object over the same folder: what a later launch sees.
        XCTAssertEqual(try Trust(storage: EnclaveStorage(folder: dir)).publicKey, trust.publicKey)
        XCTAssertTrue(try Trust(storage: EnclaveStorage(folder: dir)).standing(of: key).isPaired)

        let file = dir.appendingPathComponent("trust")
        let sealed = try Data(contentsOf: file)
        XCTAssertNil(sealed.range(of: trust.keyPair.raw), "the private key is not in the file in the clear")
        XCTAssertEqual(try FileManager.default.attributesOfItem(atPath: file.path)[.posixPermissions] as? Int, 0o600)

        // One flipped bit: the file does not open, and is not replaced.
        var bad = sealed
        bad[bad.count / 2] ^= 1
        try bad.write(to: file)
        XCTAssertThrowsError(try EnclaveStorage(folder: dir).load()) { XCTAssertEqual($0 as? TrustFault, .damaged) }
        XCTAssertEqual(try Data(contentsOf: file), bad)

        // The device file says it was made on other hardware: foreign, not damaged.
        try sealed.write(to: file)
        let device = dir.appendingPathComponent("device")
        var json = try XCTUnwrap(try JSONSerialization.jsonObject(with: try Data(contentsOf: device)) as? [String: Any])
        json["hardware"] = "SOME-OTHER-MAC"
        try JSONSerialization.data(withJSONObject: json).write(to: device)
        XCTAssertThrowsError(try EnclaveStorage(folder: dir).load()) { XCTAssertEqual($0 as? TrustFault, .foreign) }
        let moved = try Trust(storage: EnclaveStorage(folder: dir))
        XCTAssertEqual(moved.startNote, "foreign")
        XCTAssertTrue(try FileManager.default.contentsOfDirectory(atPath: dir.path).contains { $0.hasPrefix("trust.from-another-mac") }, "the old files were kept aside")
    }
}
