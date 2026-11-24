// Copyright (C) 2026 Niels Joubert
// SPDX-License-Identifier: GPL-3.0-or-later
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

/// What an independent review of the code found on 2026-11-24, each as the attack it described.
/// (The reviewer was given the code and the lesson of the first model's finding, "wherever code
/// asks a question and acts on the answer later, those are two steps", and not the conclusions
/// of anyone who had worked on it.) Its first finding, a manifest whose sizes overflow when
/// added up, is in `SecurityTests.testHostileNumbersAreRefusedNotCrashedOn`.
final class IndependentReviewTests: XCTestCase {
    let day = 86400.0

    override func setUp() { Tuning.pairQuietSeconds = 0.3; Tuning.speedPauseSeconds = 0 }
    override func tearDown() { Tuning.pairQuietSeconds = 10; Tuning.speedPauseSeconds = 10 }

    // MARK: A drop is sent to a key

    /// Retry sent a failed drop to whatever Mac now had the name the first one had in the list.
    /// A second paired Mac that took that name got the drop, on one click and no question.
    func testARetryGoesToTheKeyTheDropWasSentToNotToTheNameItHad() throws {
        let h = KeyPair().publicKey, m = KeyPair().publicKey
        var meant = Peer(id: "Studio._nimbusdrop._tcp.local.", name: "Studio", address: "10.0.0.5", port: 4000)
        meant.key = h
        // H has gone; M announces itself under H's name, and proves its own (paired) key.
        var taker = Peer(id: meant.id, name: "Studio", address: "10.0.0.66", port: 4000)
        taker.key = m
        let picked = meant.asItIsNow(among: [taker])
        XCTAssertEqual(picked.key, h, "the retry would expect M's key and send M the drop")
        XCTAssertEqual(picked.address, "10.0.0.5", "and would send it to where M is")

        // H comes back under another name and address: that is where its drop goes.
        var moved = Peer(id: "Studio (2)._nimbusdrop._tcp.local.", name: "Studio (2)", address: "10.0.0.9", port: 4100)
        moved.key = h
        let found = meant.asItIsNow(among: [taker, moved])
        XCTAssertEqual(found.id, moved.id)
        XCTAssertEqual(found.address, "10.0.0.9")
        XCTAssertEqual(found.key, h)

        // The key the drop's own handshake proved counts for more than what the tile said.
        var unproved = Peer(id: "x", name: "x", address: "10.0.0.7", port: 1)
        unproved.isManual = true
        XCTAssertEqual(unproved.asItIsNow(among: [taker, moved], proved: h).id, moved.id)
        // A Mac found on the network that never proved a key is not re-aimed at all.
        let never = Peer(id: meant.id, name: "Studio", address: "10.0.0.5", port: 4000)
        XCTAssertNil(never.asItIsNow(among: [taker]).key)
        XCTAssertEqual(never.asItIsNow(among: [taker]).address, "10.0.0.5")
    }

    // MARK: A yes is checked against the pairing

    /// A drop's yes is checked against the pairing before anything starts (the first review's
    /// F6). A speed test's was not: only the store's next tick ended a question whose pairing
    /// had run out, and where nothing ticks by itself (the command line) the test ran.
    func testAYesToASpeedTestWhosePairingHasRunOutStartsNothing() throws {
        let clock = FakeClock()
        let a = Trust.inMemory(clock: clock), b = Trust.inMemory(clock: clock)
        try a.store(pairing: b.publicKey, announced: "asked", method: "codes", remaining: 90 * day)
        try b.store(pairing: a.publicKey, announced: "tester", method: "codes", remaining: 3600)
        let tester = try TestMac("tester", trust: a), asked = try TestMac("asked", trust: b)
        let questions = Locked<[SpeedResponder]>([])
        asked.listener.onSpeedTest = { r in questions.withLock { $0.append(r) } }
        let t = SpeedTest(host: "127.0.0.1", port: asked.port, peerName: "asked", identity: tester.identity, trust: a, expect: asked.key, seconds: 1, streams: 2)
        t.start()
        XCTAssertTrue(until(5) { questions.withLock { $0.count } == 1 })
        // The tester's key runs out with the question still on screen, and nothing asks the
        // store anything in between.
        clock.pass(3700, calendar: 0)
        let question = questions.withLock { $0[0] }
        question.accept()
        XCTAssertTrue(until(10) { question.state.isFinal && t.state.isFinal })
        XCTAssertNotEqual(question.state, .completed, "a speed test ran under a pairing that had ended")
        XCTAssertEqual(question.progress.doneBytes, 0)
        XCTAssertNotEqual(t.state, .completed)
    }

    // MARK: A pairing does not outlive the identity it was made with

    /// Reset Identity with the codes on screen. The pairing went on: both people typed, the
    /// other Mac stored the identity that had just been given up (good for as long as that key
    /// had left, to whoever holds a copy of it), and this Mac stored the other under its new one.
    func testResetIdentityEndsAPairingThatIsInProgress() throws {
        let a = try TestMac("macbookpro"), b = try TestMac("new-imac")
        b.onRequest = { $0.proceed() }
        let old = a.key
        let mine = a.pair(with: b)
        XCTAssertTrue(until { !b.requests.withLock { $0 }.isEmpty })
        let theirs = try XCTUnwrap(b.requests.withLock { $0.last })
        let codeA = try XCTUnwrap(mine.code()), codeB = try XCTUnwrap(theirs.code())
        a.trust.completeReset(told: [])
        XCTAssertNotEqual(a.key, old)
        XCTAssertTrue(until(5) { mine.state.isFinal }, "the pairing is still going after the identity it was being made with was reset")
        mine.submit(codeB)
        theirs.submit(codeA)
        XCTAssertTrue(until { theirs.state.isFinal })
        XCTAssertFalse(mine.isPaired)
        XCTAssertFalse(theirs.isPaired, "the other Mac paired with an identity that had been given up")
        XCTAssertFalse(b.trust.standing(of: old).isPaired)
        XCTAssertTrue(a.trust.known.isEmpty)
    }

    /// And the store itself refuses a pairing made under a key this Mac no longer has: asked
    /// and answered under its lock, whatever became of the session.
    func testAPairingMadeUnderAKeyThisMacNoLongerHasIsNotStored() throws {
        let trust = Trust.inMemory()
        let old = trust.publicKey, other = KeyPair().publicKey
        XCTAssertNoThrow(try trust.store(pairing: KeyPair().publicKey, announced: "before", method: "codes", remaining: day, under: old))
        trust.completeReset(told: [])
        XCTAssertThrowsError(try trust.store(pairing: other, announced: "new-imac", method: "codes", remaining: day, under: old))
        XCTAssertEqual(trust.standing(of: other), .unknown)
        XCTAssertNoThrow(try trust.store(pairing: other, announced: "new-imac", method: "codes", remaining: day, under: trust.publicKey))
    }

    // MARK: What is shown is what is there

    /// A name from another Mac may hold characters that are not seen and that change what is:
    /// a right-to-left override, a zero-width space. They are left out of everything shown,
    /// and of the comparison that warns of a familiar name under a new key.
    func testCharactersThatCannotBeSeenAreLeftOutOfWhatIsShownAndCompared() {
        XCTAssertEqual(Sanitize.label("invoice-\u{202E}fdp.exe"), "invoice-fdp.exe", "shown with the override it reads invoice-exe.pdf")
        XCTAssertEqual(Sanitize.label("mac\u{200B}stu\u{2060}dio\u{FEFF}"), "macstudio")
        XCTAssertEqual(Sanitize.label("a\u{2066}b\u{2069}c\u{200E}\u{200F}\u{061C}"), "abc")
        XCTAssertEqual(Sanitize.label("soft\u{00AD}hyphen"), "softhyphen")
        // What scripts and emoji need in order to be written properly is kept.
        XCTAssertEqual(Sanitize.label("می\u{200C}خواهم"), "می\u{200C}خواهم")
        XCTAssertEqual(Sanitize.label("👨\u{200D}👩\u{200D}👧"), "👨\u{200D}👩\u{200D}👧")
        // Compared, nothing unseen counts at all.
        for disguised in ["mac\u{200B}studio", "mac\u{200D}studio", "\u{202E}macstudio", "mac\u{00AD}studio", "macstudio\u{FEFF}"] {
            XCTAssertEqual(Trust.fold(disguised), Trust.fold("macstudio"), disguised.unicodeScalars.map { String($0.value, radix: 16) }.joined(separator: " "))
        }
        // And so the alert about a familiar name under a new key is not got round by one.
        let trust = Trust.inMemory()
        XCTAssertNoThrow(try trust.store(pairing: KeyPair().publicKey, announced: "macstudio", method: "codes", remaining: day))
        XCTAssertNotNil(trust.nameClash("mac\u{200B}studio", key: KeyPair().publicKey))
    }
}
