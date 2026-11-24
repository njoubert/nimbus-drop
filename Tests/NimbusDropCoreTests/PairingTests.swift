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

/// A Mac for the tests: an identity, a trust store, a listener, and somebody sitting at it.
final class TestMac: @unchecked Sendable {
    let identity: Identity
    let trust: Trust
    let listener: DropListener
    /// Requests to pair that reached this Mac's person.
    let requests = Locked<[PairingSession]>([])
    /// Offers that reached this Mac's person.
    let offers = Locked<[ReceiveSession]>([])
    let refusedIdentities = Locked<[String]>([])
    /// What the person does with a request; nil leaves it unanswered.
    var onRequest: (@Sendable (PairingSession) -> Void)?

    init(_ name: String, trust: Trust = Trust.inMemory()) throws {
        identity = Identity(name: name, id: UUID().uuidString)
        self.trust = trust
        listener = try DropListener(identity: identity, trust: trust, preferredPort: 0)
        listener.onPairRequest = { [weak self] p in
            self?.requests.withLock { $0.append(p) }
            self?.onRequest?(p)
        }
        listener.onOffer = { [weak self] s in self?.offers.withLock { $0.append(s) } }
        listener.onRefusedIdentity = { [weak self] name, _ in self?.refusedIdentities.withLock { $0.append(name) } }
        listener.start()
    }

    deinit { listener.stop() }

    var port: UInt16 { listener.port }
    var key: PublicKey { trust.publicKey }

    /// Starts a pairing with another Mac, as this Mac's person would by dropping a file on it.
    func pair(with other: TestMac, port: UInt16? = nil, expect: PublicKey? = nil, replacing: PublicKey? = nil, byNumber: Bool = false) -> PairingSession {
        PairingSession(host: "127.0.0.1", port: port ?? other.port, peerName: other.identity.name, identity: identity, trust: trust,
                       expect: expect, replacing: replacing, byNumber: byNumber)
    }
}

func until(_ seconds: Double = 10, _ condition: () -> Bool) -> Bool {
    let deadline = Date().addingTimeInterval(seconds)
    while !condition(), Date() < deadline { Thread.sleep(forTimeInterval: 0.01) }
    return condition()
}

extension PairingSession {
    /// The code this side is showing, once it is.
    func code(within seconds: Double = 10) -> String? {
        var mine: String?
        _ = until(seconds) {
            if case .codes(let m, _) = state { mine = m; return true }
            return state.isFinal
        }
        return mine
    }

    var isPaired: Bool { if case .paired = state { return true }; return false }
    var failure: String? { if case .failed(let why) = state { return why }; return nil }
}

/// Pairing: two people, two codes, and everyone who would like to be a third.
final class PairingTests: XCTestCase {
    override func setUp() {
        Tuning.pairQuietSeconds = 0.3
        // Every Mac of every test here is at one address, and several ask one Mac to pair at once.
        Tuning.unpairedPerAddress = 8
    }

    override func tearDown() {
        Tuning.pairQuietSeconds = 10
        Tuning.pairSeconds = 120
        Tuning.unpaired = 8
        Tuning.unpairedPerAddress = 2
    }

    /// Two people doing it properly: each reads their code out and types the other's.
    @discardableResult
    func pairProperly(_ a: TestMac, _ b: TestMac, file: StaticString = #filePath, line: UInt = #line) throws -> (PairingSession, PairingSession) {
        b.onRequest = { $0.proceed() }
        let mine = a.pair(with: b)
        XCTAssertTrue(until { !b.requests.withLock { $0 }.isEmpty }, "the request reached the other person", file: file, line: line)
        let theirs = try XCTUnwrap(b.requests.withLock { $0.last })
        let codeA = try XCTUnwrap(mine.code(), "\(mine.state)", file: file, line: line), codeB = try XCTUnwrap(theirs.code(), "\(theirs.state)", file: file, line: line)
        mine.submit(codeB)
        theirs.submit(codeA)
        XCTAssertTrue(until { mine.state.isFinal && theirs.state.isFinal }, file: file, line: line)
        return (mine, theirs)
    }

    func testTwoPeopleTwoCodes() throws {
        let a = try TestMac("macbookpro"), b = try TestMac("dads-imac")
        XCTAssertEqual(a.trust.standing(of: b.key), .unknown)
        let (mine, theirs) = try pairProperly(a, b)
        XCTAssertTrue(mine.isPaired, "\(mine.state)")
        XCTAssertTrue(theirs.isPaired, "\(theirs.state)")
        guard case .paired(let b2) = a.trust.standing(of: b.key), case .paired(let a2) = b.trust.standing(of: a.key) else { return XCTFail("not stored") }
        XCTAssertEqual(b2.name, "dads-imac")
        XCTAssertEqual(a2.name, "macbookpro")
        XCTAssertEqual(b2.method, "codes")
    }

    func testTheCodesAreSixDigitsAndDifferOnTheTwoMacs() throws {
        let a = try TestMac("a"), b = try TestMac("b")
        b.onRequest = { $0.proceed() }
        let mine = a.pair(with: b)
        XCTAssertTrue(until { !b.requests.withLock { $0 }.isEmpty })
        let theirs = b.requests.withLock { $0[0] }
        let codeA = try XCTUnwrap(mine.code()), codeB = try XCTUnwrap(theirs.code())
        XCTAssertEqual(codeA.count, 6)
        XCTAssertEqual(codeB.count, 6)
        XCTAssertNotEqual(codeA, codeB, "each Mac shows its own code, so nobody can type what is on their own screen")
        // Typing what is on one's own screen is a wrong code.
        mine.submit(codeA)
        guard case .codes(_, let left) = mine.state else { return XCTFail("\(mine.state)") }
        XCTAssertEqual(left, 2)
        mine.cancel()
    }

    /// The window shows one code at a time: the Mac that was asked types first, then reads
    /// its own out. So its code must outlast its own entry, and the Mac that asked must hear
    /// that it is its turn.
    func testAMacStillKnowsItsCodeAfterItsPersonHasTyped() throws {
        let a = try TestMac("a"), b = try TestMac("b")
        b.onRequest = { $0.proceed() }
        let mine = a.pair(with: b)
        XCTAssertTrue(until { !b.requests.withLock { $0 }.isEmpty })
        let theirs = b.requests.withLock { $0[0] }
        let codeA = try XCTUnwrap(mine.code()), codeB = try XCTUnwrap(theirs.code())
        XCTAssertFalse(mine.otherTyped)
        let told = Locked(0)
        mine.onChange = { told.withLock { $0 += 1 } }
        theirs.submit(codeA)
        XCTAssertEqual(theirs.state, .confirming)
        XCTAssertEqual(theirs.myCode, codeB, "it is still to be read out")
        XCTAssertTrue(until { mine.otherTyped })
        XCTAssertTrue(until { told.withLock { $0 } > 0 }, "the window is told it is its turn")
        XCTAssertFalse(mine.isPaired, "hearing that they typed pairs nothing")
        XCTAssertEqual(a.trust.standing(of: b.key), .unknown)
        mine.submit(codeB)
        XCTAssertTrue(until { mine.isPaired && theirs.isPaired })
    }

    func testNothingIsPairedUntilBothPeopleHaveTypedTheRightCode() throws {
        let a = try TestMac("a"), b = try TestMac("b")
        b.onRequest = { $0.proceed() }
        let mine = a.pair(with: b)
        XCTAssertTrue(until { !b.requests.withLock { $0 }.isEmpty })
        let theirs = b.requests.withLock { $0[0] }
        let codeB = try XCTUnwrap(theirs.code())
        _ = mine.code()
        mine.submit(codeB)
        XCTAssertTrue(until { mine.state == .confirming })
        Thread.sleep(forTimeInterval: 0.3)
        XCTAssertEqual(a.trust.standing(of: b.key), .unknown, "one right code pairs nobody")
        XCTAssertEqual(b.trust.standing(of: a.key), .unknown)
        theirs.cancel()
        XCTAssertTrue(until { mine.state.isFinal })
        XCTAssertEqual(a.trust.standing(of: b.key), .unknown)
    }

    func testThreeWrongCodesEndItOnBothMacs() throws {
        let a = try TestMac("a"), b = try TestMac("b")
        b.onRequest = { $0.proceed() }
        let mine = a.pair(with: b)
        XCTAssertTrue(until { !b.requests.withLock { $0 }.isEmpty })
        let theirs = b.requests.withLock { $0[0] }
        _ = mine.code()
        _ = theirs.code()
        for _ in 0..<3 { mine.submit("000000") }
        XCTAssertTrue(until { mine.state.isFinal && theirs.state.isFinal })
        XCTAssertTrue(mine.failure?.contains("do not match") == true, "\(mine.state)")
        XCTAssertTrue(theirs.failure?.contains("did not match") == true, "\(theirs.state)")
        XCTAssertEqual(a.trust.standing(of: b.key), .unknown)
        XCTAssertEqual(b.trust.standing(of: a.key), .unknown)
    }

    /// Mallory sits between: the sender's connection ends at her, and she opens her own to the
    /// receiver (two copies sharing nothing but her intent: one answers the sender, the other
    /// calls the receiver). She runs the exchange honestly on both sides, hears every code read
    /// out, and types the right ones on her own two sessions. The two people still read and type
    /// across the room, and the codes of her two sessions do not agree.
    func runTheMiddleByHand(sender: TestMac, receiver: TestMac) throws {
        let answering = try TestMac("dads-imac"), calling = try TestMac("macbookpro")
        answering.onRequest = { $0.proceed() }
        receiver.onRequest = { $0.proceed() }
        let toMallory = sender.pair(with: receiver, port: answering.port)
        let fromMallory = calling.pair(with: receiver)
        XCTAssertTrue(until { !receiver.requests.withLock { $0 }.isEmpty && !answering.requests.withLock { $0 }.isEmpty })
        let atReceiver = receiver.requests.withLock { $0[0] }, atMallory = answering.requests.withLock { $0[0] }
        let senderShows = try XCTUnwrap(toMallory.code()), receiverShows = try XCTUnwrap(atReceiver.code())
        let malloryShowsSender = try XCTUnwrap(atMallory.code()), malloryShowsReceiver = try XCTUnwrap(fromMallory.code())
        XCTAssertNotEqual(malloryShowsSender, receiverShows, "what the sender is asked for is not what the receiver reads out")
        XCTAssertNotEqual(malloryShowsReceiver, senderShows, "nor the other way")
        // Mallory, who hears everything, types the right codes on her two sessions.
        atMallory.submit(senderShows)
        fromMallory.submit(receiverShows)
        // The people read and type across the room.
        for _ in 0..<3 { toMallory.submit(receiverShows); atReceiver.submit(senderShows) }
        XCTAssertTrue(until { toMallory.state.isFinal && atReceiver.state.isFinal })
        XCTAssertFalse(toMallory.isPaired, "\(toMallory.state)")
        XCTAssertFalse(atReceiver.isPaired, "\(atReceiver.state)")
        XCTAssertTrue(toMallory.failure?.contains("Something may be between") == true, "\(toMallory.state)")
        XCTAssertEqual(sender.trust.standing(of: answering.key), .unknown, "the sender stored nothing")
        XCTAssertEqual(receiver.trust.standing(of: calling.key), .unknown, "nor did the receiver")
        XCTAssertTrue(sender.trust.known.isEmpty && receiver.trust.known.isEmpty)
    }

    func testSomeoneInTheMiddleWhoHearsBothCodesStillFails() throws {
        try runTheMiddleByHand(sender: try TestMac("macbookpro"), receiver: try TestMac("dads-imac"))
    }

    func testNoCodeExistsUntilAPersonAgrees() throws {
        // A stranger connects and asks. Until somebody at this Mac says yes there is no code to
        // guess, and a stranger who gives up has had no guesses.
        let b = try TestMac("b")
        let stranger = try TestMac("stranger")
        let p = stranger.pair(with: b)
        XCTAssertTrue(until { !b.requests.withLock { $0 }.isEmpty })
        XCTAssertEqual(p.state, .asking)
        Thread.sleep(forTimeInterval: 0.3)
        XCTAssertEqual(p.state, .asking, "still waiting on a person; no code on either side")
        b.requests.withLock { $0[0] }.refuse()
        XCTAssertTrue(until { p.state.isFinal })
        XCTAssertTrue(p.failure?.contains("declined") == true, "\(p.state)")
    }

    func testRequestsToPairAreRationed() throws {
        Tuning.pairQuietSeconds = 30
        let b = try TestMac("b")
        // The first request is shown; while it is on screen, more wait or are turned away.
        let first = try TestMac("s1").pair(with: b)
        XCTAssertTrue(until { b.requests.withLock { $0.count } == 1 })
        var later: [PairingSession] = []
        for i in 0..<7 { later.append(try TestMac("s\(i + 2)").pair(with: b)) }
        Thread.sleep(forTimeInterval: 0.6)
        XCTAssertEqual(b.requests.withLock { $0.count }, 1, "one question on screen, however many ask")
        XCTAssertEqual(later.filter { $0.state.isFinal }.count, 7 - Tuning.pairRequestsWaiting, "the rest are turned away at once, beyond the few that may wait")
        // "Not expecting this": nobody is shown for a while after that, including those waiting.
        b.requests.withLock { $0[0] }.refuse()
        XCTAssertTrue(until { first.state.isFinal && later.allSatisfy { $0.state.isFinal } })
        XCTAssertEqual(b.requests.withLock { $0.count }, 1, "those who waited were not shown either")
        let after = try TestMac("s9").pair(with: b)
        XCTAssertTrue(until { after.state.isFinal })
        XCTAssertTrue(after.failure?.contains("not showing requests to pair") == true, "\(after.state)")
        XCTAssertNotNil(after.pausedFor, "and it says for how long, so the tile here can say to start from that Mac")
        XCTAssertEqual(b.requests.withLock { $0.count }, 1)
    }

    func testRequestsCanBeTurnedOffAltogether() throws {
        let b = try TestMac("b")
        b.trust.requestsOff = true
        let p = try TestMac("a").pair(with: b)
        XCTAssertTrue(until { p.state.isFinal })
        XCTAssertTrue(b.requests.withLock { $0.isEmpty })
        XCTAssertTrue(p.failure?.contains("not taking requests to pair") == true, "\(p.state)")
    }

    func testOnePairingAtATime() throws {
        let a = try TestMac("a"), b = try TestMac("b"), c = try TestMac("c")
        let first = a.pair(with: b)
        XCTAssertTrue(until { first.state == .asking })
        let second = a.pair(with: c)
        XCTAssertTrue(until { second.state.isFinal })
        XCTAssertTrue(second.failure?.contains("another pairing") == true, "\(second.state)")
        first.cancel()
    }

    func testPairingByIdentityNumber() throws {
        let a = try TestMac("a"), b = try TestMac("b")
        b.onRequest = { $0.proceed() }
        let mine = a.pair(with: b, byNumber: true)
        XCTAssertTrue(until { !b.requests.withLock { $0 }.isEmpty })
        let theirs = b.requests.withLock { $0[0] }
        XCTAssertTrue(theirs.byNumber)
        XCTAssertEqual(mine.code(), "", "there is no code to read out: each enters the other's number")
        _ = theirs.code()
        // A wrong number first: someone else's.
        mine.submit(KeyPair().publicKey.identityNumber)
        guard case .codes(_, 2) = mine.state else { return XCTFail("\(mine.state)") }
        // Then the right ones, as they were sent in a message: grouped, with spaces.
        mine.submit(PublicKey.grouped(b.key.identityNumber))
        theirs.submit(a.key.identityNumber)
        XCTAssertTrue(until { mine.state.isFinal && theirs.state.isFinal })
        XCTAssertTrue(mine.isPaired && theirs.isPaired, "\(mine.state) \(theirs.state)")
        XCTAssertEqual(a.trust.known.first?.method, "identity number")
    }

    func testARetiredIdentityCannotBePairedAndIsNotShownAsNew() throws {
        let a = try TestMac("a"), b = try TestMac("b")
        try pairProperly(a, b)
        b.trust.retire(a.key)
        b.requests.withLock { $0 = [] }
        let again = a.pair(with: b)
        XCTAssertTrue(until { again.state.isFinal })
        XCTAssertFalse(again.isPaired)
        XCTAssertTrue(b.requests.withLock { $0.isEmpty }, "no request was shown")
        XCTAssertEqual(b.refusedIdentities.withLock { $0 }, ["a"], "the person was told a retired identity was used")
        // And from the other side: a Mac does not start a pairing with a key it has retired.
        a.trust.retire(b.key)
        let other = a.pair(with: b)
        XCTAssertTrue(until { other.state.isFinal })
        XCTAssertTrue(other.failure?.contains("cannot be paired") == true, "\(other.state)")
    }

    func testAFamiliarNameWithAnUnknownKeyIsMarkedAndTheKnownMacIsUntouched() throws {
        let me = try TestMac("macbookpro"), real = try TestMac("macstudio"), impostor = try TestMac("MacStudio-2")
        try pairProperly(me, real)
        me.requests.withLock { $0 = [] }
        // The impostor asks to pair. Its request says so; the real one is still paired.
        let p = impostor.pair(with: me)
        XCTAssertTrue(until { !me.requests.withLock { $0 }.isEmpty })
        let request = me.requests.withLock { $0[0] }
        let clash = try XCTUnwrap(request.clash)
        XCTAssertEqual(clash.key, real.key)
        XCTAssertFalse(clash.expected)
        XCTAssertTrue(me.trust.standing(of: real.key).isPaired, "nothing another key does displaces a key that is known")
        XCTAssertEqual(me.trust.known.first?.impostors, 1, "and it is counted against that name")
        request.refuse()
        XCTAssertTrue(until { p.state.isFinal })
        XCTAssertTrue(me.trust.standing(of: real.key).isPaired)
    }

    func testAReplacementIsPairedAndTheOldIdentityRetired() throws {
        let me = try TestMac("macbookpro"), old = try TestMac("macstudio"), new = try TestMac("macstudio")
        try pairProperly(me, old)
        me.requests.withLock { $0 = [] }
        // The person here says "it replaces macstudio" and pairs with the codes.
        new.onRequest = { $0.proceed() }
        let mine = me.pair(with: new, replacing: old.key)
        XCTAssertTrue(until { !new.requests.withLock { $0 }.isEmpty })
        let theirs = new.requests.withLock { $0[0] }
        let codeA = try XCTUnwrap(mine.code()), codeB = try XCTUnwrap(theirs.code())
        mine.submit(codeB)
        theirs.submit(codeA)
        XCTAssertTrue(until { mine.state.isFinal })
        XCTAssertTrue(mine.isPaired, "\(mine.state)")
        guard case .retired(let t) = me.trust.standing(of: old.key) else { return XCTFail("\(me.trust.standing(of: old.key))") }
        XCTAssertEqual(t.reason, "replaced")
        XCTAssertEqual(me.trust.known.map(\.name), ["macstudio"])
    }

    func testBothAskingAtOnceEndsInOnePairingNotNone() throws {
        let a = try TestMac("a"), b = try TestMac("b")
        a.onRequest = { $0.proceed() }
        b.onRequest = { $0.proceed() }
        let fromA = a.pair(with: b), fromB = b.pair(with: a)
        XCTAssertTrue(until { fromA.state.isFinal || fromB.state.isFinal })
        // The request from the lower key goes ahead; the other is withdrawn.
        let (winner, loser) = a.key.raw.lexicographicallyPrecedes(b.key.raw) ? (fromA, fromB) : (fromB, fromA)
        XCTAssertTrue(until { loser.state.isFinal })
        XCTAssertFalse(winner.state.isFinal, "\(winner.state) / \(loser.state)")
        XCTAssertNotNil(winner.code(), "and it gets as far as the codes")
        winner.cancel()
    }

    /// The same, when one Mac's own request is so new that it has not yet proved who it is
    /// talking to (a slow machine; CI, 2026-11-23). The other's request must not be turned
    /// away as "another pairing": it is the same one, and the lower key's goes ahead.
    func testBothAskingAtOnceWhenOneHasNotYetProvedTheOther() throws {
        defer { Tuning.pairDialDelay = 0 }
        let x = try TestMac("x"), y = try TestMac("y")
        let (low, high) = x.key.raw.lexicographicallyPrecedes(y.key.raw) ? (x, y) : (y, x)
        low.onRequest = { $0.proceed() }
        high.onRequest = { $0.proceed() }
        // The higher key's Mac asks first, and is slow to connect; the lower's request reaches it meanwhile.
        Tuning.pairDialDelay = 0.8
        let fromHigh = high.pair(with: low)
        Tuning.pairDialDelay = 0
        Thread.sleep(forTimeInterval: 0.1)
        let fromLow = low.pair(with: high)
        XCTAssertTrue(until { fromHigh.state.isFinal }, "\(fromHigh.state)")
        XCTAssertFalse(fromLow.state.isFinal, "the lower key's request was turned away: \(fromLow.state)")
        XCTAssertNotNil(fromLow.code(), "and it gets as far as the codes")
        fromLow.cancel()
    }

    func testAMacThatDoesNotKeepToThePairingIsDropped() throws {
        // A modified copy sends the exchange's messages out of order, twice, or the wrong ones.
        // The transaction ends at the first; no code is ever shown for it.
        let b = try TestMac("b")
        b.onRequest = { $0.proceed() }
        let hostile = Trust.inMemory()
        func attempt(_ send: (Channel) throws -> Void) throws -> PairingSession {
            b.requests.withLock { $0 = [] }
            let (c, _) = try Channel.dial(host: "127.0.0.1", port: b.port, trust: hostile, name: "x", purpose: .pair)
            try c.send(.pairRequest, Empty())
            XCTAssertEqual(try c.read().type, .pairGo)
            try send(c)
            XCTAssertTrue(until { b.requests.withLock { $0.first?.state.isFinal ?? false } })
            _ = until { b.trust.gate.quietSecondsLeft == 0 }   // the quiet after a failed request, longer each time
            return b.requests.withLock { $0[0] }
        }
        let value = PairValue(value: Crypto.random(32))
        // A reveal where the commitment belongs.
        XCTAssertNotNil(try attempt { try $0.send(.reveal, value) }.failure)
        // A commitment, then a second commitment where the reveal belongs.
        XCTAssertNotNil(try attempt { c in
            try c.send(.commit, value)
            _ = try c.read()
            try c.send(.commit, value)
        }.failure)
        // A reveal that is not what was committed to: the one move that would let a responder's
        // code be steered, if it were let through.
        let cheat = try attempt { c in
            try c.send(.commit, value)
            _ = try c.read()
            try c.send(.reveal, PairValue(value: Crypto.random(32)))
        }
        XCTAssertTrue(cheat.failure?.contains("did not keep to the pairing") == true, "\(cheat.state)")
        // "My person typed it right" twice.
        let twice = try attempt { c in
            let ns = Crypto.random(32)
            try c.send(.commit, PairValue(value: PairCodes.commitment(h: c.h, ns: ns)))
            _ = try c.read()
            try c.send(.reveal, PairValue(value: ns))
            try c.send(.paired, Empty())
            try c.send(.paired, Empty())
        }
        XCTAssertTrue(twice.failure?.contains("did not keep to the pairing") == true, "\(twice.state)")
        XCTAssertEqual(b.trust.standing(of: hostile.publicKey), .unknown)
    }

    func testTheOtherSideSayingItMatchedPairsNobody() throws {
        // The message "my person typed it right" can be written by anyone who completed the
        // exchange. Without this Mac's own person typing the right code, it stores nothing.
        let b = try TestMac("b")
        b.onRequest = { $0.proceed() }
        let hostile = Trust.inMemory()
        let (c, _) = try Channel.dial(host: "127.0.0.1", port: b.port, trust: hostile, name: "x", purpose: .pair)
        try c.send(.pairRequest, Empty())
        XCTAssertEqual(try c.read().type, .pairGo)
        let ns = Crypto.random(32)
        try c.send(.commit, PairValue(value: PairCodes.commitment(h: c.h, ns: ns)))
        _ = try c.read()
        try c.send(.reveal, PairValue(value: ns))
        try c.send(.paired, Empty())
        let request = b.requests.withLock { $0[0] }
        XCTAssertNotNil(request.code())
        Thread.sleep(forTimeInterval: 0.3)
        XCTAssertFalse(request.state.isFinal)
        XCTAssertEqual(b.trust.standing(of: hostile.publicKey), .unknown)
        request.refuse()
    }

    func testTheCodesComeFromWhatBothEndsSaw() {
        // The derivation itself: bound to the handshake hash and to both values.
        let h = Crypto.random(32), ns = Crypto.random(32), nr = Crypto.random(32)
        let codes = PairCodes.codes(h: h, ns: ns, nr: nr)
        XCTAssertEqual(codes.receiver.count, 6)
        XCTAssertEqual(codes.sender.count, 6)
        XCTAssertTrue(codes.receiver == PairCodes.codes(h: h, ns: ns, nr: nr).receiver)
        var different = 0
        for _ in 0..<50 {
            if PairCodes.codes(h: Crypto.random(32), ns: ns, nr: nr).receiver != codes.receiver { different += 1 }
            if PairCodes.codes(h: h, ns: Crypto.random(32), nr: nr).sender != codes.sender { different += 1 }
            if PairCodes.codes(h: h, ns: ns, nr: Crypto.random(32)).receiver != codes.receiver { different += 1 }
        }
        XCTAssertGreaterThanOrEqual(different, 149, "another session, another code (but for one chance in a million)")
        XCTAssertNotEqual(PairCodes.commitment(h: h, ns: ns), PairCodes.commitment(h: Crypto.random(32), ns: ns), "a commitment is to one session")
    }

    /// What the pairing machine's "store" causes to be stored (the last part of the contract in
    /// `formal/tla/PairingMachine.tla`): the key that THIS connection's handshake proved, under
    /// the name that connection's hello gave, by the method that was used. Not the Mac the tile
    /// was for: the person at A starts from the tile called "b", and what answers there is C.
    /// By identity number, the number that is right is the proved key's; B's is a wrong entry.
    func testWhatIsStoredIsTheKeyThisConnectionProved() throws {
        for byNumber in [false, true] {
            let a = try TestMac("a"), b = try TestMac("b"), c = try TestMac("c")
            c.onRequest = { $0.proceed() }
            let mine = a.pair(with: b, port: c.port, byNumber: byNumber)
            XCTAssertTrue(until { !c.requests.withLock { $0 }.isEmpty })
            let theirs = try XCTUnwrap(c.requests.withLock { $0.last })
            let shownAtA = try XCTUnwrap(mine.code(), "\(mine.state)"), shownAtC = try XCTUnwrap(theirs.code(), "\(theirs.state)")
            XCTAssertEqual(mine.peerName, "b", "the tile's name is all the session was given")
            XCTAssertEqual(mine.peerKey, c.key, "and the key is the one the connection proved")
            if byNumber {
                mine.submit(b.key.identityNumber)
                guard case .codes(_, 2) = mine.state else { return XCTFail("the number of the Mac the tile was for was taken: \(mine.state)") }
                mine.submit(c.key.identityNumber)
                theirs.submit(a.key.identityNumber)
            } else {
                mine.submit(shownAtC)
                theirs.submit(shownAtA)
            }
            XCTAssertTrue(until { mine.state.isFinal && theirs.state.isFinal })
            guard case .paired(let stored) = mine.state, case .paired(let asked) = theirs.state else { return XCTFail("\(mine.state) / \(theirs.state)") }
            let method = byNumber ? "identity number" : "codes"
            XCTAssertEqual(stored.key, c.key)
            XCTAssertEqual(stored.name, "c", "the name the proved connection gave, not the tile's")
            XCTAssertEqual(stored.announced, ["c"])
            XCTAssertEqual(stored.method, method)
            XCTAssertEqual(a.trust.known.map(\.key), [c.key], "one Mac is stored, and it is that one")
            XCTAssertEqual(a.trust.standing(of: b.key), .unknown, "nothing is stored for the Mac the tile was for")
            XCTAssertEqual(asked.key, a.key)
            XCTAssertEqual(asked.name, "a")
            XCTAssertEqual(asked.method, method)
            XCTAssertEqual(c.trust.known.map(\.key), [a.key])
            XCTAssertTrue(b.trust.known.isEmpty)
        }
    }
}
