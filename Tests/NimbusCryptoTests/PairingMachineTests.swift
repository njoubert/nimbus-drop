// Copyright (C) 2026 Niels Joubert
// SPDX-License-Identifier: GPL-3.0-or-later
import Foundation
import XCTest
@testable import NimbusCrypto

/// The pairing transaction by itself: no socket, no listener, no thread. This target depends on
/// `NimbusCrypto` and nothing else, which is the point of that module being pure.
///
/// Two kinds of test. The first kind are attacks on the machine, each the guard of one line in
/// `scripts/mutate.py`. The second ties the code to its specification: every state the machine
/// can reach, under every event, is written out as `formal/tla/PairingImpl.tla`, and TLC checks
/// that relation against `Step` in `formal/tla/PairingMachine.tla` (`./build.sh verify`).
final class PairingMachineTests: XCTestCase {
    static let h = Data(repeating: 0x68, count: 32)
    static let own = Data(repeating: 0xAA, count: 32)
    static let peerNs = Data(repeating: 0x11, count: 32)
    static let peerNr = Data(repeating: 0x22, count: 32)
    static let theirNumber = "293699792116939100601602599741"

    /// A machine and the other end's side of the conversation, so that "a good reveal" and
    /// "the right code" can be made for whatever state the machine is in.
    struct Driver {
        var m: PairingMachine
        var randoms = 0
        /// A value for every draw; the same one, as nothing here needs two.
        var fresh = PairingMachineTests.own

        init(_ role: PairingMachine.Role, byNumber: Bool = false) {
            m = PairingMachine(role: role, byNumber: byNumber, h: PairingMachineTests.h, theirNumber: PairingMachineTests.theirNumber)
        }

        var rightCode: String {
            if m.byNumber { return PairingMachineTests.theirNumber }
            let t = PairingMachineTests.self
            return m.role == .initiator ? PairCodes.codes(h: t.h, ns: fresh, nr: t.peerNr).receiver
                                        : PairCodes.codes(h: t.h, ns: t.peerNs, nr: fresh).sender
        }

        /// One of the specification's events, made concrete.
        func event(_ name: String) -> PairingMachine.Event {
            let t = PairingMachineTests.self
            switch name {
            case "begin": return .begin
            case "timeout": return .timeout
            case "typedRight": return .typed(rightCode)
            case "typedWrong": return .typed("not it")
            case "commit": return .received(.commit, value: PairCodes.commitment(h: t.h, ns: t.peerNs))
            case "commitDamaged": return .received(.commit, value: Data(count: 5))
            case "commitMalformed": return .received(.commit, value: nil)
            case "nonce": return .received(.nonce, value: t.peerNr)
            case "nonceDamaged": return .received(.nonce, value: Data(count: 33))
            case "nonceMalformed": return .received(.nonce, value: nil)
            case "reveal": return .received(.reveal, value: t.peerNs)
            case "revealWrong": return .received(.reveal, value: Data(repeating: 0x33, count: 32))
            case "revealDamaged": return .received(.reveal, value: Data(count: 31))
            case "revealMalformed": return .received(.reveal, value: nil)
            case "paired": return .received(.paired, value: nil)
            case "failed": return .received(.failed, value: nil)
            case "other": return .received(.other, value: nil)
            default: fatalError("no such event: \(name)")
            }
        }

        @discardableResult
        mutating func take(_ name: String) -> [PairingMachine.Effect] {
            let e = event(name)
            var drawn = 0
            let value = fresh
            let out = m.step(e) { drawn += 1; return value }
            randoms += drawn
            return out
        }

        /// The state as the specification writes it.
        var state: String {
            "[role |-> \"\(m.role.rawValue)\", byNumber |-> \(m.byNumber ? "TRUE" : "FALSE"), phase |-> \"\(m.phase.rawValue)\", " +
                "tries |-> \(m.triesLeft), local |-> \(m.localRight ? "TRUE" : "FALSE"), remote |-> \(m.remoteRight ? "TRUE" : "FALSE")]"
        }
    }

    static let events = ["begin", "typedRight", "typedWrong", "timeout",
                         "commit", "commitDamaged", "commitMalformed", "nonce", "nonceDamaged", "nonceMalformed",
                         "reveal", "revealDamaged", "revealMalformed", "revealWrong", "paired", "failed", "other"]

    static func name(_ effect: PairingMachine.Effect) -> String {
        switch effect {
        case .send(let message, _): return "send \(message.rawValue)"
        case .codes: return "codes"
        case .confirming: return "confirming"
        case .otherTyped: return "otherTyped"
        case .store: return "store"
        case .fail(let why): return "fail \(why.rawValue)"
        }
    }

    static func tuple(_ effects: [PairingMachine.Effect]) -> String {
        effects.isEmpty ? "<< >>" : "<< " + effects.map { "\"\(name($0))\"" }.joined(separator: ", ") + " >>"
    }

    // MARK: The code and its specification

    /// Every state the machine reaches from its four beginnings, under every event: the whole
    /// transition relation of the Swift code, as TLA+.
    static func relation() -> (initial: [String], transitions: Set<String>) {
        var initial: [String] = []
        var seen = Set<String>()
        var queue: [Driver] = []
        for role in PairingMachine.Role.allCases {
            for byNumber in [false, true] {
                let d = Driver(role, byNumber: byNumber)
                initial.append(d.state)
                seen.insert(d.state)
                queue.append(d)
            }
        }
        var transitions = Set<String>()
        while let d = queue.popLast() {
            for e in events {
                var next = d
                let effects = next.take(e)
                transitions.insert("<< \(d.state), \"\(e)\", \(next.state), \(tuple(effects)) >>")
                if seen.insert(next.state).inserted { queue.append(next) }
            }
        }
        return (initial.sorted(), transitions)
    }

    static var implFile: URL {
        URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
            .appendingPathComponent("formal/tla/PairingImpl.tla")
    }

    /// `formal/tla/PairingImpl.tla` is exactly what this code does. After a deliberate change to
    /// the machine: `NIMBUS_WRITE_IMPL=1 swift test --filter PairingMachineTests`, then
    /// `./build.sh verify`, which fails unless `PairingMachine.tla` was changed to match.
    func testTheWrittenOutRelationIsWhatTheCodeDoes() throws {
        let (initial, transitions) = Self.relation()
        let text = """
        ---------------------------- MODULE PairingImpl ----------------------------
        \\* GENERATED from Sources/NimbusCrypto/PairingMachine.swift by PairingMachineTests
        \\* (Tests/NimbusCryptoTests). Do not edit: every state the Swift machine reaches, under
        \\* every event, with what it said to do. PairingRefinement.tla checks it against Step.

        ImplInit == {
          \(initial.joined(separator: ",\n  "))
        }

        Impl == {
          \(transitions.sorted().joined(separator: ",\n  "))
        }

        =============================================================================

        """
        if ProcessInfo.processInfo.environment["NIMBUS_WRITE_IMPL"] != nil {
            try text.write(to: Self.implFile, atomically: true, encoding: .utf8)
        }
        let onDisk = try String(contentsOf: Self.implFile, encoding: .utf8)
        XCTAssertEqual(onDisk, text, "PairingMachine.swift no longer does what formal/tla/PairingImpl.tla says; see this test's comment")
        XCTAssertEqual(transitions.count % Self.events.count, 0)
    }

    /// The walk above keeps one machine per state of the specification. That is only the whole
    /// truth if the machine's behaviour depends on nothing else, so: long random walks, and
    /// every step of every one must be in the relation.
    func testRandomWalksStayInsideTheRelation() {
        let (_, transitions) = Self.relation()
        var rng = SystemRandomNumberGenerator()
        for _ in 0..<4000 {
            var d = Driver(Bool.random(using: &rng) ? .initiator : .responder, byNumber: Int.random(in: 0..<4, using: &rng) == 0)
            for _ in 0..<12 {
                // Mostly the events that keep a pairing going, so that walks get deep.
                let good = ["begin", "commit", "nonce", "reveal", "typedRight", "typedWrong", "paired"]
                let e = Int.random(in: 0..<5, using: &rng) > 0 ? good.randomElement(using: &rng)! : Self.events.randomElement(using: &rng)!
                let before = d.state
                let effects = d.take(e)
                XCTAssertTrue(transitions.contains("<< \(before), \"\(e)\", \(d.state), \(Self.tuple(effects)) >>"), "\(before) --\(e)--> \(d.state)")
            }
        }
    }

    // MARK: Attacks on the machine

    func testTwoPeopleWhoTypeTheRightCodesPair() {
        var s = Driver(.initiator), r = Driver(.responder)
        s.fresh = Self.peerNs
        r.fresh = Self.peerNr
        XCTAssertEqual(s.take("begin").map(Self.name), ["send commit"])
        XCTAssertEqual(r.take("begin"), [])
        XCTAssertEqual(r.take("commit").map(Self.name), ["send nonce"])
        XCTAssertEqual(s.take("nonce").map(Self.name), ["send reveal", "codes"])
        XCTAssertEqual(r.take("reveal").map(Self.name), ["codes"])
        // Each shows what the other expects, and they are different codes.
        let codes = PairCodes.codes(h: Self.h, ns: Self.peerNs, nr: Self.peerNr)
        XCTAssertEqual(s.m.mine, codes.sender)
        XCTAssertEqual(r.m.mine, codes.receiver)
        XCTAssertNotEqual(s.m.mine, r.m.mine)
        XCTAssertEqual(s.m.step(.typed(r.m.mine)).map(Self.name), ["confirming", "send paired"])
        XCTAssertEqual(r.take("paired").map(Self.name), ["otherTyped"])
        XCTAssertEqual(r.m.step(.typed(s.m.mine)).map(Self.name), ["confirming", "send paired", "store"])
        XCTAssertEqual(s.take("paired").map(Self.name), ["otherTyped", "store"])
        XCTAssertEqual(s.m.phase, .paired)
        XCTAssertEqual(r.m.phase, .paired)
    }

    /// The other Mac saying "my person typed it right" pairs nobody: this Mac's own person has
    /// to have typed the right code as well. And the reverse.
    func testNeitherAnswerAloneStoresAPairing() {
        for role in PairingMachine.Role.allCases {
            var d = Driver(role)
            d.take("begin")
            if role == .initiator { d.take("nonce") } else { d.take("commit"); d.take("reveal") }
            XCTAssertEqual(d.m.phase, .codes)
            var theirsOnly = d
            XCTAssertFalse(theirsOnly.take("paired").contains(.store))
            XCTAssertNotEqual(theirsOnly.m.phase, .paired)
            var mineOnly = d
            XCTAssertFalse(mineOnly.take("typedRight").contains(.store))
            XCTAssertNotEqual(mineOnly.m.phase, .paired)
            XCTAssertTrue(theirsOnly.take("typedRight").contains(.store))
            XCTAssertTrue(mineOnly.take("paired").contains(.store))
        }
    }

    /// A reveal that does not open the commitment ends the pairing; no codes are shown.
    func testARevealThatDoesNotOpenTheCommitmentEndsIt() {
        var d = Driver(.responder)
        d.take("begin"); d.take("commit")
        XCTAssertEqual(d.take("revealWrong"), [.fail(.didNotKeep)])
        XCTAssertEqual(d.m.phase, .failed)
        XCTAssertEqual(d.m.mine, "")
    }

    /// The responder's value does not exist until the commitment has arrived: nothing is drawn
    /// before, exactly one value is drawn then.
    func testTheRespondersValueIsMadeOnlyAfterTheCommitment() {
        var d = Driver(.responder)
        d.take("begin")
        XCTAssertEqual(d.randoms, 0)
        XCTAssertEqual(d.take("commit"), [.send(.nonce, value: Self.own)])
        XCTAssertEqual(d.randoms, 1)
        d.take("reveal")
        XCTAssertEqual(d.randoms, 1)
    }

    /// A wrong code is a wrong code: three and it is over, and the code expected never changes.
    func testAWrongCodeIsNotTakenAndThreeEndIt() {
        var d = Driver(.initiator)
        d.take("begin"); d.take("nonce")
        XCTAssertEqual(d.take("typedWrong"), [.codes(mine: d.m.mine, triesLeft: 2)])
        XCTAssertFalse(d.m.localRight)
        XCTAssertEqual(d.take("typedWrong"), [.codes(mine: d.m.mine, triesLeft: 1)])
        XCTAssertEqual(d.take("typedWrong"), [.send(.failed, value: nil), .fail(.wrongCode)])
        XCTAssertEqual(d.take("typedRight"), [])
        XCTAssertEqual(d.m.phase, .failed)
    }

    /// Each message once, and only in its turn.
    func testAnythingOutOfTurnEndsIt() {
        var twice = Driver(.responder)
        twice.take("begin"); twice.take("commit")
        XCTAssertEqual(twice.take("commit"), [.fail(.didNotKeep)])

        var early = Driver(.initiator)
        early.take("begin")
        XCTAssertEqual(early.take("paired"), [.fail(.didNotKeep)])

        var saidTwice = Driver(.initiator)
        saidTwice.take("begin"); saidTwice.take("nonce"); saidTwice.take("paired")
        XCTAssertEqual(saidTwice.take("paired"), [.fail(.didNotKeep)])

        var beforeYes = Driver(.responder)
        XCTAssertEqual(beforeYes.take("commit"), [.fail(.didNotKeep)])
    }

    /// A code typed before the codes exist is typed into nothing.
    func testNothingIsTypedBeforeTheCodesAreUp() {
        var d = Driver(.initiator)
        d.take("begin")
        XCTAssertEqual(d.m.step(.typed("")), [])
        XCTAssertFalse(d.m.localRight)
        d.take("nonce")
        XCTAssertEqual(d.m.step(.typed("")), [.codes(mine: d.m.mine, triesLeft: 2)])
    }
}
