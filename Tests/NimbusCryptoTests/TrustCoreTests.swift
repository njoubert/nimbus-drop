// Copyright (C) 2026 Niels Joubert
// SPDX-License-Identifier: GPL-3.0-or-later
import Foundation
import XCTest
@testable import NimbusCrypto

/// The trust store's decisions by themselves: no lock, no disk, no clock but the one a test sets.
///
/// Two kinds of test, as for the pairing machine. Attacks on the core, each the guard of a line
/// in `scripts/mutate.py`. And the tie to the specification: what the core does to one key, in
/// every state it can be in and under every event, is written out as `formal/tla/TrustImpl.tla`
/// and TLC checks that relation against `Step` in `formal/tla/TrustCore.tla`
/// (`./build.sh verify`), together with the two pieces of arithmetic (`count`, `saveDue`) as
/// tables.
final class TrustCoreTests: XCTestCase {
    static let day = 86400.0
    /// How long the key under test says it has, at every pairing.
    static let life = 30 * day

    struct Event: Hashable {
        var name: String
        var who: Set<Int> = []
        var due = false
        var diskOK = true

        var tla: String {
            "[e |-> \"\(name)\", who |-> \(TrustCoreTests.set(who)), due |-> \(due ? "TRUE" : "FALSE"), disk |-> \"\(diskOK ? "ok" : "full")\"]"
        }
    }

    static func set(_ ids: Set<Int>) -> String { ids.isEmpty ? "{}" : "{" + ids.sorted().map { "\"s\($0)\"" }.joined(separator: ", ") + "}" }
    static func eff(_ op: String, _ who: Set<Int> = []) -> String { "[op |-> \"\(op)\", who |-> \(set(who))]" }
    static func tuple(_ effects: [String]) -> String { effects.isEmpty ? "<< >>" : "<< " + effects.joined(separator: ", ") + " >>" }

    /// A store, the one key the specification is about, and the clocks.
    struct Driver {
        var core: TrustCore
        let k: PublicKey
        var clock: ClockReading
        var boots = 0

        init() {
            clock = ClockReading(boot: "boot-0", continuous: 1000, wall: Date(timeIntervalSince1970: 1_800_000_000))
            // This Mac's own key does not run out in these tests: that is not in the specification.
            // And it keeps three tombstones, not two thousand, so that one can be pushed out.
            core = TrustCore(fresh: clock, lifetime: 1e15, tombstonesKept: 3)
            k = KeyPair().publicKey
        }

        var mac: KnownMac? { core.file.known.first { $0.key == k } }
        var renewal: Renewal? { core.file.again.first { $0.key == k } }
        var tracked: Set<Int> { Set(core.sessions.filter { $0.key == k }.map(\.id)) }
        /// K has an elapsed end ahead of it, on whichever list.
        var endAhead: Double? {
            if let mac { return core.file.elapsed < mac.endsElapsed ? mac.endsElapsed : nil }
            return renewal?.endsElapsed
        }

        /// The state as the specification writes it.
        var state: String {
            let f = core.file
            let known = mac.map { f.elapsed < $0.endsElapsed ? "current" : "ranOut" } ?? "no"
            let again = renewal.map { $0.pairedAgain ? "pairedAgain" : "waiting" } ?? "no"
            let tomb = f.tombstones.first { $0.key == k }.map { $0.reason == "expired" ? "expired" : "forGood" } ?? "none"
            return "[known |-> \"\(known)\", again |-> \"\(again)\", tomb |-> \"\(tomb)\", tracked |-> \(TrustCoreTests.set(tracked)), "
                + "unsaved |-> \(core.unsaved ? "TRUE" : "FALSE")]"
        }

        /// K's elapsed end passes at a tick that reaches it (the specification's RunsOutNow).
        var runsOutNow: Bool { mac.map { core.file.elapsed < $0.endsElapsed } ?? false || renewal != nil }
        var tombstone: Tombstone? { core.file.tombstones.first { $0.key == k } }
        /// K ran out, is still on the Known list, and its tombstone was pushed out (Untombed).
        var untombed: Bool { mac.map { core.file.elapsed >= $0.endsElapsed } ?? false && tombstone == nil }

        func enabled(_ e: Event) -> Bool {
            switch e.name {
            case "track": return e.who.isDisjoint(with: tracked)
            case "prune": return e.who.isSubset(of: tracked)
            case "quiet": return e.who.isSubset(of: tracked) && (!e.due || !untombed)
            // Not while a session of an earlier pairing is running out its grace under a key
            // that is on neither list: see TrustCore.tla, "One case of it is left out".
            case "evict": return tombstone != nil && !(mac == nil && !tracked.isEmpty)
            case "k": return e.who.isSubset(of: tracked) && !e.due && endAhead != nil
            case "wallK": return e.who.isSubset(of: tracked) && !e.due && mac != nil && endAhead != nil
            case "late": return e.who.isSubset(of: tracked) && !tracked.isEmpty && (!e.due || !(runsOutNow || untombed))
            default: return true
            }
        }

        // MARK: Time

        func after(_ seconds: Double, calendar: Double? = nil) -> ClockReading {
            ClockReading(boot: clock.boot, continuous: clock.continuous + seconds, wall: clock.wall.addingTimeInterval(calendar ?? seconds))
        }

        /// What a tick at `next` finds, by the numbers: the specification's name for it.
        func found(at next: ClockReading) -> (kind: String, due: Bool) {
            let f = core.file
            let then = TrustCore.count(elapsed: f.elapsed, lastBoot: f.lastBoot, lastContinuous: f.lastContinuous, lastWall: f.lastWall, now: next)
            let late = core.sessions.contains { then > $0.deadline }
            let endPasses = (mac.map { f.elapsed < $0.endsElapsed && then >= $0.endsElapsed } ?? false) || (renewal.map { then >= $0.endsElapsed } ?? false)
            let datePasses = mac.map { then < $0.endsElapsed && next.wall >= $0.endsWall } ?? false
            let timer = TrustCore.saveDue(changed: false, unsaved: core.unsaved, sinceSave: then - core.lastSave, sinceTry: then - core.lastTry)
            if late { return ("late", !endPasses && !untombed && timer) }
            if endPasses { return ("k", false) }
            if datePasses { return ("wallK", false) }
            return ("quiet", !untombed && timer)
        }

        /// Clock readings at which a tick finds what `e` names; nil if there are none from here.
        /// May first let time pass in a way that changes nothing the specification sees.
        mutating func reading(for e: Event) -> ClockReading? {
            let f = core.file
            switch e.name {
            case "quiet": return after(e.due ? (core.unsaved ? 30 : 3601) : 0.001)
            case "k": return endAhead.map { after($0 - f.elapsed + 1) }
            case "wallK": return mac.map { after(0.001, calendar: $0.endsWall.timeIntervalSince(clock.wall) + 1) }
            case "late":
                guard let deadline = core.sessions.first?.deadline else { return nil }
                if !runsOutNow, !untombed, !e.due, deadline - f.elapsed > 2 {
                    // Up to just short of the deadline first, so that the tick across it comes
                    // too soon after the last write for another to be due.
                    let before = state
                    let quiet = after(deadline - f.elapsed - 1)
                    guard found(at: quiet).kind == "quiet" else { return nil }
                    _ = step(tick: quiet, waiting: [], diskOK: !core.unsaved)
                    guard state == before else { return nil }
                    return after(2)
                }
                return after(deadline - f.elapsed + 1)
            default: return nil
            }
        }

        // MARK: Events

        func render(_ effects: [TrustCore.Effect]) -> [String] {
            effects.compactMap { effect -> String? in
                switch effect {
                case .save: return TrustCoreTests.eff("save")
                case .end(let ending):
                    let op: String
                    switch ending.why {
                    case .withdrawn: op = "end"
                    case .duringSetUp: op = "endNew"
                    case .pastGrace: op = "endLate"
                    case .unbegun: op = "endUnbegun"
                    }
                    return TrustCoreTests.eff(op, Set(ending.sessions))
                case .tell(let key):
                    precondition(key == k, "the listeners were told of a key this test does not have")
                    return TrustCoreTests.eff("tell")
                case .log: return nil
                case .changed: return TrustCoreTests.eff("changed")
                }
            }
        }

        /// As `Trust.perform` has it: a write that was asked for is made at once, and the core
        /// is told how it went before anything else happens.
        mutating func settle(_ effects: [TrustCore.Effect], diskOK: Bool) -> [String] {
            guard effects.contains(.save) else { return render(effects) }
            return render(effects) + render(core.saved(diskOK))
        }

        mutating func step(tick next: ClockReading, waiting: Set<Int>, diskOK: Bool) -> [String] {
            let effects = core.tick(next, waiting: waiting)
            clock = next
            return settle(effects, diskOK: diskOK)
        }

        /// One of the specification's events, made concrete. Nil when it cannot be made from here.
        mutating func take(_ e: Event) -> [String]? {
            guard enabled(e) else { return nil }
            let wall = clock.wall
            switch e.name {
            case "standing":
                let name: String
                switch core.standing(of: k, wall: wall) {
                case .mine: name = "mine"
                case .paired: name = "paired"
                case .expired: name = "expired"
                case .retired: name = "retired"
                case .renew: name = "renew"
                case .unknown: name = "unknown"
                }
                return [TrustCoreTests.eff(name)]
            case "track": return settle(core.track(e.who.first!, key: k), diskOK: e.diskOK)
            case "prune":
                core.prune(e.who)
                return []
            case "retire": return settle(core.retire(k, wall: wall), diskOK: e.diskOK)
            case "forget": return settle(core.forget(k, wall: wall), diskOK: e.diskOK)
            case "gone": return settle(core.notePairingGone(k, wall: wall), diskOK: e.diskOK)
            case "removeAgain": return settle(core.removeFromAgain(k, wall: wall), diskOK: e.diskOK)
            case "reset": return settle(core.reset(told: [], wall: wall), diskOK: e.diskOK)
            case "commit": return settle([.save], diskOK: e.diskOK)
            case "evict":
                // Other keys are retired until K's tombstone is the oldest of too many.
                for _ in 0...core.tombstonesKept where tombstone != nil { _ = core.retire(KeyPair().publicKey, wall: wall) }
                return tombstone == nil ? [] : nil
            case "store":
                guard let (_, effects) = try? core.store(pairing: k, announced: "k", method: "codes", remaining: TrustCoreTests.life, major: 3,
                                                         replacing: nil, name: nil, wall: wall) else { return [TrustCoreTests.eff("refused")] }
                return settle(effects, diskOK: e.diskOK)
            case "replaced":
                // Another Mac is paired in K's place. It is forgotten again at once, so that the
                // store holds nothing but K: the specification is about one key.
                let other = KeyPair().publicKey
                guard let (_, effects) = try? core.store(pairing: other, announced: "other", method: "codes", remaining: TrustCoreTests.life, major: 3,
                                                         replacing: k, name: nil, wall: wall) else { return nil }
                let out = settle(effects, diskOK: e.diskOK)
                _ = core.forget(other, wall: wall)
                return out
            default:
                guard let next = reading(for: e), found(at: next) == (e.name, e.due) else { return nil }
                return step(tick: next, waiting: e.who, diskOK: e.diskOK)
            }
        }
    }

    static var events: [Event] {
        var all: [Event] = []
        for ok in [true, false] {
            for name in ["standing", "retire", "forget", "replaced", "gone", "store", "removeAgain", "reset", "commit", "evict"] {
                all.append(Event(name: name, diskOK: ok))
            }
            for name in ["track", "prune"] { for id in [1, 2] { all.append(Event(name: name, who: [id], diskOK: ok)) } }
            for name in ["quiet", "k", "wallK", "late"] {
                for who: Set<Int> in [[], [1], [2], [1, 2]] { for due in [false, true] { all.append(Event(name: name, who: who, due: due, diskOK: ok)) } }
            }
        }
        return all
    }

    // MARK: The code and its specification

    /// Every state of the specification the core reaches, under every event that can happen in
    /// it: the transition relation of the Swift code, as TLA+. Fails if an event the
    /// specification allows could not be made to happen.
    static func relation() -> (initial: String, transitions: Set<String>, unmade: [String]) {
        let first = Driver()
        var seen: Set<String> = [first.state]
        var queue = [first]
        var transitions = Set<String>()
        var unmade: [String] = []
        while let d = queue.popLast() {
            for e in events where d.enabled(e) {
                var next = d
                guard let effects = next.take(e) else { unmade.append("\(d.state) under \(e.tla)"); continue }
                transitions.insert("<< \(d.state), \(e.tla), \(next.state), \(tuple(effects)) >>")
                if seen.insert(next.state).inserted { queue.append(next) }
            }
        }
        return (first.state, transitions, unmade)
    }

    /// `TrustCore.count` and `TrustCore.saveDue` at every point of a small grid.
    static func tables() -> (count: [String], saveDue: [String]) {
        var count: [String] = [], due: [String] = []
        let range = 0...2
        for e in range { for same in [true, false] { for lc in range { for c in range { for lw in range { for w in range {
            let now = ClockReading(boot: same ? "a" : "b", continuous: Double(c), wall: Date(timeIntervalSince1970: Double(w)))
            let out = TrustCore.count(elapsed: Double(e), lastBoot: "a", lastContinuous: Double(lc), lastWall: Date(timeIntervalSince1970: Double(lw)), now: now)
            count.append("<< \(e), \(same ? "TRUE" : "FALSE"), \(lc), \(c), \(lw), \(w), \(Int(out)) >>")
        } } } } } }
        for changed in [false, true] { for unsaved in [false, true] { for save in [0, 3600, 3601] { for attempt in [0, 29, 30] {
            let out = TrustCore.saveDue(changed: changed, unsaved: unsaved, sinceSave: Double(save), sinceTry: Double(attempt))
            due.append("<< \(changed ? "TRUE" : "FALSE"), \(unsaved ? "TRUE" : "FALSE"), \(save), \(attempt), \(out ? "TRUE" : "FALSE") >>")
        } } } }
        return (count, due)
    }

    static var implFile: URL {
        URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
            .appendingPathComponent("formal/tla/TrustImpl.tla")
    }

    /// `formal/tla/TrustImpl.tla` is exactly what this code does. After a deliberate change to
    /// the core: `NIMBUS_WRITE_IMPL=1 swift test --filter TrustCoreTests`, then
    /// `./build.sh verify`, which fails unless `TrustCore.tla` was changed to match.
    func testTheWrittenOutRelationIsWhatTheCodeDoes() throws {
        let (initial, transitions, unmade) = Self.relation()
        XCTAssertEqual(unmade, [], "events the specification allows that this test could not make happen")
        let (count, due) = Self.tables()
        let text = """
        ------------------------------ MODULE TrustImpl ------------------------------
        \\* GENERATED from Sources/NimbusCrypto/TrustCore.swift by TrustCoreTests
        \\* (Tests/NimbusCryptoTests). Do not edit. What the Swift core does to one key: every
        \\* state it reaches, under every event that can happen there, with what it said to do;
        \\* and its two pieces of arithmetic at every point of a small grid.
        \\* TrustRefinement.tla checks all of it against TrustCore.tla.

        ImplInit == {
          \(initial)
        }

        Impl == {
          \(transitions.sorted().joined(separator: ",\n  "))
        }

        \\* << elapsed, same boot, last continuous, continuous, last wall, wall, TrustCore.count >>
        CountTable == {
          \(count.joined(separator: ",\n  "))
        }

        \\* << changed, unsaved, since the last save, since the last try, TrustCore.saveDue >>
        SaveDueTable == {
          \(due.joined(separator: ",\n  "))
        }

        =============================================================================

        """
        if ProcessInfo.processInfo.environment["NIMBUS_WRITE_IMPL"] != nil {
            try text.write(to: Self.implFile, atomically: true, encoding: .utf8)
        }
        let onDisk = try String(contentsOf: Self.implFile, encoding: .utf8)
        XCTAssertEqual(onDisk, text, "TrustCore.swift no longer does what formal/tla/TrustImpl.tla says; see this test's comment")
    }

    /// The walk above keeps one store per state of the specification. That is only the whole
    /// truth if what the core does depends on nothing else, so: long random walks through
    /// clocks that jump, reboot and run backwards, and every step of every one must be in the
    /// relation, under the name the numbers give it.
    func testRandomWalksStayInsideTheRelation() {
        let (_, transitions, _) = Self.relation()
        // Fixed seeds, so that a failure can be had again, and one from the clock, so that
        // every run also looks somewhere new. A failure prints its seed and its whole walk.
        var steps = 0
        // NIMBUS_WALK_SEEDS=200 for a longer hunt.
        let extra = Int(ProcessInfo.processInfo.environment["NIMBUS_WALK_SEEDS"] ?? "") ?? 1
        let now = UInt64(Date().timeIntervalSince1970 * 1000)
        for seed in [1, 2, 3, 0x5EED] + (0..<extra).map({ now &+ UInt64($0) &* 7919 }) {
            var rng = SplitMix(seed: seed)
            for walk in 0..<400 {
                var d = Driver()
                var trace: [String] = []
                for _ in 0..<40 {
                    guard let line = Self.walkOneStep(&d, &rng, &trace) else { continue }
                    steps += 1
                    guard transitions.contains(line) else {
                        return XCTFail("seed \(seed), walk \(walk): not in the relation: \(line)\nthe walk:\n  " + trace.joined(separator: "\n  "))
                    }
                }
            }
        }
        XCTAssertGreaterThan(steps, 40000)
    }

    /// A generator that gives the same numbers for the same seed.
    struct SplitMix: RandomNumberGenerator {
        var state: UInt64
        init(seed: UInt64) { state = seed }
        mutating func next() -> UInt64 {
            state &+= 0x9E37_79B9_7F4A_7C15
            var z = state
            z = (z ^ (z >> 30)) &* 0xBF58_476D_1CE4_E5B9
            z = (z ^ (z >> 27)) &* 0x94D0_49BB_1331_11EB
            return z ^ (z >> 31)
        }
    }

    static let walkEvents = ["standing", "retire", "forget", "replaced", "gone", "store", "store", "store", "removeAgain", "reset", "commit", "evict",
                             "track", "track", "track", "prune", "tick", "tick", "tick", "tick", "tick", "tick"]

    /// One step of a walk: an event at random, made concrete at random. Returns the step as the
    /// relation writes it, or nil when the event could not happen from here.
    static func walkOneStep(_ d: inout Driver, _ rng: inout SplitMix, _ trace: inout [String]) -> String? {
        let before = d.state
        let ok = Int.random(in: 0..<4, using: &rng) > 0
        var e = Event(name: walkEvents.randomElement(using: &rng)!, diskOK: ok)
        let effects: [String]
        if e.name == "tick" {
            let waiting = d.tracked.filter { _ in Bool.random(using: &rng) }
            var next: ClockReading
            var how: String
            switch Int.random(in: 0..<10, using: &rng) {
            case 0: next = d.after(30); how = "+30 s"
            case 1: next = d.after(3601); how = "+3601 s"
            case 2: next = d.after((d.endAhead ?? 0) - d.core.file.elapsed + 1); how = "to the key's end"
            case 3: next = d.after(0.5, calendar: (d.mac?.endsWall.timeIntervalSince(d.clock.wall) ?? 0) + 1); how = "the calendar to the key's date"
            case 4: next = d.after((d.core.sessions.first?.deadline ?? 0) - d.core.file.elapsed + 1); how = "to the sessions' deadline"
            case 5: next = d.after(max(0.001, (d.core.sessions.first?.deadline ?? 0) - d.core.file.elapsed - 1)); how = "to just short of the deadline"
            case 6:
                // A reboot, with the calendar wherever someone has put it.
                d.boots += 1
                let up = Double.random(in: 0...50, using: &rng), calendar = Double.random(in: -400 * day...400 * day, using: &rng)
                next = ClockReading(boot: "boot-\(d.boots)", continuous: up, wall: d.clock.wall.addingTimeInterval(calendar))
                how = "a reboot, up \(up) s, the calendar moved \(calendar) s"
            case 7:
                let back = Double.random(in: 0...100 * day, using: &rng)
                next = d.after(1, calendar: -back)
                how = "+1 s, the calendar set back \(back) s"
            default: next = d.after(0.001); how = "+1 ms"
            }
            if next.continuous < d.clock.continuous, next.boot == d.clock.boot { next.continuous = d.clock.continuous }
            let (kind, due) = d.found(at: next)
            e = Event(name: kind, who: waiting, due: due, diskOK: ok)
            trace.append("tick (\(how)) = \(e.tla)   elapsed \(d.core.file.elapsed), deadlines \(d.core.sessions.map(\.deadline))")
            // Every session of the key has one deadline here, or "late" would not be one event.
            precondition(Set(d.core.sessions.map(\.deadline)).count <= 1, "sessions with different deadlines:\n  " + trace.joined(separator: "\n  "))
            effects = d.step(tick: next, waiting: waiting, diskOK: ok)
        } else {
            if e.name == "track" || e.name == "prune" { e.who = [Bool.random(using: &rng) ? 1 : 2] }
            guard let made = d.take(e) else { return nil }
            trace.append("\(e.tla)   elapsed \(d.core.file.elapsed), key ends \(d.mac?.endsElapsed ?? d.renewal?.endsElapsed ?? -1)")
            effects = made
        }
        return "<< \(before), \(e.tla), \(d.state), \(tuple(effects)) >>"
    }

    // MARK: Attacks on the core

    func paired() -> Driver {
        var d = Driver()
        XCTAssertNotNil(d.take(Event(name: "store")))
        return d
    }

    /// The finding of `TrustWithdraw.tla`, at the core: a session that registers under a key
    /// whose trust has gone is ended there, and is not on the list.
    func testASessionDoesNotRegisterUnderAKeyThatIsNoLongerPaired() {
        var d = paired()
        _ = d.take(Event(name: "forget"))
        XCTAssertEqual(d.take(Event(name: "track", who: [1])), [Self.eff("endNew", [1])])
        XCTAssertEqual(d.tracked, [])
    }

    /// Written to disk, then the sessions ended, then the listeners told: in that order.
    func testAWithdrawalIsWrittenBeforeAnythingIsEnded() {
        var d = paired()
        _ = d.take(Event(name: "track", who: [1]))
        _ = d.take(Event(name: "track", who: [2]))
        XCTAssertEqual(d.take(Event(name: "retire")), [Self.eff("save"), Self.eff("end", [1, 2]), Self.eff("tell"), Self.eff("changed")])
        XCTAssertEqual(d.tracked, [])
        XCTAssertEqual(d.take(Event(name: "standing")), [Self.eff("retired")])
        XCTAssertEqual(d.take(Event(name: "store")), [Self.eff("refused")], "a retired key cannot be paired again")
    }

    /// Reset Identity ends every session, also one whose key has dropped off both lists: its
    /// calendar date passed, then its elapsed end, and its drop was running out its day of grace.
    func testAResetEndsASessionWhoseKeyIsOnNeitherList() {
        var d = paired()
        _ = d.take(Event(name: "track", who: [1]))
        XCTAssertNotNil(d.take(Event(name: "wallK")))
        XCTAssertNotNil(d.take(Event(name: "k")))
        XCTAssertNil(d.mac)
        XCTAssertNil(d.renewal)
        XCTAssertEqual(d.tracked, [1], "it may finish, within the time allowed")
        let effects = d.take(Event(name: "reset")) ?? []
        XCTAssertTrue(effects.contains(Self.eff("end", [1])), "\(effects)")
        XCTAssertEqual(d.tracked, [])
    }

    /// Remove, on the pair-again list, ends what that Mac still has running. It gets on the
    /// list with a drop running when the calendar passes its date mid-drop.
    func testRemovingAMacFromThePairAgainListEndsWhatItHadRunning() {
        var d = paired()
        _ = d.take(Event(name: "track", who: [2]))
        XCTAssertNotNil(d.take(Event(name: "wallK")))
        XCTAssertNotNil(d.renewal, "the calendar passed its date: to be paired again")
        XCTAssertEqual(d.tracked, [2], "and its drop may finish")
        XCTAssertEqual(d.take(Event(name: "removeAgain")), [Self.eff("save"), Self.eff("end", [2]), Self.eff("tell"), Self.eff("changed")])
        XCTAssertEqual(d.tracked, [])
        XCTAssertNil(d.renewal)
    }

    /// "Refused for good" lasts as long as the tombstone does: the store keeps a bounded number,
    /// and when a retired key's is pushed out by later ones the key is an unknown key again.
    /// Not trusted, not on any list; but two people may pair it afresh, and nothing else can.
    func testARetiredKeyWhoseTombstoneWasPushedOutIsUnknownAndNotTrusted() {
        var d = paired()
        _ = d.take(Event(name: "retire"))
        XCTAssertEqual(d.take(Event(name: "store")), [Self.eff("refused")])
        XCTAssertEqual(d.take(Event(name: "evict")), [])
        XCTAssertEqual(d.take(Event(name: "standing")), [Self.eff("unknown")], "nothing trusts it")
        XCTAssertEqual(d.take(Event(name: "track", who: [1])), [Self.eff("endNew", [1])], "and nothing it authenticates may begin")
        XCTAssertEqual(d.take(Event(name: "store")), [Self.eff("save"), Self.eff("changed")], "until two people pair it again")
    }

    /// A key that ran out and is still listed gets its tombstone back at the next tick, if it
    /// was pushed out: it stays refused, and cannot be paired again.
    func testAKeyThatRanOutIsTombstonedAgainIfItsTombstoneWasPushedOut() {
        var d = paired()
        XCTAssertNotNil(d.take(Event(name: "k")))
        XCTAssertEqual(d.take(Event(name: "evict")), [])
        XCTAssertEqual(d.take(Event(name: "standing")), [Self.eff("expired")])
        XCTAssertEqual(d.take(Event(name: "store")), [Self.eff("refused")])
        XCTAssertEqual(d.take(Event(name: "quiet")), [Self.eff("save"), Self.eff("changed")])
        XCTAssertNotNil(d.tombstone)
    }

    /// A write that failed is tried again twice a minute, not at every tick: on a full disk the
    /// hourly write used to be attempted, and logged, every time anything asked who a key was.
    func testAFailedWriteIsNotTriedAgainAtEveryTick() {
        var d = Driver()
        XCTAssertEqual(d.step(tick: d.after(3601), waiting: [], diskOK: false), [Self.eff("save"), Self.eff("changed")])
        XCTAssertTrue(d.core.unsaved)
        for _ in 0..<20 { XCTAssertEqual(d.step(tick: d.after(1), waiting: [], diskOK: false), [], "a second attempt within thirty seconds") }
        XCTAssertEqual(d.step(tick: d.after(10), waiting: [], diskOK: true), [Self.eff("save"), Self.eff("changed")])
        XCTAssertFalse(d.core.unsaved)
    }

    /// The count never goes back and never misses time the Mac was up, whatever the calendar says.
    func testTheCountIsAtLeastTheTimeTheMacWasUp() {
        let t0 = Date(timeIntervalSince1970: 1_800_000_000)
        func count(_ last: (String, Double, Double), _ now: (String, Double, Double)) -> Double {
            TrustCore.count(elapsed: 100, lastBoot: last.0, lastContinuous: last.1, lastWall: t0.addingTimeInterval(last.2),
                            now: ClockReading(boot: now.0, continuous: now.1, wall: t0.addingTimeInterval(now.2)))
        }
        XCTAssertEqual(count(("a", 50, 0), ("a", 80, -1e6)), 130, "the same boot: the continuous clock, whatever the calendar did")
        XCTAssertEqual(count(("a", 50, 0), ("b", 20, -1e6)), 120, "after a reboot with the calendar set back: the time since boot")
        XCTAssertEqual(count(("a", 50, 0), ("b", 20, 500)), 600, "after a reboot: the calendar's gap, when that is more")
        XCTAssertEqual(count(("a", 50, 0), ("a", 40, 0)), 100, "never less than before")
    }
}
