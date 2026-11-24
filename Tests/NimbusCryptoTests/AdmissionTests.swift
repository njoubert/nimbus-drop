// Copyright (C) 2026 Niels Joubert
// SPDX-License-Identifier: GPL-3.0-or-later
import Foundation
import XCTest
@testable import NimbusCrypto

/// Admission by itself: no listener, no connection, no clock. Time is a number these tests
/// make up, and the limits are small enough to fill by hand.
///
/// Two kinds of test, as for the pairing machine. The first are attacks on the machine, each
/// the guard of one line in `scripts/mutate.py`. The second ties the code to its
/// specification: every state the machine can reach at two small sets of limits, under every
/// event, is written out as `formal/tla/AdmissionImpl.tla`, and TLC checks that relation
/// against `Step` in `formal/tla/Admission.tla`, both ways (`./build.sh verify`).
final class AdmissionTests: XCTestCase {
    typealias Limits = Admission.Limits

    static func key(_ n: UInt8) -> PublicKey { PublicKey(Data(repeating: n, count: 32))! }

    // MARK: The code and its specification

    /// One set of limits the machine is walked at, and what is thrown at it there.
    struct Walk {
        let name: String
        let limits: Limits
        let addresses: [String]
        let keys: [String]
        /// How far the clock has moved since the last arrival, for the next.
        let gaps: [Int]
        /// How many drops may be in progress when a connection says it is a data connection.
        let drops: [Int]
    }

    /// Two walks, because one with every limit above one has more states than a file should
    /// hold (a million transitions). Each has the part it is named for at sizes where every
    /// branch of it is taken, and the rest at one.
    ///
    /// `pools`: three places for strangers and two an address, so that the oldest of an address
    /// is neither the oldest of the pool nor the newest; the pool of data connections with one
    /// place for each drop in progress, and none, one or two drops; two keys. The rate is one
    /// arrival in a window of no length: two at the same instant, or not.
    ///
    /// `rate`: three arrivals in a window from all and two from one address, a window of one
    /// tick, and a clock that moves by nothing, by one tick (some arrivals are forgotten and
    /// some are not) or by two (all are). One place of each kind.
    static let walks = [
        Walk(name: "Pools",
             limits: Limits(strangers: 3, strangersPerAddress: 2, arrivals: 1, arrivalsPerAddress: 1, window: 0,
                            unattachedPerDrop: 1, unattachedPerAddress: 1, unpaired: 1, pairedWaiting: 1),
             addresses: ["a", "b"], keys: ["k1", "k2"], gaps: [0, 1], drops: [0, 1, 2]),
        Walk(name: "Rate",
             limits: Limits(strangers: 1, strangersPerAddress: 1, arrivals: 3, arrivalsPerAddress: 2, window: 1,
                            unattachedPerDrop: 1, unattachedPerAddress: 1, unpaired: 1, pairedWaiting: 1),
             addresses: ["a", "b"], keys: ["k1"], gaps: [0, 1, 2], drops: [0]),
    ]

    /// A connection as the specification names one: by where it stands, not by its number.
    enum Who: Hashable {
        case stranger(Int)
        case unattached(Int)
        case unpaired
        case waiting(String)
        /// A number that holds nothing: never given out, or long gone.
        case nobody

        var tla: String {
            switch self {
            case .stranger(let i): return "<< \"stranger\", \(i) >>"
            case .unattached(let i): return "<< \"unattached\", \(i) >>"
            case .unpaired: return "<< \"unpaired\", 1 >>"
            case .waiting(let k): return "<< \"waiting\", \"\(k)\" >>"
            case .nobody: return "<< \"nobody\", 1 >>"
            }
        }
    }

    /// One of the specification's events.
    enum Happening: Hashable {
        case arrive(String, local: Bool, gap: Int)
        case data(Who, drops: Int)
        /// "mine", "retired", "unpaired", or the name of a paired key.
        case proved(Who, String)
        case attached(Who)
        case purpose(Who)
        case closed(Who)

        var tla: String {
            switch self {
            case .arrive(let a, let local, let gap): return "<< \"arrive\", \"\(a)\", \"\(local ? "local" : "elsewhere")\", \(gap) >>"
            case .data(let who, let drops): return "<< \"data\", \(who.tla), \(drops) >>"
            case .proved(let who, let what): return "<< \"proved\", \(who.tla), \"\(what)\" >>"
            case .attached(let who): return "<< \"attached\", \(who.tla) >>"
            case .purpose(let who): return "<< \"purpose\", \(who.tla) >>"
            case .closed(let who): return "<< \"closed\", \(who.tla) >>"
            }
        }
    }

    /// A machine, and what turns the specification's events into the code's: which number
    /// stands where, and what time it is.
    struct Driver {
        let walk: Walk
        var m: Admission
        /// The time of the last arrival from the local network. The specification keeps ages,
        /// the code keeps times; this is the difference.
        var clock: Double
        /// For a walk at random: which of several equal holders is meant, and a number that
        /// holds nothing. The walk of every state takes the lowest and zero.
        var pick: (Set<UInt64>) -> UInt64 = { $0.min()! }
        var stale: UInt64 = 0

        init(_ walk: Walk, clock: Double = 1000) {
            self.walk = walk
            m = Admission(limits: walk.limits)
            self.clock = clock
        }

        static func proved(_ name: String, among keys: [String]) -> Admission.Proved {
            switch name {
            case "mine": return .mine
            case "retired": return .retired
            case "unpaired": return .unpaired
            default: return .paired(AdmissionTests.key(UInt8(keys.firstIndex(of: name)! + 1)))
            }
        }

        func name(of key: PublicKey) -> String { walk.keys.first { Driver.proved($0, among: walk.keys) == .paired(key) }! }

        /// The state as the specification writes it.
        var state: String {
            let pool = { (p: [Admission.Unproved]) in p.isEmpty ? "<< >>" : "<< " + p.map { "\"\($0.address)\"" }.joined(separator: ", ") + " >>" }
            let waiting = walk.keys.map { k in "\(k) |-> \(m.waiting.values.filter { name(of: $0) == k }.count)" }.joined(separator: ", ")
            let arrivals = m.arrivals.isEmpty ? "<< >>"
                : "<< " + m.arrivals.map { "[age |-> \(Int(clock - $0.at)), from |-> \"\($0.address)\"]" }.joined(separator: ", ") + " >>"
            return "[strangers |-> \(pool(m.strangers)), unattached |-> \(pool(m.unattached)), unpaired |-> \(m.unpaired.count), "
                + "waiting |-> [\(waiting)], arrivals |-> \(arrivals)]"
        }

        /// Everyone a fact can be about, in this state.
        var whos: [Who] {
            m.strangers.indices.map { Who.stranger($0 + 1) } + m.unattached.indices.map { Who.unattached($0 + 1) }
                + (m.unpaired.isEmpty ? [] : [.unpaired])
                + walk.keys.filter { k in m.waiting.values.contains { name(of: $0) == k } }.map { Who.waiting($0) }
                + [.nobody]
        }

        /// Everything that can happen in this state: every fact about every connection, in
        /// turn or out of it.
        var happenings: [Happening] {
            var all: [Happening] = []
            for a in walk.addresses {
                for gap in walk.gaps { all.append(.arrive(a, local: true, gap: gap)) }
                all.append(.arrive(a, local: false, gap: 0))
            }
            for who in whos {
                for drops in walk.drops { all.append(.data(who, drops: drops)) }
                for what in ["mine", "retired", "unpaired"] + walk.keys { all.append(.proved(who, what)) }
                all.append(.attached(who))
                all.append(.purpose(who))
                all.append(.closed(who))
            }
            return all
        }

        func number(_ who: Who) -> UInt64 {
            switch who {
            case .stranger(let i): return m.strangers[i - 1].id
            case .unattached(let i): return m.unattached[i - 1].id
            case .unpaired: return pick(m.unpaired)
            case .waiting(let k): return pick(Set(m.waiting.filter { name(of: $0.value) == k }.keys))
            case .nobody: return stale
            }
        }

        /// Does it, and gives the answer as the specification writes it: a connection that
        /// gives way is named by its place in its pool before the event, counted from one.
        mutating func take(_ happening: Happening) -> String {
            let strangers = m.strangers.map(\.id), unattached = m.unattached.map(\.id)
            let answer: Admission.Answer
            switch happening {
            case .arrive(let a, let local, let gap):
                let now = clock + Double(gap)
                answer = m.step(.arrive(from: a, local: local, now: now))
                if local { clock = now }
            case .data(let who, let drops): answer = m.step(.data(number(who), drops: drops))
            case .proved(let who, let what): answer = m.step(.proved(number(who), Driver.proved(what, among: walk.keys)))
            case .attached(let who): answer = m.step(.attached(number(who)))
            case .purpose(let who): answer = m.step(.purpose(number(who)))
            case .closed(let who): answer = m.step(.closed(number(who)))
            }
            switch answer {
            case .admitted(_, let out): return "<< \"admitted\", \(out.map { strangers.firstIndex(of: $0)! + 1 } ?? 0) >>"
            case .moved(let out): return "<< \"moved\", \(out.map { unattached.firstIndex(of: $0)! + 1 } ?? 0) >>"
            case .close(let why): return "<< \"close\", \"\(why.rawValue)\" >>"
            case .nothing: return "<< \"nothing\" >>"
            }
        }
    }

    struct Step: Hashable {
        let from: String, event: String, to: String, answer: String
    }

    /// Every state the machine reaches from an empty listener, under every event: the whole
    /// transition relation of the Swift code at these limits.
    static func relation(_ walk: Walk) -> (start: String, steps: Set<Step>) {
        let start = Driver(walk)
        var seen: Set<String> = [start.state]
        var queue = [start]
        var steps = Set<Step>()
        while let d = queue.popLast() {
            let from = d.state
            for happening in d.happenings {
                var next = d
                let answer = next.take(happening)
                let to = next.state
                steps.insert(Step(from: from, event: happening.tla, to: to, answer: answer))
                if seen.insert(to).inserted { queue.append(next) }
            }
        }
        return (start.state, steps)
    }

    /// The relation as a TLA+ module. There are tens of thousands of transitions, so they are
    /// written as numbers: each state, event and answer once, in a list, and each step as the
    /// places of its three in those lists.
    static func module() -> String {
        var text = """
        ---------------------------- MODULE AdmissionImpl ----------------------------
        \\* GENERATED from Sources/NimbusCrypto/Admission.swift by AdmissionTests
        \\* (Tests/NimbusCryptoTests). Do not edit: every state the Swift machine reaches at two
        \\* small sets of limits, under every event, with what it answered.
        \\* AdmissionRefinement.tla checks it against Step.
        \\*
        \\* For each walk: its limits and what was thrown at it; every state reached, the empty
        \\* listener first; every event; every answer; and for each state, in the same order,
        \\* what each event did there, as << event, state after, answer >>: each the place of
        \\* one in the lists above.


        """
        for walk in walks {
            let (start, steps) = relation(walk)
            let states = [start] + Set(steps.flatMap { [$0.from, $0.to] }).subtracting([start]).sorted()
            let events = Set(steps.map(\.event)).sorted(), answers = Set(steps.map(\.answer)).sorted()
            let stateAt = Dictionary(uniqueKeysWithValues: states.enumerated().map { ($1, $0 + 1) })
            let eventAt = Dictionary(uniqueKeysWithValues: events.enumerated().map { ($1, $0 + 1) })
            let answerAt = Dictionary(uniqueKeysWithValues: answers.enumerated().map { ($1, $0 + 1) })
            var rows = [[String]](repeating: [], count: states.count)
            for s in steps.sorted(by: { (eventAt[$0.event]!, $0.from) < (eventAt[$1.event]!, $1.from) }) {
                rows[stateAt[s.from]! - 1].append("<<\(eventAt[s.event]!),\(stateAt[s.to]!),\(answerAt[s.answer]!)>>")
            }
            let l = walk.limits
            let set = { (items: [String]) in "{" + items.joined(separator: ", ") + "}" }
            text += """
            \(walk.name)Limits == [
              addresses |-> \(set(walk.addresses.map { "\"\($0)\"" })), keys |-> \(set(walk.keys.map { "\"\($0)\"" })),
              gaps |-> \(set(walk.gaps.map(String.init))), drops |-> \(set(walk.drops.map(String.init))),
              strangers |-> \(l.strangers), strangersPerAddress |-> \(l.strangersPerAddress),
              arrivals |-> \(l.arrivals), arrivalsPerAddress |-> \(l.arrivalsPerAddress), window |-> \(Int(l.window)),
              unattachedPerDrop |-> \(l.unattachedPerDrop), unattachedPerAddress |-> \(l.unattachedPerAddress),
              unpaired |-> \(l.unpaired), pairedWaiting |-> \(l.pairedWaiting)]

            \\* \(states.count) states
            \(walk.name)States == <<
              \(states.joined(separator: ",\n  "))
            >>

            \(walk.name)Events == <<
              \(events.joined(separator: ",\n  "))
            >>

            \(walk.name)Answers == <<
              \(answers.joined(separator: ",\n  "))
            >>

            \\* \(steps.count) steps
            \(walk.name)Steps == <<
              \(rows.map { "{" + $0.joined(separator: ",") + "}" }.joined(separator: ",\n  "))
            >>


            """
        }
        return text + "=============================================================================\n"
    }

    static var implFile: URL {
        URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
            .appendingPathComponent("formal/tla/AdmissionImpl.tla")
    }

    /// `formal/tla/AdmissionImpl.tla` is exactly what this code does. After a deliberate change
    /// to the machine: `NIMBUS_WRITE_IMPL=1 swift test --filter AdmissionTests`, then
    /// `./build.sh verify`, which fails unless `Admission.tla` was changed to match.
    func testTheWrittenOutRelationIsWhatTheCodeDoes() throws {
        let text = Self.module()
        if ProcessInfo.processInfo.environment["NIMBUS_WRITE_IMPL"] != nil {
            try text.write(to: Self.implFile, atomically: true, encoding: .utf8)
        }
        let onDisk = try String(contentsOf: Self.implFile, encoding: .utf8)
        // Not XCTAssertEqual: on a mismatch it would print both megabytes.
        XCTAssertTrue(onDisk == text, "Admission.swift no longer does what formal/tla/AdmissionImpl.tla says; see this test's comment")
    }

    /// The walk above keeps one machine for each state of the specification, always takes the
    /// lowest number where several stand alike, and starts its clock at one time. That is only
    /// the whole truth if the machine's behaviour depends on none of those, so: long walks at
    /// random, with other numbers, other times and numbers long gone, and every step of every
    /// one must be in the relation.
    func testRandomWalksStayInsideTheRelation() {
        var rng = SystemRandomNumberGenerator()
        for walk in Self.walks {
            let steps = Self.relation(walk).steps
            for _ in 0..<300 {
                var d = Driver(walk, clock: Double(Int.random(in: -5000...5000, using: &rng)))
                var gone: [UInt64] = [0, 7_000_000]
                d.pick = { $0.randomElement()! }
                for _ in 0..<60 {
                    let before = d.state
                    let held = Set(d.m.strangers.map(\.id) + d.m.unattached.map(\.id)).union(d.m.unpaired).union(d.m.waiting.keys)
                    d.stale = gone.randomElement(using: &rng)!
                    // Mostly arrivals and what a connection does next, so that the pools fill.
                    let all = d.happenings
                    let likely = all.filter {
                        switch $0 {
                        case .arrive(_, local: true, _), .data(.stranger, _), .proved(.stranger, _): return true
                        default: return false
                        }
                    }
                    let happening = (Int.random(in: 0..<3, using: &rng) > 0 ? likely : all).randomElement(using: &rng)!
                    let answer = d.take(happening)
                    XCTAssertTrue(steps.contains(Step(from: before, event: happening.tla, to: d.state, answer: answer)),
                                  "\(walk.name): \(before) --\(happening.tla)--> \(d.state) \(answer)")
                    let now = Set(d.m.strangers.map(\.id) + d.m.unattached.map(\.id)).union(d.m.unpaired).union(d.m.waiting.keys)
                    gone.append(contentsOf: held.subtracting(now))
                }
            }
        }
    }

    // MARK: Attacks on the machine

    /// Limits that can be filled by hand: three places for strangers and two an address, two
    /// places for data connections for each drop and two an address, two keys nobody paired,
    /// two connections of a paired key. A rate nobody reaches.
    static let small = Limits(strangers: 3, strangersPerAddress: 2, arrivals: 1000, arrivalsPerAddress: 1000, window: 1,
                              unattachedPerDrop: 2, unattachedPerAddress: 2, unpaired: 2, pairedWaiting: 2)

    /// A machine, and arrivals that are expected to be given a place.
    struct Desk {
        var m: Admission
        var now = 100.0
        init(_ limits: Limits = AdmissionTests.small) { m = Admission(limits: limits) }

        /// A connection from the local network arrives: its number, and who gave way for it.
        mutating func arrive(_ from: String, file: StaticString = #filePath, line: UInt = #line) -> (id: UInt64, out: UInt64?) {
            guard case .admitted(let id, let out) = m.step(.arrive(from: from, local: true, now: now)) else {
                XCTFail("an arrival within the rate was not given a place", file: file, line: line)
                return (0, nil)
            }
            return (id, out)
        }

        /// Everyone who holds a place of any kind.
        var held: Set<UInt64> { Set(m.strangers.map(\.id) + m.unattached.map(\.id)).union(m.unpaired).union(m.waiting.keys) }
    }

    /// F1. A pool full of connections that say nothing does not keep the next one out: it gets
    /// a place, and the one that has waited longest gives way. (The first listener refused the
    /// newcomer, and 64 silent connections kept every paired Mac out.)
    func testAFullPoolDoesNotKeepANewcomerOut() {
        var d = Desk()
        let silent = ["a", "b", "c"].map { d.arrive($0).id }
        XCTAssertEqual(d.m.strangers.map(\.id), silent)
        let late = d.arrive("d")
        XCTAssertEqual(late.out, silent[0], "the one that has waited longest gives way")
        XCTAssertEqual(d.m.strangers.map(\.id), [silent[1], silent[2], late.id], "and the newcomer has its place")
        // For as long as they keep coming.
        var last = late.id
        for i in 0..<50 {
            let next = d.arrive("e\(i)")
            XCTAssertEqual(d.m.strangers.last?.id, next.id)
            XCTAssertNotEqual(next.out, last, "never the newest")
            last = next.id
        }
    }

    /// An address that holds as many places as one address may pushes out its own oldest: not
    /// the oldest of all, which is somebody else's, and not its own newest.
    func testAnAddressAtItsLimitPushesOutItsOwnOldest() {
        var d = Desk()
        let b = d.arrive("b").id, first = d.arrive("a").id, second = d.arrive("a").id
        let third = d.arrive("a")
        XCTAssertEqual(third.out, first)
        XCTAssertEqual(d.m.strangers.map(\.id), [b, second, third.id])
        for _ in 0..<20 { XCTAssertNotEqual(d.arrive("a").out, b, "one address can only ever push out its own") }
        XCTAssertEqual(d.m.strangers.first?.id, b)
        XCTAssertEqual(d.m.strangers.filter { $0.address == "a" }.count, 2)
    }

    /// Whatever arrives, and whatever those that arrived then do: never more in a pool than it
    /// has places, nor from one address more than an address may hold.
    func testNoPoolIsEverOverItsLimit() {
        var rng = SystemRandomNumberGenerator()
        var d = Desk()
        let addresses = ["a", "b", "c", "d", "e"], keys = [Self.key(1), Self.key(2), Self.key(3)]
        for _ in 0..<6000 {
            switch Int.random(in: 0..<10, using: &rng) {
            case 0..<5: _ = d.m.step(.arrive(from: addresses.randomElement(using: &rng)!, local: true, now: d.now))
            case 5: if let s = d.m.strangers.randomElement(using: &rng) { _ = d.m.step(.data(s.id, drops: 1)) }
            case 6: if let s = d.m.strangers.randomElement(using: &rng) { _ = d.m.step(.proved(s.id, .unpaired)) }
            case 7: if let s = d.m.strangers.randomElement(using: &rng) { _ = d.m.step(.proved(s.id, .paired(keys.randomElement(using: &rng)!))) }
            case 8: if let id = d.held.randomElement(using: &rng) { _ = d.m.step(.closed(id)) }
            default: if let id = d.m.waiting.keys.randomElement(using: &rng) { _ = d.m.step(.purpose(id)) }
            }
            XCTAssertLessThanOrEqual(d.m.strangers.count, 3)
            XCTAssertLessThanOrEqual(d.m.unattached.count, 2, "two places for each drop, and there is one")
            for a in addresses {
                XCTAssertLessThanOrEqual(d.m.strangers.filter { $0.address == a }.count, 2)
                XCTAssertLessThanOrEqual(d.m.unattached.filter { $0.address == a }.count, 2)
            }
            XCTAssertLessThanOrEqual(d.m.unpaired.count, 2)
            for k in keys { XCTAssertLessThanOrEqual(d.m.waiting.values.filter { $0 == k }.count, 2) }
        }
    }

    /// The rate: so many arrivals in a window from everyone, so many from one address, and an
    /// arrival counts for exactly the window after it. Over the rate it is the newcomer that is
    /// closed, and one that was closed does not count against the next.
    func testArrivalsAreRationedInAllAndFromOneAddress() {
        var m = Admission(limits: Limits(strangers: 100, strangersPerAddress: 100, arrivals: 4, arrivalsPerAddress: 2, window: 1,
                                         unattachedPerDrop: 1, unattachedPerAddress: 1, unpaired: 1, pairedWaiting: 1))
        func arrive(_ from: String, _ now: Double) -> Admission.Answer {
            let answer = m.step(.arrive(from: from, local: true, now: now))
            if case .admitted = answer { return .nothing }
            return answer
        }
        XCTAssertEqual(arrive("a", 10), .nothing)
        XCTAssertEqual(arrive("a", 10.25), .nothing)
        XCTAssertEqual(arrive("a", 10.5), .close(.rate), "a third from one address within the window")
        XCTAssertEqual(arrive("b", 10.5), .nothing, "which is not held against another address")
        XCTAssertEqual(arrive("c", 10.5), .nothing)
        XCTAssertEqual(arrive("d", 10.75), .close(.rate), "a fifth from anyone")
        XCTAssertEqual(m.strangers.count, 4, "over the rate nobody gives way: the newcomer is closed")
        XCTAssertEqual(arrive("d", 11), .close(.rate), "the first is exactly one window old, and still counts")
        XCTAssertEqual(arrive("d", 11.125), .nothing, "now it is forgotten; and the three that were turned away never counted")
        XCTAssertEqual(arrive("e", 11.125), .close(.rate))
        XCTAssertEqual(arrive("a", 11.5), .nothing, "its first two are both more than a window ago")
        XCTAssertEqual(m.arrivals.count, 4)
    }

    /// A connection from outside the local network gets no place, pushes nobody out and is not
    /// counted against the rate: whatever arrives from elsewhere, it costs a local Mac nothing.
    func testAConnectionFromElsewhereGetsNothingAndCountsForNothing() {
        var m = Admission(limits: Limits(strangers: 2, strangersPerAddress: 2, arrivals: 3, arrivalsPerAddress: 3, window: 1,
                                         unattachedPerDrop: 1, unattachedPerAddress: 1, unpaired: 1, pairedWaiting: 1))
        guard case .admitted(let first, _) = m.step(.arrive(from: "a", local: true, now: 5)) else { return XCTFail("not admitted") }
        for _ in 0..<100 { XCTAssertEqual(m.step(.arrive(from: "far", local: false, now: 5)), .close(.elsewhere)) }
        XCTAssertEqual(m.strangers.map(\.id), [first])
        XCTAssertEqual(m.arrivals.count, 1)
        guard case .admitted = m.step(.arrive(from: "b", local: true, now: 5)) else { return XCTFail("a hundred from elsewhere used up the rate") }
        XCTAssertEqual(m.strangers.first?.id, first, "and none of them pushed anyone out")
    }

    /// A data connection when no drop is in progress has nothing to belong to: closed, and no
    /// place taken or kept.
    func testADataConnectionWithNoDropInProgressGetsNoPlace() {
        var d = Desk()
        let c = d.arrive("a").id
        XCTAssertEqual(d.m.step(.data(c, drops: 0)), .close(.noDrop))
        XCTAssertTrue(d.held.isEmpty)
    }

    /// Data connections that have not proved their drop: so many for each drop in progress, so
    /// many from one address, and at either limit the oldest gives way, as among the strangers.
    func testDataConnectionsHaveSoManyPlacesForEachDropInProgress() {
        var d = Desk()
        func data(_ from: String, drops: Int) -> (id: UInt64, out: UInt64?) {
            let c = d.arrive(from).id
            guard case .moved(let out) = d.m.step(.data(c, drops: drops)) else { XCTFail("no place"); return (c, nil) }
            XCTAssertFalse(d.m.strangers.contains { $0.id == c }, "it holds one place, not two")
            return (c, out)
        }
        let a = data("a", drops: 1), b = data("b", drops: 1)
        XCTAssertNil(a.out)
        XCTAssertNil(b.out)
        let c = data("c", drops: 1)
        XCTAssertEqual(c.out, a.id, "one drop, two places: the oldest gives way")
        let e = data("e", drops: 2), f = data("f", drops: 2)
        XCTAssertNil(e.out, "two drops, four places")
        XCTAssertNil(f.out)
        XCTAssertEqual(d.m.unattached.map(\.id), [b.id, c.id, e.id, f.id])
        let g = data("f", drops: 2), h = data("f", drops: 2)
        XCTAssertEqual(g.out, b.id, "the pool is full and f has one place of its two: the oldest of all")
        XCTAssertEqual(h.out, f.id, "f holds two: its own oldest, and not the oldest of all")
        XCTAssertEqual(d.m.unattached.map(\.id), [c.id, e.id, g.id, h.id])
    }

    /// A data connection that has proved its drop is the drop's to count, and leaves its place
    /// here for the next.
    func testAnAttachedDataConnectionLeavesItsPlace() {
        var d = Desk()
        var attached: [UInt64] = []
        for _ in 0..<10 {
            let c = d.arrive("a").id
            XCTAssertEqual(d.m.step(.data(c, drops: 1)), .moved(displacing: nil), "an attached connection was still holding a place")
            XCTAssertEqual(d.m.step(.attached(c)), .nothing)
            attached.append(c)
        }
        XCTAssertTrue(d.held.isEmpty)
    }

    /// A key nobody here has paired is one of so many at once, whoever they are, and for as
    /// long as its connection lasts: saying what it came for (a request to pair) frees nothing.
    func testAKeyNobodyPairedIsCountedForAsLongAsItsConnectionLasts() {
        var d = Desk()
        let one = d.arrive("a").id, two = d.arrive("b").id, three = d.arrive("c").id
        XCTAssertEqual(d.m.step(.proved(one, .unpaired)), .moved(displacing: nil))
        XCTAssertEqual(d.m.step(.proved(two, .unpaired)), .moved(displacing: nil))
        XCTAssertEqual(d.m.step(.proved(three, .unpaired)), .close(.tooManyUnpaired), "a third, when two is all there may be")
        XCTAssertFalse(d.held.contains(three), "and the one turned away holds nothing")
        XCTAssertEqual(d.m.step(.purpose(one)), .nothing)
        let four = d.arrive("d").id
        XCTAssertEqual(d.m.step(.proved(four, .unpaired)), .close(.tooManyUnpaired), "asking to pair does not end the counting")
        XCTAssertEqual(d.m.step(.closed(one)), .nothing)
        let five = d.arrive("e").id
        XCTAssertEqual(d.m.step(.proved(five, .unpaired)), .moved(displacing: nil), "its connection ending does")
    }

    /// A paired key is counted too, by itself, from its handshake until it says what it came
    /// for. What one key has waiting is nothing to another key, or to a key nobody paired.
    func testEachPairedKeyIsCountedByItselfUntilItSaysWhatItCameFor() {
        var d = Desk()
        let k = Self.key(1), other = Self.key(2)
        let one = d.arrive("a").id, two = d.arrive("a").id
        XCTAssertEqual(d.m.step(.proved(one, .paired(k))), .moved(displacing: nil))
        XCTAssertEqual(d.m.step(.proved(two, .paired(k))), .moved(displacing: nil))
        let three = d.arrive("a").id
        XCTAssertEqual(d.m.step(.proved(three, .paired(k))), .close(.tooManyWaiting))
        XCTAssertFalse(d.held.contains(three))
        let theirs = d.arrive("a").id, nobodys = d.arrive("a").id
        XCTAssertEqual(d.m.step(.proved(theirs, .paired(other))), .moved(displacing: nil), "another key's connections are another count")
        XCTAssertEqual(d.m.step(.proved(nobodys, .unpaired)), .moved(displacing: nil))
        XCTAssertEqual(d.m.step(.purpose(one)), .nothing)
        XCTAssertFalse(d.held.contains(one), "it has said what it came for, and is no longer counted")
        let four = d.arrive("a").id
        XCTAssertEqual(d.m.step(.proved(four, .paired(k))), .moved(displacing: nil))
        XCTAssertEqual(d.m.step(.closed(two)), .nothing)
        let five = d.arrive("a").id
        XCTAssertEqual(d.m.step(.proved(five, .paired(k))), .moved(displacing: nil), "nor one that has gone")
    }

    /// The one that gives way has proved nothing. A connection that has proved a key, paired
    /// or not, is out of the pool at that moment and no number of newcomers closes it.
    func testAConnectionThatHasProvedAKeyNeverGivesWay() {
        var d = Desk()
        let paired = d.arrive("a").id, stranger = d.arrive("a").id
        XCTAssertEqual(d.m.step(.proved(paired, .paired(Self.key(1)))), .moved(displacing: nil))
        XCTAssertEqual(d.m.step(.proved(stranger, .unpaired)), .moved(displacing: nil))
        XCTAssertTrue(d.m.strangers.isEmpty, "a connection that proved a key was left among those that have proved nothing")
        for i in 0..<200 {
            let out = d.arrive(i % 2 == 0 ? "a" : "z\(i)").out
            XCTAssertNotEqual(out, paired)
            XCTAssertNotEqual(out, stranger)
        }
        XCTAssertTrue(d.held.contains(paired))
        XCTAssertTrue(d.held.contains(stranger))
    }

    /// A connection that has given way is closed, and whatever is then said of it (it may have
    /// got its opening in, or finished its handshake, in the same instant) earns it nothing:
    /// no place, and nobody else's.
    func testAConnectionThatGaveWayGetsNothingMore() {
        var d = Desk()
        let first = d.arrive("a").id, second = d.arrive("a").id
        XCTAssertEqual(d.arrive("a").out, first)
        XCTAssertEqual(d.arrive("a").out, second)
        let before = d.m
        XCTAssertEqual(d.m.step(.data(first, drops: 1)), .close(.gone))
        XCTAssertEqual(d.m.step(.proved(second, .unpaired)), .close(.gone))
        XCTAssertEqual(d.m.step(.proved(second, .paired(Self.key(1)))), .close(.gone))
        XCTAssertEqual(d.m.step(.attached(first)), .nothing)
        XCTAssertEqual(d.m.step(.purpose(first)), .nothing)
        XCTAssertEqual(d.m.step(.closed(first)), .nothing)
        XCTAssertEqual(d.m.strangers, before.strangers)
        XCTAssertTrue(d.m.unattached.isEmpty)
        XCTAssertTrue(d.m.unpaired.isEmpty)
        XCTAssertTrue(d.m.waiting.isEmpty)
    }

    /// An address decides who waits and nothing else. The same keys doing the same things get
    /// the same answers wherever they come from, and whatever else that address is up to.
    func testWhereAKeyComesFromDecidesNothing() {
        let k = Self.key(1)
        func answers(_ addresses: [String], crowd: String?) -> [Admission.Answer] {
            var d = Desk()
            var out: [Admission.Answer] = []
            for (i, a) in addresses.enumerated() {
                if let crowd { _ = d.arrive(crowd) }
                let c = d.arrive(a).id
                out.append(d.m.step(.proved(c, i % 3 == 0 ? .unpaired : .paired(k))))
                if i == 2 { out.append(d.m.step(.purpose(c))) }
            }
            return out
        }
        let same = answers(["a", "a", "a", "a", "a", "a", "a"], crowd: "a")
        XCTAssertEqual(same, answers(["a", "b", "c", "d", "e", "f", "g"], crowd: nil))
        XCTAssertEqual(same, answers(["x", "x", "y", "y", "x", "y", "x"], crowd: "y"))
        XCTAssertTrue(same.contains(.close(.tooManyUnpaired)) && same.contains(.close(.tooManyWaiting)), "the limits were reached, so the answers say something")
    }

    /// This Mac's own key, and a key that was given up, are closed on proving themselves and
    /// counted nowhere.
    func testARetiredKeyAndThisMacsOwnGetNoPlace() {
        var d = Desk()
        let own = d.arrive("a").id, old = d.arrive("b").id
        XCTAssertEqual(d.m.step(.proved(own, .mine)), .close(.mine))
        XCTAssertEqual(d.m.step(.proved(old, .retired)), .close(.retired))
        XCTAssertTrue(d.held.isEmpty)
    }

    /// Every place is given back when its connection is gone, whatever it was: nothing is
    /// counted that nobody holds.
    func testEveryPlaceIsGivenBack() {
        var d = Desk()
        let data = d.arrive("a").id
        XCTAssertEqual(d.m.step(.data(data, drops: 1)), .moved(displacing: nil))
        let unpaired = d.arrive("b").id
        XCTAssertEqual(d.m.step(.proved(unpaired, .unpaired)), .moved(displacing: nil))
        let paired = d.arrive("b").id
        XCTAssertEqual(d.m.step(.proved(paired, .paired(Self.key(1)))), .moved(displacing: nil))
        let stranger = d.arrive("a").id
        XCTAssertEqual(d.held, [stranger, data, unpaired, paired])
        for id in [stranger, data, unpaired, paired] {
            XCTAssertEqual(d.m.step(.closed(id)), .nothing)
            XCTAssertFalse(d.held.contains(id), "a connection that is gone still holds its place")
        }
        XCTAssertTrue(d.m.strangers.isEmpty && d.m.unattached.isEmpty && d.m.unpaired.isEmpty && d.m.waiting.isEmpty)
    }
}
