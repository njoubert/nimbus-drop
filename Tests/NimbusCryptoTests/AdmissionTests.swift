// Copyright (C) 2026 Niels Joubert
// SPDX-License-Identifier: GPL-3.0-or-later
import Foundation
import XCTest
@testable import NimbusCrypto

/// Admission by itself: no listener, no connection, no clock. Time is a number these tests
/// make up, and the limits are small enough to fill by hand.
///
/// Three kinds of test. Attacks on the machine, each the guard of one line in
/// `scripts/mutate.py`. The tie to the specification: every state the machine can reach at two
/// small sets of limits, under every event, is written out as `formal/tla/AdmissionImpl.tla`,
/// and TLC checks that relation against `Step` in `formal/tla/Admission.tla`, both ways
/// (`./build.sh verify`). And what that tie leaves out, tried at random: the abstraction
/// (`Naming`, `abstract`, `label`, `answer` below; the contract is at the top of Admission.tla)
/// keeps one machine for each state of the specification, so walks with other numbers, other
/// addresses, other keys, other times and long histories must stay inside the relation; and
/// at limits nobody wrote out, every step is held to the rule said a second time (`World`).
final class AdmissionTests: XCTestCase {
    typealias Limits = Admission.Limits

    static func key(_ n: UInt8) -> PublicKey { PublicKey(Data(repeating: n, count: 32))! }

    // MARK: Chance, with a seed

    /// SplitMix64: the walks are random, and a walk that fails can be had again.
    struct Seeded: RandomNumberGenerator {
        var state: UInt64
        mutating func next() -> UInt64 {
            state &+= 0x9E37_79B9_7F4A_7C15
            var z = state
            z = (z ^ (z >> 30)) &* 0xBF58_476D_1CE4_E5B9
            z = (z ^ (z >> 27)) &* 0x94D0_49BB_1331_11EB
            return z ^ (z >> 31)
        }
    }

    /// `NIMBUS_SEED=… swift test --filter AdmissionTests` repeats a run.
    static func seed() -> UInt64 {
        ProcessInfo.processInfo.environment["NIMBUS_SEED"].flatMap { UInt64($0) } ?? UInt64.random(in: 0...UInt64.max)
    }

    static func randomKey(using rng: inout Seeded) -> PublicKey {
        while true {
            var bytes = (0..<32).map { _ in UInt8.random(in: 0...255, using: &rng) }
            bytes[31] &= 0x7f
            if let key = PublicKey(Data(bytes)) { return key }
        }
    }

    static func randomAddress(using rng: inout Seeded) -> String {
        Bool.random(using: &rng)
            ? "10.\(Int.random(in: 0...255, using: &rng)).\(Int.random(in: 0...255, using: &rng)).\(Int.random(in: 1...254, using: &rng))"
            : "fe80::\(String(UInt32.random(in: 1...UInt32.max, using: &rng), radix: 16))%en\(Int.random(in: 0...9, using: &rng))"
    }

    // MARK: The code and its specification

    /// One set of limits the machine is walked at, and what is thrown at it there, in the
    /// specification's terms: names for addresses and keys, time in whole ticks.
    struct Walk {
        let name: String
        /// `window` in ticks.
        let limits: Limits
        let addresses: [String]
        let keys: [String]
        /// How far the clock has moved since the last arrival from the local network, for the
        /// next: from one tick more than the window (everything is forgotten) to as far BACK
        /// (everything counted is from later than now, and is forgotten too).
        let gaps: [Int]
        /// How many drops may be in progress when a connection says it is a data connection.
        let drops: [Int]

        var window: Int { Int(limits.window) }
    }

    /// Four walks, because one with every limit above one has more states than a file should
    /// hold (millions of transitions). Each has the part it is named for at sizes where every
    /// branch of it is taken, and the rest at one, or (paired keys) not there at all.
    ///
    /// `Pools`: three places for strangers and two an address, so that the oldest of an address
    /// is neither the oldest of the pool nor the newest; the pool of data connections with one
    /// place for each drop in progress, and none, one or two drops. The rate is one arrival in
    /// a window of no length: two at the same instant, or not, or a clock set back.
    ///
    /// `Rate`: three arrivals in a window from all and two from one address, a window of one
    /// tick, and a clock that moves by nothing, by one tick (some arrivals are forgotten and
    /// some are not) or by two (all are), forward or back.
    ///
    /// `Keys`: three places for keys nobody paired and two an address, any of them having asked
    /// or not: the oldest of an address that has asked for nothing is neither the oldest of
    /// all, nor the oldest of its address, nor the newest. One paired key beside them.
    ///
    /// `Waiting`: two paired keys, each counted by itself, and a key nobody paired.
    static let walks = [
        Walk(name: "Pools",
             limits: Limits(strangers: 3, strangersPerAddress: 2, arrivals: 1, arrivalsPerAddress: 1, window: 0,
                            unattachedPerDrop: 1, unattachedPerAddress: 1, unpaired: 1, unpairedPerAddress: 1, pairedWaiting: 1),
             addresses: ["a", "b"], keys: [], gaps: [-1, 0, 1], drops: [0, 1, 2]),
        Walk(name: "Rate",
             limits: Limits(strangers: 1, strangersPerAddress: 1, arrivals: 3, arrivalsPerAddress: 2, window: 1,
                            unattachedPerDrop: 1, unattachedPerAddress: 1, unpaired: 1, unpairedPerAddress: 1, pairedWaiting: 1),
             addresses: ["a", "b"], keys: [], gaps: [-2, -1, 0, 1, 2], drops: [0]),
        Walk(name: "Keys",
             limits: Limits(strangers: 1, strangersPerAddress: 1, arrivals: 1, arrivalsPerAddress: 1, window: 0,
                            unattachedPerDrop: 1, unattachedPerAddress: 1, unpaired: 3, unpairedPerAddress: 2, pairedWaiting: 1),
             addresses: ["a", "b"], keys: ["k1"], gaps: [-1, 0, 1], drops: [0]),
        Walk(name: "Waiting",
             limits: Limits(strangers: 1, strangersPerAddress: 1, arrivals: 1, arrivalsPerAddress: 1, window: 0,
                            unattachedPerDrop: 1, unattachedPerAddress: 1, unpaired: 1, unpairedPerAddress: 1, pairedWaiting: 1),
             addresses: ["a", "b"], keys: ["k1", "k2"], gaps: [-1, 0, 1], drops: [0]),
    ]

    /// What the specification is not told: which strings its addresses are, which keys its
    /// keys, how long a tick is and when the clock started. The walk that is written out uses
    /// one naming; the walks at random use others, and must get the same relation.
    struct Naming {
        /// The specification's name for each address, and for each paired key.
        var addresses: [String: String]
        var keys: [PublicKey: String]
        /// One tick of the specification's time, in the machine's.
        var tick: Double
        /// The time of an arrival when there has been none before it.
        var origin: Double

        /// a, b … are "a", "b" …; k1, k2 … are thirty-two bytes of 1, of 2 …; a tick is 1; time starts at 1000.
        static func plain(_ walk: Walk) -> Naming {
            Naming(addresses: Dictionary(uniqueKeysWithValues: walk.addresses.map { ($0, $0) }),
                   keys: Dictionary(uniqueKeysWithValues: walk.keys.enumerated().map { (AdmissionTests.key(UInt8($0 + 1)), $1) }),
                   tick: 1, origin: 1000)
        }

        /// Other addresses, other keys, another length of tick (a power of two, so that whole
        /// ticks stay exact), another beginning.
        static func random(_ walk: Walk, using rng: inout Seeded) -> Naming {
            var addresses: [String: String] = [:], keys: [PublicKey: String] = [:]
            for name in walk.addresses.shuffled(using: &rng) {
                var a = AdmissionTests.randomAddress(using: &rng)
                while addresses[a] != nil { a = AdmissionTests.randomAddress(using: &rng) }
                addresses[a] = name
            }
            for name in walk.keys { keys[AdmissionTests.randomKey(using: &rng)] = name }
            let tick = [0.125, 0.5, 1, 2, 64, 4096].randomElement(using: &rng)!
            return Naming(addresses: addresses, keys: keys, tick: tick, origin: tick * Double(Int.random(in: -1_000_000...1_000_000, using: &rng)))
        }

        func address(named name: String) -> String { addresses.first { $0.value == name }!.key }
        func key(named name: String) -> PublicKey { keys.first { $0.value == name }!.key }

        /// The machine's limits for a walk's: the window is so many ticks.
        func limits(_ walk: Walk) -> Limits {
            var l = walk.limits
            l.window = Double(walk.window) * tick
            return l
        }
    }

    /// A connection as the specification names one: by where it stands, not by its number.
    enum Who: Hashable {
        case stranger(Int)
        case unattached(Int)
        case unpaired(Int)
        case waiting(String)
        /// A number that holds nothing: never given out, or long gone.
        case nobody

        var tla: String {
            switch self {
            case .stranger(let i): return "<< \"stranger\", \(i) >>"
            case .unattached(let i): return "<< \"unattached\", \(i) >>"
            case .unpaired(let i): return "<< \"unpaired\", \(i) >>"
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
        /// So many drops are in progress now.
        case drops(Int)

        var tla: String {
            switch self {
            case .arrive(let a, let local, let gap): return "<< \"arrive\", \"\(a)\", \"\(local ? "local" : "elsewhere")\", \(gap) >>"
            case .data(let who, let drops): return "<< \"data\", \(who.tla), \(drops) >>"
            case .proved(let who, let what): return "<< \"proved\", \(who.tla), \"\(what)\" >>"
            case .attached(let who): return "<< \"attached\", \(who.tla) >>"
            case .purpose(let who): return "<< \"purpose\", \(who.tla) >>"
            case .closed(let who): return "<< \"closed\", \(who.tla) >>"
            case .drops(let n): return "<< \"drops\", \(n) >>"
            }
        }
    }

    // The abstraction, as three functions of the machine's value and nothing else (the
    // contract in words is at the top of formal/tla/Admission.tla).

    /// The specification's state for a machine's value.
    static func abstract(_ m: Admission, _ walk: Walk, _ n: Naming) -> String {
        let pool = { (p: [Admission.Unproved]) in p.isEmpty ? "<< >>" : "<< " + p.map { "\"\(n.addresses[$0.address]!)\"" }.joined(separator: ", ") + " >>" }
        let waiting = walk.keys.map { k in "\(k) |-> \(m.waiting.values.filter { n.keys[$0] == k }.count)" }.joined(separator: ", ")
        let age = { (a: Admission.Arrival) in Int(((m.asOf! - a.at) / n.tick).rounded()) }
        let arrivals = m.arrivals.isEmpty ? "<< >>"
            : "<< " + m.arrivals.map { "[age |-> \(age($0)), from |-> \"\(n.addresses[$0.address]!)\"]" }.joined(separator: ", ") + " >>"
        let unpaired = m.unpaired.isEmpty ? "<< >>"
            : "<< " + m.unpaired.map { "[from |-> \"\(n.addresses[$0.address]!)\", asked |-> \($0.asked ? "TRUE" : "FALSE")]" }.joined(separator: ", ") + " >>"
        // (With no paired key at all, the function from keys to counts is the empty one.)
        return "[strangers |-> \(pool(m.strangers)), unattached |-> \(pool(m.unattached)), unpaired |-> \(unpaired), "
            + "waiting |-> \(walk.keys.isEmpty ? "<< >>" : "[\(waiting)]"), arrivals |-> \(arrivals)]"
    }

    /// Whom a number is, in a machine's value.
    static func who(_ id: UInt64, in m: Admission, _ n: Naming) -> Who {
        if let i = m.strangers.firstIndex(where: { $0.id == id }) { return .stranger(i + 1) }
        if let i = m.unattached.firstIndex(where: { $0.id == id }) { return .unattached(i + 1) }
        if let i = m.unpaired.firstIndex(where: { $0.id == id }) { return .unpaired(i + 1) }
        if let key = m.waiting[id] { return .waiting(n.keys[key]!) }
        return .nobody
    }

    /// The specification's event for one of the machine's, in the state it is given in: what
    /// the numbers say. Nil when the specification has no such event at this walk's sizes.
    static func label(_ event: Admission.Event, in m: Admission, _ walk: Walk, _ n: Naming) -> Happening? {
        switch event {
        case .arrive(let from, let local, let now):
            guard let name = n.addresses[from] else { return nil }
            guard local else { return .arrive(name, local: false, gap: 0) }
            let ticks = (now - (m.asOf ?? n.origin)) / n.tick
            guard ticks == ticks.rounded(), walk.gaps.min() == -walk.window - 1, walk.gaps.max() == walk.window + 1 else { return nil }
            // More than a window on forgets everything, however much more; and so does more
            // than a window back.
            return .arrive(name, local: true, gap: Int(max(Double(-walk.window - 1), min(ticks, Double(walk.window + 1)))))
        case .data(let id, let drops):
            return walk.drops.contains(drops) ? .data(who(id, in: m, n), drops: drops) : nil
        case .proved(let id, let what):
            switch what {
            case .mine: return .proved(who(id, in: m, n), "mine")
            case .retired: return .proved(who(id, in: m, n), "retired")
            case .unpaired: return .proved(who(id, in: m, n), "unpaired")
            case .paired(let key): return n.keys[key].map { .proved(who(id, in: m, n), $0) }
            }
        case .attached(let id): return .attached(who(id, in: m, n))
        case .purpose(let id): return .purpose(who(id, in: m, n))
        case .closed(let id): return .closed(who(id, in: m, n))
        case .drops(let count): return walk.drops.contains(count) ? .drops(count) : nil
        }
    }

    /// The specification's answer for one of the machine's, given the value it was asked in:
    /// WHO gives way is said by its place in its pool before the event, counted from one (for
    /// a data connection the pool of those that have not attached; for a key nobody paired,
    /// the pool of those).
    static func answer(_ answer: Admission.Answer, before m: Admission) -> String {
        switch answer {
        case .admitted(_, let out): return "<< \"admitted\", \(out.map { id in m.strangers.firstIndex { $0.id == id }! + 1 } ?? 0) >>"
        case .moved(let out):
            let place = out.map { id in (m.unattached.firstIndex { $0.id == id } ?? m.unpaired.firstIndex { $0.id == id }!) + 1 }
            return "<< \"moved\", \(place ?? 0) >>"
        case .close(let why): return "<< \"close\", \"\(why.rawValue)\" >>"
        case .giveWay(let out):
            // The specification says how many give way, and means the ones that have waited longest.
            guard out == m.unattached.prefix(out.count).map(\.id) else { return "<< \"giveWay\", \"not the oldest\" >>" }
            return "<< \"giveWay\", \(out.count) >>"
        case .nothing: return "<< \"nothing\" >>"
        }
    }

    /// A machine under one naming, and what turns the specification's events into its own.
    struct Driver {
        let walk: Walk
        let naming: Naming
        var m: Admission
        /// Every number given out so far: an arrival must be given a new one.
        var given = Set<UInt64>()
        /// For a walk at random: which of several connections of one paired key is meant, and a
        /// number that holds nothing. The walk of every state takes the lowest, and zero.
        var pick: (Set<UInt64>) -> UInt64 = { $0.min()! }
        var stale: UInt64 = 0

        init(_ walk: Walk, _ naming: Naming? = nil) {
            self.walk = walk
            self.naming = naming ?? .plain(walk)
            m = Admission(limits: self.naming.limits(walk))
        }

        var state: String { AdmissionTests.abstract(m, walk, naming) }
        var held: Set<UInt64> { Set(m.strangers.map(\.id) + m.unattached.map(\.id) + m.unpaired.map(\.id)).union(m.waiting.keys) }

        /// Everyone a fact can be about, in this state.
        var whos: [Who] {
            m.strangers.indices.map { Who.stranger($0 + 1) } + m.unattached.indices.map { Who.unattached($0 + 1) }
                + m.unpaired.indices.map { Who.unpaired($0 + 1) }
                + walk.keys.filter { k in m.waiting.values.contains { naming.keys[$0] == k } }.map { Who.waiting($0) }
                + [.nobody]
        }

        /// Everything the specification says can happen in this state: every fact about every
        /// connection, in turn or out of it.
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
            for drops in walk.drops { all.append(.drops(drops)) }
            return all
        }

        func number(_ who: Who) -> UInt64 {
            switch who {
            case .stranger(let i): return m.strangers[i - 1].id
            case .unattached(let i): return m.unattached[i - 1].id
            case .unpaired(let i): return m.unpaired[i - 1].id
            case .waiting(let k): return pick(Set(m.waiting.filter { naming.keys[$0.value] == k }.keys))
            case .nobody: return stale
            }
        }

        /// One of the machine's events that the specification calls `happening`, here.
        func make(_ happening: Happening) -> Admission.Event {
            switch happening {
            case .arrive(let a, let local, let gap):
                return .arrive(from: naming.address(named: a), local: local, now: (m.asOf ?? naming.origin) + Double(gap) * naming.tick)
            case .data(let who, let drops): return .data(number(who), drops: drops)
            case .proved(let who, let what):
                switch what {
                case "mine": return .proved(number(who), .mine)
                case "retired": return .proved(number(who), .retired)
                case "unpaired": return .proved(number(who), .unpaired)
                default: return .proved(number(who), .paired(naming.key(named: what)))
                }
            case .attached(let who): return .attached(number(who))
            case .purpose(let who): return .purpose(number(who))
            case .closed(let who): return .closed(number(who))
            case .drops(let n): return .drops(n)
            }
        }

        /// Gives the machine one of its own events; returns the answer as the specification
        /// writes it. Nil (and a failed test) if an arrival was given a number given before.
        mutating func take(_ event: Admission.Event) -> String? {
            let before = m
            let answer = m.step(event)
            if case .admitted(let id, _) = answer, !given.insert(id).inserted {
                XCTFail("an arrival was given the number \(id), which another had")
                return nil
            }
            return AdmissionTests.answer(answer, before: before)
        }
    }

    struct Step: Hashable {
        let from: String, event: String, to: String, answer: String
    }

    /// Every state the machine reaches from an empty listener, under every event: the whole
    /// transition relation of the Swift code at these limits. `unmade`: events the
    /// specification has that could not be made to happen (there must be none).
    static func relation(_ walk: Walk) -> (start: String, steps: Set<Step>, unmade: [String]) {
        let start = Driver(walk)
        var seen: Set<String> = [start.state]
        var queue = [start]
        var steps = Set<Step>()
        var unmade: [String] = []
        while let d = queue.popLast() {
            let from = d.state
            for happening in d.happenings {
                var next = d
                let event = d.make(happening)
                // What was made must be what was meant, by the numbers.
                guard label(event, in: d.m, walk, d.naming) == happening, let answer = next.take(event) else {
                    unmade.append("\(from) under \(happening.tla)")
                    continue
                }
                let to = next.state
                steps.insert(Step(from: from, event: happening.tla, to: to, answer: answer))
                if seen.insert(to).inserted { queue.append(next) }
            }
        }
        return (start.state, steps, unmade)
    }

    /// The relation as a TLA+ module. There are tens of thousands of transitions, so they are
    /// written as numbers: each state, event and answer once, in a list, and each step as the
    /// places of its three in those lists.
    static func module() -> (text: String, unmade: [String]) {
        var text = """
        ---------------------------- MODULE AdmissionImpl ----------------------------
        \\* GENERATED from Sources/NimbusCrypto/Admission.swift by AdmissionTests
        \\* (Tests/NimbusCryptoTests). Do not edit: every state the Swift machine reaches at two
        \\* small sets of limits, under every event, with what it answered.
        \\* AdmissionRefinement.tla checks it against Step.
        \\*
        \\* For each walk: its limits and what was thrown at it; every state reached, the empty
        \\* listener first; every event; every answer; and for each state, in the same order,
        \\* what each event did there, three numbers a step and one step after another:
        \\* event, state after, answer, each the place of one in the lists above.
        EXTENDS Integers


        """
        var unmade: [String] = []
        for walk in walks {
            let (start, steps, missing) = relation(walk)
            unmade += missing
            let states = [start] + Set(steps.flatMap { [$0.from, $0.to] }).subtracting([start]).sorted()
            let events = Set(steps.map(\.event)).sorted(), answers = Set(steps.map(\.answer)).sorted()
            let stateAt = Dictionary(uniqueKeysWithValues: states.enumerated().map { ($1, $0 + 1) })
            let eventAt = Dictionary(uniqueKeysWithValues: events.enumerated().map { ($1, $0 + 1) })
            let answerAt = Dictionary(uniqueKeysWithValues: answers.enumerated().map { ($1, $0 + 1) })
            var rows = [[String]](repeating: [], count: states.count)
            for s in steps.sorted(by: { (eventAt[$0.event]!, $0.from) < (eventAt[$1.event]!, $1.from) }) {
                rows[stateAt[s.from]! - 1].append("\(eventAt[s.event]!),\(stateAt[s.to]!),\(answerAt[s.answer]!)")
            }
            let l = walk.limits
            let set = { (items: [String]) in "{" + items.joined(separator: ", ") + "}" }
            text += """
            \(walk.name)Limits == [
              addresses |-> \(set(walk.addresses.map { "\"\($0)\"" })), keys |-> \(set(walk.keys.map { "\"\($0)\"" })),
              gaps |-> \(set(walk.gaps.map(String.init))), drops |-> \(set(walk.drops.map(String.init))),
              strangers |-> \(l.strangers), strangersPerAddress |-> \(l.strangersPerAddress),
              arrivals |-> \(l.arrivals), arrivalsPerAddress |-> \(l.arrivalsPerAddress), window |-> \(walk.window),
              unattachedPerDrop |-> \(l.unattachedPerDrop), unattachedPerAddress |-> \(l.unattachedPerAddress),
              unpaired |-> \(l.unpaired), unpairedPerAddress |-> \(l.unpairedPerAddress), pairedWaiting |-> \(l.pairedWaiting)]

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
              \(rows.map { "<<" + $0.joined(separator: ", ") + ">>" }.joined(separator: ",\n  "))
            >>


            """
        }
        return (text + "=============================================================================\n", unmade)
    }

    static var implFile: URL {
        URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
            .appendingPathComponent("formal/tla/AdmissionImpl.tla")
    }

    /// `formal/tla/AdmissionImpl.tla` is exactly what this code does. After a deliberate change
    /// to the machine: `NIMBUS_WRITE_IMPL=1 swift test --filter AdmissionTests`, then
    /// `./build.sh verify`, which fails unless `Admission.tla` was changed to match.
    func testTheWrittenOutRelationIsWhatTheCodeDoes() throws {
        let (text, unmade) = Self.module()
        XCTAssertEqual(unmade, [], "events the specification has that this test could not make happen")
        if ProcessInfo.processInfo.environment["NIMBUS_WRITE_IMPL"] != nil {
            try text.write(to: Self.implFile, atomically: true, encoding: .utf8)
        }
        let onDisk = try String(contentsOf: Self.implFile, encoding: .utf8)
        // Not XCTAssertEqual: on a mismatch it would print both megabytes.
        XCTAssertTrue(onDisk == text, "Admission.swift no longer does what formal/tla/AdmissionImpl.tla says; see this test's comment")
    }

    /// The walk that is written out keeps one machine for each state of the specification,
    /// under one naming: it always takes the lowest number where several stand alike, calls
    /// the addresses "a" and "b", ticks once a second from one beginning, and never goes far.
    /// That is the whole truth only if the machine's behaviour depends on nothing the
    /// specification's state leaves out. So: long walks at random that vary all of it (other
    /// addresses, keys, lengths of tick and beginnings; any holder where several stand alike;
    /// numbers long gone; gaps of any number of ticks; histories of hundreds of events), each
    /// event the machine's own and labelled by what the numbers say, and every step of every
    /// walk must be in the relation: the same state after, the same answer, the same
    /// connection giving way.
    func testRandomWalksStayInsideTheRelation() {
        let seed = Self.seed()
        print("AdmissionTests.testRandomWalksStayInsideTheRelation: NIMBUS_SEED=\(seed)")
        var rng = Seeded(state: seed)
        var count = 0
        for walk in Self.walks {
            let steps = Self.relation(walk).steps
            for _ in 0..<250 {
                var d = Driver(walk, .random(walk, using: &rng))
                let addresses = Array(d.naming.addresses.keys), keys = Array(d.naming.keys.keys)
                var gone: [UInt64] = [0, UInt64.max]
                var trace: [String] = []
                for _ in 0..<240 {
                    let held = d.held
                    let anyone = { (rng: inout Seeded) -> UInt64 in
                        (Int.random(in: 0..<6, using: &rng) == 0 ? gone.randomElement(using: &rng) : held.randomElement(using: &rng)) ?? 0
                    }
                    let stranger = { (rng: inout Seeded) -> UInt64 in d.m.strangers.randomElement(using: &rng)?.id ?? anyone(&rng) }
                    let event: Admission.Event
                    // Mostly arrivals and what a stranger does next, so that the pools fill.
                    switch Int.random(in: 0..<17, using: &rng) {
                    case 0..<6:
                        let ticks = [0, 0, 0, 1, 1, 2, 3, 17, 100_000, -1, -1, -2, -3, -40_000].randomElement(using: &rng)!
                        event = .arrive(from: addresses.randomElement(using: &rng)!, local: Int.random(in: 0..<8, using: &rng) > 0,
                                        now: (d.m.asOf ?? d.naming.origin) + Double(ticks) * d.naming.tick)
                    case 6, 7: event = .data(stranger(&rng), drops: walk.drops.randomElement(using: &rng)!)
                    case 8: event = .proved(stranger(&rng), .unpaired)
                    case 9, 10: event = .proved(stranger(&rng), keys.randomElement(using: &rng).map { .paired($0) } ?? .unpaired)
                    case 11: event = .proved(anyone(&rng), [.mine, .retired].randomElement(using: &rng)!)
                    case 12: event = .attached(d.m.unattached.randomElement(using: &rng)?.id ?? anyone(&rng))
                    case 13: event = .purpose((Bool.random(using: &rng) ? d.m.unpaired.randomElement(using: &rng)?.id : nil) ?? anyone(&rng))
                    case 14: event = .closed(anyone(&rng))
                    case 15: event = .drops(walk.drops.randomElement(using: &rng)!)
                    default: event = .data(anyone(&rng), drops: walk.drops.randomElement(using: &rng)!)
                    }
                    guard let happening = Self.label(event, in: d.m, walk, d.naming) else { XCTFail("an event with no name: \(event)"); return }
                    let before = d.state
                    guard let answer = d.take(event) else { return }
                    let step = Step(from: before, event: happening.tla, to: d.state, answer: answer)
                    trace.append("\(event)\n      = \(step.event) -> \(step.answer)\n      \(step.to)")
                    count += 1
                    guard steps.contains(step) else {
                        XCTFail("\(walk.name), seed \(seed): a step that is not in the relation. The walk:\n  "
                            + trace.joined(separator: "\n  ") + "\nunder \(d.naming)")
                        return
                    }
                    gone.append(contentsOf: held.subtracting(d.held))
                }
            }
        }
        print("AdmissionTests.testRandomWalksStayInsideTheRelation: \(count) steps")
    }

    // MARK: The rule, said a second time

    /// Admission said of the world and not of arrays: who holds what, where each came from,
    /// and the order in which each took its present place. From that and an event it says what
    /// the answer must be, down to which connection gives way; `AdmissionTests` then holds the
    /// machine to it at limits, addresses and times that nothing was written out for.
    struct World {
        enum Place: Equatable { case stranger, unattached, unpaired, waiting(PublicKey) }
        var place: [UInt64: Place] = [:]
        var address: [UInt64: String] = [:]
        /// Those that proved a key nobody paired and have since said what they came for.
        var asked = Set<UInt64>()
        /// When each took its present place among those that have proved nothing: a count.
        var since: [UInt64: Int] = [:]
        var placements = 0
        var given = Set<UInt64>()
        /// The arrivals that were given a place and still count, oldest first.
        var taken: [Admission.Arrival] = []

        func those(_ p: Place) -> [UInt64] { place.filter { $0.value == p }.map(\.key).sorted { since[$0]! < since[$1]! } }

        /// Who gives way in a pool for a newcomer from `a`: the one that has waited longest
        /// from that address when the address holds as many places as it may; otherwise the
        /// one that has waited longest of all when the pool is full; otherwise nobody.
        func givesWay(_ p: Place, for a: String, limit: Int, perAddress: Int) -> UInt64? {
            let pool = those(p), own = pool.filter { address[$0] == a }
            if !own.isEmpty, own.count >= perAddress { return own.first }
            if !pool.isEmpty, pool.count >= limit { return pool.first }
            return nil
        }

        mutating func put(_ id: UInt64, _ p: Place) {
            place[id] = p
            placements += 1
            since[id] = placements
        }

        /// What the answer to `event` must be, and the world after it. For an arrival that is
        /// to be given a place the number is the machine's to choose: `admitted(0, …)` here,
        /// and `arrived` once it has chosen.
        mutating func expect(_ event: Admission.Event, _ l: Limits) -> Admission.Answer {
            switch event {
            case .arrive(let from, let local, let now):
                guard local else { return .close(.elsewhere) }
                // It counts for one window after it, and not at all from before it.
                taken = taken.filter { $0.at <= now && now - $0.at <= l.window }
                if taken.count >= l.arrivals || taken.filter({ $0.address == from }).count >= l.arrivalsPerAddress { return .close(.rate) }
                taken.append(Admission.Arrival(at: now, address: from))
                let out = givesWay(.stranger, for: from, limit: l.strangers, perAddress: l.strangersPerAddress)
                if let out { place[out] = nil }
                return .admitted(0, displacing: out)
            case .data(let id, let drops):
                guard place[id] == .stranger else { return .close(.gone) }
                place[id] = nil
                guard drops > 0 else { return .close(.noDrop) }
                let out = givesWay(.unattached, for: address[id]!, limit: l.unattachedPerDrop * drops, perAddress: l.unattachedPerAddress)
                if let out { place[out] = nil }
                put(id, .unattached)
                return .moved(displacing: out)
            case .proved(let id, let what):
                guard place[id] == .stranger else { return .close(.gone) }
                place[id] = nil
                switch what {
                case .mine: return .close(.mine)
                case .retired: return .close(.retired)
                case .unpaired:
                    // As among the strangers, except that only one that has asked for nothing
                    // can be the one that gives way; if there is none where one is needed, the
                    // newcomer is turned away.
                    let pool = those(.unpaired), a = address[id]!
                    let own = pool.filter { address[$0] == a }
                    var out: UInt64?
                    if !own.isEmpty, own.count >= l.unpairedPerAddress {
                        guard let silent = own.first(where: { !asked.contains($0) }) else { return .close(.tooManyUnpaired) }
                        out = silent
                    } else if !pool.isEmpty, pool.count >= l.unpaired {
                        guard let silent = pool.first(where: { !asked.contains($0) }) else { return .close(.tooManyUnpaired) }
                        out = silent
                    }
                    if let out { place[out] = nil }
                    put(id, .unpaired)
                    return .moved(displacing: out)
                case .paired(let key):
                    guard those(.waiting(key)).count < l.pairedWaiting else { return .close(.tooManyWaiting) }
                    put(id, .waiting(key))
                }
                return .moved(displacing: nil)
            case .attached(let id):
                if place[id] == .unattached { place[id] = nil }
                return .nothing
            case .purpose(let id):
                if case .waiting = place[id] { place[id] = nil }
                if place[id] == .unpaired { asked.insert(id) }
                return .nothing
            case .closed(let id):
                place[id] = nil
                return .nothing
            case .drops(let drops):
                // The pool has so many places for each drop in progress; those over that, the
                // ones that have waited longest, give way.
                let pool = those(.unattached)
                let out = Array(pool.prefix(max(0, pool.count - l.unattachedPerDrop * drops)))
                for id in out { place[id] = nil }
                return out.isEmpty ? .nothing : .giveWay(out)
            }
        }

        /// The machine gave an arrival this number.
        mutating func arrived(_ id: UInt64, from: String) -> Bool {
            guard given.insert(id).inserted else { return false }
            address[id] = from
            put(id, .stranger)
            return true
        }

        /// The machine holds exactly what the world says is held, in the same order.
        func agrees(with m: Admission) -> Bool {
            let pool = { (p: Place) in those(p).map { Admission.Unproved(id: $0, address: address[$0]!) } }
            var waiting: [UInt64: PublicKey] = [:]
            for (id, p) in place { if case .waiting(let key) = p { waiting[id] = key } }
            let unpaired = those(.unpaired).map { Admission.Unpaired(id: $0, address: address[$0]!, asked: asked.contains($0)) }
            return m.strangers == pool(.stranger) && m.unattached == pool(.unattached) && m.unpaired == unpaired && m.waiting == waiting
        }
    }

    /// At limits, addresses and times nobody wrote a relation out for (each limit from one to
    /// six or so, chosen at random and changed in the middle of a walk, as the listener's can
    /// be; up to six addresses and three keys; times that are not whole ticks, among them
    /// exactly one window apart), every answer is the one `World` says it must be, the same
    /// connection gives way, and the machine holds what the world holds.
    func testRandomWalksAtOtherLimitsKeepToTheRule() {
        let seed = Self.seed()
        print("AdmissionTests.testRandomWalksAtOtherLimitsKeepToTheRule: NIMBUS_SEED=\(seed)")
        var rng = Seeded(state: seed)
        func limits() -> Limits {
            Limits(strangers: Int.random(in: 1...6, using: &rng), strangersPerAddress: Int.random(in: 1...4, using: &rng),
                   arrivals: Int.random(in: 1...9, using: &rng), arrivalsPerAddress: Int.random(in: 1...5, using: &rng),
                   window: [0, 0.5, 1, 1, 10].randomElement(using: &rng)!,
                   unattachedPerDrop: Int.random(in: 1...3, using: &rng), unattachedPerAddress: Int.random(in: 1...3, using: &rng),
                   unpaired: Int.random(in: 1...4, using: &rng), unpairedPerAddress: Int.random(in: 1...3, using: &rng), pairedWaiting: Int.random(in: 1...3, using: &rng))
        }
        var count = 0
        for _ in 0..<300 {
            var m = Admission(limits: limits()), world = World()
            let addresses = (0..<Int.random(in: 1...6, using: &rng)).map { _ in Self.randomAddress(using: &rng) }
            let keys = (0..<Int.random(in: 1...3, using: &rng)).map { _ in Self.randomKey(using: &rng) }
            var now = Double.random(in: -1e6...1e6, using: &rng)
            var gone: [UInt64] = [0, UInt64.max]
            var trace: [String] = []
            for _ in 0..<300 {
                if Int.random(in: 0..<60, using: &rng) == 0 {
                    m.limits = limits()
                    trace.append("the limits become \(m.limits)")
                }
                let held = Set(world.place.keys)
                let anyone = { (rng: inout Seeded) -> UInt64 in
                    (Int.random(in: 0..<6, using: &rng) == 0 ? gone.randomElement(using: &rng) : held.randomElement(using: &rng)) ?? 0
                }
                let stranger = { (rng: inout Seeded) -> UInt64 in world.those(.stranger).randomElement(using: &rng) ?? anyone(&rng) }
                let event: Admission.Event
                switch Int.random(in: 0..<17, using: &rng) {
                case 0..<6:
                    let w = m.limits.window
                    now += [0, 0, 0.001, w / 2, w, w, w + 0.001, 3 * w + 1, Double.random(in: 0...2, using: &rng),
                            -0.001, -w / 2, -w, -3 * w - 1].randomElement(using: &rng)!
                    event = .arrive(from: addresses.randomElement(using: &rng)!, local: Int.random(in: 0..<8, using: &rng) > 0, now: now)
                case 6, 7: event = .data(stranger(&rng), drops: Int.random(in: 0...3, using: &rng))
                case 8: event = .proved(stranger(&rng), .unpaired)
                case 9, 10: event = .proved(stranger(&rng), .paired(keys.randomElement(using: &rng)!))
                case 11: event = .proved(anyone(&rng), [.mine, .retired].randomElement(using: &rng)!)
                case 12: event = .attached(world.those(.unattached).randomElement(using: &rng) ?? anyone(&rng))
                case 13: event = .purpose((Bool.random(using: &rng) ? world.those(.unpaired).randomElement(using: &rng) : nil) ?? anyone(&rng))
                case 14: event = .closed(anyone(&rng))
                case 15: event = .drops(Int.random(in: 0...3, using: &rng))
                default: event = .data(anyone(&rng), drops: Int.random(in: 0...3, using: &rng))
                }
                var expected = world.expect(event, m.limits)
                let answer = m.step(event)
                var fresh = true
                if case .admitted(let id, let out) = answer, case .admitted(_, let should) = expected, case .arrive(let from, _, _) = event {
                    fresh = world.arrived(id, from: from)
                    expected = .admitted(id, displacing: should)
                    _ = out
                }
                trace.append("\(event) -> \(answer)")
                count += 1
                var same = answer == expected && fresh && world.agrees(with: m)
                if case .arrive(_, true, _) = event { same = same && m.arrivals == world.taken }
                guard same else {
                    XCTFail("seed \(seed): the machine answered \(answer) and the rule says \(expected)" + (fresh ? "" : " (a number given twice)")
                        + ", or they no longer hold the same. The walk, at \(m.limits):\n  " + trace.joined(separator: "\n  "))
                    return
                }
                gone.append(contentsOf: held.subtracting(world.place.keys))
            }
        }
        print("AdmissionTests.testRandomWalksAtOtherLimitsKeepToTheRule: \(count) steps")
    }

    // MARK: Attacks on the machine

    /// Limits that can be filled by hand: three places for strangers and two an address, two
    /// places for data connections for each drop and two an address, three keys nobody paired
    /// and two an address, two connections of a paired key. A rate nobody reaches.
    static let small = Limits(strangers: 3, strangersPerAddress: 2, arrivals: 1000, arrivalsPerAddress: 1000, window: 1,
                              unattachedPerDrop: 2, unattachedPerAddress: 2, unpaired: 3, unpairedPerAddress: 2, pairedWaiting: 2)

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
        var held: Set<UInt64> { Set(m.strangers.map(\.id) + m.unattached.map(\.id) + m.unpaired.map(\.id)).union(m.waiting.keys) }

        /// A connection arrives from the local network and proves a key nobody has paired:
        /// its number, and what it was told.
        mutating func fresh(_ from: String, file: StaticString = #filePath, line: UInt = #line) -> (id: UInt64, answer: Admission.Answer) {
            let c = arrive(from, file: file, line: line).id
            return (c, m.step(.proved(c, .unpaired)))
        }
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
            default: if let id = (d.m.waiting.keys + d.m.unpaired.map(\.id)).randomElement(using: &rng) { _ = d.m.step(.purpose(id)) }
            }
            XCTAssertLessThanOrEqual(d.m.strangers.count, 3)
            XCTAssertLessThanOrEqual(d.m.unattached.count, 2, "two places for each drop, and there is one")
            for a in addresses {
                XCTAssertLessThanOrEqual(d.m.strangers.filter { $0.address == a }.count, 2)
                XCTAssertLessThanOrEqual(d.m.unattached.filter { $0.address == a }.count, 2)
            }
            XCTAssertLessThanOrEqual(d.m.unpaired.count, 3)
            for a in addresses { XCTAssertLessThanOrEqual(d.m.unpaired.filter { $0.address == a }.count, 2) }
            for k in keys { XCTAssertLessThanOrEqual(d.m.waiting.values.filter { $0 == k }.count, 2) }
        }
    }

    /// The rate: so many arrivals in a window from everyone, so many from one address, and an
    /// arrival counts for exactly the window after it. Over the rate it is the newcomer that is
    /// closed, and one that was closed does not count against the next.
    func testArrivalsAreRationedInAllAndFromOneAddress() {
        var m = Admission(limits: Limits(strangers: 100, strangersPerAddress: 100, arrivals: 4, arrivalsPerAddress: 2, window: 1,
                                         unattachedPerDrop: 1, unattachedPerAddress: 1, unpaired: 1, unpairedPerAddress: 1, pairedWaiting: 1))
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

    /// Found by the model (AdmissionSystem.tla, on a clock that can be set back), 2026-11-24.
    /// The listener timed arrivals by the calendar. Set back an hour, the calendar leaves every
    /// arrival of the last second an hour ahead of now: none more than a second old, so all
    /// still counted, for the hour. With the rate full (three addresses can fill it) every
    /// connection from every Mac was turned away until the calendar came round again. The
    /// listener now reads a clock that cannot be set; and the machine, whatever clock it is
    /// given, forgets an arrival that is from later than now.
    func testAnArrivalFromLaterThanNowIsForgotten() {
        var m = Admission(limits: Limits(strangers: 10, strangersPerAddress: 10, arrivals: 3, arrivalsPerAddress: 2, window: 1,
                                         unattachedPerDrop: 1, unattachedPerAddress: 1, unpaired: 1, unpairedPerAddress: 1, pairedWaiting: 1))
        func arrives(_ from: String, _ now: Double) -> Bool {
            if case .admitted = m.step(.arrive(from: from, local: true, now: now)) { return true }
            return false
        }
        XCTAssertTrue(arrives("a", 5000))
        XCTAssertTrue(arrives("a", 5000.5))
        XCTAssertTrue(arrives("b", 5000.5))
        XCTAssertFalse(arrives("c", 5000.75), "the rate is full")
        // The clock is set back an hour, and half a minute goes by.
        XCTAssertTrue(arrives("c", 1430), "a Mac was turned away for arrivals that are an hour in the future")
        XCTAssertTrue(arrives("a", 1430.5), "and one address for its own")
        XCTAssertEqual(m.arrivals.map(\.at), [1430, 1430.5])
        // Set back by less than a window: what is still from before now goes on counting.
        XCTAssertTrue(arrives("b", 1430.25))
        XCTAssertEqual(m.arrivals.map(\.at), [1430, 1430.25], "the arrival at 1430.5 is from later than now")
        XCTAssertTrue(arrives("b", 1430.25))
        XCTAssertFalse(arrives("c", 1431), "three in the window that ends now")
    }

    /// A connection from outside the local network gets no place, pushes nobody out and is not
    /// counted against the rate: whatever arrives from elsewhere, it costs a local Mac nothing.
    func testAConnectionFromElsewhereGetsNothingAndCountsForNothing() {
        var m = Admission(limits: Limits(strangers: 2, strangersPerAddress: 2, arrivals: 3, arrivalsPerAddress: 3, window: 1,
                                         unattachedPerDrop: 1, unattachedPerAddress: 1, unpaired: 1, unpairedPerAddress: 1, pairedWaiting: 1))
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

    /// Found by the model (AdmissionSystem.tla, UnattachedWithinItsLimit), 2026-11-24. The pool
    /// has so many places for each drop in progress, and when a drop ended nobody gave any up:
    /// with two drops' worth of connections waiting and one drop left, or none (when there is
    /// nothing any of them could attach to), they all stayed for as long as they cared to. Now
    /// the places a drop gave end with it, and the ones that have waited longest give way.
    func testWhenADropEndsThePlacesItGaveAreGivenUp() {
        var d = Desk()
        var waiting: [UInt64] = []
        for from in ["a", "b", "c", "e"] {
            let c = d.arrive(from).id
            XCTAssertEqual(d.m.step(.data(c, drops: 2)), .moved(displacing: nil), "two drops, four places")
            waiting.append(c)
        }
        XCTAssertEqual(d.m.step(.drops(2)), .nothing)
        XCTAssertEqual(d.m.step(.drops(3)), .nothing, "a drop that begins costs nobody a place")
        XCTAssertEqual(d.m.step(.drops(1)), .giveWay([waiting[0], waiting[1]]), "one drop left, two places: the two that have waited longest")
        XCTAssertEqual(d.m.unattached.map(\.id), [waiting[2], waiting[3]])
        XCTAssertEqual(d.m.step(.drops(1)), .nothing)
        XCTAssertEqual(d.m.step(.drops(0)), .giveWay([waiting[2], waiting[3]]), "no drop left: nothing they could belong to")
        XCTAssertTrue(d.held.isEmpty)
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

    /// F1, in the pool its fix had not reached (an independent review, 2026-11-24; the model had
    /// it written down as a limit). Anyone can make a key, so a connection that has proved one
    /// nobody here has paired has proved nothing: when the places for such are all taken by
    /// connections that have asked for nothing, the one that has waited longest gives way to
    /// the newcomer. It was the newcomer that was closed, and one host holding every place
    /// kept every Mac that was not paired at that moment from asking to pair.
    func testKeysNobodyPairedGiveWayAsStrangersDo() {
        var d = Desk()
        let silent = ["a", "b", "c"].map { d.fresh($0) }
        XCTAssertEqual(silent.map(\.answer), [.moved(displacing: nil), .moved(displacing: nil), .moved(displacing: nil)])
        let late = d.fresh("d")
        XCTAssertEqual(late.answer, .moved(displacing: silent[0].id), "the pool is full of keys that have said nothing: the one that has waited longest gives way")
        XCTAssertEqual(d.m.unpaired.map(\.id), [silent[1].id, silent[2].id, late.id], "and the newcomer has its place")
        for i in 0..<40 { XCTAssertNotEqual(d.fresh("e\(i)").answer, .close(.tooManyUnpaired)) }
        XCTAssertEqual(d.m.unpaired.count, 3)
    }

    /// An address holds its share of those places and no more, and at its share pushes out its
    /// own: the oldest of its own that has asked for nothing, not the oldest of all.
    func testAnAddressHasItsShareAmongTheKeysNobodyPaired() {
        var d = Desk()
        let b = d.fresh("b").id, first = d.fresh("a").id, second = d.fresh("a").id
        XCTAssertEqual(d.m.step(.purpose(first)), .nothing)
        let third = d.fresh("a")
        XCTAssertEqual(third.answer, .moved(displacing: second), "the first has asked, and keeps its place; b's is not a's to take")
        XCTAssertEqual(d.m.unpaired.map(\.id), [b, first, third.id])
        for _ in 0..<20 { XCTAssertNotEqual(d.fresh("a").answer, .moved(displacing: b), "one address can only ever push out its own") }
        XCTAssertEqual(d.m.unpaired.filter { $0.address == "a" }.count, 2)
        XCTAssertEqual(d.m.unpaired.first?.id, b)
    }

    /// A connection whose request has been read (to pair: it may be on a person's screen for
    /// minutes) is never closed to make room. Asking does not end the counting either: it
    /// keeps its place and it is still one of so many. Where everyone who could give way has
    /// asked, the newcomer is the one turned away, and holds nothing.
    func testAKeyNobodyPairedThatHasAskedKeepsItsPlace() {
        var d = Desk()
        let one = d.fresh("a").id, two = d.fresh("a").id
        XCTAssertEqual(d.m.step(.purpose(one)), .nothing)
        XCTAssertEqual(d.m.step(.purpose(two)), .nothing)
        XCTAssertEqual(d.m.unpaired.map(\.asked), [true, true])
        let third = d.fresh("a")
        XCTAssertEqual(third.answer, .close(.tooManyUnpaired), "its address holds its share, and both have asked")
        XCTAssertFalse(d.held.contains(third.id), "the one turned away holds nothing")
        let other = d.fresh("b").id
        XCTAssertEqual(d.m.step(.purpose(other)), .nothing)
        XCTAssertEqual(d.fresh("c").answer, .close(.tooManyUnpaired), "the pool is full, and everyone in it has asked")
        for i in 0..<50 { _ = d.fresh("z\(i)") }
        XCTAssertEqual(d.m.unpaired.map(\.id), [one, two, other], "fifty strangers with fresh keys later")
        XCTAssertEqual(d.m.step(.closed(one)), .nothing)
        XCTAssertEqual(d.fresh("c").answer, .moved(displacing: nil), "a place is given back when its connection ends")
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
        let theirs = d.arrive("a").id
        XCTAssertEqual(d.m.step(.proved(theirs, .paired(other))), .moved(displacing: nil), "another key's connections are another count")
        XCTAssertEqual(d.fresh("a").answer, .moved(displacing: nil))
        XCTAssertEqual(d.m.step(.purpose(one)), .nothing)
        XCTAssertFalse(d.held.contains(one), "it has said what it came for, and is no longer counted")
        let four = d.arrive("a").id
        XCTAssertEqual(d.m.step(.proved(four, .paired(k))), .moved(displacing: nil))
        XCTAssertEqual(d.m.step(.closed(two)), .nothing)
        let five = d.arrive("a").id
        XCTAssertEqual(d.m.step(.proved(five, .paired(k))), .moved(displacing: nil), "nor one that has gone")
    }

    /// The one that gives way has proved nothing that counts here. A connection that has proved
    /// a PAIRED key is out of every pool where anyone gives way, and no number of newcomers,
    /// with keys or without, closes it.
    func testAConnectionThatHasProvedAPairedKeyNeverGivesWay() {
        var d = Desk()
        let paired = d.arrive("a").id
        XCTAssertEqual(d.m.step(.proved(paired, .paired(Self.key(1)))), .moved(displacing: nil))
        XCTAssertTrue(d.m.strangers.isEmpty, "a connection that proved a key was left among those that have proved nothing")
        for i in 0..<200 {
            let from = i % 2 == 0 ? "a" : "z\(i)"
            XCTAssertNotEqual(d.arrive(from).out, paired)
            XCTAssertNotEqual(d.fresh(from).answer, .moved(displacing: paired))
        }
        XCTAssertTrue(d.held.contains(paired))
        XCTAssertEqual(d.m.waiting[paired], Self.key(1))
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

    /// An address decides who waits and nothing else. The same paired keys doing the same
    /// things get the same answers wherever they come from, whatever else that address is up
    /// to, and whatever keys nobody paired are doing.
    func testWhereAPairedKeyComesFromDecidesNothing() {
        let k = Self.key(1), other = Self.key(2)
        func answers(_ addresses: [String], crowd: String?) -> [Admission.Answer] {
            var d = Desk()
            var out: [Admission.Answer] = []
            for (i, a) in addresses.enumerated() {
                if let crowd {
                    _ = d.arrive(crowd)
                    _ = d.fresh(crowd)
                }
                let c = d.arrive(a).id
                out.append(d.m.step(.proved(c, i % 3 == 0 ? .paired(other) : .paired(k))))
                if i == 2 { out.append(d.m.step(.purpose(c))) }
            }
            return out
        }
        let same = answers(["a", "a", "a", "a", "a", "a", "a"], crowd: "a")
        XCTAssertEqual(same, answers(["a", "b", "c", "d", "e", "f", "g"], crowd: nil))
        XCTAssertEqual(same, answers(["x", "x", "y", "y", "x", "y", "x"], crowd: "y"))
        XCTAssertEqual(same.filter { $0 == .close(.tooManyWaiting) }.count, 2, "the limits were reached, so the answers say something")
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
        let unpaired = d.fresh("b").id
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
