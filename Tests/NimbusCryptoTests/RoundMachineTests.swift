// Copyright (C) 2026 Niels Joubert
// SPDX-License-Identifier: GPL-3.0-or-later
import Foundation
import XCTest
@testable import NimbusCrypto

/// A drop's conversation by itself, at either end: no socket, no disk, no thread.
///
/// Two kinds of test, as for the pairing machine. The first kind are attacks on the two
/// machines, each the guard of one line in `scripts/mutate.py`. The second ties the code to its
/// specification: every state each machine can reach, under every event, is written out as
/// `formal/tla/RoundImpl.tla`, and TLC checks those relations against `SenderStep` and
/// `ReceiverStep` in `formal/tla/RoundMachine.tla` (`./build.sh verify`).
///
/// The tie rests on an abstraction (stated in full at the top of `RoundMachine.tla`), and it is
/// written here as functions: `state(_:)` takes a Swift machine to the specification's state,
/// `label(_:in:)` takes a Swift event to the specification's event BY WHAT THE NUMBERS SAY (a
/// plan is "planMore" when it names more bytes than any before it, whatever the machine then
/// does with it), and `name(_:)` takes an effect to its name with the class of what it carries
/// (which message, which reason). What the abstraction leaves out (how many bytes, which
/// description was offered, what came before) the random walks vary.
final class RoundMachineTests: XCTestCase {
    typealias Sender = RoundMachine.Sender
    typealias Receiver = RoundMachine.Receiver

    static let offered = RoundMachine.Described(files: 2, bytes: 10, names: ["a", "b"])
    /// What a manifest may be instead of what was offered: one more file, one more byte, another name.
    static let others = [RoundMachine.Described(files: 3, bytes: 10, names: ["a", "b"]),
                         RoundMachine.Described(files: 2, bytes: 11, names: ["a", "b"]),
                         RoundMachine.Described(files: 2, bytes: 10, names: ["a", "c"]),
                         RoundMachine.Described(files: 2, bytes: 10, names: ["a"])]

    // MARK: The abstraction, as functions

    /// A Swift machine as the specification's state.
    static func state(_ m: Sender) -> String { "[phase |-> \"\(m.phase.rawValue)\", fruitless |-> \(m.fruitless), patience |-> \(m.patience)]" }
    static func state(_ m: Receiver) -> String { "[phase |-> \"\(m.phase.rawValue)\", idle |-> \(m.idle), patience |-> \(m.patience)]" }

    /// A Swift event as the specification's event, by what the numbers say: computed from the
    /// event and the machine BEFORE the step, never from what the step then did.
    static func label(_ event: Sender.Event, in m: Sender) -> String {
        switch event {
        case .begin: return "begin"
        case .received(.accept): return "accept"
        case .received(.decline(let readable)): return readable ? "decline" : "declineMalformed"
        case .received(.plan(let have)):
            guard let have else { return "planMalformed" }
            return have > m.best ? "planMore" : "planSame"
        case .received(.complete): return "complete"
        case .received(.error): return "error"
        case .received(.other): return "other"
        case .written: return "written"
        case .lost: return "lost"
        case .gaveUp: return "gaveUp"
        case .silent: return "silent"
        case .stopped(let tell): return tell ? "stopped" : "stoppedSilently"
        case .withdrawn: return "withdrawn"
        case .cancelled: return "cancelled"
        }
    }

    /// `offered`: what the machine was made with (it keeps that to itself).
    static func label(_ event: Receiver.Event, offered: RoundMachine.Described) -> String {
        switch event {
        case .begin(let askable): return askable ? "begin" : "beginNobody"
        case .yes(let paired): return paired ? "yes" : "yesUnpaired"
        case .no: return "no"
        case .received(.manifest(.unreadable)): return "manifestMalformed"
        case .received(.manifest(.invalid)): return "manifestInvalid"
        case .received(.manifest(.described(let it))): return it == offered ? "manifest" : "manifestOther"
        case .received(.done(let readable)): return readable ? "done" : "doneMalformed"
        case .received(.error(let readable)): return readable ? "error" : "errorMalformed"
        case .received(.other): return "other"
        case .said: return "said"
        case .prepared: return "prepared"
        case .settled(let judgement): return judgement.rawValue
        case .placed: return "placed"
        case .lost: return "lost"
        case .senderBack: return "senderBack"
        case .gaveUp: return "gaveUp"
        case .silent: return "silent"
        case .stopped(let tell): return tell ? "stopped" : "stoppedSilently"
        case .withdrawn: return "withdrawn"
        case .cancelled: return "cancelled"
        }
    }

    // MARK: The specification's events, made concrete

    struct SenderDriver {
        var m: Sender

        init(patience: Int = 3) { m = Sender(patience: patience) }

        /// One Swift event that the numbers make a `name`.
        func event(_ name: String) -> Sender.Event {
            switch name {
            case "begin": return .begin
            case "accept": return .received(.accept)
            case "decline": return .received(.decline(readable: true))
            case "declineMalformed": return .received(.decline(readable: false))
            case "planMore": return .received(.plan(have: m.best + 1))
            case "planSame": return .received(.plan(have: m.best))
            case "planMalformed": return .received(.plan(have: nil))
            case "complete": return .received(.complete)
            case "error": return .received(.error)
            case "other": return .received(.other)
            case "written": return .written
            case "lost": return .lost
            case "gaveUp": return .gaveUp
            case "silent": return .silent
            case "stopped": return .stopped(tell: true)
            case "stoppedSilently": return .stopped(tell: false)
            case "withdrawn": return .withdrawn
            case "cancelled": return .cancelled
            default: fatalError("no such event: \(name)")
            }
        }

        @discardableResult
        mutating func take(_ name: String) -> [Sender.Effect] {
            let e = event(name)
            XCTAssertEqual(RoundMachineTests.label(e, in: m), name, "the event made for “\(name)” is not one")
            return m.step(e)
        }

        var state: String { RoundMachineTests.state(m) }
    }

    struct ReceiverDriver {
        var m: Receiver
        let offered: RoundMachine.Described
        /// Which of the ways not to be what was offered a "manifestOther" is.
        var other = 0

        init(patience: Int = 5, offered: RoundMachine.Described = RoundMachineTests.offered) {
            self.offered = offered
            m = Receiver(offered: offered, patience: patience)
        }

        func event(_ name: String) -> Receiver.Event {
            switch name {
            case "begin": return .begin(askable: true)
            case "beginNobody": return .begin(askable: false)
            case "yes": return .yes(paired: true)
            case "yesUnpaired": return .yes(paired: false)
            case "no": return .no
            case "manifest": return .received(.manifest(.described(offered)))
            case "manifestOther": return .received(.manifest(.described(RoundMachineTests.others[other % RoundMachineTests.others.count])))
            case "manifestInvalid": return .received(.manifest(.invalid))
            case "manifestMalformed": return .received(.manifest(.unreadable))
            case "done": return .received(.done(readable: true))
            case "doneMalformed": return .received(.done(readable: false))
            case "error": return .received(.error(readable: true))
            case "errorMalformed": return .received(.error(readable: false))
            case "other": return .received(.other)
            case "said": return .said
            case "prepared": return .prepared
            case "whole": return .settled(.whole)
            case "more": return .settled(.more)
            case "nothingNew": return .settled(.nothingNew)
            case "placed": return .placed
            case "lost": return .lost
            case "senderBack": return .senderBack
            case "gaveUp": return .gaveUp
            case "silent": return .silent
            case "stopped": return .stopped(tell: true)
            case "stoppedSilently": return .stopped(tell: false)
            case "withdrawn": return .withdrawn
            case "cancelled": return .cancelled
            default: fatalError("no such event: \(name)")
            }
        }

        @discardableResult
        mutating func take(_ name: String) -> [Receiver.Effect] {
            let e = event(name)
            XCTAssertEqual(RoundMachineTests.label(e, offered: offered), name, "the event made for “\(name)” is not one")
            return m.step(e)
        }

        @discardableResult
        mutating func take(_ names: [String]) -> [Receiver.Effect] { names.reduce([]) { _, name in take(name) } }

        var state: String { RoundMachineTests.state(m) }
    }

    static let senderEvents = ["begin", "accept", "decline", "declineMalformed", "planMore", "planSame", "planMalformed", "complete", "error",
                               "other", "written", "lost", "gaveUp", "silent", "stopped", "stoppedSilently", "withdrawn", "cancelled"]
    static let receiverEvents = ["begin", "beginNobody", "yes", "yesUnpaired", "no", "manifest", "manifestOther", "manifestInvalid",
                                 "manifestMalformed", "done", "doneMalformed", "error", "errorMalformed", "other", "said", "prepared", "whole",
                                 "more", "nothingNew", "placed", "lost", "senderBack", "gaveUp", "silent", "stopped", "stoppedSilently",
                                 "withdrawn", "cancelled"]
    /// The patience each relation is written out for. The app's own are 3 (a sender) and 5 (a
    /// receiver, `Tuning.idleRounds`); the smaller ones are what `Drop.tla` can afford to run.
    static let senderPatience = [1, 2, 3]
    static let receiverPatience = [1, 2, 3, 5]

    static func ending<F: RawRepresentable>(_ end: RoundMachine.Ending<F>) -> String where F.RawValue == String {
        switch end {
        case .completed: return "end completed"
        case .declined: return "end declined"
        case .cancelled: return "end cancelled"
        case .failed(let why): return "fail \(why.rawValue)"
        }
    }

    static func name(_ effect: Sender.Effect) -> String {
        switch effect {
        case .send(let said): return "send \(said.rawValue)"
        case .adopt: return "adopt"
        case .round: return "round"
        case .reconnect: return "reconnect"
        case .reconnected: return "reconnected"
        case .hangUp: return "hangUp"
        case .end(let end): return ending(end)
        }
    }

    static func name(_ effect: Receiver.Effect) -> String {
        switch effect {
        case .ask: return "ask"
        case .unask: return "unask"
        case .send(.accept): return "send accept"
        case .send(.decline(let why)): return "send decline \(why.rawValue)"
        case .send(.plan): return "send plan"
        case .send(.complete): return "send complete"
        case .send(.error): return "send error"
        case .prepare: return "prepare"
        case .settle: return "settle"
        case .place: return "place"
        case .hold: return "hold"
        case .hangUp: return "hangUp"
        case .end(let end): return ending(end)
        }
    }

    static func tuple(_ names: [String]) -> String {
        names.isEmpty ? "<< >>" : "<< " + names.map { "\"\($0)\"" }.joined(separator: ", ") + " >>"
    }

    // MARK: The code and its specification

    struct Relation {
        var initial: [String] = []
        var transitions = Set<String>()
        /// For the tests about the relation's shape: from, event, to, effects.
        var steps: [(from: String, event: String, to: String, effects: [String])] = []
        /// How each state is reached: the patience the machine was made with and the events, in order.
        var paths: [String: (patience: Int, events: [String])] = [:]
    }

    /// Every state the sending machine reaches from its beginnings, under every event.
    static func senderRelation() -> Relation {
        var r = Relation()
        var seen = Set<String>()
        var queue = senderPatience.map { SenderDriver(patience: $0) }
        for d in queue { r.initial.append(d.state); seen.insert(d.state); r.paths[d.state] = (d.m.patience, []) }
        while let d = queue.popLast() {
            for e in senderEvents {
                var next = d
                let effects = next.take(e).map(name)
                r.transitions.insert("<< \(d.state), \"\(e)\", \(next.state), \(tuple(effects)) >>")
                r.steps.append((d.state, e, next.state, effects))
                if seen.insert(next.state).inserted {
                    queue.append(next)
                    r.paths[next.state] = (d.m.patience, r.paths[d.state]!.events + [e])
                }
            }
        }
        r.initial.sort()
        return r
    }

    /// And the receiving machine.
    static func receiverRelation() -> Relation {
        var r = Relation()
        var seen = Set<String>()
        var queue = receiverPatience.map { ReceiverDriver(patience: $0) }
        for d in queue { r.initial.append(d.state); seen.insert(d.state); r.paths[d.state] = (d.m.patience, []) }
        while let d = queue.popLast() {
            for e in receiverEvents {
                var next = d
                let effects = next.take(e).map(name)
                r.transitions.insert("<< \(d.state), \"\(e)\", \(next.state), \(tuple(effects)) >>")
                r.steps.append((d.state, e, next.state, effects))
                if seen.insert(next.state).inserted {
                    queue.append(next)
                    r.paths[next.state] = (d.m.patience, r.paths[d.state]!.events + [e])
                }
            }
        }
        r.initial.sort()
        return r
    }

    /// Every state the receiving machine reaches in which it says a data connection may be let in.
    static func takingData() -> [String] {
        var seen = Set<String>(), taking = Set<String>()
        var queue = receiverPatience.map { ReceiverDriver(patience: $0) }
        for d in queue { seen.insert(d.state) }
        while let d = queue.popLast() {
            if d.m.takesData { taking.insert(d.state) }
            for e in receiverEvents {
                var next = d
                next.take(e)
                if seen.insert(next.state).inserted { queue.append(next) }
            }
        }
        return taking.sorted()
    }

    static var implFile: URL {
        URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
            .appendingPathComponent("formal/tla/RoundImpl.tla")
    }

    /// `formal/tla/RoundImpl.tla` is exactly what this code does. After a deliberate change to
    /// either machine: `NIMBUS_WRITE_IMPL=1 swift test --filter RoundMachineTests`, then
    /// `./build.sh verify`, which fails unless `RoundMachine.tla` was changed to match.
    func testTheWrittenOutRelationsAreWhatTheCodeDoes() throws {
        let s = Self.senderRelation(), r = Self.receiverRelation()
        let text = """
        ----------------------------- MODULE RoundImpl -----------------------------
        \\* GENERATED from Sources/NimbusCrypto/RoundMachine.swift by RoundMachineTests
        \\* (Tests/NimbusCryptoTests). Do not edit: every state each of the two Swift machines
        \\* reaches, under every event, with what it said to do. RoundRefinement.tla checks them
        \\* against SenderStep and ReceiverStep.

        SenderImplInit == {
          \(s.initial.joined(separator: ",\n  "))
        }

        SenderImpl == {
          \(s.transitions.sorted().joined(separator: ",\n  "))
        }

        ReceiverImplInit == {
          \(r.initial.joined(separator: ",\n  "))
        }

        ReceiverImpl == {
          \(r.transitions.sorted().joined(separator: ",\n  "))
        }

        \\* The states in which Receiver.takesData is true.
        ReceiverTakesData == {
          \(Self.takingData().joined(separator: ",\n  "))
        }

        =============================================================================

        """
        if ProcessInfo.processInfo.environment["NIMBUS_WRITE_IMPL"] != nil {
            try text.write(to: Self.implFile, atomically: true, encoding: .utf8)
        }
        let onDisk = try String(contentsOf: Self.implFile, encoding: .utf8)
        XCTAssertEqual(onDisk, text, "RoundMachine.swift no longer does what formal/tla/RoundImpl.tla says; see this test's comment")
        // Every event of the specification is one this test can make happen in every state the
        // code reaches (the drivers check that what they made is what was asked for).
        XCTAssertEqual(s.transitions.count, Set(s.steps.map(\.from)).count * Self.senderEvents.count)
        XCTAssertEqual(r.transitions.count, Set(r.steps.map(\.from)).count * Self.receiverEvents.count)
        XCTAssertEqual(Set(s.steps.map(\.event)), Set(Self.senderEvents))
        XCTAssertEqual(Set(r.steps.map(\.event)), Set(Self.receiverEvents))
    }

    /// A generator that gives the same numbers for the same seed.
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

    /// From every state of each relation: this many machines, each made afresh with numbers of
    /// its own, each then walked this many steps at random.
    static let machinesAState = 6, stepsAWalk = 50

    /// A Swift event that the numbers make a `label`, with whatever the label leaves open
    /// chosen at random. Nil when no such event exists for THIS machine: a plan cannot name
    /// more bytes than the largest number there is.
    static func senderEvent(_ label: String, _ rng: inout Seeded, _ m: Sender) -> Sender.Event? {
        switch label {
        case "planMore":
            guard m.best < .max else { return nil }
            switch Int.random(in: 0..<4, using: &rng) {
            case 0: return .received(.plan(have: m.best + 1))
            case 1: return .received(.plan(have: .max))
            default: return .received(.plan(have: Int64.random(in: (m.best + 1) ... .max, using: &rng)))
            }
        case "planSame":
            switch Int.random(in: 0..<4, using: &rng) {
            case 0: return .received(.plan(have: m.best))
            case 1: return .received(.plan(have: .min))
            default: return .received(.plan(have: Int64.random(in: .min ... m.best, using: &rng)))
            }
        default: return SenderDriver(patience: m.patience).event(label)
        }
    }

    /// What an offer may describe: nothing, one thing, numbers no drop has, names that are odd.
    static func description(_ rng: inout Seeded) -> RoundMachine.Described {
        let names = ["", "a", "b", "A", "é", "e\u{301}", "a/b", "..", String(repeating: "x", count: 300)]
        return RoundMachine.Described(files: [0, 1, 2, 1000, -1, .max, .min].randomElement(using: &rng)!,
                                      bytes: [0, 1, 10, -1, .max, .min, Int64.random(in: .min ... .max, using: &rng)].randomElement(using: &rng)!,
                                      names: (0..<Int.random(in: 0...4, using: &rng)).map { _ in names.randomElement(using: &rng)! })
    }

    static func receiverEvent(_ label: String, _ rng: inout Seeded, offered: RoundMachine.Described) -> Receiver.Event? {
        switch label {
        case "manifest": return .received(.manifest(.described(offered)))
        case "manifestOther":
            // A near miss of what was offered, or anything else that is not it.
            var it = offered
            switch Int.random(in: 0..<5, using: &rng) {
            case 0: it.files = it.files == .max ? 0 : it.files + 1
            case 1: it.bytes = it.bytes == .max ? 0 : it.bytes + 1
            case 2: it.names.append("a")
            case 3: if it.names.isEmpty { it.names = [""] } else { it.names.removeLast() }
            default: it = description(&rng)
            }
            return it == offered ? nil : .received(.manifest(.described(it)))
        default: return ReceiverDriver(offered: offered).event(label)
        }
    }

    /// The label of a step to take at random: mostly one that is in turn for the phase the
    /// machine is in, so that walks go deep and the counts get used; sometimes anything.
    static func senderLabel(_ rng: inout Seeded, _ m: Sender) -> String {
        let inTurn: [Sender.Phase: [String]] = [
            .idle: ["begin"], .awaitAnswer: ["accept"], .awaitPlan: ["planMore", "planSame"], .sending: ["written", "lost", "silent"],
            .awaitVerdict: ["planMore", "planSame", "planSame", "lost", "silent"], .reconnecting: ["planMore", "planSame", "planSame", "other", "lost"]]
        if Int.random(in: 0..<5, using: &rng) > 0, let some = inTurn[m.phase] { return some.randomElement(using: &rng)! }
        return senderEvents.randomElement(using: &rng)!
    }

    static func receiverLabel(_ rng: inout Seeded, _ m: Receiver) -> String {
        let inTurn: [Receiver.Phase: [String]] = [
            .idle: ["begin"], .deciding: ["yes"], .awaitManifest: ["manifest"], .preparing: ["prepared"], .planning: ["said"],
            .reading: ["done", "done", "lost", "silent"], .settling: ["nothingNew", "nothingNew", "more", "silent"],
            .awaitSender: ["senderBack", "senderBack", "silent"], .placing: ["placed"], .completed: ["senderBack"]]
        if Int.random(in: 0..<5, using: &rng) > 0, let some = inTurn[m.phase] { return some.randomElement(using: &rng)! }
        return receiverEvents.randomElement(using: &rng)!
    }

    /// The relations are written out from one machine per state of the specification, fed
    /// small numbers. That is only the whole truth if a machine's behaviour depends on nothing
    /// the specification's state leaves out: how many bytes a plan names and how many the plans
    /// before it named, what was offered and in which way a manifest is not that, the order
    /// things happened in. So, from EVERY state of each relation, machines made afresh with
    /// numbers of their own (brought there by the same events, made with other numbers), each
    /// then given every event once and walked on at random; every step is given the name the
    /// numbers give it BEFORE it is taken, and must be in the relation under that name. An
    /// event the specification has that could not be made to happen is a failure too.
    ///
    /// Fixed seeds, so that a failure can be had again, and one from the clock, so that every
    /// run also looks somewhere new. A failure prints its seed and its whole walk;
    /// `NIMBUS_SEED=n` runs that seed alone, `NIMBUS_WALK_SEEDS=200` is a longer hunt.
    func testRandomWalksStayInsideTheRelations() {
        let environment = ProcessInfo.processInfo.environment
        let extra = Int(environment["NIMBUS_WALK_SEEDS"] ?? "") ?? 1
        let now = UInt64(Date().timeIntervalSince1970 * 1000)
        // Each with its type written out: the compiler CI builds with took the one expression for [Any]?.
        let named: [UInt64]? = environment["NIMBUS_SEED"].flatMap { UInt64($0) }.map { [$0] }
        let fresh: [UInt64] = (0..<extra).map { now &+ UInt64($0) &* 7919 }
        let seeds: [UInt64] = named ?? ([1, 2, 3, 0x5EED] + fresh)
        var steps = 0
        for seed in seeds {
            guard walk(seed: seed, steps: &steps) else { return }
        }
        print("RoundMachineTests: \(steps) random steps over \(seeds.count) seeds (the last: \(seeds.last!)), from every state of both relations, every one in its relation")
        XCTAssertGreaterThan(steps, 60000 * seeds.count)
    }

    /// One seed's walks, from every state of both relations. False when a step was not in its
    /// relation (the test has failed and said so).
    func walk(seed: UInt64, steps: inout Int) -> Bool {
        var rng = Seeded(state: seed)

        let s = Self.senderRelation()
        for (state, reached) in s.paths.sorted(by: { $0.key < $1.key }) {
            for _ in 0..<Self.machinesAState {
                var m = Sender(patience: reached.patience)
                var trace: [String] = []
                /// Takes one step by its label; false (and the test has failed) when it is not in the relation.
                func take(_ label: String, on m: inout Sender, required: Bool, _ steps: inout Int) -> Bool {
                    guard let event = Self.senderEvent(label, &rng, m) else {
                        if required { XCTFail("NIMBUS_SEED=\(seed): “\(label)” could not be made to happen in \(Self.state(m)) (best \(m.best))") }
                        return !required
                    }
                    let before = Self.state(m), named = Self.label(event, in: m), best = m.best
                    let effects = m.step(event).map(Self.name)
                    steps += 1
                    trace.append("  \(before) best \(best)  --\(event) as “\(named)”-->  \(Self.state(m))  \(effects)")
                    guard named == label, s.transitions.contains("<< \(before), \"\(named)\", \(Self.state(m)), \(Self.tuple(effects)) >>") else {
                        XCTFail("NIMBUS_SEED=\(seed): a sender's step that is not in the relation (meant as “\(label)”). The walk:\n" + trace.joined(separator: "\n"))
                        return false
                    }
                    return true
                }
                for label in reached.events { guard take(label, on: &m, required: true, &steps) else { return false } }
                guard Self.state(m) == state else { XCTFail("NIMBUS_SEED=\(seed): \(reached.events) leads to \(Self.state(m)), not \(state)"); return false }
                // Every event of the specification, here, on a machine with numbers of its own.
                // (The one that cannot always be made: a plan naming more than the largest number.)
                for label in Self.senderEvents {
                    var copy = m
                    let kept = trace
                    guard take(label, on: &copy, required: label != "planMore" || m.best < .max, &steps) else { return false }
                    trace = kept
                }
                for _ in 0..<Self.stepsAWalk { guard take(Self.senderLabel(&rng, m), on: &m, required: false, &steps) else { return false } }
            }
        }

        let r = Self.receiverRelation()
        for (state, reached) in r.paths.sorted(by: { $0.key < $1.key }) {
            for _ in 0..<Self.machinesAState {
                let offered = Self.description(&rng)
                var m = Receiver(offered: offered, patience: reached.patience)
                var trace = ["  offered \(offered)"]
                func take(_ label: String, on m: inout Receiver, _ steps: inout Int) -> Bool {
                    guard let event = Self.receiverEvent(label, &rng, offered: offered) else { return true }   // a random description that happened to be the offer
                    let before = Self.state(m), named = Self.label(event, offered: offered)
                    let effects = m.step(event).map(Self.name)
                    steps += 1
                    trace.append("  \(before)  --\(event) as “\(named)”-->  \(Self.state(m))  \(effects)")
                    guard named == label, r.transitions.contains("<< \(before), \"\(named)\", \(Self.state(m)), \(Self.tuple(effects)) >>") else {
                        XCTFail("NIMBUS_SEED=\(seed): a receiver's step that is not in the relation (meant as “\(label)”). The walk:\n" + trace.joined(separator: "\n"))
                        return false
                    }
                    return true
                }
                for label in reached.events { guard take(label, on: &m, &steps) else { return false } }
                guard Self.state(m) == state else { XCTFail("NIMBUS_SEED=\(seed): \(reached.events) leads to \(Self.state(m)), not \(state)"); return false }
                for label in Self.receiverEvents {
                    var copy = m
                    let kept = trace
                    guard take(label, on: &copy, &steps) else { return false }
                    trace = kept
                }
                for _ in 0..<Self.stepsAWalk { guard take(Self.receiverLabel(&rng, m), on: &m, &steps) else { return false } }
            }
        }
        return true
    }

    /// The relations are written out for a few patiences (the app's, and smaller). For any
    /// other the code is the same and only the number differs; that much is tested directly:
    /// the count ends the drop at exactly the patience it was given, whatever that is.
    func testALargerPatienceIsOnlyALargerNumber() {
        for patience in [4, 7, 20, 50, 200] {
            var s = Self.sender(at: .sending, patience: patience)
            for n in 1..<patience {
                s.take("lost")
                XCTAssertEqual(s.take("planSame"), [.reconnected, .adopt, .round], "\(patience): reconnect \(n)")
            }
            s.take("lost")
            XCTAssertEqual(s.take("planSame"), [.reconnected, .adopt, .send(.error), .end(.failed(.fruitless))], "\(patience)")

            var r = Self.receiver(at: .reading, patience: patience)
            for n in 1..<patience { XCTAssertEqual(r.take(["done", "nothingNew"]), [.send(.plan)], "\(patience): round \(n)") }
            XCTAssertEqual(r.take(["done", "nothingNew"]), [.send(.error), .end(.failed(.incomplete))], "\(patience)")
        }
    }

    /// What the two shells count on, of every transition there is: an effect that ends with a
    /// report to the machine is the last of its list (the shell does the list in order and then
    /// reports), and a drop is ended at most once, exactly when its machine reaches an end.
    func testEveryTransitionEndsAtMostOnceAndAsksForAReportLast() {
        let final = ["completed", "declined", "failed", "cancelled"]
        func isFinal(_ state: String) -> Bool { final.contains { state.contains("phase |-> \"\($0)\"") } }
        func isEnd(_ effect: String) -> Bool { effect.hasPrefix("end ") || effect.hasPrefix("fail ") }
        let reports = ["round", "reconnect", "prepare", "settle", "place", "hold", "send accept", "send plan",
                       "send decline notReceiving", "send decline declined"]
        for step in Self.senderRelation().steps + Self.receiverRelation().steps {
            let ends = step.effects.filter(isEnd).count
            XCTAssertEqual(ends, !isFinal(step.from) && isFinal(step.to) ? 1 : 0, "\(step)")
            if isFinal(step.from) { XCTAssertEqual(step.to, step.from, "an end is an end: \(step)") }
            for (i, effect) in step.effects.enumerated() where reports.contains(effect) {
                XCTAssertEqual(i, step.effects.count - 1, "\(effect) is not the last thing said: \(step)")
            }
        }
    }

    // MARK: Attacks on the sending machine

    /// A sender at the given point of an honest drop.
    static func sender(at phase: Sender.Phase, patience: Int = 3) -> SenderDriver {
        var d = SenderDriver(patience: patience)
        let path: [Sender.Phase: [String]] = [
            .idle: [], .awaitAnswer: ["begin"], .awaitPlan: ["begin", "accept"], .sending: ["begin", "accept", "planMore"],
            .awaitVerdict: ["begin", "accept", "planMore", "written"], .reconnecting: ["begin", "accept", "planMore", "lost"],
            .completed: ["begin", "accept", "planMore", "written", "complete"], .declined: ["begin", "decline"],
            .failed: ["begin", "error"], .cancelled: ["cancelled"]]
        for e in path[phase]! { d.take(e) }
        XCTAssertEqual(d.m.phase, phase, "an honest drop no longer gets here")
        return d
    }

    func testAnHonestDropRunsItsRounds() {
        var d = SenderDriver()
        XCTAssertEqual(d.take("begin"), [.send(.offer)])
        XCTAssertEqual(d.take("accept"), [.send(.manifest)])
        XCTAssertEqual(d.take("planMore"), [.adopt, .round])
        XCTAssertEqual(d.take("written"), [.send(.done)])
        // Something was missing: the answer to "done" is a plan, and that is another round.
        XCTAssertEqual(d.take("planMore"), [.adopt, .round])
        XCTAssertEqual(d.take("written"), [.send(.done)])
        XCTAssertEqual(d.take("complete"), [.end(.completed)])
        XCTAssertEqual(d.m.phase, .completed)
    }

    /// "It all arrived" is believed only as the answer to "done", or to a reconnect: not before
    /// a single chunk was asked for, and not in the middle of a round.
    func testCompleteIsBelievedOnlyAsTheAnswerToDoneOrToAReconnect() {
        for phase in [Sender.Phase.idle, .awaitAnswer, .awaitPlan, .sending] {
            var d = Self.sender(at: phase)
            let effects = d.take("complete")
            XCTAssertFalse(effects.contains(.end(.completed)), "\(phase)")
            XCTAssertEqual(d.m.phase, .failed, "\(phase)")
            XCTAssertEqual(effects.last, .end(.failed(.unexpected)), "\(phase)")
        }
        var afterDone = Self.sender(at: .awaitVerdict)
        XCTAssertEqual(afterDone.take("complete"), [.end(.completed)])
        var back = Self.sender(at: .reconnecting)
        XCTAssertEqual(back.take("complete"), [.reconnected, .end(.completed)])
    }

    /// An end is an end: a second "complete", a plan, the receiver's error, a loss, all mean nothing.
    func testNothingMeansAnythingAfterAnEnd() {
        for phase in [Sender.Phase.completed, .declined, .failed, .cancelled] {
            for e in Self.senderEvents {
                var d = Self.sender(at: phase)
                XCTAssertEqual(d.take(e), [], "\(phase) \(e)")
                XCTAssertEqual(d.m.phase, phase, "\(phase) \(e)")
            }
        }
    }

    /// The manifest (every path in the drop) goes only to a receiver that said yes, and chunks
    /// only for a plan: a plan before the answer, or a decline after it, ends the drop.
    func testEachAnswerIsTakenOnlyInItsTurn() {
        var early = Self.sender(at: .awaitAnswer)
        XCTAssertEqual(early.take("planMore"), [.send(.error), .end(.failed(.unexpected))])
        var twice = Self.sender(at: .awaitPlan)
        XCTAssertEqual(twice.take("accept"), [.send(.error), .end(.failed(.unexpected))])
        var late = Self.sender(at: .awaitVerdict)
        XCTAssertEqual(late.take("decline"), [.send(.error), .end(.failed(.unexpected))])
        var no = Self.sender(at: .awaitAnswer)
        XCTAssertEqual(no.take("decline"), [.end(.declined)])
        var unreadable = Self.sender(at: .awaitAnswer)
        XCTAssertEqual(unreadable.take("declineMalformed"), [.send(.error), .end(.failed(.malformed))])
        var plan = Self.sender(at: .awaitVerdict)
        XCTAssertEqual(plan.take("planMalformed"), [.send(.error), .end(.failed(.malformed))])
        // Before the offer nothing has been said, and nothing is: no manifest, no round.
        for e in ["accept", "planMore", "written", "complete"] {
            var idle = SenderDriver()
            let effects = idle.take(e)
            XCTAssertFalse(effects.contains(.send(.manifest)) || effects.contains(.round) || effects.contains(.send(.done)), e)
        }
    }

    /// A lost conversation is got back once the receiver has said what it holds. Before that
    /// nothing is held at the other end: the drop ends, and nobody is told (there is no
    /// connection to tell them on).
    func testALostConversationIsGotBackOnlyOnceTheDropIsUnderWay() {
        for phase in [Sender.Phase.idle, .awaitAnswer, .awaitPlan] {
            var d = Self.sender(at: phase)
            XCTAssertEqual(d.take("lost"), [.end(.failed(.lost))], "\(phase)")
        }
        for phase in [Sender.Phase.sending, .awaitVerdict] {
            var d = Self.sender(at: phase)
            XCTAssertEqual(d.take("lost"), [.reconnect], "\(phase)")
            XCTAssertEqual(d.m.phase, .reconnecting)
            XCTAssertEqual(d.take("lost"), [], "already being got back")
            XCTAssertEqual(d.take("gaveUp"), [.send(.error), .end(.failed(.couldNotGetBack))])
        }
        var notWaiting = Self.sender(at: .awaitVerdict)
        XCTAssertEqual(notWaiting.take("gaveUp"), [], "nobody was reconnecting")
    }

    /// Reconnect after reconnect to a receiver that takes nothing in is not progress: after so
    /// many in a row the drop is given up. A round that is merely slow does not count, and
    /// anything new arriving starts the count again.
    func testReconnectsThatFindNothingNewEndTheDrop() {
        var d = Self.sender(at: .sending)
        for n in 1...2 {
            d.take("lost")
            XCTAssertEqual(d.take("planSame"), [.reconnected, .adopt, .round], "reconnect \(n)")
            XCTAssertEqual(d.m.fruitless, n)
        }
        d.take("lost")
        XCTAssertEqual(d.take("planSame"), [.reconnected, .adopt, .send(.error), .end(.failed(.fruitless))])
        XCTAssertEqual(d.m.phase, .failed)

        var recovered = Self.sender(at: .sending)
        recovered.take("lost"); recovered.take("planSame")
        recovered.take("lost"); recovered.take("planSame")
        recovered.take("lost")
        XCTAssertEqual(recovered.take("planMore"), [.reconnected, .adopt, .round], "something new arrived")
        XCTAssertEqual(recovered.m.fruitless, 0)

        // Rounds that end with nothing new, on a conversation that was never lost, are the
        // receiver's to count (its idle rounds), not the sender's.
        var slow = Self.sender(at: .sending)
        for _ in 0..<10 {
            slow.take("written")
            XCTAssertEqual(slow.take("planSame"), [.adopt, .round])
        }
        XCTAssertEqual(slow.m.fruitless, 0)

        var impatient = Self.sender(at: .sending, patience: 1)
        impatient.take("lost")
        XCTAssertEqual(impatient.take("planSame").last, .end(.failed(.fruitless)))
    }

    /// On a connection that has just proved the drop, only a plan or "complete" is an answer.
    /// Anything else is an attempt that got nowhere: the drop neither ends nor carries on.
    func testOnlyAPlanOrCompleteAnswersAReconnect() {
        for e in ["accept", "decline", "declineMalformed", "other", "written", "begin"] {
            var d = Self.sender(at: .reconnecting)
            XCTAssertEqual(d.take(e), [], e)
            XCTAssertEqual(d.m.phase, .reconnecting, e)
        }
        var d = Self.sender(at: .reconnecting)
        XCTAssertEqual(d.take("planMalformed"), [.reconnected, .send(.error), .end(.failed(.malformed))])
    }

    /// Withdrawing trust says no farewell, in any phase: a farewell is a write, and a Mac that
    /// has stopped reading would hold whoever withdrew the trust (the review's F7).
    func testWithdrawingTrustSaysNoFarewell() {
        for phase in Sender.Phase.allCases where !phase.isFinal {
            var d = Self.sender(at: phase)
            XCTAssertEqual(d.take("withdrawn"), [.end(.failed(.withdrawn))], "\(phase)")
            XCTAssertEqual(d.m.phase, .failed)
        }
        for phase in Receiver.Phase.allCases where !phase.isFinal {
            var d = Self.receiver(at: phase)
            let effects = d.take("withdrawn")
            XCTAssertFalse(effects.contains { if case .send = $0 { return true } else { return false } }, "\(phase): \(effects)")
            XCTAssertEqual(effects.first, .end(.failed(.withdrawn)), "\(phase)")
            XCTAssertEqual(d.m.phase, .failed)
        }
    }

    /// The link's own fault is not said on the link, and before there is a conversation there
    /// is nobody to say anything to. A reason of this Mac's own is said, and then the drop ends.
    func testAReasonIsSaidOnlyWhenItCanBe() {
        for phase in Sender.Phase.allCases where !phase.isFinal {
            var told = Self.sender(at: phase)
            XCTAssertEqual(told.take("stopped"), (phase == .idle ? [] : [.send(.error)]) + [.end(.failed(.here))], "\(phase)")
            var quiet = Self.sender(at: phase)
            XCTAssertEqual(quiet.take("stoppedSilently"), [.end(.failed(.here))], "\(phase)")
            var stopped = Self.sender(at: phase)
            XCTAssertEqual(stopped.take("cancelled"), (phase == .idle ? [] : [.send(.error)]) + [.end(.cancelled)], "\(phase)")
            XCTAssertEqual(stopped.m.phase, .cancelled)
            var theirs = Self.sender(at: phase)
            XCTAssertEqual(theirs.take("error").last, .end(.failed(.theirs)), "\(phase)")
        }
        // The receiving end always has a conversation (it began with the offer). What it does
        // not say is what is not the sender's to hear: another session taking the drop over.
        for phase in Receiver.Phase.allCases where !phase.isFinal {
            var told = Self.receiver(at: phase)
            XCTAssertEqual(Array(told.take("stopped").prefix(2)), [.send(.error), .end(.failed(.here))], "\(phase)")
            var quiet = Self.receiver(at: phase)
            XCTAssertEqual(quiet.take("stoppedSilently").first, .end(.failed(.here)), "\(phase)")
            var stopped = Self.receiver(at: phase)
            XCTAssertEqual(Array(stopped.take("cancelled").prefix(2)), [.send(.error), .end(.cancelled)], "\(phase)")
        }
    }

    /// With the drop under way, silence is taken for a lost connection (the conversation is
    /// closed so that it is got back); before that, and while reconnecting, it is the end.
    func testSilenceUnderWayIsALostConnectionNotTheEnd() {
        for phase in [Sender.Phase.sending, .awaitVerdict] {
            var d = Self.sender(at: phase)
            XCTAssertEqual(d.take("silent"), [.hangUp], "\(phase)")
            XCTAssertEqual(d.m.phase, phase)
        }
        for phase in [Sender.Phase.awaitAnswer, .awaitPlan, .reconnecting] {
            var d = Self.sender(at: phase)
            XCTAssertEqual(d.take("silent"), [.send(.error), .end(.failed(.silent))], "\(phase)")
        }
        for phase in [Receiver.Phase.reading, .settling, .awaitSender] {
            var d = Self.receiver(at: phase)
            XCTAssertEqual(d.take("silent"), [.hangUp], "\(phase)")
            XCTAssertEqual(d.m.phase, phase)
        }
        for phase in [Receiver.Phase.awaitManifest, .preparing, .planning, .placing] {
            var d = Self.receiver(at: phase)
            XCTAssertEqual(d.take("silent"), [.end(.failed(.silent))], "\(phase)")
        }
    }

    // MARK: Attacks on the receiving machine

    /// A receiver at the given point of an honest drop.
    static func receiver(at phase: Receiver.Phase, patience: Int = 5) -> ReceiverDriver {
        var d = ReceiverDriver(patience: patience)
        let reading = ["begin", "yes", "manifest", "prepared", "said"]
        let path: [Receiver.Phase: [String]] = [
            .idle: [], .deciding: ["begin"], .declining: ["begin", "no"], .awaitManifest: ["begin", "yes"],
            .preparing: ["begin", "yes", "manifest"], .planning: ["begin", "yes", "manifest", "prepared"], .reading: reading,
            .settling: reading + ["done"], .awaitSender: reading + ["lost"], .placing: reading + ["done", "whole"],
            .completed: reading + ["done", "whole", "placed"], .declined: ["begin", "no", "said"], .failed: ["begin", "lost"],
            .cancelled: ["cancelled"]]
        for e in path[phase]! { d.take(e) }
        XCTAssertEqual(d.m.phase, phase, "an honest drop no longer gets here")
        return d
    }

    func testAnHonestDropIsAskedAboutPreparedJudgedAndPutInPlace() {
        var d = ReceiverDriver()
        XCTAssertEqual(d.take("begin"), [.ask])
        XCTAssertEqual(d.take("yes"), [.send(.accept)])
        XCTAssertEqual(d.take("manifest"), [.prepare])
        XCTAssertEqual(d.take("prepared"), [.send(.plan)])
        XCTAssertEqual(d.take("said"), [])
        XCTAssertEqual(d.take("done"), [.settle])
        // Something is missing: the answer is what is here, and another round.
        XCTAssertEqual(d.take("more"), [.send(.plan)])
        XCTAssertEqual(d.take("done"), [.settle])
        XCTAssertEqual(d.take("whole"), [.place])
        XCTAssertEqual(d.take("placed"), [.send(.complete), .end(.completed)])
        XCTAssertEqual(d.m.phase, .completed)
    }

    /// Nothing is accepted, prepared, written or judged before the person said yes: whatever a
    /// sender says while the question is up is its giving up, and the reports a shell makes
    /// later in a drop mean nothing yet.
    func testNothingStartsBeforeTheYes() {
        for e in Self.receiverEvents where e != "yes" {
            for phase in [Receiver.Phase.idle, .deciding] {
                var d = Self.receiver(at: phase)
                let effects = d.take(e)
                for forbidden in [Receiver.Effect.send(.accept), .prepare, .send(.plan), .settle, .place, .hold, .send(.complete)] {
                    XCTAssertFalse(effects.contains(forbidden), "\(phase) \(e): \(effects)")
                }
                XCTAssertFalse([.awaitManifest, .preparing, .planning, .reading, .settling, .placing, .completed].contains(d.m.phase), "\(phase) \(e)")
            }
        }
        var manifest = Self.receiver(at: .deciding)
        XCTAssertEqual(manifest.take("manifest"), [.end(.failed(.wentAway)), .unask])
        var theirs = Self.receiver(at: .deciding)
        XCTAssertEqual(theirs.take("error"), [.end(.failed(.theirs)), .unask])
        var unshown = ReceiverDriver()
        XCTAssertEqual(unshown.take("yes"), [], "a yes to a question that was never asked")
        XCTAssertEqual(unshown.m.phase, .idle)
    }

    /// Nobody to ask means no: the question is not shown, the sender is told, and that is the end.
    func testNobodyToAskMeansNo() {
        var d = ReceiverDriver()
        XCTAssertEqual(d.take("beginNobody"), [.send(.decline(.notReceiving))])
        XCTAssertEqual(d.take("yes"), [], "and there is nothing to say yes to")
        XCTAssertEqual(d.take("said"), [.end(.declined)])
        XCTAssertEqual(d.m.phase, .declined)
    }

    /// A drop that ended before it was shown is not shown: trust withdrawn (or anything else
    /// that ends it) while the offer was on its way in, and nobody is asked about it.
    func testAnOfferThatEndedBeforeItWasShownIsNotShown() {
        for e in ["withdrawn", "cancelled", "stopped", "stoppedSilently", "silent"] {
            var d = ReceiverDriver()
            d.take(e)
            XCTAssertTrue(d.m.phase.isFinal, e)
            XCTAssertEqual(d.take("begin"), [], e)
        }
    }

    /// The question was asked under a pairing. A yes after that pairing ended starts nothing
    /// (the review's F6): the sender is told, and no accept goes out.
    func testAYesAfterThePairingEndedStartsNothing() {
        var d = Self.receiver(at: .deciding)
        XCTAssertEqual(d.take("yesUnpaired"), [.send(.decline(.pairingRanOut)), .send(.error), .end(.failed(.pairingRanOut))])
        XCTAssertEqual(d.m.phase, .failed)
        XCTAssertEqual(d.take("manifest"), [])
    }

    /// The person said yes to what the offer described. A manifest that is anything else (one
    /// more file, one more byte, another name, a name fewer) is refused and nothing is prepared.
    func testAManifestThatIsNotWhatWasOfferedIsRefused() {
        for i in Self.others.indices {
            var d = Self.receiver(at: .awaitManifest)
            d.other = i
            XCTAssertEqual(d.take("manifestOther"), [.send(.error), .end(.failed(.notAsOffered))], "\(Self.others[i])")
            XCTAssertEqual(d.m.phase, .failed)
        }
        var invalid = Self.receiver(at: .awaitManifest)
        XCTAssertEqual(invalid.take("manifestInvalid"), [.send(.error), .end(.failed(.invalidManifest))])
        var unreadable = Self.receiver(at: .awaitManifest)
        XCTAssertEqual(unreadable.take("manifestMalformed"), [.send(.error), .end(.failed(.malformed))])
        var good = Self.receiver(at: .awaitManifest)
        XCTAssertEqual(good.take("manifest"), [.prepare])
    }

    /// "Complete" is said only of a drop that was judged whole and then put in place, and the
    /// drop is put in place only when it was judged whole.
    func testCompleteIsSaidOnlyOfADropThatIsWholeAndInPlace() {
        for phase in Receiver.Phase.allCases where phase != .placing && phase != .completed {
            var d = Self.receiver(at: phase)
            XCTAssertEqual(d.take("placed"), [], "\(phase)")
            XCTAssertEqual(d.m.phase, phase)
        }
        for phase in Receiver.Phase.allCases where phase != .settling {
            for verdict in ["whole", "more", "nothingNew"] {
                var d = Self.receiver(at: phase)
                XCTAssertEqual(d.take(verdict), [], "\(phase) \(verdict)")
            }
        }
        for verdict in ["more", "nothingNew"] {
            var d = Self.receiver(at: .settling)
            XCTAssertEqual(d.take(verdict), [.send(.plan)], verdict)
            XCTAssertEqual(d.m.phase, .reading)
        }
        // And over every transition there is: "complete" follows `placed`, or answers a sender
        // that came back to a drop already finished. `place` follows a round judged whole.
        for step in Self.receiverRelation().steps {
            if step.effects.contains("send complete") {
                XCTAssertTrue((step.event == "placed" && step.from.contains("\"placing\"")) || (step.event == "senderBack" && step.from.contains("\"completed\"")), "\(step)")
            }
            if step.effects.contains("place") { XCTAssertTrue(step.event == "whole" && step.from.contains("\"settling\""), "\(step)") }
            if step.effects.contains("end completed") { XCTAssertTrue(step.event == "placed" && step.from.contains("\"placing\""), "\(step)") }
        }
    }

    /// Data connections are let in while rounds are being received and at no other time: not
    /// before the folder is ready (there is nothing to write into), and not once the drop has
    /// been judged whole or has ended, so that what is put in place is what was judged.
    func testDataIsTakenOnlyWhileRoundsAreBeingReceived() {
        for phase in Receiver.Phase.allCases {
            XCTAssertEqual(Self.receiver(at: phase).m.takesData, [.planning, .reading, .settling, .awaitSender].contains(phase), "\(phase)")
        }
        // Whatever the machine was made with and however it got there: it is the phase alone.
        var rng = Seeded(state: 7)
        for _ in 0..<2000 {
            var m = Receiver(offered: Self.description(&rng), patience: Self.receiverPatience.randomElement(using: &rng)!)
            for _ in 0..<30 {
                _ = Self.receiverEvent(Self.receiverLabel(&rng, m), &rng, offered: Self.offered).map { m.step($0) }
                XCTAssertEqual(m.takesData, [.planning, .reading, .settling, .awaitSender].contains(m.phase))
            }
        }
    }

    /// Round after round that delivers nothing new ends the drop; one that delivers anything
    /// starts the count again.
    func testRoundsThatDeliverNothingEndTheDrop() {
        var d = Self.receiver(at: .reading, patience: 3)
        d.take(["done", "nothingNew"]); d.take(["done", "nothingNew"])
        XCTAssertEqual(d.m.idle, 2)
        XCTAssertEqual(d.take(["done", "more"]), [.send(.plan)])
        XCTAssertEqual(d.m.idle, 0)
        d.take(["done", "nothingNew"]); d.take(["done", "nothingNew"])
        XCTAssertEqual(d.take(["done", "nothingNew"]), [.send(.error), .end(.failed(.incomplete))])
        XCTAssertEqual(d.m.phase, .failed)
    }

    /// Once the first plan is out the drop is accepted and partly here: a lost conversation is
    /// held for the sender to come back to. Before that there is nothing to hold.
    func testALostConversationIsHeldOnlyOnceTheDropIsUnderWay() {
        var reading = Self.receiver(at: .reading)
        XCTAssertEqual(reading.take("lost"), [.hold])
        XCTAssertEqual(reading.m.phase, .awaitSender)
        XCTAssertEqual(reading.take("lost"), [], "already held")
        XCTAssertEqual(reading.take("senderBack"), [.send(.plan)])
        XCTAssertEqual(reading.m.phase, .reading)
        // The plan could not be said (lost again already): held again.
        XCTAssertEqual(reading.take("lost"), [.hold])
        XCTAssertEqual(reading.take("gaveUp"), [.send(.error), .end(.failed(.didNotComeBack))])

        for phase in [Receiver.Phase.declining, .awaitManifest, .preparing, .planning] {
            var d = Self.receiver(at: phase)
            XCTAssertEqual(d.take("lost"), [.send(.error), .end(.failed(.lost))], "\(phase)")
        }
        var deciding = Self.receiver(at: .deciding)
        XCTAssertEqual(deciding.take("lost"), [.end(.failed(.wentAway)), .unask])
        // A sender "coming back" to a drop that is not being held for it changes nothing.
        for phase in Receiver.Phase.allCases where phase != .awaitSender && phase != .completed {
            var d = Self.receiver(at: phase)
            XCTAssertEqual(d.take("senderBack"), [], "\(phase)")
            XCTAssertEqual(d.take("gaveUp"), [], "\(phase)")
        }
    }

    /// A decline is the end only once it has been said, and the first plan starts the rounds
    /// only once it has been said: a conversation lost under either is a drop that failed.
    func testWhatIsSaidCountsOnlyOnceItIsOut() {
        var no = Self.receiver(at: .declining)
        XCTAssertEqual(no.m.phase, .declining)
        XCTAssertEqual(no.take("said"), [.end(.declined)])
        var first = Self.receiver(at: .planning)
        XCTAssertEqual(first.take("done"), [.send(.error), .end(.failed(.unexpected))], "the rounds have not begun")
        var begun = Self.receiver(at: .planning)
        XCTAssertEqual(begun.take("said"), [])
        XCTAssertEqual(begun.m.phase, .reading)
        XCTAssertEqual(begun.take("said"), [], "said once")
        XCTAssertEqual(begun.m.phase, .reading)
        // And "it went out" of something that was never to be said is nothing.
        for phase in Receiver.Phase.allCases where phase != .declining && phase != .planning {
            var d = Self.receiver(at: phase)
            XCTAssertEqual(d.take("said"), [], "\(phase)")
            XCTAssertEqual(d.m.phase, phase)
        }
    }

    /// The person answers once, and only a question that is up: a no after the yes, a yes
    /// after the no, an answer before the question or after the end, mean nothing.
    func testThePersonAnswersOnceAndOnlyAQuestionThatIsUp() {
        for phase in Receiver.Phase.allCases where phase != .deciding {
            for answer in ["yes", "yesUnpaired", "no"] {
                var d = Self.receiver(at: phase)
                XCTAssertEqual(d.take(answer), [], "\(phase) \(answer)")
                XCTAssertEqual(d.m.phase, phase)
            }
        }
        var no = Self.receiver(at: .deciding)
        XCTAssertEqual(no.take("no"), [.send(.decline(.declined))])
        // The question is asked once: a session that has begun does not begin again.
        for phase in Receiver.Phase.allCases where phase != .idle {
            for begin in ["begin", "beginNobody"] {
                var d = Self.receiver(at: phase)
                XCTAssertEqual(d.take(begin), [], "\(phase) \(begin)")
            }
        }
    }

    /// A finished drop answers one thing, and that only with "complete" again: a sender that
    /// lost the conversation before it heard. Nothing else moves it, and no other end answers.
    func testAFinishedDropSaysCompleteAgainAndNothingElse() {
        for e in Self.receiverEvents {
            var d = Self.receiver(at: .completed)
            XCTAssertEqual(d.take(e), e == "senderBack" ? [.send(.complete)] : [], e)
            XCTAssertEqual(d.m.phase, .completed)
        }
        for phase in [Receiver.Phase.declined, .failed, .cancelled] {
            for e in Self.receiverEvents {
                var d = Self.receiver(at: phase)
                XCTAssertEqual(d.take(e), [], "\(phase) \(e)")
                XCTAssertEqual(d.m.phase, phase)
            }
        }
    }

    /// Each message in its turn: a manifest only after the yes and only once, "done" only while
    /// a round is being read. Anything else ends the drop, and the sender is told.
    func testAnythingOutOfTurnEndsTheDrop() {
        let unexpected: [Receiver.Effect] = [.send(.error), .end(.failed(.unexpected))]
        var early = Self.receiver(at: .awaitManifest)
        XCTAssertEqual(early.take("done"), unexpected)
        var theirs = Self.receiver(at: .awaitManifest)
        XCTAssertEqual(theirs.take("error"), unexpected)
        for phase in [Receiver.Phase.preparing, .planning, .reading, .settling, .awaitSender, .placing] {
            var second = Self.receiver(at: phase)
            XCTAssertEqual(second.take("manifest"), unexpected, "\(phase)")
        }
        for phase in [Receiver.Phase.preparing, .planning, .settling, .awaitSender, .placing] {
            var d = Self.receiver(at: phase)
            XCTAssertEqual(d.take("done"), unexpected, "\(phase)")
        }
        var other = Self.receiver(at: .reading)
        XCTAssertEqual(other.take("other"), unexpected)
        var unreadable = Self.receiver(at: .reading)
        XCTAssertEqual(unreadable.take("doneMalformed"), [.send(.error), .end(.failed(.malformed))])
        var reason = Self.receiver(at: .reading)
        XCTAssertEqual(reason.take("error"), [.send(.error), .end(.failed(.theirs))])
    }

    /// A question still on screen goes when the drop does, however it ended; and once the
    /// person has answered there is no question to take away.
    func testTheQuestionGoesWhenTheDropDoes() {
        for step in Self.receiverRelation().steps {
            let wasUp = step.from.contains("\"deciding\"")
            let ended = ["failed", "cancelled"].contains { step.to.contains("\"\($0)\"") }
            XCTAssertEqual(step.effects.contains("unask"), wasUp && ended && !step.effects.contains("send decline pairingRanOut"), "\(step)")
        }
        var cancelled = Self.receiver(at: .deciding)
        XCTAssertEqual(cancelled.take("cancelled"), [.send(.error), .end(.cancelled), .unask])
    }
}
