// Copyright (C) 2026 Niels Joubert
// SPDX-License-Identifier: GPL-3.0-or-later
import CryptoKit
import Foundation
import XCTest
@testable import NimbusCrypto

/// The pairing transaction by itself: no socket, no listener, no thread. This target depends on
/// `NimbusCrypto` and nothing else, which is the point of that module being pure.
///
/// Three kinds of test.
///
/// The tie to the specification. Every state the machine can reach, under every event, is
/// written out as `formal/tla/PairingImpl.tla`, and TLC checks that relation against `Step` in
/// `formal/tla/PairingMachine.tla` (`./build.sh verify`). That file is written from ONE machine
/// per state of the specification, and it says what the machine was TOLD to do by name only
/// ("send commit", "codes"). So, beside it, the two things it cannot say, which are the
/// abstraction contract at the top of `PairingMachine.tla`:
///
///   - CONGRUENCE: many machines for every state of the specification (other handshake hashes,
///     other values, other numbers, other histories, every event in many concrete forms), and
///     every step of every one of them is the step the relation has;
///   - PAYLOADS: at every one of those steps, what was sent and what was shown is what the
///     protocol says it is, worked out here a second time from the protocol's description and
///     from nothing inside the machine.
///
/// And the attacks on the machine, each the guard of one line in `scripts/mutate.py`.
final class PairingMachineTests: XCTestCase {
    typealias Event = PairingMachine.Event
    typealias Effect = PairingMachine.Effect

    // MARK: - The contract's three functions

    /// THE ABSTRACTION OF A STATE: what the specification sees of a machine. Six things, and
    /// none of them a value of the exchange.
    struct Abstract: Hashable {
        var role: PairingMachine.Role
        var byNumber: Bool
        var phase: PairingMachine.Phase
        var tries: Int
        var local: Bool
        var remote: Bool

        init(_ m: PairingMachine) { self.init(m.control) }

        init(_ c: PairingMachine.Control) {
            role = c.role
            byNumber = c.byNumber
            phase = c.phase
            tries = c.triesLeft
            local = c.localRight
            remote = c.remoteRight
        }

        /// The specification's `Start(role, byNumber)`.
        init(start role: PairingMachine.Role, byNumber: Bool) {
            self.role = role
            self.byNumber = byNumber
            phase = .idle
            tries = 3
            local = false
            remote = false
        }

        /// As the specification writes it.
        var tla: String {
            "[role |-> \"\(role.rawValue)\", byNumber |-> \(byNumber ? "TRUE" : "FALSE"), phase |-> \"\(phase.rawValue)\", " +
                "tries |-> \(tries), local |-> \(local ? "TRUE" : "FALSE"), remote |-> \(remote ? "TRUE" : "FALSE")]"
        }
    }

    /// The specification's events.
    static let events = ["begin", "typedRight", "typedWrong", "timeout",
                         "commit", "commitDamaged", "commitMalformed", "nonce", "nonceDamaged", "nonceMalformed",
                         "reveal", "revealDamaged", "revealMalformed", "revealWrong", "paired", "failed", "other"]

    /// THE ABSTRACTION OF AN EFFECT: its name. What it carries is the payload oracle's business.
    static func name(_ effect: Effect) -> String {
        switch effect {
        case .send(.commit, _): return "send commit"
        case .send(.nonce, _): return "send nonce"
        case .send(.reveal, _): return "send reveal"
        case .send(.paired, _): return "send paired"
        case .send(.failed, _): return "send failed"
        case .send(.other, _): return "send other"
        case .codes: return "codes"
        case .confirming: return "confirming"
        case .otherTyped: return "otherTyped"
        case .store: return "store"
        case .fail(let why): return "fail \(why.rawValue)"
        }
    }

    /// The name of the effect a decision becomes; `keep` becomes none.
    static func name(_ decision: PairingMachine.Decision) -> String? {
        switch decision {
        case .keep: return nil
        case .send(let message): return name(.send(message, value: nil))
        case .showCodes, .askAgain: return "codes"
        case .confirming: return "confirming"
        case .otherTyped: return "otherTyped"
        case .store: return "store"
        case .fail(let why): return "fail \(why.rawValue)"
        }
    }

    static func tuple(_ effects: [String]) -> String {
        effects.isEmpty ? "<< >>" : "<< " + effects.map { "\"\($0)\"" }.joined(separator: ", ") + " >>"
    }

    // MARK: - The protocol, a second time

    /// The two derivations of a pairing, written from the protocol's description (CLAUDE.md, The
    /// protocol; the same lines as `scripts/vectors.py`) on CryptoKit's SHA-256 and HMAC, and on
    /// nothing of `NimbusCrypto`: not `PairCodes`, not `Crypto.kdf`.
    ///
    ///     commit = SHA-256("nimbus-drop pair commit v1" ‖ h ‖ Ns)
    ///     codes  = KDF(Ns ‖ Nr, "nimbus-drop pair codes v1" ‖ h, 16), KDF being HKDF-SHA-256 with an
    ///              empty salt; the first eight bytes are the code the receiver shows, the last eight
    ///              the sender's, each as a big-endian number modulo a million, six digits
    enum Described {
        static func commitment(h: Data, to ns: Data) -> Data {
            Data(SHA256.hash(data: Data("nimbus-drop pair commit v1".utf8) + h + ns))
        }

        static func codes(h: Data, ns: Data, nr: Data) -> (receiver: String, sender: String) {
            // HKDF by its definition (RFC 5869), one block: extract with a salt of zeros, expand with info ‖ 0x01.
            let prk = Data(HMAC<SHA256>.authenticationCode(for: ns + nr, using: SymmetricKey(data: Data(count: 32))))
            let block = Data(HMAC<SHA256>.authenticationCode(for: Data("nimbus-drop pair codes v1".utf8) + h + Data([1]), using: SymmetricKey(data: prk)))
            let bytes = [UInt8](block.prefix(16))
            func six(_ part: ArraySlice<UInt8>) -> String {
                var v: UInt64 = 0
                for b in part { v = v << 8 | UInt64(b) }
                let digits = String(v % 1_000_000)
                return String(repeating: "0", count: 6 - digits.count) + digits
            }
            return (six(bytes[0..<8]), six(bytes[8..<16]))
        }
    }

    /// What went wrong at a step, and which of the two obligations it breaks.
    struct Complaint: Error {
        enum Kind { case control, payload }
        var kind: Kind
        var text: String
    }

    /// THE ORACLE. What the protocol says of one Mac's side of a pairing, kept from what went
    /// into the machine and what came out of it and from nothing inside it.
    struct Transcript {
        let role: PairingMachine.Role
        let byNumber: Bool
        let h: Data
        let theirNumber: String
        /// Every value the machine has taken from its random source.
        var drawn: [Data] = []
        /// A responder: the commitment that arrived in its turn.
        var commitment: Data?
        /// The other Mac's value: Nr to an initiator; to a responder Ns, once it has opened the commitment.
        var theirs: Data?
        /// The code this Mac shows and the code its person is to type, once the codes exist.
        var shows: String?
        var expects: String?
        var stores = 0

        /// THE ABSTRACTION OF AN EVENT, by what the numbers say:
        ///   - a commitment, a value or a reveal is malformed when it could not be read, damaged
        ///     when it is not 32 bytes, and otherwise good; except that a reveal of 32 bytes is
        ///     good only if a commitment was taken and SHA-256(label ‖ h ‖ reveal) is that
        ///     commitment, and wrong if not;
        ///   - an entry is right if the codes exist and it is, byte for byte, the code expected;
        ///     wrong otherwise;
        ///   - "paired", "failed" and anything else are themselves, whatever they carry.
        func label(_ event: Event) -> String {
            switch event {
            case .begin: return "begin"
            case .timeout: return "timeout"
            case .typed(let entry):
                guard let expects else { return "typedWrong" }
                return Array(entry.utf8) == Array(expects.utf8) ? "typedRight" : "typedWrong"
            case .received(.commit, let v):
                guard let v else { return "commitMalformed" }
                return v.count == 32 ? "commit" : "commitDamaged"
            case .received(.nonce, let v):
                guard let v else { return "nonceMalformed" }
                return v.count == 32 ? "nonce" : "nonceDamaged"
            case .received(.reveal, let v):
                guard let v else { return "revealMalformed" }
                guard v.count == 32 else { return "revealDamaged" }
                guard let commitment, Described.commitment(h: h, to: v) == commitment else { return "revealWrong" }
                return "reveal"
            case .received(.paired, _): return "paired"
            case .received(.failed, _): return "failed"
            case .received(.other, _): return "other"
            }
        }

        /// What the machine must have said to do, values and all, given the NAMES of what it
        /// was to do. Throws when the protocol has no such step.
        ///
        ///   - a commitment that is sent is the commitment, under this connection's hash, to the
        ///     one value drawn in this step;
        ///   - a value that is sent (a responder's) is the one value drawn in this step, and the
        ///     commitment that has just arrived is the one a reveal will be held to;
        ///   - a reveal that is sent is the value that was committed to;
        ///   - nothing is drawn in any other step, and never a second value in one transaction;
        ///   - the codes are those of (h, Ns, Nr): the sender shows `sender` and is to type
        ///     `receiver`, the receiver the other way round; by identity number, nothing is
        ///     shown and the other Mac's number is to be typed; once they exist they do not change;
        ///   - the tries left that are shown are the state's;
        ///   - a pairing is stored at most once.
        mutating func effects(named names: [String], after event: Event, called label: String, leaving state: Abstract, drew: [Data]) throws -> [Effect] {
            func no(_ what: String) -> Complaint { Complaint(kind: .payload, text: what) }
            var carried: Data?
            if case .received(_, let v) = event { carried = v }
            let made = names.filter { $0 == "send commit" || $0 == "send nonce" }.count
            guard drew.count == made else { throw no("\(drew.count) values were drawn from the random source in a step where the protocol makes \(made)") }
            drawn += drew
            guard drawn.count <= 1 else { throw no("a second value was drawn in one transaction") }
            var out: [Effect] = []
            for name in names {
                switch name {
                case "send commit":
                    guard role == .initiator, !byNumber, label == "begin", let ns = drawn.first else { throw no("a commitment is sent by an initiator, by codes, as it begins") }
                    out.append(.send(.commit, value: Described.commitment(h: h, to: ns)))
                case "send nonce":
                    guard role == .responder, !byNumber, label == "commit", let arrived = carried, let nr = drawn.first else { throw no("a responder's value is sent when the commitment arrives") }
                    commitment = arrived
                    out.append(.send(.nonce, value: nr))
                case "send reveal":
                    guard role == .initiator, !byNumber, label == "nonce", let arrived = carried, let ns = drawn.first else { throw no("the commitment is opened when the responder's value arrives") }
                    theirs = arrived
                    out.append(.send(.reveal, value: ns))
                case "codes":
                    if shows == nil {
                        if byNumber {
                            guard label == "begin" else { throw no("by identity number the question is asked as the pairing begins") }
                            (shows, expects) = ("", theirNumber)
                        } else {
                            if role == .responder {
                                guard label == "reveal", let arrived = carried else { throw no("a responder's codes exist when the commitment is opened") }
                                theirs = arrived
                            }
                            guard let mine = drawn.first, let theirs else { throw no("the codes exist only when both values do") }
                            let codes = role == .initiator ? Described.codes(h: h, ns: mine, nr: theirs) : Described.codes(h: h, ns: theirs, nr: mine)
                            (shows, expects) = role == .initiator ? (codes.sender, codes.receiver) : (codes.receiver, codes.sender)
                        }
                    }
                    out.append(.codes(mine: shows ?? "", triesLeft: state.tries))
                case "send paired": out.append(.send(.paired, value: nil))
                case "send failed": out.append(.send(.failed, value: nil))
                case "confirming": out.append(.confirming)
                case "otherTyped": out.append(.otherTyped)
                case "store":
                    stores += 1
                    guard stores == 1 else { throw no("a pairing was stored a second time") }
                    out.append(.store)
                default:
                    guard name.hasPrefix("fail "), let why = PairingMachine.Failure(rawValue: String(name.dropFirst(5))) else { throw no("an effect the protocol does not have: \(name)") }
                    out.append(.fail(why))
                }
            }
            guard (state.phase == .paired) == (stores == 1) else { throw no("the machine is \(state.phase.rawValue) and has said to store \(stores) times") }
            return out
        }
    }

    // MARK: - A representative

    /// SplitMix64: the same numbers from the same seed, on every machine and every run.
    struct Seeded {
        var state: UInt64

        init(_ seed: UInt64) { state = seed }

        mutating func next() -> UInt64 {
            state &+= 0x9E37_79B9_7F4A_7C15
            var z = state
            z = (z ^ (z >> 30)) &* 0xBF58_476D_1CE4_E5B9
            z = (z ^ (z >> 27)) &* 0x94D0_49BB_1331_11EB
            return z ^ (z >> 31)
        }

        mutating func below(_ n: Int) -> Int { Int(next() % UInt64(n)) }

        mutating func bytes(_ count: Int) -> Data {
            var out = [UInt8]()
            out.reserveCapacity(count + 8)
            while out.count < count { withUnsafeBytes(of: next()) { out.append(contentsOf: $0) } }
            return Data(out.prefix(count))
        }

        mutating func digits(_ count: Int) -> String {
            var out = ""
            for _ in 0..<count { out.append(Character(UnicodeScalar(UInt8(48 + below(10))))) }
            return out
        }
    }

    /// One concrete machine and everything around it: the oracle's account of it, the state
    /// the SPECIFICATION is in (followed through the relation, never read from the machine),
    /// and what the other end knows, so that "the value committed to" and "the code expected
    /// with one digit changed" can be made for whatever has happened so far.
    struct Rep {
        var m: PairingMachine
        var t: Transcript
        var s: Abstract
        /// Supplies the machine's random source and the other end's choices.
        var gen: Seeded
        /// Another connection's handshake hash.
        let otherH: Data
        /// The commitment the other end last sent, with the value behind it (if it has one).
        var offered: (commitment: Data, ns: Data?)?
        /// The value behind the commitment the machine took.
        var opening: Data?
        /// What the machine has sent.
        var sentCommitment: Data?
        /// What has been typed, in order.
        var entries: [String] = []
        /// What has happened, for a failure to print.
        var trace: [(form: String, event: Event, label: String, effects: [Effect])] = []

        init(role: PairingMachine.Role, byNumber: Bool, h: Data, theirNumber: String, otherH: Data, gen: Seeded) {
            m = PairingMachine(role: role, byNumber: byNumber, h: h, theirNumber: theirNumber)
            t = Transcript(role: role, byNumber: byNumber, h: h, theirNumber: theirNumber)
            s = Abstract(start: role, byNumber: byNumber)
            self.gen = gen
            self.otherH = otherH
        }

        /// A machine nobody has seen before: its hash, its number and every value from `gen`.
        static func fresh(role: PairingMachine.Role, byNumber: Bool, _ gen: inout Seeded) -> Rep {
            let h: Data
            switch gen.below(16) {
            case 0: h = Data(count: 32)
            case 1: h = Data(repeating: 0xFF, count: 32)
            case 2: h = Data(repeating: 0x68, count: 32)     // the one hash every machine had before this test
            case 3: h = gen.bytes(gen.below(65))             // not 32 bytes: the shell gives no such hash, and the machine is not to care
            case 4: h = gen.bytes(48).dropFirst(9).prefix(32) // from the middle of a longer buffer
            default: h = gen.bytes(32)
            }
            let number: String
            switch gen.below(byNumber ? 12 : 4) {
            case 0: number = ""                              // what the shell gives a pairing by codes
            case 1: number = gen.digits(6)
            case 2: number = String(repeating: "0", count: 30)
            case 3: number = gen.digits(31)
            default: number = gen.digits(30)
            }
            let other = gen.bytes(32)
            return Rep(role: role, byNumber: byNumber, h: h, theirNumber: number, otherH: other, gen: gen)
        }

        /// How many digits the code to type has, or will have.
        var length: Int {
            let n = t.expects?.count ?? (t.byNumber ? t.theirNumber.count : 6)
            return n == 0 ? 6 : n
        }

        var summary: String {
            "\(t.role.rawValue), by \(t.byNumber ? "identity number" : "codes"); h = \(PairingMachineTests.hex(t.h)); the other Mac's number = \"\(t.theirNumber)\""
        }
    }

    static func hex(_ data: Data?) -> String { data.map { $0.isEmpty ? "(no bytes)" : $0.map { String(format: "%02x", $0) }.joined() } ?? "(unreadable)" }

    static func describe(_ event: Event) -> String {
        switch event {
        case .begin: return "begin"
        case .timeout: return "timeout"
        case .typed(let entry): return "typed \(entry.count > 80 ? "\(entry.count) characters" : String(reflecting: entry))"
        case .received(let message, let value): return "received \(message.rawValue) \(hex(value))"
        }
    }

    static func describe(_ effects: [Effect]) -> String {
        "[" + effects.map { effect -> String in
            switch effect {
            case .send(let message, let value): return "send \(message.rawValue)" + (value.map { " " + hex($0) } ?? "")
            case .codes(let mine, let left): return "codes(mine: \"\(mine)\", triesLeft: \(left))"
            default: return name(effect)
            }
        }.joined(separator: ", ") + "]"
    }

    // MARK: - Every concrete form an event can take

    enum Family { case begin, timeout, typed, commit, nonce, reveal, paired, failed, other }

    static func family(of label: String) -> Family {
        switch label {
        case "begin": return .begin
        case "timeout": return .timeout
        case "typedRight", "typedWrong": return .typed
        case "commit", "commitDamaged", "commitMalformed": return .commit
        case "nonce", "nonceDamaged", "nonceMalformed": return .nonce
        case "reveal", "revealDamaged", "revealMalformed", "revealWrong": return .reveal
        case "paired": return .paired
        case "failed": return .failed
        default: return .other
        }
    }

    /// One way an event can look. `make` is nil where this form cannot be made (there is no
    /// code to mistype yet). WHICH event of the specification a form is, is never said here:
    /// the oracle says it, from the numbers.
    struct Form {
        let name: String
        let family: Family
        let make: (inout Rep) -> Event?
    }

    static let forms: [Form] = {
        var all: [Form] = [Form(name: "begin", family: .begin) { _ in .begin }, Form(name: "time runs out", family: .timeout) { _ in .timeout }]

        // What a person can type.
        func typed(_ name: String, _ text: @escaping (inout Rep) -> String?) {
            all.append(Form(name: name, family: .typed) { rep in text(&rep).map { .typed($0) } })
        }
        func mistyped(_ how: String, _ change: @escaping (String, inout Rep) -> String?) {
            typed("the code expected, \(how)") { rep in
                guard let code = rep.t.expects else { return nil }
                return change(code, &rep)
            }
        }
        func changed(_ code: String, at index: Int) -> String? {
            var digits = Array(code.utf8)
            guard digits.indices.contains(index), digits[index] >= 48, digits[index] <= 57 else { return nil }
            digits[index] = 48 + (digits[index] - 48 + 1) % 10
            return String(decoding: digits, as: UTF8.self)
        }
        typed("the code expected") { $0.t.expects }
        mistyped("with a space in the middle") { code, _ in String(code.prefix(code.count / 2)) + " " + String(code.dropFirst(code.count / 2)) }
        mistyped("with a hyphen in the middle") { code, _ in String(code.prefix(code.count / 2)) + "-" + String(code.dropFirst(code.count / 2)) }
        mistyped("grouped in fives") { code, _ in PublicKey.grouped(code) + " " }
        mistyped("with a space before it") { code, _ in " " + code }
        mistyped("with a newline after it") { code, _ in code + "\n" }
        mistyped("with a NUL after it") { code, _ in code + "\0" }
        mistyped("and one digit more") { code, rep in code + rep.gen.digits(1) }
        mistyped("less its last digit") { code, _ in code.isEmpty ? nil : String(code.dropLast()) }
        mistyped("with its first digit changed") { code, _ in changed(code, at: 0) }
        mistyped("with its last digit changed") { code, _ in changed(code, at: code.utf8.count - 1) }
        mistyped("with one digit changed") { code, rep in code.isEmpty ? nil : changed(code, at: rep.gen.below(code.utf8.count)) }
        mistyped("backwards") { code, _ in String(code.reversed()) }
        mistyped("twice over") { code, _ in code + code }
        mistyped("in full-width digits") { code, _ in String(String.UnicodeScalarView(code.unicodeScalars.map { UnicodeScalar($0.value - 48 + 0xFF10) ?? $0 })) }
        mistyped("in Arabic-Indic digits") { code, _ in String(String.UnicodeScalarView(code.unicodeScalars.map { UnicodeScalar($0.value - 48 + 0x0660) ?? $0 })) }
        typed("the code this Mac itself shows") { $0.t.shows }
        typed("nothing") { _ in "" }
        typed("letters") { _ in "not it" }
        typed("what the other way of pairing would ask for") { rep in rep.t.byNumber ? rep.gen.digits(6) : (rep.t.theirNumber.isEmpty ? rep.gen.digits(30) : rep.t.theirNumber) }
        for digit in 0...9 { typed("all \(digit)s") { rep in String(repeating: "\(digit)", count: rep.length) } }
        typed("random digits, as many as the code has") { rep in rep.gen.digits(rep.length) }
        typed("the first entry again") { $0.entries.first }
        typed("the last entry again") { $0.entries.last }
        typed("the code of the same two values on another connection") { rep in
            guard !rep.t.byNumber, let mine = rep.t.drawn.first, let theirs = rep.t.theirs else { return nil }
            let codes = rep.t.role == .initiator ? Described.codes(h: rep.otherH, ns: mine, nr: theirs) : Described.codes(h: rep.otherH, ns: theirs, nr: mine)
            return rep.t.role == .initiator ? codes.receiver : codes.sender
        }
        typed("the code of the two values the other way round") { rep in
            guard !rep.t.byNumber, let mine = rep.t.drawn.first, let theirs = rep.t.theirs else { return nil }
            let codes = rep.t.role == .initiator ? Described.codes(h: rep.t.h, ns: theirs, nr: mine) : Described.codes(h: rep.t.h, ns: mine, nr: theirs)
            return rep.t.role == .initiator ? codes.receiver : codes.sender
        }
        typed("two thousand digits") { rep in rep.gen.digits(2000) }

        // What can arrive where a commitment belongs.
        func arrives(_ message: PairingMachine.Message, _ family: Family, _ name: String, _ value: @escaping (inout Rep) -> Data??) {
            all.append(Form(name: name, family: family) { rep in value(&rep).map { .received(message, value: $0) } })
        }
        func commitment(_ name: String, _ make: @escaping (inout Rep) -> (commitment: Data, ns: Data?)) {
            arrives(.commit, .commit, name) { rep in
                let made = make(&rep)
                rep.offered = made
                return .some(made.commitment)
            }
        }
        commitment("a commitment to a value, under this connection's hash") { rep in
            let ns = rep.gen.bytes(32)
            return (Described.commitment(h: rep.t.h, to: ns), ns)
        }
        commitment("a commitment to a value, under another connection's hash") { rep in
            let ns = rep.gen.bytes(32)
            return (Described.commitment(h: rep.otherH, to: ns), ns)
        }
        commitment("a commitment to a value, under no hash at all") { rep in
            let ns = rep.gen.bytes(32)
            return (Described.commitment(h: Data(), to: ns), ns)
        }
        commitment("32 random bytes where the commitment belongs") { rep in (rep.gen.bytes(32), nil) }
        commitment("32 bytes from the middle of a longer buffer where the commitment belongs") { rep in (rep.gen.bytes(48).dropFirst(9).prefix(32), nil) }
        commitment("32 zero bytes where the commitment belongs") { _ in (Data(count: 32), nil) }
        for count in [0, 1, 31, 33, 64] { commitment("a commitment of \(count) bytes") { rep in (rep.gen.bytes(count), nil) } }
        arrives(.commit, .commit, "a commitment that cannot be read") { _ in .some(nil) }

        // Where a responder's value belongs.
        arrives(.nonce, .nonce, "a value of 32 random bytes") { rep in .some(rep.gen.bytes(32)) }
        arrives(.nonce, .nonce, "a value of 32 zero bytes") { _ in .some(Data(count: 32)) }
        arrives(.nonce, .nonce, "a value of 32 bytes from the middle of a longer buffer") { rep in .some(rep.gen.bytes(48).dropFirst(9).prefix(32)) }
        arrives(.nonce, .nonce, "this Mac's own commitment, sent back as the value") { rep in rep.sentCommitment.map { .some($0) } }
        arrives(.nonce, .nonce, "this Mac's own value, sent back as the value") { rep in rep.t.drawn.first.map { .some($0) } }
        for count in [0, 1, 31, 33, 64] { arrives(.nonce, .nonce, "a value of \(count) bytes") { rep in .some(rep.gen.bytes(count)) } }
        arrives(.nonce, .nonce, "a value that cannot be read") { _ in .some(nil) }

        // Where the commitment is to be opened.
        func committed(_ rep: Rep) -> Data? { rep.opening ?? rep.offered?.ns }
        arrives(.reveal, .reveal, "the value committed to") { rep in committed(rep).map { .some($0) } }
        arrives(.reveal, .reveal, "the value committed to, from the middle of a longer buffer") { rep in
            committed(rep).map { .some((rep.gen.bytes(7) + $0 + rep.gen.bytes(3)).dropFirst(7).prefix(32)) }
        }
        arrives(.reveal, .reveal, "32 random bytes where the reveal belongs") { rep in .some(rep.gen.bytes(32)) }
        arrives(.reveal, .reveal, "the commitment, sent back as the reveal") { rep in (rep.t.commitment ?? rep.offered?.commitment).map { .some($0) } }
        arrives(.reveal, .reveal, "this Mac's own value, sent back as the reveal") { rep in rep.t.drawn.first.map { .some($0) } }
        arrives(.reveal, .reveal, "the value committed to, one bit changed") { rep in
            guard var ns = committed(rep) else { return nil }
            let bit = rep.gen.below(256)
            ns[ns.startIndex + bit / 8] ^= 1 << UInt8(bit % 8)
            return .some(ns)
        }
        arrives(.reveal, .reveal, "the value committed to, less its last byte") { rep in committed(rep).map { .some($0.dropLast()) } }
        arrives(.reveal, .reveal, "the value committed to, and a byte more") { rep in committed(rep).map { .some($0 + Data([0])) } }
        for count in [0, 1, 64] { arrives(.reveal, .reveal, "a reveal of \(count) bytes") { rep in .some(rep.gen.bytes(count)) } }
        arrives(.reveal, .reveal, "a reveal that cannot be read") { _ in .some(nil) }

        // The three that carry nothing, carrying nothing and carrying something.
        for (message, family, what) in [(PairingMachine.Message.paired, Family.paired, "'my person typed it right'"), (.failed, .failed, "'it failed here'"),
                                        (.other, .other, "something that is no part of a pairing")] {
            arrives(message, family, what) { _ in .some(nil) }
            arrives(message, family, "\(what), carrying 32 bytes") { rep in .some(rep.gen.bytes(32)) }
            arrives(message, family, "\(what), carrying no bytes") { _ in .some(Data()) }
        }
        return all
    }()

    // MARK: - One step, held to everything

    struct Row: Equatable {
        var next: Abstract
        var effects: [String]
    }

    struct Taken {
        var label: String
        var before: Abstract
        var after: Abstract
        var effects: [Effect]
        var complaint: Complaint?
    }

    /// One event at one representative. The machine must say the event is what the NUMBERS
    /// say it is. With `rows` (the relation): the state the machine is left in and the names of
    /// what it said to do must be the relation's row for the state the SPECIFICATION was in and
    /// that event; and then every value must be the oracle's. Without (while the relation
    /// itself is being written out): the values only, for the names the machine gave.
    static func take(_ event: Event, at rep: inout Rep, rows: [Abstract: [String: Row]]?) -> Taken {
        let label = rep.t.label(event)
        let before = rep.s
        guard Abstract(rep.m) == before else {
            return Taken(label: label, before: before, after: Abstract(rep.m), effects: [],
                         complaint: Complaint(kind: .control, text: "the specification is in \(before.tla) and the machine in \(Abstract(rep.m).tla)"))
        }
        let kind = rep.m.classify(event)
        guard kind.rawValue == label else {
            return Taken(label: label, before: before, after: before, effects: [],
                         complaint: Complaint(kind: .control, text: "in \(before.tla) the machine takes this for \(kind.rawValue); by the numbers it is \(label)"))
        }
        var gen = rep.gen
        var drew: [Data] = []
        let effects = rep.m.step(event) {
            let value = gen.bytes(32)
            drew.append(value)
            return value
        }
        rep.gen = gen
        let after = Abstract(rep.m)
        let names = effects.map(name)
        var taken = Taken(label: label, before: before, after: after, effects: effects)
        if let rows {
            guard let row = rows[before]?[label] else {
                taken.complaint = Complaint(kind: .control, text: "the relation has no row for \(label) in \(before.tla)")
                return taken
            }
            guard row.next == after, row.effects == names else {
                taken.complaint = Complaint(kind: .control, text: "in \(before.tla), \(label):\n    the relation says \(row.next.tla) \(tuple(row.effects))\n    the machine did   \(after.tla) \(tuple(names))")
                return taken
            }
        }
        rep.s = after
        if case .typed(let entry) = event { rep.entries.append(entry) }
        for case .send(.commit, let value) in effects { rep.sentCommitment = value }
        do {
            let expected = try rep.t.effects(named: names, after: event, called: label, leaving: after, drew: drew)
            guard effects == expected else {
                throw Complaint(kind: .payload, text: "in \(before.tla), \(label):\n    the protocol says \(describe(expected))\n    the machine said  \(describe(effects))")
            }
            guard rep.m.mine == (rep.t.shows ?? "") else {
                throw Complaint(kind: .payload, text: "the machine's own code is \"\(rep.m.mine)\"; the protocol says \"\(rep.t.shows ?? "")\"")
            }
        } catch {
            taken.complaint = error as? Complaint ?? Complaint(kind: .payload, text: "\(error)")
        }
        if rep.opening == nil, let took = rep.t.commitment, let offered = rep.offered, offered.commitment == took { rep.opening = offered.ns }
        return taken
    }

    // MARK: - The code and its specification

    struct Relation {
        var initial: [Abstract] = []
        var rows: [Abstract: [String: Row]] = [:]
        /// What could not be written out as the contract has it.
        var problems: [String] = []
        /// Values that were not the protocol's, at a step of the writing out.
        var payloads: [String] = []

        var transitions: [String] {
            rows.flatMap { state, row in row.map { "<< \(state.tla), \"\($0.key)\", \($0.value.next.tla), \(PairingMachineTests.tuple($0.value.effects)) >>" } }.sorted()
        }

        var count: Int { rows.values.reduce(0) { $0 + $1.count } }
    }

    /// One of the specification's events, in the form the written-out relation is made from.
    static func canonical(_ name: String, at rep: inout Rep) -> Event {
        func form(_ wanted: String) -> Event? { forms.first { $0.name == wanted }.flatMap { $0.make(&rep) } }
        switch name {
        case "begin": return .begin
        case "timeout": return .timeout
        // Where no code is expected yet there is no right entry to make; see `relation`.
        case "typedRight": return form("the code expected") ?? .typed("000000")
        case "typedWrong": return .typed("not it")
        case "commit": return form("a commitment to a value, under this connection's hash")!
        case "commitDamaged": return .received(.commit, value: Data(count: 5))
        case "commitMalformed": return .received(.commit, value: nil)
        case "nonce": return .received(.nonce, value: Data(repeating: 0x22, count: 32))
        case "nonceDamaged": return .received(.nonce, value: Data(count: 33))
        case "nonceMalformed": return .received(.nonce, value: nil)
        // Where no commitment was taken there is no reveal that opens it.
        case "reveal": return form("the value committed to") ?? .received(.reveal, value: Data(repeating: 0x11, count: 32))
        case "revealWrong": return .received(.reveal, value: Data(repeating: 0x33, count: 32))
        case "revealDamaged": return .received(.reveal, value: Data(count: 31))
        case "revealMalformed": return .received(.reveal, value: nil)
        case "paired": return .received(.paired, value: nil)
        case "failed": return .received(.failed, value: nil)
        case "other": return .received(.other, value: nil)
        default: fatalError("no such event: \(name)")
        }
    }

    /// Every state the machine reaches from its four beginnings, under every event: the whole
    /// transition relation of the Swift code, as the specification would write it. One machine
    /// per state (the first to get there), which is why the walks below exist.
    ///
    /// Two of the specification's events cannot be made in every state: no entry is RIGHT
    /// before a code is expected, and no reveal OPENS a commitment that was never taken. There
    /// the row is written from an entry, or a reveal, that the numbers call wrong, and it is
    /// checked that the specification's row for the wrong one is the same row: `Step` does not
    /// tell the two apart in such a state, so nothing is said that was not seen.
    static func relation() -> Relation {
        var out = Relation()
        var queue: [Rep] = []
        for role in PairingMachine.Role.allCases {
            for byNumber in [false, true] {
                let rep = Rep(role: role, byNumber: byNumber, h: Data(repeating: 0x68, count: 32), theirNumber: "293699792116939100601602599741",
                              otherH: Data(repeating: 0x69, count: 32), gen: Seeded(0x68))
                out.initial.append(rep.s)
                out.rows[rep.s] = [:]
                queue.append(rep)
                if Abstract(rep.m) != rep.s { out.problems.append("a new machine is \(Abstract(rep.m).tla), not \(rep.s.tla)") }
            }
        }
        var stoodIn: [(state: Abstract, name: String, label: String)] = []
        while let rep = queue.popLast() {
            for name in events {
                var next = rep
                let event = canonical(name, at: &next)
                let taken = take(event, at: &next, rows: nil)
                if let complaint = taken.complaint {
                    if complaint.kind == .payload { out.payloads.append(complaint.text) } else { out.problems.append(complaint.text) }
                }
                if taken.label != name { stoodIn.append((rep.s, name, taken.label)) }
                out.rows[rep.s]?[name] = Row(next: taken.after, effects: taken.effects.map(Self.name))
                if out.rows[taken.after] == nil {
                    out.rows[taken.after] = [:]
                    next.s = taken.after
                    queue.append(next)
                }
            }
        }
        for (state, name, label) in stoodIn {
            guard (name == "typedRight" && label == "typedWrong") || (name == "reveal" && label == "revealWrong") else {
                out.problems.append("in \(state.tla) the event made for \(name) is, by the numbers, \(label)")
                continue
            }
            if out.rows[state]?[name] != out.rows[state]?[label] {
                out.problems.append("in \(state.tla) no \(name) can be made, and the row written for it is not the row for \(label)")
            }
        }
        return out
    }

    static var implFile: URL {
        URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
            .appendingPathComponent("formal/tla/PairingImpl.tla")
    }

    /// `formal/tla/PairingImpl.tla` is exactly what this code does. After a deliberate change to
    /// the machine: `NIMBUS_WRITE_IMPL=1 swift test --filter PairingMachineTests`, then
    /// `./build.sh verify`, which fails unless `PairingMachine.tla` was changed to match.
    func testTheWrittenOutRelationIsWhatTheCodeDoes() throws {
        let relation = Self.relation()
        let text = """
        ---------------------------- MODULE PairingImpl ----------------------------
        \\* GENERATED from Sources/NimbusCrypto/PairingMachine.swift by PairingMachineTests
        \\* (Tests/NimbusCryptoTests). Do not edit: every state the Swift machine reaches, under
        \\* every event, with what it said to do. PairingRefinement.tla checks it against Step.

        ImplInit == {
          \(relation.initial.map(\.tla).sorted().joined(separator: ",\n  "))
        }

        Impl == {
          \(relation.transitions.joined(separator: ",\n  "))
        }

        =============================================================================

        """
        if ProcessInfo.processInfo.environment["NIMBUS_WRITE_IMPL"] != nil {
            try text.write(to: Self.implFile, atomically: true, encoding: .utf8)
        }
        let onDisk = try String(contentsOf: Self.implFile, encoding: .utf8)
        XCTAssertEqual(onDisk, text, "PairingMachine.swift no longer does what formal/tla/PairingImpl.tla says; see this test's comment")
        XCTAssertEqual(relation.count, relation.rows.count * Self.events.count, "a row for every event in every state")
        XCTAssertEqual(relation.problems, [], "the relation could not be written out as the contract has it")
    }

    // MARK: - Many machines for every state

    /// Whether SOME machine in this state can be sent this event. The two that cannot always
    /// be made: an entry that is right (a code must be expected), a reveal that opens the
    /// commitment (one must have been taken: a responder, by codes, past that point).
    static func canHappen(_ label: String, in state: Abstract) -> Bool {
        switch label {
        case "typedRight": return ![.idle, .awaitCommit, .awaitNonce, .awaitReveal].contains(state.phase)
        case "reveal": return state.role == .responder && !state.byNumber && [.awaitReveal, .codes, .paired, .failed].contains(state.phase)
        default: return true
        }
    }

    /// Whether EVERY machine the walks bring to this state can be sent it. Not so for those
    /// two events in the states that are reached both ways: a pairing that failed before its
    /// codes existed and one that failed after are the same state to the specification, and a
    /// responder waiting for the reveal may have been sent a commitment nobody can open.
    static func canAlwaysHappen(_ label: String, in state: Abstract) -> Bool {
        guard canHappen(label, in: state) else { return false }
        guard label == "typedRight" || label == "reveal" else { return true }
        return state.phase == .codes || state.phase == .paired || (state.phase == .failed && (state.tries < 3 || state.local || state.remote))
    }

    /// A form of event that the numbers call `label` at this machine, chosen at random among
    /// those that can be made. `opens`: a commitment is to be one the other end can open later.
    static func some(_ label: String, at rep: inout Rep, opens: Bool) -> (Form, Event)? {
        let wanted = family(of: label)
        var candidates = forms.filter { $0.family == wanted }
        if label == "commit", opens { candidates = candidates.filter { $0.name == "a commitment to a value, under this connection's hash" } }
        while !candidates.isEmpty {
            let form = candidates.remove(at: rep.gen.below(candidates.count))
            var copy = rep
            guard let event = form.make(&copy), copy.t.label(event) == label else { continue }
            rep.gen = copy.gen
            rep.offered = copy.offered
            return (form, event)
        }
        return nil
    }

    /// An event that, by the relation, takes the pairing a step on from here without ending it
    /// badly; nil where there is none (it is over).
    static func onward(from rep: inout Rep, rows: [Abstract: [String: Row]]) -> (Form, Event)? {
        guard let row = rows[rep.s] else { return nil }
        var labels = events.filter { row[$0].map { $0.next != rep.s && $0.next.phase != .failed } ?? false }
        while !labels.isEmpty {
            let label = labels.remove(at: rep.gen.below(labels.count))
            if let made = some(label, at: &rep, opens: rep.gen.below(8) > 0) { return made }
        }
        return nil
    }

    struct Outcome {
        var seeds: [UInt64] = []
        /// Whether one of the seeds is the clock's: an ordinary run, held to its coverage.
        var ordinary = false
        var walks = 0
        var steps = 0
        var seconds = 0.0
        /// Machines at which every form of every event was tried, by the state they were in.
        var representatives: [Abstract: Int] = [:]
        /// The different ways (as the numbers name the events) those machines came to their state.
        var histories: [Abstract: Set<[String]>] = [:]
        /// Steps taken, by the state and the event the numbers said it was.
        var covered: [Abstract: [String: Int]] = [:]
        var formsUsed: [String: Int] = [:]
        var control: [String] = []
        var payload: [String] = []
        var broken: [String] = []
        var relation = Relation()

        /// The fewest times any (state, event) pair was taken: among those every machine can be sent, and among the rest that can happen at all.
        var fewest: (pairs: Int, always: Int, sometimes: Int) {
            var pairs = 0, always = Int.max, sometimes = Int.max
            for (state, row) in relation.rows {
                for name in row.keys where PairingMachineTests.canHappen(name, in: state) {
                    pairs += 1
                    let times = covered[state]?[name] ?? 0
                    if PairingMachineTests.canAlwaysHappen(name, in: state) { always = min(always, times) } else { sometimes = min(sometimes, times) }
                }
            }
            return (pairs, always, sometimes)
        }

        var summary: String {
            let fewest = fewest
            return "pairing machine: seeds \(seeds.map { String(format: "0x%llx", $0) }.joined(separator: " ")); \(walks) walks; "
                + "\(representatives.values.reduce(0, +)) representatives of \(representatives.count) states (at least \(representatives.values.min() ?? 0) of each) "
                + "by \(histories.values.reduce(0) { $0 + $1.count }) different histories; \(steps) steps; "
                + "each of \(fewest.pairs) (state, event) pairs at least \(fewest.always) times (\(fewest.sometimes) where not every machine can be sent it); "
                + "\(PairingMachineTests.forms.count) forms of event; " + String(format: "%.1f s", seconds)
        }
    }

    /// The exploration, made once and read by the two tests below.
    static let outcome: Outcome = explore()

    /// Walks to each state of the specification, and walks to wherever, for each seed.
    static let perState = 12
    static let freeWalks = 150

    /// Many machines for every state of the specification, and every form of every event at
    /// each of them. Deterministic from its seeds: two that never change, and the clock (said
    /// in the summary line, and in any failure, with the whole trace). To walk one again:
    /// `NIMBUS_PAIRING_SEED=0x… swift test --filter PairingMachineTests`; for more of the same,
    /// `NIMBUS_PAIRING_ROUNDS=50`.
    static func explore() -> Outcome {
        var out = Outcome()
        out.relation = relation()
        let rows = out.relation.rows
        let started = Date()
        let environment = ProcessInfo.processInfo.environment
        func number(_ text: String?) -> UInt64? {
            guard let text else { return nil }
            return text.hasPrefix("0x") ? UInt64(text.dropFirst(2), radix: 16) : UInt64(text)
        }
        if let given = number(environment["NIMBUS_PAIRING_SEED"]) {
            out.seeds = [given]
        } else {
            out.seeds = [0x4E69_6D62_7573, 0x0D72_6F70, UInt64(Date().timeIntervalSince1970 * 1_000_000)]
            out.ordinary = true
        }
        let rounds = Int(number(environment["NIMBUS_PAIRING_ROUNDS"]) ?? 1)
        // Into each state: every way of arriving that changes the state, to walk backwards along.
        var into: [Abstract: [(from: Abstract, label: String)]] = [:]
        for (state, row) in rows {
            for (label, to) in row where to.next != state && canHappen(label, in: state) { into[to.next, default: []].append((state, label)) }
        }
        for key in into.keys { into[key]?.sort { ($0.from.tla, $0.label) < ($1.from.tla, $1.label) } }
        let targets = rows.keys.sorted { $0.tla < $1.tla }

        for seed in out.seeds {
            var number = 0

            func complain(_ complaint: Complaint, _ rep: Rep, _ last: String?, target: Abstract?) {
                var lines = [String(format: "seed 0x%llx, walk \(number)", seed) + (target.map { " (to \($0.tla))" } ?? " (free)") + ": \(rep.summary)"]
                for (i, step) in rep.trace.enumerated() {
                    lines.append("  \(i + 1). \(step.form): \(describe(step.event)) [\(step.label)] -> \(describe(step.effects))")
                }
                if let last { lines.append("  then, at a copy of that machine: \(last)") }
                lines.append("  " + complaint.text)
                lines.append(String(format: "  to walk it again: NIMBUS_PAIRING_SEED=0x%llx swift test --filter PairingMachineTests", seed))
                let text = lines.joined(separator: "\n")
                switch complaint.kind {
                case .control: if out.control.count < 3 { out.control.append(text) }
                case .payload: if out.payload.count < 3 { out.payload.append(text) }
                }
            }

            /// The event on the walk itself. False when it broke something: the walk ends there.
            func advance(_ rep: inout Rep, _ form: Form, _ event: Event, target: Abstract?) -> Bool {
                let taken = take(event, at: &rep, rows: rows)
                out.steps += 1
                out.covered[taken.before, default: [:]][taken.label, default: 0] += 1
                out.formsUsed[form.name, default: 0] += 1
                rep.trace.append((form.name, event, taken.label, taken.effects))
                if let complaint = taken.complaint {
                    complain(complaint, rep, nil, target: target)
                    return false
                }
                return true
            }

            /// Every form of every event, each at its own copy of this machine: the machine is
            /// one representative of its state, and whatever it is sent it must do what the
            /// relation says of that state.
            func fan(_ rep: Rep, target: Abstract?) -> Bool {
                out.representatives[rep.s, default: 0] += 1
                out.histories[rep.s, default: []].insert(rep.trace.map(\.label))
                for form in forms {
                    var copy = rep
                    guard let event = form.make(&copy) else { continue }
                    let taken = take(event, at: &copy, rows: rows)
                    out.steps += 1
                    out.covered[taken.before, default: [:]][taken.label, default: 0] += 1
                    out.formsUsed[form.name, default: 0] += 1
                    if let complaint = taken.complaint {
                        complain(complaint, rep, "\(form.name): \(describe(event)) [\(taken.label)] -> \(describe(taken.effects))", target: target)
                        return false
                    }
                }
                return true
            }

            /// Something that, by the relation, changes nothing in this state (an entry before
            /// the codes are up, a second "begin"): a history is not only the steps that count.
            func idle(_ rep: inout Rep, target: Abstract?) -> Bool {
                let form = forms[rep.gen.below(forms.count)]
                var copy = rep
                guard let event = form.make(&copy), let row = rows[rep.s]?[copy.t.label(event)], row.next == rep.s else { return true }
                rep.gen = copy.gen
                rep.offered = copy.offered
                return advance(&rep, form, event, target: target)
            }

            /// To one state of the specification, by a way chosen at random among all the ways
            /// there and with values nobody has used before; every form of every event there;
            /// and then a little further, whatever comes.
            func directed(to target: Abstract) {
                number += 1
                out.walks += 1
                var gen = Seeded(seed &+ UInt64(number) &* 0x2545_F491_4F6C_DD1D)
                var labels: [String] = []
                var at = target
                while let ways = into[at], !ways.isEmpty {
                    let way = ways[gen.below(ways.count)]
                    labels.insert(way.label, at: 0)
                    at = way.from
                }
                var rep = Rep.fresh(role: target.role, byNumber: target.byNumber, &gen)
                let opens = labels.contains("reveal") || gen.below(2) == 0
                for label in labels {
                    if rep.gen.below(4) == 0, !idle(&rep, target: target) { return }
                    guard let (form, event) = some(label, at: &rep, opens: opens) else {
                        out.broken.append("walk \(number): no \(label) could be made in \(rep.s.tla)")
                        return
                    }
                    guard advance(&rep, form, event, target: target) else { return }
                }
                guard rep.s == target else {
                    out.broken.append("walk \(number) was to reach \(target.tla) and is in \(rep.s.tla)")
                    return
                }
                guard fan(rep, target: target) else { return }
                for _ in 0..<rep.gen.below(3) {
                    let form = forms[rep.gen.below(forms.count)]
                    guard let event = form.make(&rep) else { continue }
                    guard advance(&rep, form, event, target: target), fan(rep, target: target) else { return }
                }
            }

            /// From a beginning to wherever the events lead: mostly the ones that keep a
            /// pairing going, with every form of every event tried at every machine on the
            /// way, and a few more after it is over.
            func free() {
                number += 1
                out.walks += 1
                var gen = Seeded(seed &+ UInt64(number) &* 0x2545_F491_4F6C_DD1D)
                var rep = Rep.fresh(role: gen.below(2) == 0 ? .initiator : .responder, byNumber: gen.below(3) == 0, &gen)
                var afterTheEnd = 0
                for _ in 0..<16 {
                    guard fan(rep, target: nil) else { return }
                    var next: (Form, Event)?
                    switch rep.gen.below(8) {
                    case 0:
                        let form = forms[rep.gen.below(forms.count)]
                        if let event = form.make(&rep) { next = (form, event) }
                    case 1, 2: next = some("typedWrong", at: &rep, opens: true)
                    default: next = onward(from: &rep, rows: rows)
                    }
                    if next == nil {
                        let form = forms[rep.gen.below(forms.count)]
                        if let event = form.make(&rep) { next = (form, event) }
                    }
                    guard let (form, event) = next else { continue }
                    guard advance(&rep, form, event, target: nil) else { return }
                    if rep.s.phase.isFinal {
                        afterTheEnd += 1
                        if afterTheEnd > 2 { break }
                    }
                }
                _ = fan(rep, target: nil)
            }

            for _ in 0..<rounds {
                for _ in 0..<perState { for target in targets { directed(to: target) } }
                for _ in 0..<freeWalks { free() }
            }
        }
        out.seconds = Date().timeIntervalSince(started)
        print(out.summary)
        return out
    }

    /// CONGRUENCE. What the machine does depends on the specification's state and the
    /// specification's event and on nothing else: not on the handshake hash, the values, the
    /// identity number, how the state was come by, or which of its many forms the event took.
    /// At every step of every walk: the machine says the event is what the numbers say it is
    /// (`classify` against the oracle's `label`), and the state it is left in and the names of
    /// what it said to do are the relation's row for the state the specification was in.
    ///
    /// Bounded, and said as such: so many machines for each state, so many steps (the summary
    /// line gives both). A trigger that one machine in some hundreds would meet is found; one
    /// that needs a particular 32 bytes is not, by this test. That is what the machine's being
    /// in three parts is for: see the contract in `formal/tla/PairingMachine.tla`, which says
    /// what is enumerated, what is explored and what is argued.
    func testEveryMachineInAStateDoesWhatTheRelationSaysOfThatState() {
        let out = Self.outcome
        if !out.control.isEmpty { XCTFail("\n" + out.control.joined(separator: "\n\n")) }
        XCTAssertEqual(out.broken, [], "the walks could not be made")
        // What follows is about how far the walks went, and they went nowhere if something stopped them.
        guard out.control.isEmpty, out.payload.isEmpty, out.broken.isEmpty, out.ordinary else { return }
        XCTAssertEqual(out.representatives.count, out.relation.rows.count, "a representative of every state")
        let floor = Self.perState * out.seeds.count
        for (state, row) in out.relation.rows {
            XCTAssertGreaterThanOrEqual(out.representatives[state] ?? 0, floor, "representatives of \(state.tla)")
            for name in row.keys {
                let times = out.covered[state]?[name] ?? 0
                if Self.canAlwaysHappen(name, in: state) {
                    XCTAssertGreaterThanOrEqual(times, floor, "\(name) in \(state.tla)")
                } else if Self.canHappen(name, in: state) {
                    XCTAssertGreaterThanOrEqual(times, Self.seldom, "\(name) in \(state.tla)")
                } else {
                    // Never made, and nothing is lost: the specification has one row for it and for the event that was made in its place.
                    XCTAssertEqual(times, 0, "\(name) was thought impossible in \(state.tla)")
                    let stands = name == "typedRight" ? "typedWrong" : "revealWrong"
                    XCTAssertEqual(row[name], row[stands], "the specification tells \(name) from \(stands) in \(state.tla), where no \(name) can be made")
                }
            }
        }
        for form in Self.forms { XCTAssertGreaterThan(out.formsUsed[form.name] ?? 0, 0, "the form \"\(form.name)\" was never made") }
        XCTAssertGreaterThan(out.steps, 500_000)
    }

    /// The fewest times an event that only some machines in a state can be sent must have been
    /// taken there. The two seeds that never change give more than this by themselves.
    static let seldom = 8

    /// PAYLOADS. At every step of the written-out relation and of every walk, each value the
    /// machine sent, each code it showed, the tries it said were left and each value it drew
    /// is what the protocol says (`Transcript.effects`, which knows nothing of the machine's
    /// inside): the commitment is to this connection's hash and to the value later revealed,
    /// the responder's value is the one drawn when the commitment arrived, the codes are the
    /// two codes of (h, Ns, Nr) the right way round, a pairing is stored once.
    func testEveryValueSentAndEveryCodeShownIsWhatTheProtocolSays() {
        let out = Self.outcome
        XCTAssertEqual(out.relation.payloads, [], "while the relation was written out")
        if !out.payload.isEmpty { XCTFail("\n" + out.payload.joined(separator: "\n\n")) }
        // The second implementation and the first agree on what they both compute, wherever the walks went.
        var gen = Seeded(out.seeds.last ?? 1)
        for _ in 0..<200 {
            let h = gen.bytes(gen.below(8) == 0 ? gen.below(65) : 32), ns = gen.bytes(32), nr = gen.bytes(32)
            XCTAssertEqual(PairCodes.commitment(h: h, ns: ns), Described.commitment(h: h, to: ns))
            let codes = PairCodes.codes(h: h, ns: ns, nr: nr), described = Described.codes(h: h, ns: ns, nr: nr)
            XCTAssertEqual(codes.receiver, described.receiver)
            XCTAssertEqual(codes.sender, described.sender)
        }
    }

    /// THE PART THAT DECIDES SEES NO VALUE. The relation was written out from whole machines,
    /// values and all. `PairingMachine.Control` is the part of the machine that decides: six
    /// fields, the specification's state, and a `step` that is handed one of seventeen kinds
    /// of event and nothing else. Walked by itself from the same four beginnings, it is the
    /// same relation, row for row; so the relation is a table of a function that had no
    /// handshake hash, no value, no code and no number to look at.
    func testWhatIsDecidedIsDecidedWithNoValueInSight() {
        let relation = Self.relation()
        XCTAssertEqual(PairingMachine.Kind.allCases.map(\.rawValue).sorted(), Self.events.sorted(), "the kinds are the specification's events")
        var rows: [Abstract: [String: Row]] = [:]
        var queue: [PairingMachine.Control] = []
        for role in PairingMachine.Role.allCases {
            for byNumber in [false, true] {
                let control = PairingMachine.Control(role: role, byNumber: byNumber)
                XCTAssertEqual(Abstract(control), Abstract(start: role, byNumber: byNumber))
                rows[Abstract(control)] = [:]
                queue.append(control)
            }
        }
        while let control = queue.popLast() {
            for kind in PairingMachine.Kind.allCases {
                var next = control
                let decisions = next.step(kind)
                rows[Abstract(control)]?[kind.rawValue] = Row(next: Abstract(next), effects: decisions.compactMap(Self.name))
                if rows[Abstract(next)] == nil {
                    rows[Abstract(next)] = [:]
                    queue.append(next)
                }
            }
        }
        XCTAssertEqual(rows.count, relation.rows.count)
        XCTAssertEqual(rows, relation.rows)
    }

    /// The contract (the header of `formal/tla/PairingMachine.tla`) says of EVERY stored
    /// property of the machine whether the specification sees it, and if not why that is safe.
    /// A property it has not heard of fails here, until the contract has an entry for it.
    func testTheContractAccountsForEveryStoredProperty() throws {
        let machine = PairingMachine(role: .initiator, byNumber: false, h: Data(), theirNumber: "")
        let ofTheMachine = Mirror(reflecting: machine).children.compactMap(\.label)
        let ofItsControl = Mirror(reflecting: machine.control).children.compactMap(\.label)
        XCTAssertEqual(ofItsControl, ["role", "byNumber", "phase", "triesLeft", "localRight", "remoteRight"], "Control is the specification's state and nothing more")
        XCTAssertEqual(ofTheMachine, ["control", "mine", "h", "theirNumber", "ns", "nr", "commit", "expected"])
        let contract = try String(contentsOf: Self.implFile.deletingLastPathComponent().appendingPathComponent("PairingMachine.tla"), encoding: .utf8)
        for name in ofItsControl + ofTheMachine {
            XCTAssertNotNil(contract.range(of: "\n\\(\\*   \(name) +\\S", options: .regularExpression), "the contract's inventory has no entry for `\(name)`")
        }
    }

    // MARK: - Attacks on the machine

    static let h = Data(repeating: 0x68, count: 32)
    static let own = Data(repeating: 0xAA, count: 32)
    static let peerNs = Data(repeating: 0x11, count: 32)
    static let peerNr = Data(repeating: 0x22, count: 32)
    static let theirNumber = "293699792116939100601602599741"

    /// A machine and the other end's side of the conversation, with values that never change:
    /// for the attacks below, each of which is about one thing.
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
            case "nonce": return .received(.nonce, value: t.peerNr)
            case "reveal": return .received(.reveal, value: t.peerNs)
            case "revealWrong": return .received(.reveal, value: Data(repeating: 0x33, count: 32))
            case "paired": return .received(.paired, value: nil)
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
    }

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
