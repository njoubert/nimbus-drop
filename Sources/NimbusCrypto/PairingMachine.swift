// Copyright (C) 2026 Niels Joubert
// SPDX-License-Identifier: GPL-3.0-or-later
import Foundation
import NimbusBase

/// The pairing transaction, and nothing else: no socket, no person, no clock, no lock.
///
/// `PairingSession` (in the security core) owns the connection, the questions on screen and the
/// deadlines; for every thing that happens it asks this machine what it means (`step`) and does
/// what it is told (`Effect`). Everything the security of a pairing rests on is decided here:
///
/// - each message is taken once, and only when it is its turn; anything else ends the pairing;
/// - the responder's value is made only after the commitment has arrived (`random` is called
///   then and not before);
/// - the reveal must open the commitment;
/// - the codes are computed once, and what is expected does not change afterwards;
/// - three wrong entries end it;
/// - `store` is said only when this Mac's own person typed the right code AND the other Mac said
///   that its person did too.
///
/// It is in three parts, and `step` is those three in a row:
///
/// 1. `classify` says what an event IS: one of the seventeen events of the specification
///    (`Kind`). It is the only place where what arrived, or what was typed, is looked at.
/// 2. `Control.step` says what that MEANS. `Control` is the state of the specification, field
///    for field, and holds no value of the exchange; its `step` is handed a `Kind` and nothing
///    else. So what is decided cannot depend on a handshake hash, a nonce, a code or a number:
///    there is none where the deciding is done.
/// 3. `effect(of:)` puts the VALUES to what was decided: which bytes are sent, which code is shown.
///
/// `formal/tla/PairingMachine.tla` is the same machine written as a specification, and its
/// header is the contract between the two: what of this struct the specification sees, what it
/// does not, and why that is safe. `formal/tla/Pairing.tla` checks the properties above over
/// every state that specification can reach. `PairingMachineTests` writes out every state THIS
/// code can reach under every event, and TLC confirms the two transition relations are equal
/// (`formal/tla/PairingRefinement.tla`); it then holds many machines for each of those states
/// to that relation, and every value they send or show to the protocol. A change here that is
/// not a change there fails `./build.sh verify`.
package struct PairingMachine: Sendable {
    package enum Role: String, Sendable, CaseIterable { case initiator, responder }

    package enum Phase: String, Sendable {
        /// Nothing yet: the other person has not said yes.
        case idle
        /// A responder, waiting for the commitment.
        case awaitCommit
        /// An initiator that has committed, waiting for the responder's value.
        case awaitNonce
        /// A responder that has sent its value, waiting for the commitment to be opened.
        case awaitReveal
        /// The codes exist. The person types; the other Mac says when its person has.
        case codes
        case paired
        case failed

        package var isFinal: Bool { self == .paired || self == .failed }
    }

    /// What the other Mac can say during a pairing. `other` is anything else at all.
    package enum Message: String, Sendable { case commit, nonce, reveal, paired, failed, other }

    package enum Event: Sendable {
        /// Both people have agreed to pair: the exchange starts.
        case begin
        /// A message from the other Mac. `value`: what a commit, nonce or reveal carried, nil
        /// when it could not be read.
        case received(Message, value: Data?)
        /// What this Mac's person typed, digits only.
        case typed(String)
        /// The time allowed has passed.
        case timeout
    }

    package enum Failure: String, Sendable {
        /// The other Mac sent something out of turn, twice, or that did not open its commitment.
        case didNotKeep
        /// A value of the wrong length.
        case damaged
        /// A value that could not be read at all.
        case malformed
        /// Three wrong entries here.
        case wrongCode
        /// The other Mac said the pairing failed there.
        case theirsFailed
        case timedOut
    }

    package enum Effect: Equatable, Sendable {
        case send(Message, value: Data?)
        /// Show this code (empty for a pairing by identity number) and ask for theirs.
        case codes(mine: String, triesLeft: Int)
        /// This side's entry was right; waiting to hear the same from the other.
        case confirming
        /// The other Mac says its person typed this Mac's code. A hint for a window; proves nothing.
        case otherTyped
        /// Both are true: store the key of this connection's handshake.
        case store
        case fail(Failure)
    }

    /// What an event is, once what it carried has been looked at: the events of the
    /// specification, name for name. A value is good (32 bytes), damaged (another length) or
    /// malformed (it could not be read); a reveal of 32 bytes is good only if it opens the
    /// commitment, and wrong if not; an entry is right or wrong.
    package enum Kind: String, Sendable, CaseIterable {
        case begin, typedRight, typedWrong, timeout
        case commit, commitDamaged, commitMalformed
        case nonce, nonceDamaged, nonceMalformed
        case reveal, revealDamaged, revealMalformed, revealWrong
        case paired, failed, other
    }

    /// What is decided, before any value is put to it: an `Effect` without what it carries, or
    /// `keep`.
    package enum Decision: Equatable, Sendable {
        /// The value this message carried came in its turn and is what it should be: the
        /// pairing goes on with it.
        case keep(Message)
        case send(Message)
        /// The codes exist from here: work them out, show this Mac's and ask for the other's.
        case showCodes
        /// A wrong entry, and tries are left: ask again.
        case askAgain
        case confirming
        case otherTyped
        case store
        case fail(Failure)
    }

    /// Everything the machine decides WITH: the state of `formal/tla/PairingMachine.tla`, field
    /// for field. No value of the exchange is in it, and `step` is handed none.
    package struct Control: Hashable, Sendable {
        package let role: Role
        package let byNumber: Bool
        package private(set) var phase: Phase = .idle
        package private(set) var triesLeft = 3
        /// This Mac's person typed the right code.
        package private(set) var localRight = false
        /// The other Mac said its person did.
        package private(set) var remoteRight = false

        package init(role: Role, byNumber: Bool) {
            self.role = role
            self.byNumber = byNumber
        }

        private mutating func fail(_ why: Failure, saying: Bool = false) -> [Decision] {
            phase = .failed
            return (saying ? [.send(.failed)] : []) + [.fail(why)]
        }

        private mutating func showCodes() -> Decision {
            triesLeft = 3
            phase = .codes
            return .showCodes
        }

        /// What `kind` means now: `Step` of the specification. After a final phase nothing
        /// means anything.
        package mutating func step(_ kind: Kind) -> [Decision] {
            guard !phase.isFinal else { return [] }
            switch kind {
            case .timeout:
                return fail(.timedOut)

            case .begin:
                guard phase == .idle else { return [] }
                if byNumber { return [showCodes()] }
                if role == .responder { phase = .awaitCommit; return [] }
                phase = .awaitNonce
                return [.send(.commit)]

            case .typedRight, .typedWrong:
                guard phase == .codes, !localRight else { return [] }
                if kind == .typedRight {
                    localRight = true
                    var out: [Decision] = [.confirming, .send(.paired)]
                    if localRight && remoteRight { phase = .paired; out.append(.store) }
                    return out
                }
                triesLeft -= 1
                if triesLeft <= 0 { return fail(.wrongCode, saying: true) }
                return [.askAgain]

            case .commit where phase == .awaitCommit:
                phase = .awaitReveal
                return [.keep(.commit), .send(.nonce)]

            case .nonce where phase == .awaitNonce:
                return [.keep(.nonce), .send(.reveal), showCodes()]

            case .reveal where phase == .awaitReveal:
                return [.keep(.reveal), showCodes()]

            case .revealWrong where phase == .awaitReveal:
                return fail(.didNotKeep)

            case .commitDamaged where phase == .awaitCommit, .nonceDamaged where phase == .awaitNonce, .revealDamaged where phase == .awaitReveal:
                return fail(.damaged)

            case .commitMalformed where phase == .awaitCommit, .nonceMalformed where phase == .awaitNonce, .revealMalformed where phase == .awaitReveal:
                return fail(.malformed)

            case .paired where phase == .codes:
                // Said once. A second time is not keeping to the pairing.
                guard !remoteRight else { return fail(.didNotKeep) }
                remoteRight = true
                var out: [Decision] = [.otherTyped]
                if localRight && remoteRight { phase = .paired; out.append(.store) }
                return out

            case .failed where phase == .codes:
                return fail(.theirsFailed)

            default:
                // Out of turn, or a second time.
                return fail(.didNotKeep)
            }
        }
    }

    /// What is decided with. Its fields change in `Control.step` and nowhere else (they are
    /// `private(set)` to it), and `Control.step` is called in one place, by `step` below.
    package private(set) var control: Control
    package var role: Role { control.role }
    package var byNumber: Bool { control.byNumber }
    package var phase: Phase { control.phase }
    package var triesLeft: Int { control.triesLeft }
    /// This Mac's person typed the right code.
    package var localRight: Bool { control.localRight }
    /// The other Mac said its person did.
    package var remoteRight: Bool { control.remoteRight }
    /// This Mac's code, once there is one.
    package private(set) var mine = ""

    // The values. `classify` reads them and `effect(of:)` writes them; `Control` never sees one.
    private let h: Data
    private let theirNumber: String
    private var ns = Data()
    private var nr = Data()
    private var commit = Data()
    /// The code this Mac's person is to type: nil until the codes exist, set once, never changed.
    private var expected: String?

    /// `h`: the handshake hash of the connection the pairing runs on. `theirNumber`: the other
    /// Mac's identity number, from the key that handshake proved (used when `byNumber`).
    package init(role: Role, byNumber: Bool, h: Data, theirNumber: String) {
        control = Control(role: role, byNumber: byNumber)
        self.h = h
        self.theirNumber = theirNumber
    }

    /// What `event` is. The one place where what arrived, or what was typed, is looked at; it
    /// changes nothing.
    package func classify(_ event: Event) -> Kind {
        switch event {
        case .begin: return .begin
        case .timeout: return .timeout
        case .typed(let digits):
            // Right only against a code that exists.
            guard let expected else { return .typedWrong }
            return Crypto.same(Data(digits.utf8), Data(expected.utf8)) ? .typedRight : .typedWrong
        case .received(.commit, let carried):
            guard let v = carried else { return .commitMalformed }
            return v.count == 32 ? .commit : .commitDamaged
        case .received(.nonce, let carried):
            guard let v = carried else { return .nonceMalformed }
            return v.count == 32 ? .nonce : .nonceDamaged
        case .received(.reveal, let carried):
            guard let v = carried else { return .revealMalformed }
            guard v.count == 32 else { return .revealDamaged }
            // It must open the commitment that was taken. Where none was, nothing opens it.
            guard Crypto.same(PairCodes.commitment(h: h, ns: v), commit) else { return .revealWrong }
            return .reveal
        case .received(.paired, _): return .paired
        case .received(.failed, _): return .failed
        case .received(.other, _): return .other
        }
    }

    /// What `event` means now. `random` gives 32 fresh random bytes and is called at the moment
    /// a value is needed, never earlier. After a final phase nothing means anything.
    package mutating func step(_ event: Event, random: () -> Data = { Crypto.random(32) }) -> [Effect] {
        let kind = classify(event)
        let decisions = control.step(kind)
        var effects: [Effect] = []
        for decision in decisions {
            if let effect = effect(of: decision, after: event, random) { effects.append(effect) }
        }
        return effects
    }

    /// The values that go with one decision. It decides nothing: one effect for each decision
    /// but `keep`, of the same name, and `control` is not touched.
    private mutating func effect(of decision: Decision, after event: Event, _ random: () -> Data) -> Effect? {
        switch decision {
        case .keep(let message):
            guard case .received(_, let carried?) = event else { return nil }
            switch message {
            case .commit: commit = carried
            case .nonce: nr = carried
            case .reveal: ns = carried
            case .paired, .failed, .other: break
            }
            return nil
        case .send(.commit):
            ns = random()
            return .send(.commit, value: PairCodes.commitment(h: h, ns: ns))
        case .send(.nonce):
            // Made only now: the other side has committed and cannot choose its value to suit this one.
            nr = random()
            return .send(.nonce, value: nr)
        case .send(.reveal):
            return .send(.reveal, value: ns)
        case .send(let message):
            return .send(message, value: nil)
        case .showCodes:
            // Worked out here, once. By identity number nothing is shown, and theirs is asked for.
            if byNumber {
                expected = theirNumber
            } else {
                let codes = PairCodes.codes(h: h, ns: ns, nr: nr)
                (mine, expected) = role == .initiator ? (codes.sender, codes.receiver) : (codes.receiver, codes.sender)
            }
            return .codes(mine: mine, triesLeft: triesLeft)
        case .askAgain:
            return .codes(mine: mine, triesLeft: triesLeft)
        case .confirming: return .confirming
        case .otherTyped: return .otherTyped
        case .store: return .store
        case .fail(let why): return .fail(why)
        }
    }
}
