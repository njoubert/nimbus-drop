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
/// It is small on purpose. `formal/tla/Pairing.tla` is the same machine written as a
/// specification, with those properties checked over every state it can reach, and
/// `PairingMachineTests` walks every state THIS code can reach and has TLC confirm the two
/// transition relations are equal (`formal/tla/PairingRefinement.tla`). A change here that is
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

    package let role: Role
    package let byNumber: Bool
    package private(set) var phase: Phase = .idle
    package private(set) var triesLeft = 3
    /// This Mac's person typed the right code.
    package private(set) var localRight = false
    /// The other Mac said its person did.
    package private(set) var remoteRight = false
    /// This Mac's code, once there is one.
    package private(set) var mine = ""

    private let h: Data
    private let theirNumber: String
    private var ns = Data()
    private var nr = Data()
    private var commit = Data()
    private var expected = ""

    /// `h`: the handshake hash of the connection the pairing runs on. `theirNumber`: the other
    /// Mac's identity number, from the key that handshake proved (used when `byNumber`).
    package init(role: Role, byNumber: Bool, h: Data, theirNumber: String) {
        self.role = role
        self.byNumber = byNumber
        self.h = h
        self.theirNumber = theirNumber
    }

    private mutating func fail(_ why: Failure, saying: Bool = false) -> [Effect] {
        phase = .failed
        return (saying ? [.send(.failed, value: nil)] : []) + [.fail(why)]
    }

    private mutating func showCodes(mine: String, expecting: String) -> Effect {
        self.mine = mine
        expected = expecting
        triesLeft = 3
        phase = .codes
        return .codes(mine: mine, triesLeft: 3)
    }

    /// One value of the exchange: 32 bytes, or the pairing ends.
    private mutating func value(_ v: Data?) -> (Data?, [Effect]) {
        guard let v else { return (nil, fail(.malformed)) }
        guard v.count == 32 else { return (nil, fail(.damaged)) }
        return (v, [])
    }

    /// What `event` means now. `random` gives 32 fresh random bytes and is called at the moment
    /// a value is needed, never earlier. After a final phase nothing means anything.
    package mutating func step(_ event: Event, random: () -> Data = { Crypto.random(32) }) -> [Effect] {
        guard !phase.isFinal else { return [] }
        switch event {
        case .timeout:
            return fail(.timedOut)

        case .begin:
            guard phase == .idle else { return [] }
            if byNumber { return [showCodes(mine: "", expecting: theirNumber)] }
            if role == .responder { phase = .awaitCommit; return [] }
            ns = random()
            phase = .awaitNonce
            return [.send(.commit, value: PairCodes.commitment(h: h, ns: ns))]

        case .typed(let digits):
            guard phase == .codes, !localRight else { return [] }
            if Crypto.same(Data(digits.utf8), Data(expected.utf8)) {
                localRight = true
                var out: [Effect] = [.confirming, .send(.paired, value: nil)]
                if localRight && remoteRight { phase = .paired; out.append(.store) }
                return out
            }
            triesLeft -= 1
            if triesLeft <= 0 { return fail(.wrongCode, saying: true) }
            return [.codes(mine: mine, triesLeft: triesLeft)]

        case .received(let message, let carried):
            switch (phase, message) {
            case (.awaitCommit, .commit):
                let (v, failed) = value(carried)
                guard let v else { return failed }
                commit = v
                // Made only now: the other side has committed and cannot choose its value to suit this one.
                nr = random()
                phase = .awaitReveal
                return [.send(.nonce, value: nr)]

            case (.awaitNonce, .nonce):
                let (v, failed) = value(carried)
                guard let v else { return failed }
                nr = v
                let codes = PairCodes.codes(h: h, ns: ns, nr: nr)
                return [.send(.reveal, value: ns), showCodes(mine: codes.sender, expecting: codes.receiver)]

            case (.awaitReveal, .reveal):
                let (v, failed) = value(carried)
                guard let v else { return failed }
                guard Crypto.same(PairCodes.commitment(h: h, ns: v), commit) else { return fail(.didNotKeep) }
                ns = v
                let codes = PairCodes.codes(h: h, ns: ns, nr: nr)
                return [showCodes(mine: codes.receiver, expecting: codes.sender)]

            case (.codes, .paired):
                // Said once. A second time is not keeping to the pairing.
                guard !remoteRight else { return fail(.didNotKeep) }
                remoteRight = true
                var out: [Effect] = [.otherTyped]
                if localRight && remoteRight { phase = .paired; out.append(.store) }
                return out

            case (.codes, .failed):
                return fail(.theirsFailed)

            default:
                return fail(.didNotKeep)
            }
        }
    }
}
