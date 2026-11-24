// Copyright (C) 2026 Niels Joubert
// SPDX-License-Identifier: GPL-3.0-or-later
import Foundation
import NimbusBase

/// A drop's conversation, and nothing else: no connection, no file, no clock, no lock.
///
///     offer -> accept | decline -> manifest -> plan -> chunks… done -> plan | complete
///
/// and, when the connection carrying it is lost, both ends holding the drop until the sender
/// has come back and proved it is the same one. There is a machine for each end. `SendSession`
/// and `ReceiveSession` (in the transfer core) own the connections, the threads, the disk and
/// the deadlines; for every thing that happens they ask their machine what it means (`step`)
/// and do what it says (`Effect`). What a drop's conversation rests on is decided here:
///
/// - each message is taken only when it is its turn; anything else ends the drop;
/// - nothing is accepted, prepared or written before the person at the receiving Mac said yes,
///   and a yes under a pairing that has since ended starts nothing;
/// - a manifest that is not what was offered is refused;
/// - "it all arrived" is said only of a drop that was judged whole and put in place, and
///   believed only as the answer to "done" or to a reconnect;
/// - a lost conversation is got back, not given up, once the drop is under way; and how long
///   either end goes on with nothing arriving is counted here (`patience`);
/// - an end is an end: nothing that arrives afterwards changes it. Withdrawing trust says no
///   farewell.
///
/// `formal/tla/RoundMachine.tla` is the same two machines written as a specification;
/// `RoundMachineTests` walks every state THIS code can reach under every event and has TLC
/// confirm the two transition relations are equal (`formal/tla/RoundRefinement.tla`).
/// `formal/tla/Drop.tla` is two of them and a network that misbehaves. A change here that is
/// not a change there fails `./build.sh verify`.
package enum RoundMachine {
    /// How a drop ends, at either end.
    package enum Ending<Failure: Equatable & Sendable>: Equatable, Sendable {
        case completed
        case declined
        case cancelled
        case failed(Failure)
    }

    // MARK: The sending end

    package struct Sender: Sendable {
        package enum Phase: String, Sendable, CaseIterable {
            /// Nothing said yet: scanning, connecting, proving the two keys.
            case idle
            /// The offer is out; the other person has not answered.
            case awaitAnswer
            /// Accepted, and the manifest is out; the receiver has not yet said what it holds.
            case awaitPlan
            /// A round: the chunks the last plan asked for are going out.
            case sending
            /// "Done" is out: the receiver answers with what is missing, or that it all arrived.
            case awaitVerdict
            /// The conversation's connection is lost and is being got back.
            case reconnecting
            case completed, declined, failed, cancelled

            package var isFinal: Bool { self == .completed || self == .declined || self == .failed || self == .cancelled }
        }

        /// What the receiver can say. `other` is anything else at all.
        package enum Message: Equatable, Sendable {
            case accept
            /// `readable`: its reason could be read.
            case decline(readable: Bool)
            /// `have`: the bytes the receiver holds by this plan; nil when it could not be read.
            case plan(have: Int64?)
            case complete
            /// The receiver's reason for stopping.
            case error
            case other
        }

        package enum Event: Equatable, Sendable {
            /// The receiver has proved its key and both ends hold the pairing: the offer goes.
            case begin
            /// A message from the receiver, taken from the conversation in the order it came.
            case received(Message)
            /// Everything this round had to send has been written to a connection.
            case written
            /// The conversation's connection is lost.
            case lost
            /// The time for getting it back has passed.
            case gaveUp
            /// No sign of life from the receiver for too long.
            case silent
            /// This Mac cannot go on, for a reason of its own (a source that changed, a key no
            /// longer paired). `tell`: the reason is one the other Mac can be told.
            case stopped(tell: Bool)
            /// Trust in the receiver's key was withdrawn.
            case withdrawn
            /// The person here stopped it.
            case cancelled
        }

        package enum Said: String, Sendable { case offer, manifest, done, error }

        package enum Failure: String, Sendable {
            /// A message out of turn.
            case unexpected
            /// A message that could not be read.
            case malformed
            /// The receiver said why it stopped.
            case theirs
            /// Reconnect after reconnect with nothing new arriving there.
            case fruitless
            /// The conversation was lost before the drop was under way.
            case lost
            case couldNotGetBack
            case silent
            /// This Mac's own reason (`stopped`).
            case here
            case withdrawn
        }

        package enum Effect: Equatable, Sendable {
            case send(Said)
            /// The plan is taken: the progress is what the receiver holds, the chunks to send
            /// are what it lacks.
            case adopt
            /// Send those chunks on data connections; then `written`.
            case round
            /// Reach the receiver again and prove the drop; what it answers is `received`, and
            /// when the time runs out, `gaveUp`.
            case reconnect
            /// The receiver answered a reconnect: the conversation is back.
            case reconnected
            /// Close the conversation's connection, so that its loss is noticed and it is got back.
            case hangUp
            case end(Ending<Failure>)
        }

        package private(set) var phase: Phase = .idle
        /// Reconnects in a row that found nothing new at the receiver.
        package private(set) var fruitless = 0
        /// The most the receiver has ever said it holds.
        package private(set) var best: Int64 = -1
        /// How many fruitless reconnects in a row end the drop.
        package let patience: Int

        package init(patience: Int) { self.patience = patience }

        /// Ends the drop, saying why when there is a conversation to say it on.
        private mutating func fail(_ why: Failure) -> [Effect] {
            let connected = phase != .idle
            phase = .failed
            return (connected ? [.send(.error)] : []) + [.end(.failed(why))]
        }

        /// A plan in its turn. `back`: it is the answer to a reconnect.
        private mutating func take(_ have: Int64?, back: Bool) -> [Effect] {
            guard let have else { return fail(.malformed) }
            // Reconnecting again and again to a receiver that takes nothing in is not progress.
            if have > best { best = have; fruitless = 0 } else if back { fruitless += 1 }
            guard fruitless < patience else { return [.adopt] + fail(.fruitless) }
            phase = .sending
            return [.adopt, .round]
        }

        /// What `event` means now. After an end nothing means anything.
        package mutating func step(_ event: Event) -> [Effect] {
            guard !phase.isFinal else { return [] }
            switch event {
            case .cancelled:
                let connected = phase != .idle
                phase = .cancelled
                return (connected ? [.send(.error)] : []) + [.end(.cancelled)]

            case .withdrawn:
                // No farewell: a Mac that has stopped reading would hold whoever withdrew the trust.
                phase = .failed
                return [.end(.failed(.withdrawn))]

            case .stopped(let tell):
                let connected = phase != .idle
                phase = .failed
                return (tell && connected ? [.send(.error)] : []) + [.end(.failed(.here))]

            case .silent:
                // Under way, silence is taken for a lost connection; before that, for the end.
                if phase == .sending || phase == .awaitVerdict { return [.hangUp] }
                return fail(.silent)

            case .begin:
                guard phase == .idle else { return [] }
                phase = .awaitAnswer
                return [.send(.offer)]

            case .written:
                guard phase == .sending else { return [] }
                phase = .awaitVerdict
                return [.send(.done)]

            case .lost:
                switch phase {
                case .sending, .awaitVerdict:
                    phase = .reconnecting
                    return [.reconnect]
                case .reconnecting:
                    return []
                default:
                    // Nothing is held for it at the other end yet, and there is nobody to tell.
                    phase = .failed
                    return [.end(.failed(.lost))]
                }

            case .gaveUp:
                guard phase == .reconnecting else { return [] }
                return fail(.couldNotGetBack)

            case .received(let message):
                if message == .error { return fail(.theirs) }
                switch (phase, message) {
                case (.awaitAnswer, .accept):
                    phase = .awaitPlan
                    return [.send(.manifest)]

                case (.awaitAnswer, .decline(let readable)):
                    guard readable else { return fail(.malformed) }
                    phase = .declined
                    return [.end(.declined)]

                case (.awaitPlan, .plan(let have)), (.awaitVerdict, .plan(let have)):
                    return take(have, back: false)

                case (.awaitVerdict, .complete):
                    phase = .completed
                    return [.end(.completed)]

                case (.reconnecting, .plan(let have)):
                    return [.reconnected] + take(have, back: true)

                case (.reconnecting, .complete):
                    // Its "complete" was lost with the old connection, and it says it again.
                    phase = .completed
                    return [.reconnected, .end(.completed)]

                case (.reconnecting, _):
                    // Not an answer to a reconnect: that attempt got nowhere, and the next is made.
                    return []

                default:
                    return fail(.unexpected)
                }
            }
        }
    }

    // MARK: The receiving end

    /// What an offer describes and what a manifest turns out to be: the two must be the same.
    package struct Described: Equatable, Sendable {
        package var files: Int
        package var bytes: Int64
        package var names: [String]
        package init(files: Int, bytes: Int64, names: [String]) { self.files = files; self.bytes = bytes; self.names = names }
    }

    package struct Receiver: Sendable {
        package enum Phase: String, Sendable, CaseIterable {
            /// The offer has arrived; nothing has been done about it.
            case idle
            /// The person here is being asked.
            case deciding
            /// The no is on its way out.
            case declining
            /// The yes is out; the manifest has not come.
            case awaitManifest
            /// The manifest is what was offered: the partial folder and the ledger are being made.
            case preparing
            /// The first plan is on its way out.
            case planning
            /// A round: chunks arrive on data connections; the conversation waits for "done".
            case reading
            /// "Done" has come: the data connections finish, then the drop is judged.
            case settling
            /// The conversation's connection is lost; the drop is held for the sender to come back to.
            case awaitSender
            /// Whole: being put in place.
            case placing
            case completed, declined, failed, cancelled

            package var isFinal: Bool { self == .completed || self == .declined || self == .failed || self == .cancelled }
        }

        /// A manifest as it arrived.
        package enum Manifest: Equatable, Sendable {
            case unreadable
            /// It did not pass `Manifest.validate`.
            case invalid
            case described(Described)
        }

        /// What the sender can say. `other` is anything else at all.
        package enum Message: Equatable, Sendable {
            case manifest(Manifest)
            case done(readable: Bool)
            /// The sender's reason for stopping.
            case error(readable: Bool)
            case other
        }

        /// The drop as it stands once a round's data connections have finished.
        package enum Judgement: String, Sendable {
            /// Every chunk is here (`Ledger.isComplete`).
            case whole
            /// Something arrived since the last plan was said.
            case more
            case nothingNew
        }

        package enum Event: Equatable, Sendable {
            /// The session starts. `askable`: there is somebody to ask.
            case begin(askable: Bool)
            /// The person said yes. `paired`: the sender's key is still paired now.
            case yes(paired: Bool)
            case no
            /// A message from the sender.
            case received(Message)
            /// What was to be said went out (a decline, the first plan).
            case said
            /// The partial folder and the ledger are ready.
            case prepared
            case settled(Judgement)
            /// The drop was put in place.
            case placed
            /// The conversation's connection is lost: a read or a write on it failed.
            case lost
            /// The sender came back on a new connection and proved it is the same drop.
            case senderBack
            /// Nobody came back in time.
            case gaveUp
            /// No sign of life from the sender for too long.
            case silent
            /// This Mac cannot go on (the disk, the folder, another session took the drop over).
            /// `tell`: the sender is told why.
            case stopped(tell: Bool)
            /// Trust in the sender's key was withdrawn.
            case withdrawn
            /// The person here stopped it.
            case cancelled
        }

        package enum Decline: String, Sendable {
            /// Nobody here to ask.
            case notReceiving
            /// The person's answer.
            case declined
            /// The pairing ended while the question was up.
            case pairingRanOut
        }

        package enum Said: Equatable, Sendable {
            case accept
            case decline(Decline)
            case plan
            case complete
            case error
        }

        package enum Failure: String, Sendable {
            /// The sender gave up, or said something, while the person was deciding.
            case wentAway
            case theirs
            case unexpected
            case malformed
            case invalidManifest
            case notAsOffered
            case pairingRanOut
            /// Round after round with nothing new.
            case incomplete
            case lost
            case didNotComeBack
            case silent
            case here
            case withdrawn
        }

        package enum Effect: Equatable, Sendable {
            /// Show the question.
            case ask
            /// Take the question away: the drop ended while it was up.
            case unask
            case send(Said)
            /// Make the partial folder and the ledger, and let data connections attach; then `prepared`.
            case prepare
            /// Let the data connections finish, close what is left, and judge; then `settled`.
            case settle
            /// Put the drop in place; then `placed`.
            case place
            /// Hold the drop for the sender; then `senderBack` or `gaveUp`.
            case hold
            /// Close the conversation's connection, so that the sender finds out and comes back.
            case hangUp
            case end(Ending<Failure>)
        }

        package private(set) var phase: Phase = .idle
        /// Rounds in a row that delivered nothing new.
        package private(set) var idle = 0
        /// How many of those in a row end the drop.
        package let patience: Int
        /// What the person is shown and says yes or no to.
        private let offered: Described

        package init(offered: Described, patience: Int) {
            self.offered = offered
            self.patience = patience
        }

        /// Whether a data connection of the drop may be let in to write: from when the folder
        /// is ready, for as long as rounds are being received. Not before (there is nothing to
        /// write into), and not once the drop has been judged whole: what is put in place is
        /// what was judged.
        package var takesData: Bool { phase == .planning || phase == .reading || phase == .settling || phase == .awaitSender }

        /// Ends the drop and tells the sender why.
        private mutating func fail(_ why: Failure) -> [Effect] {
            phase = .failed
            return [.send(.error), .end(.failed(why))]
        }

        /// What `event` means now. After an end nothing means anything, but for one thing: a
        /// sender that lost the conversation before it heard "complete" is told again.
        package mutating func step(_ event: Event) -> [Effect] {
            if phase == .completed, event == .senderBack { return [.send(.complete)] }
            guard !phase.isFinal else { return [] }
            // A question that is still up goes when the drop does.
            let unask: [Effect] = phase == .deciding ? [.unask] : []
            switch event {
            case .cancelled:
                phase = .cancelled
                return [.send(.error), .end(.cancelled)] + unask

            case .withdrawn:
                phase = .failed
                return [.end(.failed(.withdrawn))] + unask

            case .stopped(let tell):
                phase = .failed
                return (tell ? [.send(.error)] : []) + [.end(.failed(.here))] + unask

            case .silent:
                // With the drop under way, silence is taken for a lost connection.
                if phase == .reading || phase == .settling || phase == .awaitSender { return [.hangUp] }
                phase = .failed
                return [.end(.failed(.silent))] + unask

            case .begin(let askable):
                guard phase == .idle else { return [] }
                // Nobody to ask means no.
                guard askable else { phase = .declining; return [.send(.decline(.notReceiving))] }
                phase = .deciding
                return [.ask]

            case .yes(let paired):
                guard phase == .deciding else { return [] }
                // The question was asked under a pairing: a yes after it ended starts nothing.
                guard paired else {
                    phase = .failed
                    return [.send(.decline(.pairingRanOut)), .send(.error), .end(.failed(.pairingRanOut))]
                }
                phase = .awaitManifest
                return [.send(.accept)]

            case .no:
                guard phase == .deciding else { return [] }
                phase = .declining
                return [.send(.decline(.declined))]

            case .said:
                if phase == .declining { phase = .declined; return [.end(.declined)] }
                if phase == .planning { phase = .reading }
                return []

            case .prepared:
                guard phase == .preparing else { return [] }
                phase = .planning
                return [.send(.plan)]

            case .settled(let judgement):
                guard phase == .settling else { return [] }
                switch judgement {
                case .whole:
                    phase = .placing
                    return [.place]
                case .more:
                    idle = 0
                case .nothingNew:
                    idle += 1
                    guard idle < patience else { return fail(.incomplete) }
                }
                // Something is missing: the answer is what is here, not a failure.
                phase = .reading
                return [.send(.plan)]

            case .placed:
                guard phase == .placing else { return [] }
                phase = .completed
                return [.send(.complete), .end(.completed)]

            case .lost:
                switch phase {
                case .deciding:
                    phase = .failed
                    return [.end(.failed(.wentAway)), .unask]
                case .reading:
                    // Accepted and partly here: wait for the sender rather than ending it.
                    phase = .awaitSender
                    return [.hold]
                case .settling, .awaitSender, .placing:
                    return []
                default:
                    return fail(.lost)
                }

            case .senderBack:
                guard phase == .awaitSender else { return [] }
                phase = .reading
                return [.send(.plan)]

            case .gaveUp:
                guard phase == .awaitSender else { return [] }
                return fail(.didNotComeBack)

            case .received(let message):
                switch (phase, message) {
                case (.deciding, .error(readable: true)):
                    phase = .failed
                    return [.end(.failed(.theirs)), .unask]

                case (.deciding, _):
                    // Anything at all from a sender that is waiting for an answer is its giving up.
                    phase = .failed
                    return [.end(.failed(.wentAway)), .unask]

                case (.awaitManifest, .manifest(let manifest)):
                    switch manifest {
                    case .unreadable: return fail(.malformed)
                    case .invalid: return fail(.invalidManifest)
                    case .described(let it):
                        // The person said yes to what the offer described, and to nothing else.
                        guard it == offered else { return fail(.notAsOffered) }
                        phase = .preparing
                        return [.prepare]
                    }

                case (.reading, .done(let readable)):
                    guard readable else { return fail(.malformed) }
                    phase = .settling
                    return [.settle]

                case (.reading, .error(let readable)):
                    return fail(readable ? .theirs : .malformed)

                default:
                    return fail(.unexpected)
                }
            }
        }
    }
}
