// Copyright (C) 2026 Niels Joubert
// SPDX-License-Identifier: GPL-3.0-or-later
import Darwin
import Foundation
import NimbusBase
import NimbusCrypto
import NimbusNet
import NimbusSafeStorageCore
import NimbusSecurityCore

/// One incoming drop: first a question for the person at this Mac, then the transfer.
///
/// The transfer runs in rounds (see `SendSession`): a data connection that is lost or carries a
/// damaged chunk is closed and what it did not deliver is asked for again, on the same accepted
/// drop, without asking the person twice.
public final class ReceiveSession: Transfer, DataSession, @unchecked Sendable {
    /// The sender's key, as text: what a re-sent drop is recognised by.
    public let senderID: String
    /// The Known Mac the sender proved to be.
    public let sender: KnownMac
    /// What the sender says it is sending, for the prompt.
    public let offeredFiles: Int
    public let offeredBytes: Int64
    /// The sender's app version and protocol version ("0.3.1", "3.0"), as it stated them.
    public let senderAppVersion: String
    public let senderProtocol: String

    /// Called once if the sender gives up while this Mac is still deciding.
    public var onWithdrawn: (@Sendable () -> Void)?

    /// The connection the conversation is on. Replaced when the sender reconnects, by this
    /// session's thread, while the listener's thread (a resume), the stream threads and a
    /// farewell read it: so under a lock of its own.
    private var control: Channel {
        get { controlLock.withLock { _control } }
        set { controlLock.withLock { _control = newValue } }
    }
    private var _control: Channel
    private let controlLock = NSLock()
    /// A connection the sender has opened to pick the drop up again, waiting to be taken.
    private var incoming: Channel?
    private weak var listener: DropListener?
    /// The drop's keys; gone when the drop ends or trust in the sender is withdrawn.
    private var keys: DropKeys?
    /// Data connection numbers that have been presented. Each is taken once.
    private var claimed = Set<UInt64>()
    private var reserved = 0
    /// What the person was shown and agreed to; the manifest must be that and nothing else.
    private let offered: Offer
    private var tree: SafeTree!

    private enum Decision { case accept(URL), decline(String) }
    private var decision: Decision?

    private var manifest: Manifest!
    private var ledger: Ledger!
    private var itemsRoot: URL!
    /// The data connections: those attached now, and how many have come and gone in all.
    private let streams = NSCondition()
    private var active: [Socket] = []
    private var finished = 0
    private var roundStartBytes: Int64 = 0
    private var conducted = false
    /// `SafeTree` keeps one directory open between calls; the stream threads take turns.
    private let treeLock = NSLock()
    /// Which `Transfer.dataConnections` entry each data connection is.
    private let streamInfo = Locked<[ObjectIdentifier: Int]>([:])
    /// The control connection is gone and the session is waiting for the sender to bring another.
    private var awaitingControl = false
    /// The conversation itself: what each message, each answer, each loss and each ending means,
    /// and how many rounds that deliver nothing are borne (`RoundMachine.Receiver`, in the crypto
    /// module, which has no I/O in it). This class is the connections, the disk, the person and
    /// the clock around it: it says nothing on the conversation, and ends the drop in no way,
    /// but as the machine's effect. Under `lock`.
    private var machine: RoundMachine.Receiver
    private typealias Effect = RoundMachine.Receiver.Effect
    /// The machine said to take the question away; the session's thread does, at its next look.
    private var unasked = false

    init(channel: Channel, offer: Offer, hello: SecureHello, mac: KnownMac, listener: DropListener) {
        _control = channel
        machine = RoundMachine.Receiver(offered: RoundMachine.Described(files: offer.fileCount, bytes: offer.totalBytes, names: offer.items),
                                        patience: Tuning.idleRounds)
        self.listener = listener
        sender = mac
        senderID = channel.remote.raw.map { String(format: "%02x", $0) }.joined()
        offeredFiles = offer.fileCount
        offeredBytes = offer.totalBytes
        senderAppVersion = Sanitize.label(hello.app, limit: 24)
        senderProtocol = "\(protocolVersion).\(hello.minor)"
        offered = offer
        keys = DropKeys(master: channel.master)
        // The name shown is the one the person here gave that Mac, not what it calls itself today.
        super.init(direction: .receive, state: .waitingForAccept, peerName: mac.name, peerAddress: channel.socket.peerAddress)
        setPeerKey(channel.remote)
        setItems(offer.items.prefix(1000).map { Sanitize.label($0, limit: 255) })
        log("offer from \(peerName) (\(channel.remote.tag)) at \(channel.socket.peerAddress) (Nimbus Drop \(senderAppVersion), protocol \(senderProtocol)): “\(items.prefix(20).joined(separator: "”, “"))”, \(offer.fileCount) files, \(offer.totalBytes) bytes")
        update { $0.totalBytes = offer.totalBytes; $0.totalFiles = offer.fileCount }
        track(channel.socket)
        // From here on, withdrawing trust in the sender ends this drop, asked about or not.
        listener.trust.track(self, key: channel.remote)
    }

    private func step(_ event: RoundMachine.Receiver.Event) -> [Effect] { lock.withLock { machine.step(event) } }

    /// An ending the machine gave to a thread that is not the session's own (or to the session's
    /// own, for an error of this Mac's): the word, then the end. A question still on screen is
    /// taken away by the session's thread, which is the one that put it there.
    private func conclude(_ effects: [Effect], with error: Error) {
        noteKind(of: error)
        for effect in effects {
            switch effect {
            case .send(.error): try? control.send(.error, Reason(message: (error as? DropError)?.message ?? error.localizedDescription))
            case .end(.failed): super.fail(error)
            case .unask: lock.withLock { unasked = true }
            default: break
            }
        }
        // Cancelled a moment ago, its end still waiting on the farewell: it ends now instead.
        if lock.withLock({ cancelRequested }) { super.fail(error) }
    }

    /// The drop cannot go on, for a reason of this Mac's. `tell`: the sender is told why, when
    /// it is still there to hear it (the machine says whether it is).
    private func stop(_ error: Error, tell: Bool) { conclude(step(.stopped(tell: tell)), with: error) }

    /// Ended from outside without a word: the sender offered the same drop again, and that
    /// session took this one's partial folder.
    override func fail(_ error: Error) { stop(error, tell: false) }

    /// Trust in the sender was withdrawn. The keys go first, so that nothing can attach or
    /// resume; what was being written stays in its partial folder and is not put in place.
    package override func withdrawn(_ error: DropError) {
        lock.withLock { keys = nil }
        conclude(step(.withdrawn), with: error)
        streams.lock()
        incoming?.socket.shutdown()
        streams.broadcast()
        streams.unlock()
    }

    /// Stops the drop. What has arrived stays in the partial folder, so sending the same drop
    /// again continues it.
    public override func cancel() {
        let effects = lock.withLock { () -> [Effect] in
            cancelRequested = true
            return machine.step(.cancelled)
        }
        if effects.contains(.unask) { lock.withLock { unasked = true } }
        // Best effort, so the other side can say who stopped it rather than "connection lost":
        // the word on a queue of its own, and the end a moment after it.
        if effects.contains(.send(.error)) {
            DispatchQueue.global().async { [weak self] in try? self?.control.send(.error, Reason(message: "Cancelled on the other Mac")) }
            DispatchQueue.global().asyncAfter(deadline: .now() + 0.3) { self.finish(.cancelled) }
        } else {
            finish(.cancelled)
        }
    }

    /// A data connection presents `conn` and a tag over the challenge this Mac just made for
    /// it. True, once, for the first connection that proves it holds the drop's keys now.
    func claim(conn: UInt64, tag: Data, challenge: Data) -> Bool {
        lock.withLock {
            guard let keys, !_isFinalOrCancelled, Crypto.same(tag, keys.attachTag(conn: conn, challenge: challenge)),
                  claimed.count < 1 << 20, claimed.insert(conn).inserted else { return false }
            return true
        }
    }

    private var _isFinalOrCancelled: Bool { cancelRequested }

    /// Take the drop into `destination` (a folder). Each top-level item lands there under its
    /// own name, or a "keep both" name when that is taken.
    public func accept(destination: URL) { lock.withLock { if decision == nil { decision = .accept(destination) } } }

    public func decline(_ reason: String = "Declined") { lock.withLock { if decision == nil { decision = .decline(reason) } } }

    func run() {
        do { try conduct() } catch {
            // Tell the sender why, when it is still there to hear it.
            stop(error, tell: true)
        }
        streams.lock()
        conducted = true
        streams.broadcast()
        streams.unlock()
    }

    /// A long silence is treated as a lost connection (see `SendSession.silence`): the drop is
    /// held open for the sender to come back to, rather than ended. Before it is under way
    /// there is nothing to hold, and silence ends it.
    override func silence() {
        let effects = step(.silent)
        if effects == [.hangUp] {
            log("no sign of life from \(peerName); treating the connection as lost", .warn)
            control.socket.shutdown()
            return
        }
        log("no sign of life from \(peerName) for too long; giving up", .error)
        conclude(effects, with: DropError("\(peerName) stopped responding; send the drop again to continue it"))
    }

    /// Returns once this session's own thread has finished with the drop.
    func waitUntilOver() {
        streams.lock()
        let deadline = Date().addingTimeInterval(15)
        while !conducted, streams.wait(until: deadline) {}
        streams.unlock()
    }

    /// The sender has reconnected on `socket` and wants to carry on. Called on the listener's
    /// thread; the session's own thread takes the connection from here. If that thread is still
    /// listening on the old connection (the sender noticed the loss first), closing the old one
    /// is what tells it.
    func resume(on channel: Channel, proof: Data) -> Bool {
        guard let keys = lock.withLock({ keys }), !isOver,
              Crypto.same(proof, DropKeys.resumeProof(keys.resumeKey, "resume", h: channel.h)),
              (try? channel.send(.resumed, Resumed(proof: DropKeys.resumeProof(keys.resumeKey, "resumed", h: channel.h)))) != nil else { return false }
        channel.limit = control.limit
        streams.lock()
        incoming?.socket.shutdown()
        incoming = channel
        let old = control
        streams.broadcast()
        streams.unlock()
        old.socket.shutdown()
        return true
    }

    /// The control connection is gone. Holds the drop open for `Tuning.reconnectSeconds`, with
    /// everything written so far kept, until the sender reconnects; then takes the connection
    /// it came back on and puts the progress as it stands, ready to say what is here. False
    /// when nobody came, or the drop ended meanwhile.
    private func hold(after lost: Error?) -> Bool {
        if isOver { return false }
        log("lost the control connection: \((lost as? DropError)?.message ?? "\(String(describing: lost))"); holding the drop for \(Int(Tuning.reconnectSeconds)) s", .warn)
        setState(.reconnecting)
        // Whatever is wrong with the old connection (gone, or it delivered a damaged
        // message), it is finished: closing it is how the sender learns to reconnect.
        control.socket.shutdown()
        streams.lock()
        for s in active { s.shutdown() }
        awaitingControl = true
        // The minute is counted from the last sign of the sender: while data connections are
        // open and delivering, it is there, whatever has become of the control connection.
        var deadline = Date().addingTimeInterval(Tuning.reconnectSeconds)
        var seen = progress.doneBytes
        while incoming == nil, !isOver, Date() < deadline {
            streams.wait(until: min(deadline, Date().addingTimeInterval(0.2)))
            let bytes = progress.doneBytes
            if bytes != seen {
                seen = bytes
                deadline = Date().addingTimeInterval(Tuning.reconnectSeconds)
            }
        }
        let fresh = incoming
        incoming = nil
        awaitingControl = false
        streams.unlock()
        guard !isOver, let fresh else { return false }
        replaceControl(control.socket, with: fresh.socket)
        control = fresh
        setPeerAddress(fresh.socket.peerAddress)
        log("the sender is back, from \(fresh.socket.peerAddress), and proved it is the same Mac and the same drop")
        // The old data connections are closing; let them finish before saying what is here.
        streams.lock()
        let settled = Date().addingTimeInterval(5)
        while !active.isEmpty, streams.wait(until: settled) {}
        streams.unlock()
        let have = ledger.doneBytes
        lock.withLock { roundStartBytes = have }
        update { $0.doneBytes = have }
        note { $0.reconnects += 1 }
        return true
    }

    /// Ends the drop as failed: only ever the machine's effect.
    private func end(_ error: Error) { super.fail(error) }

    /// The session's own thread, from the offer to the end. It tells the machine what happened
    /// (the person's answer, each message, each loss, how each round came out) and does what
    /// the machine answers. It reads the conversation only where the machine is waiting for
    /// it: while the person decides (anything the sender says then is its giving up), for the
    /// manifest, and for each round's "done".
    private func conduct() throws {
        typealias Machine = RoundMachine.Receiver
        let listener = listener
        let ask = listener?.onOffer
        // What this thread has in hand while the machine decides.
        var destination: URL?
        var declining = "Declined", declinedAs = "Declined"
        var candidate: Manifest?, refused: Error?
        var theirs = ""
        var done = Done(streams: 0)
        var partial: URL?
        var held: DropKeys?
        var complete = Complete(saved: [])
        var firstPlan = false, back = false
        var cause: Error?
        var was = Machine.Phase.idle
        defer {
            if let held { listener?.unregister(id: held.sessionID) }
            if let partial { listener?.release(partial.path, by: self) }
            if reserved > 0 { listener?.unreserve(reserved) }
        }

        /// What a message from the sender is, to the machine.
        func event(_ frame: (type: FrameType, body: Data)) -> Machine.Event {
            switch frame.type {
            case .manifest:
                // Read only when it is its turn; out of turn the machine refuses it unread.
                guard was == .awaitManifest, let m = try? decode(Manifest.self, from: frame.body) else { return .received(.manifest(.unreadable)) }
                do { try m.validate() } catch { refused = error; return .received(.manifest(.invalid)) }
                candidate = m
                return .received(.manifest(.described(RoundMachine.Described(files: m.fileCount, bytes: m.totalBytes, names: m.topLevelNames))))
            case .done:
                guard let d = try? decode(Done.self, from: frame.body) else { return .received(.done(readable: false)) }
                done = d
                return .received(.done(readable: true))
            case .error:
                guard let reason = try? decode(Reason.self, from: frame.body).message else { return .received(.error(readable: false)) }
                theirs = Sanitize.label(reason, limit: 300)
                return .received(.error(readable: true))
            default:
                return .received(.other)
            }
        }

        /// What the drop fails with when the machine ends it for a reason of the conversation's.
        func failure(_ why: Machine.Failure) -> Error {
            switch why {
            case .wentAway: return DropError("The sender went away")
            case .theirs: return DropError(theirs)
            case .unexpected: return DropError(was == .awaitManifest ? "Unexpected message from the sender" : "Unexpected message from \(peerName)")
            case .malformed: return DropError("Malformed message from the other Mac")
            case .invalidManifest: return refused ?? DropError("Malformed message from the other Mac")
            // The person said yes to what the offer described. A manifest that is something else
            // (more files, more bytes, other names) is not what was agreed to.
            case .notAsOffered: return DropError("The drop is not what was offered; it was refused")
            case .pairingRanOut: return DropError("The pairing with \(peerName) ran out before the drop was accepted")
            case .incomplete: return DropError("The drop arrived incomplete; send it again to continue it")
            case .didNotComeBack: return DropError("Lost the connection to \(peerName) and it did not come back; send the drop again to continue it")
            case .lost, .silent, .here, .withdrawn: return cause ?? DropError("The connection to \(peerName) was lost", connection: true)
            }
        }

        /// Does what the machine said, in order. The last of them may end with something to
        /// tell the machine (the word went out, the folder is ready, the round is judged, the
        /// sender is back); what it says to that is returned, to be done next.
        func perform(_ effects: [Effect]) throws -> [Effect] {
            var reason = cause
            for case .end(.failed(let why)) in effects { reason = failure(why) }
            for effect in effects {
                switch effect {
                case .ask:
                    ask?(self)

                case .unask:
                    lock.withLock { unasked = true }

                case .send(.decline(.pairingRanOut)):
                    // A yes to an offer whose pairing has since ended starts nothing: the question
                    // was asked under a key that no longer holds (it ran out with the panel still up).
                    try? control.send(.decline, Reason(message: "The pairing with \(listener?.identity.name ?? "this Mac") has run out; pair again and send it again"))

                case .send(.decline(let why)):
                    if why == .notReceiving { declining = "Not receiving"; declinedAs = "Not receiving" }
                    do { try control.send(.decline, Reason(message: declining)) } catch { cause = error; return step(.lost) }
                    return step(.said)

                case .send(.accept):
                    guard let listener, let destination else { break }
                    log("accepted, saving to \(destination.path)")
                    // Accepting authorises metadata in proportion to what was accepted, out of a budget all
                    // drops share: a manifest of 64 KB plus 2 KB for each file the offer announced.
                    let room = min(maxFrameBytes, (64 << 10) + 2048 * max(0, min(offered.fileCount, 1 << 22)))
                    listener.reserve(room)
                    reserved = room
                    control.limit = room
                    do { try control.send(.accept, Empty()) } catch { cause = error; return step(.lost) }

                case .prepare:
                    guard let listener, let destination, let candidate else { break }
                    held = try prepare(candidate, in: destination, partial: &partial, listener: listener)
                    firstPlan = true
                    return step(.prepared)

                case .send(.plan):
                    do { try control.send(.plan, ledger.plan()) } catch { cause = error; return step(.lost) }
                    if firstPlan {
                        firstPlan = false
                        let next = step(.said)
                        setState(.transferring)
                        startWatchdog()
                        return next
                    }
                    if back { back = false; setState(.transferring) }

                case .settle:
                    // Rounds. The sender writes what it was asked for and says done; if connections died or
                    // chunks arrived damaged along the way, something is missing, and the machine's answer
                    // is a new plan rather than a failure. It ends when everything is here, or when round
                    // after round delivers nothing.
                    let roundStart = lock.withLock { roundStartBytes }
                    if let resent = done.resent { note { $0.retransmittedChunks = resent } }
                    let next = settle(opened: done.streams) { [self] in
                        let soFar = stats
                        log("the sender says it is done (\(done.streams) data connections opened in all, \(done.resent ?? 0) chunks retransmitted); here: \(soFar.chunks) chunks received, \(soFar.damagedChunks) damaged, \(ledger.doneBytes) of \(manifest.totalBytes) bytes", .debug)
                        if isOver { return [] }
                        return step(.settled(ledger.isComplete ? .whole : ledger.doneBytes > roundStart ? .more : .nothingNew))
                    }
                    if next == [.send(.plan)] {
                        note { $0.rounds += 1 }
                        let have = ledger.doneBytes
                        log("the sender is done but \(manifest.totalBytes - have) bytes are missing; asking for them (round \(stats.rounds + 1))", .warn)
                        lock.withLock { roundStartBytes = have }
                        update { $0.doneBytes = have }
                    }
                    return next

                case .place:
                    // Trust withdrawn while the last chunks arrived: nothing is put in place.
                    guard !isOver, let partial, let destination else { return [] }
                    setState(.finishing)
                    let saved = try finalize(partial: partial, destination: destination)
                    setSaved(saved)
                    update { $0.doneBytes = $0.totalBytes; $0.doneFiles = $0.totalFiles }
                    log("saved as \(saved.map(\.path).joined(separator: ", "))")
                    let p = progress, s = stats
                    let seconds = max(0.001, Date().timeIntervalSince(transferStartedAt ?? startedAt))
                    log("summary: \(Format.files(p.totalFiles)), \(Format.bytes(p.totalBytes - p.resumedBytes)) received in \(String(format: "%.1f", seconds)) s = \(Format.bitRate(Double(p.totalBytes - p.resumedBytes) / seconds))"
                        + (p.resumedBytes > 0 ? " (\(Format.bytes(p.resumedBytes)) were already here)" : "")
                        + "; \(s.chunks) chunks, \(s.damagedChunks) damaged, \(s.retransmittedChunks) retransmitted by the sender; \(s.rounds + 1) rounds; \(s.connectionFailures) connections dropped; \(s.reconnects) reconnects")
                    complete = Complete(saved: saved.map(\.lastPathComponent))
                    return step(.placed)

                case .send(.complete):
                    try? control.send(.complete, complete)
                    // A sender that lost the connection meanwhile will come back asking; it is told then,
                    // by this drop's machine as it stands now. The drop's keys are done with, but for
                    // the one a late "did it arrive?" is proved with.
                    if let held, let listener {
                        listener.remember(completed: held.sessionID, complete, resumeKey: held.resumeKey, key: control.remote, rounds: lock.withLock { machine })
                    }
                    lock.withLock { self.keys = nil }
                    if let fresh = streams.withLock({ incoming }) { try? fresh.send(.complete, complete) }

                case .hold:
                    // The conversation's connection is gone. The drop was accepted and is partly
                    // here: wait for the sender to come back rather than ending it.
                    guard hold(after: cause) else { return isOver ? [] : step(.gaveUp) }
                    back = true
                    return step(.senderBack)

                case .hangUp:
                    break   // a silence is the watchdog's to act on

                case .send(.error):
                    // Tell the sender why, when it is still there to hear it.
                    if let reason { try? control.send(.error, Reason(message: (reason as? DropError)?.message ?? reason.localizedDescription)) }

                case .end(.completed):
                    finish(.completed)

                case .end(.declined):
                    finish(.declined(declinedAs))

                case .end(.cancelled):
                    finish(.cancelled)

                case .end(.failed):
                    if let reason { end(reason) }
                }
            }
            return []
        }

        var todo = step(.begin(askable: ask != nil))
        while true {
            while !todo.isEmpty { todo = try perform(todo) }
            // The drop ended with the question still up (the sender gave up, trust was
            // withdrawn, it was stopped here): the question goes.
            if lock.withLock({ unasked }) { onWithdrawn?(); return }
            cause = nil
            was = lock.withLock { machine.phase }
            switch was {
            case .deciding:
                // Wait for the person here, while watching for the sender giving up.
                if control.socket.waitReadable(milliseconds: 200) {
                    do { todo = step(event(try control.read())) } catch { todo = step(.lost) }
                } else if let decision = lock.withLock({ decision }) {
                    switch decision {
                    case .accept(let folder):
                        destination = folder
                        todo = step(.yes(paired: listener?.trust.standing(of: control.remote).isPaired ?? false))
                    case .decline(let reason):
                        declining = reason
                        todo = step(.no)
                    }
                }

            case .awaitManifest, .reading:
                do {
                    let frame = try control.read()
                    if was == .reading { touch() }
                    todo = step(event(frame))
                } catch {
                    cause = error
                    todo = step(.lost)
                }

            default:
                // An end, or nothing more that this thread is to wait for.
                return
            }
        }
    }

    /// The manifest is what was offered and the person said yes: everything the drop is built
    /// in, and the moment data connections may attach. Returns the drop's keys, with the
    /// session registered under them.
    private func prepare(_ accepted: Manifest, in destination: URL, partial claimed: inout URL?, listener: DropListener) throws -> DropKeys {
        manifest = accepted
        setItems(manifest.topLevelNames)
        update { $0.totalBytes = manifest.totalBytes; $0.totalFiles = manifest.fileCount }

        // Everything is built inside one partial folder in the destination (so the final move
        // is a rename on the same volume), named after the drop's key so a re-send finds it.
        let key = manifest.key(senderID: senderID)
        let label = String((manifest.topLevelNames.first ?? "Drop").prefix(80))
        // 32 hex digits of the key: enough that two different drops cannot be made to share a
        // partial folder (12 could be, by trying sixteen million manifests).
        let partial = destination.appendingPathComponent("\(label).\(key.prefix(32)).nimbusdrop-partial", isDirectory: true)
        listener.claim(partial.path, for: self)
        claimed = partial
        itemsRoot = partial.appendingPathComponent("items", isDirectory: true)
        do { try FileManager.default.createDirectory(at: itemsRoot, withIntermediateDirectories: true) }
        catch { throw DropError("Cannot write to \(destination.path): \(error.localizedDescription)") }
        tree = try SafeTree(root: itemsRoot)
        try prepareTree()
        ledger = try Ledger(url: partial.appendingPathComponent("ledger"), manifest: manifest, tree: tree)

        let empties = manifest.entries.indices.filter { manifest.entries[$0].kind == .file && manifest.chunkCount($0) == 0 }.count
        update { $0.resumedBytes = ledger.doneBytes; $0.doneBytes = ledger.doneBytes; $0.doneFiles = ledger.doneFiles + empties }
        roundStartBytes = ledger.doneBytes
        log("partial folder \(partial.lastPathComponent); already here: \(ledger.doneBytes) of \(manifest.totalBytes) bytes", .debug)
        let needed = manifest.totalBytes - ledger.doneBytes
        if let free = try? destination.resourceValues(forKeys: [.volumeAvailableCapacityForImportantUsageKey]).volumeAvailableCapacityForImportantUsage,
           free < needed {
            throw DropError("Not enough space on \(listener.identity.name): \(Format.bytes(needed)) needed, \(Format.bytes(free)) free")
        }

        guard let keys = lock.withLock({ keys }) else { throw DropError("\(peerName) is no longer trusted") }
        // Nothing larger than a `done` is expected from here on.
        control.limit = Channel.fragment
        listener.register(self, id: keys.sessionID)
        return keys
    }

    /// After the sender says done: wait for the data connections it opened to finish here too
    /// (their last chunks may still be on the wire or on their way to disk), then close whatever
    /// is left so that nothing writes into the drop once it is judged.
    ///
    /// `judge` reads the ledger and tells the machine how the drop stands. It runs with the
    /// data connections' lock still held: no connection is open when the drop is judged, and
    /// none can be let in between the judgement and the machine's hearing it (`runStream` asks
    /// the machine, under the same lock). So a drop that is judged whole is put in place as it
    /// was judged. Until 2026-11-24 the lock was let go first and nothing asked the machine: a
    /// data connection that arrived late was written into a drop being moved
    /// (`testNothingIsWrittenIntoADropOnceItHasBeenJudgedWhole`).
    private func settle(opened: Int, judge: () -> [Effect]) -> [Effect] {
        streams.lock()
        var quietSince = Date()
        var lastBytes = progress.doneBytes
        while finished < opened, !isOver {
            streams.wait(until: Date().addingTimeInterval(0.05))
            let bytes = progress.doneBytes
            if bytes != lastBytes { lastBytes = bytes; quietSince = Date() }
            // A connection the sender counts but that never got here (reset on the way) will
            // never finish; one that is here but silent has stalled.
            let patience = active.isEmpty ? Tuning.settleSeconds : Tuning.stallSeconds
            if Date().timeIntervalSince(quietSince) > patience { break }
        }
        // Whatever is open is closed, and whatever is let in while that is waited for too.
        let deadline = Date().addingTimeInterval(10)
        while !active.isEmpty, Date() < deadline {
            let left = active
            streams.unlock()
            for s in left { s.shutdown() }
            streams.lock()
            if !active.isEmpty { streams.wait(until: min(deadline, Date().addingTimeInterval(0.05))) }
        }
        defer { streams.unlock() }
        return judge()
    }

    /// Folders, symlinks and empty files, before any data. All through `SafeTree`: whatever is
    /// already there (a resumed drop) must be what the manifest says it is.
    private func prepareTree() throws {
        for e in manifest.entries {
            switch e.kind {
            case .directory: try tree.makeDirectory(e.path)
            case .symlink:
                // A link out of the drop is not recreated: it would be a door from the received
                // folder to somewhere else on this Mac. Links within the drop are kept.
                guard Manifest.linkStaysInside(path: e.path, link: e.link ?? "") else {
                    note { $0.skippedLinks += 1 }
                    log("left out the link \(Sanitize.label(e.path, limit: 200)) → \(Sanitize.label(e.link ?? "", limit: 200)): it points outside the drop", .warn)
                    continue
                }
                try tree.makeSymlink(e.path, to: e.link ?? "")
            case .file where e.size == 0: close(try tree.openFile(e.path))
            case .file: break
            }
        }
    }

    /// One data connection: read a chunk, check it, write it where it belongs, note it.
    ///
    /// Trouble with the connection (it closed, it stalled, what it carried is damaged) ends this
    /// connection only; the chunks it did not deliver are asked for again. Trouble with the disk
    /// ends the drop.
    func runStream(_ socket: Socket, conn: UInt64) {
        let from = socket.peerAddress
        track(socket)
        streams.lock()
        // The machine says when a drop takes data: not before its folder is ready, and not once
        // it has been judged whole. Asked with the lock held under which the drop is judged.
        guard lock.withLock({ machine.takesData }) else {
            streams.unlock()
            log("refused a data connection from \(from): the drop is not taking data (it has been judged, or has not begun)", .warn)
            socket.shutdown()
            return
        }
        guard active.count < Tuning.streamsPerDrop else {
            streams.unlock()
            log("refused a data connection from \(from): \(Tuning.streamsPerDrop) are open already", .warn)
            socket.shutdown()
            return
        }
        active.append(socket)
        let waiting = awaitingControl
        streams.unlock()
        update { $0.connections += 1 }
        // The conversation's connection is still missing, but the sender is plainly there and
        // sending: this is a drop that is moving, and it says so. (The sender finds out about
        // the dead connection only when it next has something to say, which may be at the end.)
        let info = streamOpened(remote: from)
        defer { streamClosed(info) }
        streamInfo.withLock { $0[ObjectIdentifier(socket)] = info }
        defer { streamInfo.withLock { $0[ObjectIdentifier(socket)] = nil } }
        if waiting, state == .reconnecting {
            log("data is arriving again from \(from), ahead of the control connection")
            setState(.transferring)
        }
        do { try receive(socket, conn: conn) } catch let fault as StreamFault {
            log(fault == .damaged ? "a record from \(from) did not open (damaged, or not from the sender); closing that connection" : "a data connection from \(from) was lost", .warn)
            note {
                $0.connectionFailures += 1
                if fault == .damaged { $0.damagedChunks += 1 }
            }
            socket.shutdown()
        } catch {
            // Trouble with the disk ends the drop, and the sender is told why.
            stop(error, tell: true)
        }
        untrack(socket)
        update { $0.connections -= 1 }
        streams.lock()
        active.removeAll { $0 === socket }
        finished += 1
        let idleAgain = awaitingControl && active.isEmpty
        streams.broadcast()
        streams.unlock()
        // Nothing arriving and still no conversation: back to waiting for the sender.
        if idleAgain, state == .transferring { setState(.reconnecting) }
    }

    private enum StreamFault: Error { case lost, damaged }

    /// Records, until the end marker. Each is a sealed header, opened before anything else is
    /// read, then the chunk it describes, sealed with that header as associated data. A chunk is
    /// opened whole into a buffer nothing else can see, and only what opened is written.
    private func receive(_ socket: Socket, conn: UInt64) throws {
        guard var cipher = lock.withLock({ keys })?.stream(conn) else { throw StreamFault.lost }
        let buffer = UnsafeMutableRawPointer.allocate(byteCount: manifest.chunkSize + 16, alignment: 16384)
        defer { buffer.deallocate() }
        var sealedHeader = Data(count: RecordHeader.sealedSize)
        var openFile = -1
        var fd: Int32 = -1
        defer { if fd >= 0 { close(fd) } }
        var carried: Int64 = 0

        while true {
            do { try sealedHeader.withUnsafeMutableBytes { try socket.readExactly($0.baseAddress!, RecordHeader.sealedSize) } }
            catch { throw StreamFault.lost }
            guard let headerBytes = try? cipher.open(sealedHeader), let header = RecordHeader(headerBytes) else { throw StreamFault.damaged }
            if header.file == RecordHeader.endMarker {
                // Exactly this, and nothing after it.
                guard header.chunk == 0, header.length == 0 else { throw StreamFault.damaged }
                return
            }
            // A header that opened but describes something the manifest does not have came from
            // the sender's own keys and is still refused: an ordinary file of this drop, a chunk
            // that file has, and exactly the length that chunk must be.
            let file = Int(header.file), chunk = Int(header.chunk), length = Int(header.length)
            guard file < manifest.entries.count, manifest.entries[file].kind == .file, chunk < manifest.chunkCount(file),
                  length == manifest.chunkLength(file: file, chunk: chunk) else { throw StreamFault.damaged }
            // One stream key carries so many bytes and no more; an honest sender has moved to
            // another connection, and so another key, before this.
            carried += Int64(length)
            guard carried <= DropKeys.streamBytes else { throw StreamFault.damaged }
            var counted = 0
            do {
                try socket.readExactly(buffer, length + 16) { [self] n in
                    let add = min(n, length - counted)
                    counted += add
                    if add > 0 { update { $0.doneBytes += Int64(add) } }
                }
            } catch { throw StreamFault.lost }
            guard let plain = try? cipher.open(bytes: buffer, count: length, ad: headerBytes), plain.count == length else { throw StreamFault.damaged }
            if isOver { throw StreamFault.lost }
            if openFile != file {
                if fd >= 0 { close(fd) }
                fd = -1
                fd = try treeLock.withLock { try tree.openFile(manifest.entries[file].path) }
                openFile = file
            }
            let offset = Int64(chunk) * Int64(manifest.chunkSize)
            try plain.withUnsafeBytes { p in
                var wrote = 0
                while wrote < length {
                    let n = pwrite(fd, p.baseAddress! + wrote, length - wrote, offset + Int64(wrote))
                    if n > 0 { wrote += n }
                    else if errno != EINTR { throw errnoError("Cannot write \(manifest.entries[file].path)") }
                }
            }
            if let info = streamInfo.withLock({ $0[ObjectIdentifier(socket)] }) { streamCarried(info, bytes: length) }
            if try ledger.record(file: file, chunk: chunk) { update { $0.doneFiles += 1 } }
        }
    }

    /// Modes and times, deepest first; then each top-level item moves into the destination.
    private func finalize(partial: URL, destination: URL) throws -> [URL] {
        // Everything received is marked as having come from elsewhere, as AirDrop marks it:
        // an app or a script in the drop then gets Gatekeeper's question the first time it is run.
        let quarantine = Quarantine.value()
        // The tree's lock is taken for each use of it, as the stream threads take it. None of
        // them should be left by now (`settle` closed them and waited, and no new one is let
        // in); one that outlived the ten seconds `settle` waits must still not find the tree
        // half way through a call.
        for e in manifest.entries.reversed() where e.kind != .symlink {
            // The owner keeps access to what they were just sent, whatever the mode was; and
            // nothing arrives set-uid (the mask drops every bit above the permissions).
            treeLock.withLock {
                tree.finish(e.path, mtime: e.mtime, mode: mode_t(e.mode & 0o777) | (e.kind == .directory ? 0o700 : 0o600), quarantine: quarantine)
            }
        }
        treeLock.withLock { tree.release() }
        var saved: [URL] = []
        let fm = FileManager.default
        for e in manifest.entries where !e.path.contains("/") {
            // A top-level item that was a link out of the drop was left out; there is nothing to move.
            if e.kind == .symlink, !Manifest.linkStaysInside(path: e.path, link: e.link ?? "") { continue }
            let name = Naming.unique(e.path, isDirectory: e.kind == .directory) {
                fm.fileExists(atPath: destination.appendingPathComponent($0).path)
            }
            let target = destination.appendingPathComponent(name)
            // Trust withdrawn while this was being put in place: stop putting.
            if isOver { throw DropError("\(peerName) is no longer trusted") }
            guard rename(itemsRoot.appendingPathComponent(e.path).path, target.path) == 0 else {
                throw errnoError("Cannot move \(e.path) into \(destination.path)")
            }
            saved.append(target)
        }
        try? fm.removeItem(at: partial)
        return saved
    }
}
