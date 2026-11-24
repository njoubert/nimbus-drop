// Copyright (C) 2026 Niels Joubert
// SPDX-License-Identifier: GPL-3.0-or-later
import Darwin
import Foundation
import NimbusBase
import NimbusRuntime
import NimbusCrypto
import NimbusNet
import NimbusSafeStorageCore
import NimbusSecurityCore

/// Accepts connections from other Macs. Each new drop from a paired Mac is handed to `onOffer`
/// as a `ReceiveSession` that waits for `accept(destination:)` or `decline()`; nothing is written
/// before that. A request to pair is handed to `onPairRequest`.
///
/// Every connection is held to the budget of what it has proved so far (the plan's Admission
/// table): a slot is taken before any work is done for it and kept until its class changes.
/// Completing a handshake proves possession of some key, not a place among the Known Macs, and
/// raises no limit by itself.
///
/// Which connection has a place and which gives way is not decided here. `Admission` (in the
/// crypto module, which has no I/O in it) decides; this class keeps the sockets, the lock and
/// the clock, tells it each thing that happens to a connection (`ask`), and does what it
/// answers. `formal/tla/Admission.tla` is that machine as a specification, held equal to it.
public final class DropListener: @unchecked Sendable {
    public let port: UInt16
    public let identity: Identity
    public let trust: Trust
    /// Called on a background thread for every incoming offer.
    public var onOffer: (@Sendable (ReceiveSession) -> Void)?
    /// Called on a background thread when another Mac asks to pair and its request has reached
    /// the front of the queue. One at a time.
    public var onPairRequest: (@Sendable (PairingSession) -> Void)?
    /// A paired Mac asks to measure the link to this one. Called on a background thread; the
    /// test waits for `accept()` or `decline()`, and with nobody to ask it is declined.
    public var onSpeedTest: (@Sendable (SpeedResponder) -> Void)?
    /// A retired or run-out identity was used, and the person should be told (rationed).
    public var onRefusedIdentity: (@Sendable (_ name: String, _ address: String) -> Void)?

    private let fd: Int32
    private let lock = NSLock()
    private var stopped = false
    private var sessions: [Data: DataSession] = [:]
    /// One speed test (or one question about one) at a time on this Mac, whoever asks. Set by
    /// the one that is let in and cleared by it alone, when it has ended and not before: an
    /// earlier version cleared it early as well, and a third test got in beside a second.
    private var speedTesting = false
    /// When each key last had a speed test answered, allowed or not: a pause before its next.
    private var speedAsked: [PublicKey: Date] = [:]
    private var holders: [String: ReceiveSession] = [:]
    /// Who has a place: the connections that have proved nothing (in order of arrival: the one
    /// that has waited longest gives way), the ones that proved a key nobody paired, the ones
    /// from a paired key that have not yet said what they came for, and the arrivals of the
    /// last second. Asked with the lock held, and only through `ask`.
    private var admission = Admission(limits: DropListener.limits)
    /// Each connection `admission` knows, by the number it gave it, from its arrival until it
    /// is done with: to close the one that is told to give way.
    private var connections: [UInt64: Socket] = [:]
    private var turnedAway = Set<String>()
    private var _localOnly = true
    /// Take connections only from the local network (the default). Off: from anything that can reach the port.
    public var localOnly: Bool {
        get { lock.withLock { _localOnly } }
        set { lock.withLock { _localOnly = newValue; turnedAway = [] } }
    }
    /// Tests only: decides which addresses are let in, in place of the subnet rule.
    var allows: ((String) -> Bool)?
    private var waiting: [(session: ReceiveSession?, key: PublicKey)] = []
    /// Drops that finished a moment ago: the answer, the one key of the drop that is still
    /// needed, whose drop it was, when (on the clock that cannot be set), and the drop's
    /// conversation as it ended (`rounds`), which is what says that a finished drop answers
    /// "complete" again. See `remember`.
    private var completed: [Data: (answer: Complete, resumeKey: Secret, key: PublicKey, at: Double, rounds: RoundMachine.Receiver)] = [:]
    /// Tests only: how many finished drops' answers (and resume keys) are being kept.
    var remembered: Int { lock.withLock { completed.count } }
    private var showing: PairingSession?
    /// Requests waiting behind the one on screen.
    private var waitingRequests: [PairingSession] = []
    private var queued = 0
    private var reassembling = 0
    private let budget = NSCondition()
    private var counted: [String: (count: Int, since: Date)] = [:]

    /// Listens on `preferredPort`, or on any free port when that one is taken (0 asks for any).
    public init(identity: Identity, trust: Trust, preferredPort: UInt16 = defaultPort) throws {
        self.identity = identity
        self.trust = trust
        if let got = try? Socket.listen(port: preferredPort) {
            (fd, port) = got
        } else {
            (fd, port) = try Socket.listen(port: 0)
        }
        // A key whose trust is withdrawn loses what it had waiting here too.
        trust.onWithdrawn { [weak self] key in self?.withdraw(key) }
    }

    deinit { close(fd) }

    public func start() {
        Thread.detachNewThread { [self] in
            while !lock.withLock({ stopped }) {
                var p = pollfd(fd: fd, events: Int16(POLLIN), revents: 0)
                guard poll(&p, 1, 250) > 0 else { continue }
                let client = accept(fd, nil, nil)
                guard client >= 0 else { continue }
                let socket = Socket(fd: client)
                // Admission before a thread: the address, the rate, and a stranger's slot.
                guard let ticket = admit(socket) else { socket.shutdown(); continue }
                Thread.detachNewThread { [self] in serve(socket, ticket) }
            }
        }
    }

    /// Stops taking new drops. Drops already under way carry on.
    public func stop() { lock.withLock { stopped = true } }

    /// One line per kind per minute, with a count: what strangers cause is counted, not listed.
    private func logCounted(_ kind: String, _ message: @autoclosure () -> String, _ level: LogLevel = .warn) {
        let now = Date()
        let say: Int? = lock.withLock {
            if let c = counted[kind], now.timeIntervalSince(c.since) < 60 {
                counted[kind] = (c.count + 1, c.since)
                return nil
            }
            let before = counted[kind]?.count ?? 0
            counted[kind] = (0, now)
            return before
        }
        guard let say else { return }
        DropLog.write(message() + (say > 0 ? " (and \(say) more like it in the last minute)" : ""), level)
    }

    /// The limits `admission` works to: `Tuning`'s, as they are now (the tests change them).
    private static var limits: Admission.Limits {
        Admission.Limits(strangers: Tuning.strangers, strangersPerAddress: Tuning.strangersPerAddress,
                         arrivals: Tuning.arrivalsPerSecond, arrivalsPerAddress: Tuning.arrivalsPerAddress, window: 1,
                         unattachedPerDrop: Tuning.unattachedPerDrop, unattachedPerAddress: Tuning.unattachedPerAddress,
                         unpaired: Tuning.unpaired, unpairedPerAddress: Tuning.unpairedPerAddress, pairedWaiting: Tuning.pairedWaiting)
    }

    /// The time `admission` is given with each arrival: seconds on the clock that cannot be set
    /// (it counts from boot, through sleep), as for the lifetimes of keys. It was the calendar
    /// until 2026-11-24. Whoever sets that back (a time server, a person) kept the arrivals of
    /// the moment counted until the calendar came round to them again, and held still it never
    /// forgot one: with the rate full, every connection was turned away for as long
    /// (formal/tla/AdmissionSystem.tla, the run on a clock that can be set back).
    static func elapsed() -> Double { SystemClock().continuous }

    /// With the lock held. Tells `admission` what has happened; returns what it says to do, and
    /// the connections that are to give way (for the caller to close, once the lock is let
    /// go). Nothing else in this class decides who has a place.
    private func ask(_ event: Admission.Event) -> (answer: Admission.Answer, displaced: [Socket]) {
        admission.limits = Self.limits
        let answer = admission.step(event)
        switch answer {
        case .admitted(_, let out?), .moved(let out?): return (answer, [out].compactMap { connections[$0] })
        case .giveWay(let out): return (answer, out.compactMap { connections[$0] })
        default: return (answer, [])
        }
    }

    /// Changes which drops (and speed tests) are in progress, and tells `admission` how many
    /// there are now: the data connections that have not attached have so many places for
    /// each, and when one ends the places it gave end with it.
    private func drops<T>(_ change: () -> T) -> T {
        let (result, displaced) = lock.withLock { () -> (T, [Socket]) in
            let result = change()
            return (result, ask(.drops(sessions.count)).displaced)
        }
        if !displaced.isEmpty {
            logCounted("ended", "closed \(displaced.count) data connections that had proved nothing: the drop they could have belonged to is over", .debug)
        }
        for gone in displaced { gone.shutdown() }
        return result
    }

    /// Whether a connection is taken at all: from the local network (unless Settings says
    /// otherwise), within the rate at which new connections are taken, and with a stranger's
    /// slot, which is held from here. Returns the number it is known by from now on.
    private func admit(_ socket: Socket) -> UInt64? {
        let from = socket.peerAddress
        let local = allows.map { $0(from) } ?? (!localOnly || LocalNetwork.isLocal(from, among: LocalNetwork.current()))
        let (answer, displaced) = lock.withLock { () -> (Admission.Answer, [Socket]) in
            let said = ask(.arrive(from: from, local: local, now: Self.elapsed()))
            if case .admitted(let ticket, _) = said.answer { connections[ticket] = socket }
            return said
        }
        switch answer {
        case .admitted(let ticket, _):
            for gone in displaced {
                logCounted("displaced", "closed a connection that had proved nothing, to make room for one from \(from)", .debug)
                gone.shutdown()
            }
            return ticket
        case .close(.elsewhere):
            // Said once per address: a scanner knocking every second should not fill the log.
            if lock.withLock({ turnedAway.count < 1000 && turnedAway.insert(from).inserted }) {
                DropLog.write("turned away a connection from \(from): not on the local network (Settings › Receiving)", .warn)
            }
            return nil
        default:
            logCounted("full", "turned away a connection from \(from): too many in a second")
            return nil
        }
    }

    private func serve(_ socket: Socket, _ ticket: UInt64) {
        let from = socket.peerAddress
        // Whatever place it holds is given back when it is done with, however that comes about.
        defer { lock.withLock { _ = ask(.closed(ticket)); connections[ticket] = nil } }
        // Ten seconds in all (not ten per byte) to get as far as proving a key.
        let deadline = Deadline(socket, seconds: Tuning.strangerSeconds)
        defer { deadline.cancel() }
        socket.setReadTimeout(Int(Tuning.strangerSeconds.rounded(.up)))
        guard let kind = try? Opening.readKind(socket) else { socket.shutdown(); return }

        if kind == Opening.data {
            // A data connection: nothing until it proves it belongs to a drop in progress.
            let (answer, displaced) = lock.withLock { ask(.data(ticket, drops: sessions.count)) }
            for gone in displaced { gone.shutdown() }
            guard case .moved = answer else { socket.shutdown(); return }
            deadline.arm(Tuning.attachSeconds)
            let challenge = Crypto.random(16)
            var message = Data(count: 40)
            guard (try? challenge.withUnsafeBytes({ try socket.writeAll($0.baseAddress!, 16) })) != nil,
                  (try? message.withUnsafeMutableBytes({ try socket.readExactly($0.baseAddress!, 40) })) != nil else { socket.shutdown(); return }
            let id = message.prefix(16), tag = message.suffix(16)
            let conn = message.dropFirst(16).prefix(8).reduce(UInt64(0)) { $0 << 8 | UInt64($1) }
            guard let session = lock.withLock({ sessions[Data(id)] }), session.claim(conn: conn, tag: Data(tag), challenge: challenge) else {
                logCounted("attach", "refused a data connection from \(from): it did not prove it belongs to a drop here")
                socket.shutdown()
                return
            }
            deadline.cancel()
            lock.withLock { _ = ask(.attached(ticket)) }
            socket.setReadTimeout(0)
            session.runStream(socket, conn: conn)
            return
        }

        guard kind == Opening.control, let channel = try? Channel.respond(socket, keys: trust.keyPair) else {
            // Includes every probe: a connection that learns who is here and hangs up.
            socket.shutdown()
            return
        }
        // A key has been proved. What it is to this Mac decides everything from here. It is no
        // longer one of the connections that have proved nothing: it is counted with the keys
        // nobody has paired, or with the connections of its own key that have not yet said what
        // they came for (a paired key is counted too: a paired Mac that means harm could
        // otherwise hold any number of connections here for ten seconds each).
        let key = channel.remote
        var standing = trust.standing(of: key)
        let proved: Admission.Proved
        switch standing {
        case .mine: proved = .mine
        case .retired: proved = .retired
        default: proved = standing.isPaired ? .paired(key) : .unpaired
        }
        let (answer, displaced) = lock.withLock { ask(.proved(ticket, proved)) }
        // A key nobody paired takes its place as a stranger does: the one that has waited
        // longest without asking for anything gives way to it.
        for gone in displaced {
            logCounted("displacedkey", "closed a connection that had proved a key nobody paired and asked for nothing, to make room for one from \(from)", .debug)
            gone.shutdown()
        }
        switch answer {
        case .moved: break
        case .close(.retired):
            if case .retired(let t) = standing {
                logCounted("retired", "refused \(from): it proved an identity (\(key.tag)) that \(t.name) gave up or that was replaced", .error)
                if trust.noteRefused(key) { onRefusedIdentity?(t.name, from) }
            }
            socket.shutdown()
            return
        case .close(.tooManyUnpaired):
            logCounted("unpaired", "turned away \(from) (\(key.tag)): too many connections from Macs that are not paired")
            socket.shutdown()
            return
        case .close(.tooManyWaiting):
            logCounted("pairedwaiting", "turned away \(from) (\(key.tag)): too many connections from that Mac that have not said what they want")
            socket.shutdown()
            return
        default:
            // This Mac's own key; or it had already given way to a newcomer.
            socket.shutdown()
            return
        }
        // Sixteen kilobytes in all, which the one-fragment limit already holds it under per message.
        if !standing.isPaired { channel.limit = 16 << 10 }
        func saidWhatItCameFor() { lock.withLock { _ = ask(.purpose(ticket)) } }

        guard let first = try? channel.read(), first.type == .hello, let hello = try? decode(SecureHello.self, from: first.body) else { socket.shutdown(); return }
        // A Mac this one has paired proves its key and says it no longer has this Mac paired:
        // someone there chose Forget (and it is telling us), or it is about to ask to pair
        // again. This Mac's half is worth nothing from here on, and goes now rather than at
        // the next drop. Only that key can say this, sealed under its own handshake, and only
        // about itself; it is what answering a drop with `paired: false` has always done.
        // Not on a reconnect: a drop that is running may finish after its sender's own key
        // was replaced on schedule, and that sender truthfully says it no longer has this
        // Mac paired. What a resume may do is decided by its proof of the drop's keys.
        // Nor from a key paired in the last few seconds: a hello that was truthful when it was
        // sealed (a probe during the pairing, a Forget just before pairing again) can arrive
        // after the pairing it predates, and someone on the path can hold it back that long,
        // but no longer than a connection may take to prove a key.
        if standing.isPaired, !hello.paired, hello.purpose != .resume, !trust.pairedWithin(Tuning.strangerSeconds, key) {
            trust.notePairingGone(key)
            standing = trust.standing(of: key)
            // It is a key nobody has paired now, and is held to what one may send.
            channel.limit = 16 << 10
        }
        // What this Mac says of the pairing. On a reconnect from a key that has run out, the
        // drop it belongs to may still finish (below), and the sender takes `paired: false`
        // here for a Forget: so it is told what is true of the drop, that it will be taken.
        var says = standing.isPaired
        if hello.purpose == .resume, case .expired = standing { says = true }
        guard (try? channel.send(.hello, SecureHello(minor: protocolMinor, app: identity.appVersion, name: identity.name, remaining: trust.remaining,
                                                     paired: says, purpose: nil))) != nil else { socket.shutdown(); return }
        let name = Sanitize.label(hello.name, limit: 64)

        switch hello.purpose {
        case .drop:
            // Both sides must hold the pairing. One that does not has just been told so.
            guard case .paired(let mac) = standing, hello.paired else { socket.shutdown(); return }
            trust.seen(key, name: hello.name, major: protocolVersion)
            guard let frame = try? channel.read(), frame.type == .offer, let offer = try? decode(Offer.self, from: frame.body) else { socket.shutdown(); return }
            saidWhatItCameFor()
            deadline.cancel()
            socket.setReadTimeout(0)
            socket.setNoDelay()
            let session = ReceiveSession(channel: channel, offer: offer, hello: hello, mac: mac, listener: self)
            // No more questions on screen than a person can read, and no more than two from
            // one Mac: the rest are declined without being shown.
            let room = lock.withLock { () -> Bool in
                waiting = waiting.filter { $0.session?.state == .waitingForAccept }
                guard waiting.count < Tuning.pendingOffers,
                      waiting.filter({ $0.key == key }).count < Tuning.pendingOffersPerAddress else { return false }
                waiting.append((session, key))
                return true
            }
            guard room else {
                DropLog.write("declined an offer from \(mac.name) unseen: too many are waiting for an answer already", .warn)
                try? channel.send(.decline, Reason(message: "\(identity.name) has too many drops waiting for an answer"))
                return
            }
            session.run()

        case .resume:
            // A drop in progress may be picked up by the key that began it even after that key's
            // end date, within the time a running drop is allowed (see `Trust.track`).
            switch standing {
            case .paired, .expired: break
            default: socket.shutdown(); return
            }
            guard let frame = try? channel.read(), frame.type == .resume, let resume = try? decode(Resume.self, from: frame.body) else { socket.shutdown(); return }
            saidWhatItCameFor()
            // A drop that finished while its sender was out of reach: say so again.
            if let done = finished(resume.session), done.key == key,
               Crypto.same(resume.proof, DropKeys.resumeProof(done.resumeKey, "resume", h: channel.h)) {
                try? channel.send(.resumed, Resumed(proof: DropKeys.resumeProof(done.resumeKey, "resumed", h: channel.h)))
                // What a sender that comes back is told is the finished drop's own machine's to say.
                var rounds = done.rounds
                if rounds.step(.senderBack) == [.send(.complete)] { try? channel.send(.complete, done.answer) }
                return
            }
            guard let session = lock.withLock({ sessions[resume.session] }) as? ReceiveSession, session.peerKey == key, session.resume(on: channel, proof: resume.proof) else {
                logCounted("resume", "refused \(from): it asked to pick up a drop it could not prove it holds")
                socket.shutdown()
                return
            }
            deadline.cancel()
            socket.setReadTimeout(0)
            socket.setNoDelay()

        case .pair, .verify:
            guard standing.mayPair else {
                // By the name this Mac has for that key, never the one the caller gives itself.
                var known = name
                if case .expired(let mac) = standing { known = mac.name }
                if case .retired(let t) = standing { known = t.name }
                if trust.noteRefused(key) { onRefusedIdentity?(known, from) }
                socket.shutdown()
                return
            }
            guard let frame = try? channel.read(), frame.type == .pairRequest else { socket.shutdown(); return }
            saidWhatItCameFor()
            deadline.cancel()
            request(PairingSession(channel: channel, hello: hello, identity: identity, trust: trust), from: from)

        case .retire:
            // Only a key on record can be retired, only by proving it, and only itself.
            switch standing {
            case .paired, .expired, .renew: break
            default: socket.shutdown(); return
            }
            guard let frame = try? channel.read(), frame.type == .retire else { socket.shutdown(); return }
            DropLog.write("\(name) at \(from) says its identity \(key.tag) is retired", .warn)
            // Written, everything it had here ended, and only then acknowledged.
            trust.retire(key)
            guard (try? trust.commit()) != nil else { socket.shutdown(); return }
            try? channel.send(.retired, Empty())
            Thread.sleep(forTimeInterval: 0.2)
            socket.shutdown()

        case .speed:
            // As for a drop: both sides must hold the pairing, and the person here is asked
            // (the plan's Addendum B). One question, or one test, at a time.
            guard hello.paired, case .paired(let mac) = standing else { socket.shutdown(); return }
            guard let frame = try? channel.read(), frame.type == .speed, let ask = try? decode(SpeedAsk.self, from: frame.body) else { socket.shutdown(); return }
            saidWhatItCameFor()
            let refusal = lock.withLock { () -> String? in
                let now = Date()
                speedAsked = speedAsked.filter { now.timeIntervalSince($0.value) < Tuning.speedPauseSeconds }
                // A pause for each key after its last: a paired Mac cannot put question after
                // question on screen, or run test after test, without a gap.
                if let last = speedAsked[key] {
                    return "\(identity.name) answered a speed test from this Mac a moment ago; try again in \(Int((Tuning.speedPauseSeconds - now.timeIntervalSince(last)).rounded(.up))) s"
                }
                guard !speedTesting else { return "\(identity.name) is in the middle of another speed test" }
                speedTesting = true
                return nil
            }
            if let refusal {
                try? channel.send(.busy, Reason(message: refusal))
                Thread.sleep(forTimeInterval: 0.2)
                socket.shutdown()
                return
            }
            deadline.cancel()
            socket.setReadTimeout(0)
            socket.setNoDelay()
            let test = SpeedResponder(channel: channel, ask: ask, mac: mac, listener: self)
            test.run()
            // Free for the next only now; then every connection it had is closed, the control
            // connection last of all.
            lock.withLock {
                speedTesting = false
                speedAsked[key] = Date()
            }
            test.closeAll()
            socket.shutdown()

        case nil:
            socket.shutdown()
        }
    }

    // MARK: Requests to pair

    /// One request on screen at a time, a few waiting behind it, none for a while after one is
    /// refused, fails or is abandoned.
    private func request(_ pairing: PairingSession, from: String) {
        let channel = { (reason: String) in pairing.cancel(reason) }
        func busy(_ message: String, log: String, pause: Double? = nil) {
            logCounted("pairbusy", "a request to pair from \(pairing.peerName) at \(from) was not shown: \(log)")
            pairing.turnAway(message, pause: pause)
            _ = channel
        }
        if trust.requestsOff { return busy("\(identity.name) is not taking requests to pair; start the pairing from that Mac", log: "requests are off in Settings") }
        // Both asked at the same moment: the request from the lower key goes ahead. This Mac's
        // own request may be so new that it has not yet proved who it is talking to, in which
        // case it cannot be told whether the two are the same pairing: wait a moment for it.
        // Without the wait, on a slow machine, this request was answered "in the middle of
        // another pairing" and both people ended with nothing (seen in CI, 2026-11-23).
        if let mine = trust.gate.active, mine.initiator, mine.peerKey == nil {
            let patience = Date().addingTimeInterval(2)
            while mine.peerKey == nil, !mine.state.isFinal, Date() < patience { Thread.sleep(forTimeInterval: 0.02) }
        }
        if let mine = trust.gate.active, mine.initiator, mine.peerKey == pairing.peerKey, mine.state == .asking || mine.state == .connecting,
           let theirs = pairing.peerKey {
            if trust.publicKey.raw.lexicographicallyPrecedes(theirs.raw) { return busy("Both Macs asked at once; carry on with the request from \(identity.name)", log: "this Mac asked first") }
            mine.cancel("Both Macs asked at once; answer the request on this Mac")
        }
        // One pairing at a time on this Mac, in either role: while its own person is in the
        // middle of one, nobody else's request is put beside it.
        if trust.gate.active != nil { return busy("\(identity.name) is in the middle of another pairing", log: "this Mac is in the middle of a pairing of its own") }
        // The pause is for requests nobody here asked for. One from a key on record (a
        // renewal: nobody else can prove that key), or from a key this Mac's own person has
        // just tried to pair with, is shown regardless; otherwise a stranger who keeps the
        // pause running would keep two people from ever pairing (the review of the code, F9).
        var wanted = pairing.peerKey.map { trust.gate.expects($0) } ?? false
        switch pairing.standing {
        case .paired, .renew: wanted = true
        default: break
        }
        let quiet = trust.gate.quietSecondsLeft
        if quiet > 0, !wanted {
            return busy("\(identity.name) is not showing requests to pair for another \(Int(quiet.rounded(.up))) s. Start the pairing from \(identity.name) instead.",
                        log: "requests are paused after the last one", pause: quiet)
        }
        let turn = lock.withLock { () -> Bool? in
            if showing == nil || showing!.state.isFinal { showing = pairing; return true }
            guard queued < Tuning.pairRequestsWaiting else { return nil }
            queued += 1
            waitingRequests.append(pairing)
            return false
        }
        guard let turn else { return busy("\(identity.name) has too many requests to pair waiting", log: "too many are waiting") }
        if !turn {
            // Wait for the one on screen, no longer than a request may wait.
            let until = Date().addingTimeInterval(Tuning.pairSeconds)
            var mine = false
            while !mine, Date() < until, !pairing.state.isFinal {
                Thread.sleep(forTimeInterval: 0.2)
                if pairing.channelClosed { break }
                mine = lock.withLock {
                    guard showing == nil || showing!.state.isFinal else { return false }
                    showing = pairing
                    return true
                }
            }
            lock.withLock { queued -= 1; waitingRequests.removeAll { $0 === pairing } }
            guard mine, trust.gate.quietSecondsLeft == 0 || wanted, trust.gate.active == nil else {
                lock.withLock { if showing === pairing { showing = nil } }
                return busy("\(identity.name) did not get to this request in time", log: "it waited too long")
            }
        }
        DropLog.write("\(pairing.peerName) at \(from) (\(pairing.peerKey?.tag ?? "?")) asks to pair" + (pairing.clash.map { "; its name is that of \($0.name), which this Mac knows under another key" } ?? ""))
        if let clash = pairing.clash, clash.paired, !clash.expected { trust.noteImpostor(of: clash.key, at: from) }
        pairing.onEnd = { [weak self] well in
            self?.trust.gate.requestEnded(well: well)
            self?.lock.withLock { if self?.showing === pairing { self?.showing = nil } }
        }
        guard let ask = onPairRequest else { return busy("\(identity.name) is not taking requests to pair", log: "nothing is listening for them") }
        ask(pairing)
        pairing.respond()
    }

    // MARK: Sessions

    /// Keeps a finished drop's answer for a few minutes (`Tuning.completedSeconds`), for a
    /// sender whose connection was lost before it heard. With it, the one key of the drop that
    /// is still needed: the proof that whoever asks is that sender. When the time is up both
    /// are gone, whether or not anyone asked.
    ///
    /// Until 2026-11-24 the time was looked at only here, when another drop finished: a sender
    /// that asked an hour later was answered, and on a Mac that received nothing else the key
    /// stayed in memory until the app was quit (an independent review;
    /// `testAFinishedDropIsNotAnsweredForAfterItsTime`, `testAFinishedDropsKeyIsForgottenWhenItsTimeIsUp`).
    /// With them, the drop's conversation as it ended (`rounds`): what a sender that comes
    /// back is told is that machine's to say.
    func remember(completed session: Data, _ answer: Complete, resumeKey: Secret, key: PublicKey, rounds: RoundMachine.Receiver) {
        lock.withLock {
            forgetFinished()
            completed[session] = (answer, resumeKey, key, Self.elapsed(), rounds)
        }
        DispatchQueue.global().asyncAfter(deadline: .now() + Tuning.completedSeconds + 0.5) { [weak self] in self?.lock.withLock { self?.forgetFinished() } }
    }

    /// With the lock held: the finished drops whose time is up are forgotten.
    private func forgetFinished() {
        let now = Self.elapsed()
        completed = completed.filter { now - $0.value.at < Tuning.completedSeconds }
    }

    /// A finished drop's answer, if it is still within its time.
    private func finished(_ session: Data) -> (answer: Complete, resumeKey: Secret, key: PublicKey, at: Double, rounds: RoundMachine.Receiver)? {
        lock.withLock {
            forgetFinished()
            return completed[session]
        }
    }

    func register(_ session: DataSession, id: Data) { drops { sessions[id] = session } }
    func unregister(id: Data) { drops { sessions[id] = nil } }

    /// Trust in `key` was withdrawn. Its sessions have been ended by `Trust`; what is left here
    /// is what it had waiting on a person and what a finished drop of its left behind.
    private func withdraw(_ key: PublicKey) {
        var pairings = drops { () -> [PairingSession] in
            completed = completed.filter { $0.value.key != key }
            sessions = sessions.filter { $0.value.peerKey != key }
            return ([showing].compactMap { $0 } + waitingRequests).filter { $0.peerKey == key }
        }
        // And a pairing this Mac's own person started with it.
        if let mine = trust.gate.active, mine.peerKey == key, !pairings.contains(where: { $0 === mine }) { pairings.append(mine) }
        for p in pairings { p.cancel("That Mac's identity is no longer trusted") }
    }

    /// Room to reassemble a control message of `bytes`, out of what all drops share. Waits when
    /// there is none.
    func reserve(_ bytes: Int) {
        budget.lock()
        while reassembling > 0, reassembling + bytes > Tuning.controlBudget { budget.wait(until: Date().addingTimeInterval(1)) }
        reassembling += bytes
        budget.unlock()
    }

    func unreserve(_ bytes: Int) {
        budget.lock()
        reassembling -= bytes
        budget.broadcast()
        budget.unlock()
    }

    /// One drop per partial folder. A sender that gave up and offered the same drop afresh must
    /// not find an earlier session still holding the folder (waiting for a reconnect, say): the
    /// earlier one is ended first.
    func claim(_ partial: String, for session: ReceiveSession) {
        let earlier = lock.withLock { () -> ReceiveSession? in
            let e = holders[partial]
            holders[partial] = session
            return e === session ? nil : e
        }
        guard let earlier else { return }
        DropLog.write("\(earlier.tag) superseded: the sender offered the same drop again", .warn)
        earlier.fail(DropError("The sender started this drop again"))
        earlier.waitUntilOver()
    }

    func release(_ partial: String, by session: ReceiveSession) {
        lock.withLock { if holders[partial] === session { holders[partial] = nil } }
    }
}
