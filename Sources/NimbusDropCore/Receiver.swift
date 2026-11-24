// Copyright (C) 2026 Niels Joubert
// SPDX-License-Identifier: GPL-3.0-or-later
import Darwin
import Foundation

/// Closes a socket unless told in time that it has earned its keep.
final class Deadline: @unchecked Sendable {
    private let lock = NSLock()
    private var generation = 0
    private weak var socket: Socket?

    init(_ socket: Socket, seconds: Double) {
        self.socket = socket
        arm(seconds)
    }

    /// Starts the clock again, from now.
    func arm(_ seconds: Double) {
        let mine = lock.withLock { () -> Int in self.generation += 1; return self.generation }
        DispatchQueue.global().asyncAfter(deadline: .now() + seconds) { [weak self] in
            guard let self, self.lock.withLock({ self.generation == mine }) else { return }
            socket?.shutdown()
        }
    }

    func cancel() { lock.withLock { self.generation += 1 } }
}

/// Accepts connections from other Macs. Each new drop from a paired Mac is handed to `onOffer`
/// as a `ReceiveSession` that waits for `accept(destination:)` or `decline()`; nothing is written
/// before that. A request to pair is handed to `onPairRequest`.
///
/// Every connection is held to the budget of what it has proved so far (the plan's Admission
/// table): a slot is taken before any work is done for it and kept until its class changes.
/// Completing a handshake proves possession of some key, not a place among the Known Macs, and
/// raises no limit by itself.
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
    /// One speed test at a time on this Mac, whoever asks.
    private var speedTesting = false
    private var holders: [String: ReceiveSession] = [:]
    /// A connection that has proved nothing yet, and where it came from. Each pool is in order
    /// of arrival: when it is full, the first (the one that has waited longest without proving
    /// anything) gives way.
    private struct Unproved { let socket: Socket; let address: String }
    private var strangers: [Unproved] = []
    private var unattached: [Unproved] = []
    private var unpaired = 0
    private var arrivals: [(at: Date, address: String)] = []
    /// Connections from each paired key that have not yet said what they came for.
    private var pairedWaiting: [PublicKey: Int] = [:]
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
    private var completed: [Data: (answer: Complete, resumeKey: Data, key: PublicKey, at: Date)] = [:]
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
                guard admit(socket) else { socket.shutdown(); continue }
                Thread.detachNewThread { [self] in serve(socket) }
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

    /// Whether a connection is taken at all: from the local network (unless Settings says
    /// otherwise), within the rate at which new connections are taken, and with a stranger's
    /// slot free. The slot is held from here.
    private func admit(_ socket: Socket) -> Bool {
        let from = socket.peerAddress
        let local = allows.map { $0(from) } ?? (!localOnly || LocalNetwork.isLocal(from, among: LocalNetwork.current()))
        guard local else {
            // Said once per address: a scanner knocking every second should not fill the log.
            if lock.withLock({ turnedAway.count < 1000 && turnedAway.insert(from).inserted }) {
                DropLog.write("turned away a connection from \(from): not on the local network (Settings › Receiving)", .warn)
            }
            return false
        }
        var displaced: Socket?
        let taken = lock.withLock { () -> Bool in
            let now = Date()
            arrivals.removeAll { now.timeIntervalSince($0.at) > 1 }
            // The rate cannot be met by anyone giving way: over it, the newcomer is closed.
            guard arrivals.count < Tuning.arrivalsPerSecond,
                  arrivals.filter({ $0.address == from }).count < Tuning.arrivalsPerAddress else { return false }
            arrivals.append((now, from))
            displaced = place(socket, from: from, in: &strangers, limit: Tuning.strangers, perAddress: Tuning.strangersPerAddress)
            return true
        }
        if !taken { logCounted("full", "turned away a connection from \(from): too many in a second") }
        if let displaced {
            logCounted("displaced", "closed a connection that had proved nothing, to make room for one from \(from)", .debug)
            displaced.shutdown()
        }
        return taken
    }

    /// With the lock held. Puts `socket` in a pool of connections that have proved nothing
    /// yet; returns the one that gives way for it, to be closed. At its address's own limit
    /// that is the oldest from the same address, so one address can only ever push out its own;
    /// with the whole pool full it is the oldest of all. An honest Mac proves itself within
    /// milliseconds of arriving and what an attacker's connection does is wait, so the longest
    /// wait is what loses the place. Refusing the newcomer instead let 64 silent connections
    /// from one host keep every paired Mac out (the review of the code, F1).
    private func place(_ socket: Socket, from: String, in pool: inout [Unproved], limit: Int, perAddress: Int) -> Socket? {
        var out: Unproved?
        if let own = pool.indices.filter({ pool[$0].address == from }).first, pool.filter({ $0.address == from }).count >= perAddress {
            out = pool.remove(at: own)
        } else if pool.count >= limit, !pool.isEmpty {
            out = pool.removeFirst()
        }
        pool.append(Unproved(socket: socket, address: from))
        return out?.socket
    }

    private func serve(_ socket: Socket) {
        let from = socket.peerAddress
        var stranger = true
        func noLongerAStranger() { if stranger { stranger = false; lock.withLock { strangers.removeAll { $0.socket === socket } } } }
        defer { noLongerAStranger() }
        // Ten seconds in all (not ten per byte) to get as far as proving a key.
        let deadline = Deadline(socket, seconds: Tuning.strangerSeconds)
        defer { deadline.cancel() }
        socket.setReadTimeout(Int(Tuning.strangerSeconds.rounded(.up)))
        guard let kind = try? Opening.readKind(socket) else { socket.shutdown(); return }

        if kind == Opening.data {
            // A data connection: nothing until it proves it belongs to a drop in progress.
            var displaced: Socket?
            let room = lock.withLock { () -> Bool in
                guard !sessions.isEmpty else { return false }
                displaced = place(socket, from: from, in: &unattached, limit: Tuning.unattachedPerDrop * sessions.count, perAddress: Tuning.unattachedPerAddress)
                return true
            }
            noLongerAStranger()
            displaced?.shutdown()
            guard room else { socket.shutdown(); return }
            var released = false
            func release() { if !released { released = true; lock.withLock { unattached.removeAll { $0.socket === socket } } } }
            defer { release() }
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
            release()
            socket.setReadTimeout(0)
            session.runStream(socket, conn: conn)
            return
        }

        guard kind == Opening.control, let channel = try? Channel.respond(socket, keys: trust.keyPair) else {
            // Includes every probe: a connection that learns who is here and hangs up.
            socket.shutdown()
            return
        }
        // A key has been proved. What it is to this Mac decides everything from here.
        let key = channel.remote
        var standing = trust.standing(of: key)
        noLongerAStranger()
        switch standing {
        case .mine: socket.shutdown(); return
        case .retired(let t):
            logCounted("retired", "refused \(from): it proved an identity (\(key.tag)) that \(t.name) gave up or that was replaced", .error)
            if trust.noteRefused(key) { onRefusedIdentity?(t.name, from) }
            socket.shutdown()
            return
        default: break
        }
        var holdsUnpaired = false
        if !standing.isPaired {
            guard lock.withLock({ () -> Bool in
                guard unpaired < Tuning.unpaired else { return false }
                unpaired += 1
                return true
            }) else {
                logCounted("unpaired", "turned away \(from) (\(key.tag)): too many connections from Macs that are not paired")
                socket.shutdown()
                return
            }
            holdsUnpaired = true
            // Sixteen kilobytes in all, which the one-fragment limit already holds it under per message.
            channel.limit = 16 << 10
        }
        defer { if holdsUnpaired { lock.withLock { unpaired -= 1 } } }
        // A paired key is counted too until it has said what it came for: a paired Mac that
        // means harm could otherwise hold any number of connections here for ten seconds each.
        var waitsPaired = false
        func saidWhatItCameFor() { if waitsPaired { waitsPaired = false; lock.withLock { pairedWaiting[key] = (pairedWaiting[key] ?? 1) - 1; if pairedWaiting[key] == 0 { pairedWaiting[key] = nil } } } }
        if standing.isPaired {
            guard lock.withLock({ () -> Bool in
                guard pairedWaiting[key, default: 0] < Tuning.pairedWaiting else { return false }
                pairedWaiting[key, default: 0] += 1
                return true
            }) else {
                logCounted("pairedwaiting", "turned away \(from) (\(key.tag)): too many connections from that Mac that have not said what they want")
                socket.shutdown()
                return
            }
            waitsPaired = true
        }
        defer { saidWhatItCameFor() }

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
            if let done = lock.withLock({ completed[resume.session] }), done.key == key,
               Crypto.same(resume.proof, DropKeys.resumeProof(done.resumeKey, "resume", h: channel.h)) {
                try? channel.send(.resumed, Resumed(proof: DropKeys.resumeProof(done.resumeKey, "resumed", h: channel.h)))
                try? channel.send(.complete, done.answer)
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
            guard lock.withLock({ () -> Bool in
                guard !speedTesting else { return false }
                speedTesting = true
                return true
            }) else {
                try? channel.send(.busy, Reason(message: "\(identity.name) is in the middle of another speed test"))
                Thread.sleep(forTimeInterval: 0.2)
                socket.shutdown()
                return
            }
            defer { lock.withLock { speedTesting = false } }
            deadline.cancel()
            socket.setReadTimeout(0)
            socket.setNoDelay()
            let test = SpeedResponder(channel: channel, ask: ask, mac: mac, listener: self)
            // Free for the next one from the moment this one has its answer, not a moment after.
            test.served = { [weak self] in self?.lock.withLock { self?.speedTesting = false } }
            test.run()
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
        // Both asked at the same moment: the request from the lower key goes ahead.
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

    /// Keeps a finished drop's answer for a few minutes, for a sender whose connection was lost
    /// before it heard. With it, the one key of the drop that is still needed: the proof that
    /// whoever asks is that sender.
    func remember(completed session: Data, _ answer: Complete, resumeKey: Data, key: PublicKey) {
        lock.withLock {
            let now = Date()
            completed = completed.filter { now.timeIntervalSince($0.value.at) < 300 }
            completed[session] = (answer, resumeKey, key, now)
        }
    }

    func register(_ session: DataSession, id: Data) { lock.withLock { sessions[id] = session } }
    func unregister(id: Data) { lock.withLock { sessions[id] = nil } }

    /// Trust in `key` was withdrawn. Its sessions have been ended by `Trust`; what is left here
    /// is what it had waiting on a person and what a finished drop of its left behind.
    private func withdraw(_ key: PublicKey) {
        var pairings = lock.withLock { () -> [PairingSession] in
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

    init(channel: Channel, offer: Offer, hello: SecureHello, mac: KnownMac, listener: DropListener) {
        _control = channel
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
        farewell = { [weak self] message in try? self?.control.send(.error, Reason(message: message)) }
        // From here on, withdrawing trust in the sender ends this drop, asked about or not.
        listener.trust.track(self, key: channel.remote)
    }

    /// Trust in the sender was withdrawn. The keys go first, so that nothing can attach or
    /// resume; what was being written stays in its partial folder and is not put in place.
    override func withdrawn(_ error: DropError) {
        lock.withLock { keys = nil }
        super.withdrawn(error)
        streams.lock()
        incoming?.socket.shutdown()
        streams.broadcast()
        streams.unlock()
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
            if !isOver { try? control.send(.error, Reason(message: (error as? DropError)?.message ?? error.localizedDescription)) }
            fail(error)
        }
        streams.lock()
        conducted = true
        streams.broadcast()
        streams.unlock()
    }

    /// A long silence is treated as a lost connection (see `SendSession.silence`): the drop is
    /// held open for the sender to come back to, rather than ended.
    override func silence() {
        guard ledger != nil, state == .transferring else { return super.silence() }
        log("no sign of life from \(peerName); treating the connection as lost", .warn)
        control.socket.shutdown()
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
    /// everything written so far kept, until the sender reconnects; then answers with what is
    /// here. Throws when nobody comes.
    private func awaitSender(after lost: Error) throws {
        while true {
            if isOver { throw lost }
            log("lost the control connection: \((lost as? DropError)?.message ?? "\(lost)"); holding the drop for \(Int(Tuning.reconnectSeconds)) s", .warn)
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
            if isOver { throw lost }
            guard let fresh else {
                throw DropError("Lost the connection to \(peerName) and it did not come back; send the drop again to continue it")
            }
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
            do {
                try control.send(.plan, ledger.plan())
                setState(.transferring)
                return
            } catch { continue }   // lost again already: wait again
        }
    }

    private func conduct() throws {
        guard let listener, let offer = listener.onOffer else {
            try control.send(.decline, Reason(message: "Not receiving"))
            finish(.declined("Not receiving"))
            return
        }
        offer(self)

        // Wait for the person here, while watching for the sender giving up.
        var chosen: Decision?
        while chosen == nil {
            if isOver { onWithdrawn?(); return }
            if control.socket.waitReadable(milliseconds: 200) {
                let message = (try? control.read()).flatMap { $0.type == .error ? (try? decode(Reason.self, from: $0.body).message).map { Sanitize.label($0, limit: 300) } : nil }
                finish(.failed(message ?? "The sender went away"))
                onWithdrawn?()
                return
            }
            chosen = lock.withLock { decision }
        }
        guard case .accept(let destination) = chosen else {
            if case .decline(let reason) = chosen { try control.send(.decline, Reason(message: reason)) }
            finish(.declined("Declined"))
            return
        }

        // A yes to an offer whose pairing has since ended starts nothing: the question was
        // asked under a key that no longer holds (it ran out with the panel still up).
        guard listener.trust.standing(of: control.remote).isPaired else {
            try? control.send(.decline, Reason(message: "The pairing with \(listener.identity.name) has run out; pair again and send it again"))
            throw DropError("The pairing with \(peerName) ran out before the drop was accepted")
        }
        log("accepted, saving to \(destination.path)")
        // Accepting authorises metadata in proportion to what was accepted, out of a budget all
        // drops share: a manifest of 64 KB plus 2 KB for each file the offer announced.
        let room = min(maxFrameBytes, (64 << 10) + 2048 * max(0, min(offered.fileCount, 1 << 22)))
        listener.reserve(room)
        reserved = room
        defer { listener.unreserve(room) }
        control.limit = room
        try control.send(.accept, Empty())
        let frame = try control.read()
        guard frame.type == .manifest else { throw DropError("Unexpected message from the sender") }
        manifest = try decode(Manifest.self, from: frame.body)
        try manifest.validate()
        // The person said yes to what the offer described. A manifest that is something else
        // (more files, more bytes, other names) is not what was agreed to.
        guard manifest.fileCount == offered.fileCount, manifest.totalBytes == offered.totalBytes,
              manifest.topLevelNames == offered.items else {
            throw DropError("The drop is not what was offered; it was refused")
        }
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
        defer { listener.release(partial.path, by: self) }
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
        defer { listener.unregister(id: keys.sessionID) }
        try control.send(.plan, ledger.plan())
        setState(.transferring)
        startWatchdog()

        // Rounds. The sender writes what it was asked for and says done; if connections died or
        // chunks arrived damaged along the way, something is missing, and the answer is a new
        // plan rather than a failure. It ends when everything is here, or when round after
        // round delivers nothing.
        var idle = 0
        while true {
            let next: (type: FrameType, body: Data)
            do { next = try control.read() } catch {
                // The conversation's connection is gone. The drop was accepted and is partly
                // here: wait for the sender to come back rather than ending it.
                try awaitSender(after: error)
                continue
            }
            touch()
            if next.type == .error { throw DropError(Sanitize.label(try decode(Reason.self, from: next.body).message, limit: 300)) }
            guard next.type == .done else { throw DropError("Unexpected message from \(peerName)") }
            let roundStart = lock.withLock { roundStartBytes }
            let done = try decode(Done.self, from: next.body)
            if let resent = done.resent { note { $0.retransmittedChunks = resent } }
            settle(opened: done.streams)
            let soFar = stats
            log("the sender says it is done (\(done.streams) data connections opened in all, \(done.resent ?? 0) chunks retransmitted); here: \(soFar.chunks) chunks received, \(soFar.damagedChunks) damaged, \(ledger.doneBytes) of \(manifest.totalBytes) bytes", .debug)
            if isOver { return }
            if ledger.isComplete { break }
            idle = ledger.doneBytes > roundStart ? 0 : idle + 1
            guard idle < Tuning.idleRounds else { throw DropError("The drop arrived incomplete; send it again to continue it") }
            note { $0.rounds += 1 }
            let have = ledger.doneBytes
            log("the sender is done but \(manifest.totalBytes - have) bytes are missing; asking for them (round \(stats.rounds + 1))", .warn)
            lock.withLock { roundStartBytes = have }
            update { $0.doneBytes = have }
            do { try control.send(.plan, ledger.plan()) } catch {
                try awaitSender(after: error)
            }
        }

        // Trust withdrawn while the last chunks arrived: nothing is put in place.
        if isOver { return }
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
        let complete = Complete(saved: saved.map(\.lastPathComponent))
        try? control.send(.complete, complete)
        // A sender that lost the connection meanwhile will come back asking; it is told then.
        // The drop's keys are done with, but for the one a late "did it arrive?" is proved with.
        listener.remember(completed: keys.sessionID, complete, resumeKey: keys.resumeKey, key: control.remote)
        lock.withLock { self.keys = nil }
        if let fresh = streams.withLock({ incoming }) { try? fresh.send(.complete, complete) }
        finish(.completed)
    }

    /// After the sender says done: wait for the data connections it opened to finish here too
    /// (their last chunks may still be on the wire or on their way to disk), then close whatever
    /// is left so that nothing writes into the drop once it is judged.
    private func settle(opened: Int) {
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
        let left = active
        streams.unlock()
        for s in left { s.shutdown() }
        streams.lock()
        let deadline = Date().addingTimeInterval(10)
        while !active.isEmpty, streams.wait(until: deadline) {}
        streams.unlock()
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
            if !isOver { try? control.send(.error, Reason(message: (error as? DropError)?.message ?? error.localizedDescription)) }
            fail(error)
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
        for e in manifest.entries.reversed() where e.kind != .symlink {
            // The owner keeps access to what they were just sent, whatever the mode was; and
            // nothing arrives set-uid (the mask drops every bit above the permissions).
            tree.finish(e.path, mtime: e.mtime, mode: mode_t(e.mode & 0o777) | (e.kind == .directory ? 0o700 : 0o600), quarantine: quarantine)
        }
        tree.release()
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
