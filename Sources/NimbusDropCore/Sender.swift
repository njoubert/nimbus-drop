// Copyright (C) 2026 Niels Joubert
// SPDX-License-Identifier: GPL-3.0-or-later
import Darwin
import Foundation

/// Sends files and folders to one receiver.
///
/// One control connection carries the conversation (offer, the other person's answer, the
/// manifest, what the receiver already has); then `streams` data connections carry the chunks.
/// Every stream takes the next unsent chunk from one shared list, so a single large file is
/// spread across all of them and a folder of small files is too.
///
/// A data connection that dies, stalls or delivers a damaged chunk does not end the drop. When
/// the sender has written everything it says so; the receiver answers with what is still
/// missing, and the sender sends that on fresh connections. That repeats until the receiver has
/// it all.
///
/// Everything is encrypted and both ends are proved (see `Channel`): the control connection is a
/// Noise channel between the two Macs' static keys, and each data connection has a key of its
/// own derived from that handshake. Nothing about the drop is said until the receiver has proved
/// the key this sender expects, and nothing is sent to a Mac that is not paired.
///
/// If the control connection itself is lost, the sender spends up to a minute getting it back
/// (`reconnect`), asking where the receiver is now before each try, and the receiver holds the
/// accepted drop open meanwhile. Only that minute running out, a long silence from a peer that
/// is there but frozen, or somebody's decision ends a drop early.
public final class SendSession: Transfer, @unchecked Sendable {
    private let urls: [URL]
    private let prescanned: ScannedDrop?
    /// Where the receiver is. It can move (a Mac that changes networks comes back with another
    /// address), so a reconnect asks `relocate` and may change these.
    private var host: String
    private var port: UInt16
    /// Looks the receiver up afresh: its address and port as they are now, or nil when it cannot
    /// be found. Called on an engine thread, between reconnect attempts.
    public var relocate: (@Sendable () -> (host: String, port: UInt16)?)?
    /// The connection the conversation is on; replaced by a reconnect. Read on other threads
    /// than the one that replaces it (a farewell, the silence watch), so under a lock of its own.
    private var control: Channel! {
        get { controlLock.withLock { _control } }
        set { controlLock.withLock { _control = newValue } }
    }
    private var _control: Channel?
    private let controlLock = NSLock()
    /// This Mac's key as it was when the drop began. A drop finishes on the keys it started
    /// with: a reconnect proves this one, also after the key has been replaced on schedule.
    private var mine: KeyPair?
    /// The drop's keys, from the first handshake; nil until then and again once trust is withdrawn.
    private var keys: DropKeys?
    /// The receiver has said what it holds: the drop is under way, and a lost connection is
    /// worth getting back.
    private var planned = false
    private var reconnected = false
    private let identity: Identity
    private let trust: Trust
    /// The key the receiver must prove. Nil: whoever answers, provided it is paired.
    private var expect: PublicKey?
    /// The number the next data connection takes. One counter for the whole drop: a number,
    /// and so a key, is never used twice.
    private var nextConn: UInt64 = 1
    private let streams: Int
    private let chunkSize: Int

    private struct Job { var file: Int32; var chunk: Int32 }
    private var jobs: [Job] = []
    private var nextJob = 0
    private let jobLock = NSLock()
    private var scanned: ScannedDrop!

    /// Frames from the receiver, read by one thread for the whole drop so that its reason for
    /// stopping (declined, disk full, cancelled) is heard even while the streams are busy.
    private let inbox = NSCondition()
    private var frames: [(type: FrameType, body: Data)] = []
    private typealias Frame = (type: FrameType, body: Data)
    private var inboxError: Error?
    private var generation = 0

    /// One per live data connection, for the stall watch.
    private final class Stream {
        let socket: Socket
        var lastProgress = Date()
        /// Chunks written in full on this connection.
        var chunks = 0
        /// What the drop knows this connection by (`Transfer.dataConnections`).
        var info = 0
        /// Its number in the drop, which picks its key.
        let conn: UInt64
        init(_ socket: Socket, conn: UInt64) { self.socket = socket; self.conn = conn }
    }
    private var live: [Stream] = []
    private var opened = 0

    /// Tests only: fail the drop once this many chunks have been sent, as a dropped link would.
    var failAfterChunks: Int?
    private var chunksSent = 0

    /// `prescanned`: a drop already walked (and perhaps narrowed to some kinds of file), sent as
    /// it is instead of walking `urls` again.
    public init(urls: [URL], host: String, port: UInt16, peerName: String, identity: Identity, trust: Trust, expect: PublicKey? = nil,
                streams: Int = 8, chunkSize: Int = Scanner.defaultChunkSize, prescanned: ScannedDrop? = nil) {
        self.trust = trust
        self.expect = expect
        self.prescanned = prescanned
        self.urls = urls
        self.host = host
        self.port = port
        self.identity = identity
        self.streams = max(1, min(32, streams))
        self.chunkSize = chunkSize
        super.init(direction: .send, state: .scanning, peerName: peerName, peerAddress: host)
        setItems(prescanned?.manifest.topLevelNames ?? urls.map(\.lastPathComponent))
    }

    public func start() {
        Thread.detachNewThread { [self] in
            do { try run() } catch { fail(error) }
        }
    }

    private func run() throws {
        scanned = try prescanned ?? Scanner.scan(urls, chunkSize: chunkSize) { [self] in isOver }
        guard !scanned.manifest.entries.isEmpty else { throw DropError("Nothing to send") }
        let manifest = scanned.manifest
        setItems(manifest.topLevelNames)
        update { $0.totalBytes = manifest.totalBytes; $0.totalFiles = manifest.fileCount }
        if isOver { return }

        log("“\(title)” to \(peerName) at \(host):\(port): \(manifest.fileCount) files, \(manifest.totalBytes) bytes, \(streams) connections")
        setState(.connecting)
        control = try open(.drop)
        farewell = { [weak self] message in try? self?.control.send(.error, Reason(message: message)) }
        keys = DropKeys(master: control.master)
        try control.send(.offer, Offer(items: manifest.topLevelNames, fileCount: manifest.fileCount, totalBytes: manifest.totalBytes))
        setState(.waitingForAccept)
        listen(to: control)
        let answer = try nextFrame()
        switch answer.type {
        case .accept: break
        case .decline: finish(.declined(Sanitize.label(try decode(Reason.self, from: answer.body).message, limit: 300))); return
        default: throw DropError("Unexpected answer from \(peerName)")
        }

        // From here the receiver may send plans, whose size follows from the drop's own.
        control.limit = min(maxFrameBytes, (64 << 10) + 64 * manifest.entries.count + 16 * manifest.entries.indices.reduce(0) { $0 + manifest.chunkCount($1) })
        try control.send(.manifest, manifest)
        var reply = try nextFrame()
        guard reply.type == .plan else { throw DropError("Unexpected answer from \(peerName)") }
        startWatchdog()
        Thread.detachNewThread { [self] in watchStreams() }

        var first = true
        var best: Int64 = -1, fruitless = 0
        while true {
            do {
                // A reconnect can find the receiver already finished: its "complete" was lost
                // with the old connection, and it says it again.
                if reply.type == .complete {
                    update { $0.doneBytes = $0.totalBytes; $0.doneFiles = $0.totalFiles }
                    finish(.completed)
                    return
                }
                let plan = try decode(Plan.self, from: reply.body)
                planned = true
                buildJobs(manifest, plan, first: first)
                first = false
                // Reconnecting again and again to a receiver that takes nothing in is not
                // progress: three in a row with no new bytes there, and it is given up.
                let have = progress.doneBytes
                if have > best { best = have; fruitless = 0 } else if reconnected { fruitless += 1 }
                reconnected = false
                guard fruitless < 3 else { throw DropError("\(peerName) stopped responding; send the drop again to continue it") }
                note { $0.rounds += 1 }
                log("round \(stats.rounds): the receiver has \(have) of \(manifest.totalBytes) bytes; \(jobs.count) chunks to send")
                setState(.transferring)
                if !jobs.isEmpty {
                    let sockets = try openStreams()
                    log("opened \(sockets.count) data connections to \(lock.withLock { "\(host):\(port)" })", .debug)
                    let before = stats
                    defer {
                        let now = stats
                        log("round \(now.rounds) over: \(now.chunks - before.chunks) chunks sent (\(now.chunks) in all, \(now.retransmittedChunks) of them retransmissions), \(now.connectionFailures - before.connectionFailures) connections dropped, \(progress.doneBytes) of \(manifest.totalBytes) bytes written", .debug)
                    }
                    let group = DispatchGroup()
                    for s in sockets {
                        group.enter()
                        Thread.detachNewThread { [self] in
                            carry(s.socket, conn: s.conn)
                            group.leave()
                        }
                    }
                    group.wait()
                }
                if isOver { return }
                setState(.finishing)
                try control.send(.done, Done(streams: lock.withLock { opened }, resent: stats.retransmittedChunks))
                reply = try nextFrame()
                switch reply.type {
                case .complete:
                    update { $0.doneBytes = $0.totalBytes; $0.doneFiles = $0.totalFiles }
                    summarize()
                    finish(.completed)
                    return
                case .plan: continue
                default: throw DropError("Unexpected answer from \(peerName)")
                }
            } catch let lost as DropError where lost.connection {
                // The conversation's own connection is gone (the other Mac changed networks,
                // slept, lost Wi-Fi). The drop is still wanted on both sides: get it back.
                if isOver { return }
                log("lost the control connection: \(lost.message)", .warn)
                reply = try reconnect(after: lost)
                reconnected = true
            }
        }
    }

    /// The drop in one line, for the log: how much, how fast, and what it took.
    private func summarize() {
        let p = progress, s = stats
        let seconds = max(0.001, Date().timeIntervalSince(transferStartedAt ?? startedAt))
        let moved = p.totalBytes - p.resumedBytes
        log("summary: \(Format.files(p.totalFiles)), \(Format.bytes(moved)) sent in \(String(format: "%.1f", seconds)) s = \(Format.bitRate(Double(moved) / seconds))"
            + (p.resumedBytes > 0 ? " (\(Format.bytes(p.resumedBytes)) were already there)" : "")
            + "; \(s.chunks) chunks, \(s.retransmittedChunks) retransmitted; \(s.rounds) rounds; \(s.connectionFailures) connections dropped; \(s.reconnects) reconnects in \(s.reconnectAttempts) attempts")
    }

    /// Tries for `Tuning.reconnectSeconds` to reach the receiver again and pick the drop up
    /// where it stands, looking the receiver's address up afresh before each attempt. Returns
    /// the receiver's new plan. Throws when the minute runs out.
    private func reconnect(after lost: DropError) throws -> (type: FrameType, body: Data) {
        guard planned, let keys, let peer = peerKey else { throw lost }
        setState(.reconnecting)
        log("trying to reach \(peerName) again for up to \(Int(Tuning.reconnectSeconds)) s")
        for s in lock.withLock({ live }) { s.socket.shutdown() }
        let deadline = Date().addingTimeInterval(Tuning.reconnectSeconds)
        var attempt = 0
        while !isOver, Date() < deadline {
            if let found = relocate?() {
                if lock.withLock({ found.host != host || found.port != port }) { log("\(peerName) is now at \(found.host):\(found.port)") }
                lock.withLock { host = found.host; port = found.port }
                setPeerAddress(found.host)
            }
            let (h, p) = lock.withLock { (host, port) }
            attempt += 1
            note { $0.reconnectAttempts += 1 }
            // A new connection and a new handshake, which must prove the same Mac as before;
            // then proof, under a key only the two of them hold, that this is the same drop.
            let fresh: Channel?
            do {
                let socket = try Socket.connect(host: h, port: p, timeout: min(Tuning.connectTimeout, 5))
                socket.setNoDelay()
                socket.setReadTimeout(Int(max(2, Tuning.connectTimeout).rounded(.up)))
                track(socket)
                do {
                    let channel = try Channel.initiate(socket, keys: lock.withLock { mine } ?? trust.keyPair, expect: peer, expectName: peerName)
                    try channel.send(.hello, hello(.resume, to: peer))
                    let theirs = try channel.read()
                    guard theirs.type == .hello else { throw DropError.damagedMessage }
                    try channel.send(.resume, Resume(session: keys.sessionID, proof: DropKeys.resumeProof(keys.resumeKey, "resume", h: channel.h)))
                    let answer = try channel.read()
                    guard answer.type == .resumed,
                          Crypto.same(try decode(Resumed.self, from: answer.body).proof, DropKeys.resumeProof(keys.resumeKey, "resumed", h: channel.h)) else {
                        throw DropError("no answer to resume", connection: true)
                    }
                    socket.setReadTimeout(0)
                    channel.limit = control.limit
                    fresh = channel
                } catch {
                    untrack(socket)
                    socket.shutdown()
                    throw error
                }
            } catch {
                fresh = nil
                log("reconnect attempt \(attempt) to \(h):\(p): \((error as? DropError)?.message ?? "\(error)")", .warn)
            }
            if let fresh {
                replaceControl(control.socket, with: fresh.socket)
                control = fresh
                inbox.lock()
                frames = []
                inboxError = nil
                generation += 1
                inbox.unlock()
                listen(to: fresh)
                if let answer = try? nextFrame(within: max(2, Tuning.connectTimeout)), answer.type == .plan || answer.type == .complete {
                    note { $0.reconnects += 1 }
                    touch()
                    log("reconnected on attempt \(attempt); the receiver answered \(answer.type)")
                    return answer
                }
                log("reconnect attempt \(attempt) to \(h):\(p): proved, but no plan followed", .warn)
            }
            if isOver { break }
            Thread.sleep(forTimeInterval: 1)
        }
        if isOver { throw lost }
        log("gave up reconnecting after \(attempt) attempts in \(Int(Tuning.reconnectSeconds)) s", .error)
        throw DropError("Lost the connection to \(peerName) and could not get it back; send the drop again to continue it")
    }

    /// A drop that ends here for a reason of its own (a source file changed, the peer went
    /// silent) says so first, so the receiver stops at once instead of waiting out the minute it
    /// allows for a lost connection.
    override func fail(_ error: Error) {
        if !isOver, let control = control, let reason = error as? DropError, !reason.connection {
            try? control.send(.error, Reason(message: reason.message))
        }
        super.fail(error)
    }

    /// A long silence is treated as a lost connection: closing the control connection sends the
    /// drop into `reconnect`, which succeeds if the link has come back and gives up after its
    /// minute if the other Mac really is frozen.
    override func silence() {
        guard let control = control, planned, state != .reconnecting else { return super.silence() }
        log("no sign of life from \(peerName); treating the connection as lost", .warn)
        control.socket.shutdown()
    }

    /// Trust in the receiver's key was withdrawn: the drop ends and its keys go, so that nothing
    /// can be attached, resumed or sent under them afterwards.
    ///
    /// Nothing is said to the other Mac first. A farewell is a write on the control connection,
    /// and a Mac that has stopped reading it (frozen, asleep, or hostile) would hold whoever
    /// withdrew the trust for as long as it liked: the person who clicked Forget, or the listener
    /// thread acting on its retire notice. The connections close, and that is how it learns.
    override func withdrawn(_ error: DropError) {
        lock.withLock { keys = nil; planned = false; mine = nil }
        var quiet = error
        quiet.connection = true
        super.withdrawn(quiet)
    }

    // MARK: The handshake

    private func hello(_ purpose: Purpose, to key: PublicKey) -> SecureHello {
        SecureHello(minor: protocolMinor, app: identity.appVersion, name: identity.name, remaining: trust.remaining,
                    paired: trust.standing(of: key).isPaired, purpose: purpose)
    }

    /// Connects, proves both ends, and exchanges hellos. Throws before anything about this Mac
    /// or the drop is said if the Mac that answers is not the one expected, and before any offer
    /// if either side does not hold a pairing with the other.
    private func open(_ purpose: Purpose) throws -> Channel {
        let socket = try Socket.connect(host: host, port: port)
        socket.setNoDelay()
        socket.setReadTimeout(Int(Tuning.connectTimeout.rounded(.up)))
        track(socket)
        let trust = trust
        let name = peerName
        let own = trust.keyPair
        lock.withLock { mine = own }
        let channel = try Channel.initiate(socket, keys: own, expect: expect, expectName: name) { theirs in
            switch trust.standing(of: theirs) {
            case .paired: break
            case .mine: throw DropError("That is this Mac")
            case .retired, .expired:
                _ = trust.noteRefused(theirs)
                throw DropError.notPaired("\(name)'s identity is no longer good; pair with it again")
            case .renew, .unknown: throw DropError.notPaired("This Mac is not paired with \(name)")
            }
        }
        setPeerKey(channel.remote)
        try channel.send(.hello, hello(purpose, to: channel.remote))
        let reply = try channel.read()
        guard reply.type == .hello else { throw DropError("Unexpected answer from \(peerName)") }
        let theirs = try decode(SecureHello.self, from: reply.body)
        guard theirs.paired else {
            trust.notePairingGone(channel.remote)
            throw DropError.notPaired("\(peerName) no longer has this Mac paired; pair again")
        }
        socket.setReadTimeout(0)
        trust.seen(channel.remote, name: theirs.name, major: protocolVersion)
        trust.track(self, key: channel.remote)
        expect = channel.remote
        log("proved \(peerName) (\(channel.remote.tag)), Nimbus Drop \(Sanitize.label(theirs.app, limit: 24)), protocol \(protocolVersion).\(theirs.minor)", .debug)
        return channel
    }

    // MARK: The control connection

    /// Reads one control connection until it ends. After a reconnect the old connection's
    /// reader is still winding down; `generation` keeps its last words out of the new one's inbox.
    private func listen(to channel: Channel) {
        let mine = inbox.withLock { generation }
        Thread.detachNewThread { [self] in
            while true {
                do {
                    let frame = try channel.read()
                    touch()
                    if frame.type == .error {
                        // The receiver's reason, said before it closes everything.
                        let reason = DropError(Sanitize.label(try decode(Reason.self, from: frame.body).message, limit: 300))
                        guard inbox.withLock({ generation == mine }) else { return }
                        post(error: reason, generation: mine)
                        fail(reason)
                        return
                    }
                    inbox.lock()
                    if generation == mine { frames.append(frame) }
                    inbox.broadcast()
                    inbox.unlock()
                    if frame.type == .complete || frame.type == .decline { return }
                } catch {
                    // Not the end of the drop: the main thread hears of it and reconnects. The
                    // data connections go with it, so that nothing waits on a dead link.
                    guard inbox.withLock({ generation == mine }) else { return }
                    post(error: error, generation: mine)
                    for s in lock.withLock({ live }) { s.socket.shutdown() }
                    return
                }
            }
        }
    }

    private func post(error: Error, generation mine: Int) {
        inbox.lock()
        if generation == mine, inboxError == nil { inboxError = error }
        inbox.broadcast()
        inbox.unlock()
    }

    private func nextFrame(within seconds: Double? = nil) throws -> (type: FrameType, body: Data) {
        let deadline = seconds.map { Date().addingTimeInterval($0) }
        inbox.lock()
        defer { inbox.unlock() }
        while frames.isEmpty {
            if let inboxError { throw inboxError }
            if isOver { throw DropError("Cancelled") }
            if let deadline, Date() > deadline { throw DropError("No answer from \(peerName)", connection: true) }
            inbox.wait(until: Date().addingTimeInterval(0.2))
        }
        return frames.removeFirst()
    }

    // MARK: The data connections

    /// Opens up to `streams` connections. Some failing is fine; none opening is retried for a
    /// while (the link may be coming back) as long as the control connection is still up.
    private func openStreams() throws -> [(socket: Socket, conn: UInt64)] {
        let wanted = min(streams, jobs.count)
        let started = Date()
        var last: Error = DropError("Cannot connect to \(peerName)")
        while !isOver {
            // No use opening data connections for a conversation that has lost its own.
            if let dead = inbox.withLock({ inboxError }) { throw dead }
            var sockets: [(socket: Socket, conn: UInt64)] = []
            for _ in 0..<wanted {
                do { sockets.append(try attach()) } catch { last = error }
            }
            if !sockets.isEmpty { return sockets }
            guard Date().timeIntervalSince(started) < Tuning.connectRetrySeconds else { break }
            Thread.sleep(forTimeInterval: 0.5)
        }
        throw last
    }

    /// Opens one data connection and proves it belongs to this drop: the receiver sends sixteen
    /// fresh bytes, and the answer is the drop's session id, this connection's number and an
    /// HMAC over all three under a key only the two Macs hold.
    private func attach() throws -> (socket: Socket, conn: UInt64) {
        guard let keys = lock.withLock({ keys }) else { throw DropError("The drop is over") }
        let (host, port) = lock.withLock { (self.host, self.port) }
        let s = try Socket.connect(host: host, port: port)
        track(s)
        do {
            s.setReadTimeout(Int(Tuning.attachSeconds.rounded(.up)))
            try Opening.data.withUnsafeBytes { try s.writeAll($0.baseAddress!, Opening.data.count) }
            var challenge = Data(count: 16)
            try challenge.withUnsafeMutableBytes { try s.readExactly($0.baseAddress!, 16) }
            let conn = lock.withLock { () -> UInt64 in defer { nextConn += 1 }; return nextConn }
            let message = keys.sessionID + Crypto.be64(conn) + keys.attachTag(conn: conn, challenge: challenge)
            try message.withUnsafeBytes { try s.writeAll($0.baseAddress!, message.count) }
            s.setReadTimeout(0)
            lock.withLock { opened += 1 }
            return (s, conn)
        } catch {
            untrack(s)
            s.shutdown()
            throw error
        }
    }

    /// One of the round's data connections, and its replacements. A connection that fails is
    /// this round's loss, not the drop's: what it did not deliver is in the receiver's next
    /// answer. So that the drop does not limp on with fewer and fewer connections, a failed one
    /// is replaced at once, until the chunks run out or replacements stop getting anywhere.
    private func carry(_ first: Socket, conn firstConn: UInt64) {
        var socket = first, conn = firstConn
        var fruitless = 0
        while true {
            let stream = Stream(socket, conn: conn)
            stream.info = streamOpened(remote: socket.peerAddress)
            lock.withLock { live.append(stream) }
            update { $0.connections += 1 }
            var failed = false, spent = false
            do { spent = try runStream(stream) } catch {
                failed = true
                log("a data connection failed after \(stream.chunks) chunks: \((error as? DropError)?.message ?? "\(error)")", .warn)
                note { $0.connectionFailures += 1 }
                socket.shutdown()
            }
            lock.withLock { live.removeAll { $0 === stream } }
            streamClosed(stream.info)
            untrack(socket)
            update { $0.connections -= 1 }
            fruitless = stream.chunks == 0 ? fruitless + 1 : 0
            // A connection is replaced when it failed, or when its key has carried all it may.
            guard failed || spent, !isOver, fruitless < 3, jobLock.withLock({ nextJob < jobs.count }) else { return }
            if inbox.withLock({ inboxError }) != nil { return }
            guard let next = try? attach() else { return }
            (socket, conn) = next
        }
    }

    /// Closes any data connection that has moved nothing for `Tuning.stallSeconds`. Its thread
    /// then fails, and its chunks go out again on another connection.
    private func watchStreams() {
        while !state.isFinal {
            let now = Date()
            for s in lock.withLock({ live }) where now.timeIntervalSince(lock.withLock { s.lastProgress }) > Tuning.stallSeconds {
                log("a data connection has moved nothing for \(Int(Tuning.stallSeconds)) s; closing it", .warn)
                lock.withLock { s.lastProgress = now }
                s.socket.shutdown()
            }
            Thread.sleep(forTimeInterval: min(0.25, Tuning.stallSeconds / 8))
        }
    }

    /// Every chunk the receiver does not hold, in manifest order; and the progress as it really
    /// stands, which after a troubled round is less than what was written to the sockets.
    private func buildJobs(_ manifest: Manifest, _ plan: Plan, first: Bool) {
        let complete = Set(plan.completeFiles)
        var partial: [Int: Set<Int>] = [:]
        for p in plan.partialFiles { partial[p.file] = Set(p.chunks) }
        var have: Int64 = 0
        var filesDone = 0
        var list: [Job] = []
        for (i, e) in manifest.entries.enumerated() where e.kind == .file {
            let n = manifest.chunkCount(i)
            if n == 0 || complete.contains(i) {
                have += e.size
                filesDone += 1
                continue
            }
            let got = partial[i] ?? []
            for c in 0..<n {
                if got.contains(c) { have += Int64(manifest.chunkLength(file: i, chunk: c)) }
                else { list.append(Job(file: Int32(i), chunk: Int32(c))) }
            }
        }
        jobLock.withLock { jobs = list; nextJob = 0 }
        update {
            if first { $0.resumedBytes = have }
            $0.doneBytes = have
            $0.doneFiles = filesDone
        }
    }

    /// Every chunk that has been written to a connection once; one taken again is a retransmission.
    private var written = Set<UInt64>()

    private func takeJob() -> Job? {
        jobLock.lock()
        defer { jobLock.unlock() }
        guard nextJob < jobs.count else { return nil }
        if let limit = failAfterChunks, chunksSent >= limit {
            // Marked as the link's fault, so nothing is said to the receiver: a dropped link says nothing.
            DispatchQueue.global().async { self.fail(DropError("Stopped by the test", connection: true)) }
            return nil
        }
        chunksSent += 1
        nextJob += 1
        let job = jobs[nextJob - 1]
        if !written.insert(UInt64(job.file) << 32 | UInt64(job.chunk)).inserted { note { $0.retransmittedChunks += 1 } }
        return job
    }

    /// Sends chunks on one connection until there are none left (false) or the connection's
    /// key has sealed as much as one key may (true: the caller opens another).
    ///
    /// A record is the header sealed by itself (which file, which chunk, how long), then the
    /// chunk sealed with that header as associated data. Both under this connection's own key,
    /// with a counter that starts at zero and only rises.
    private func runStream(_ stream: Stream) throws -> Bool {
        let socket = stream.socket
        let manifest = scanned.manifest
        guard let keys = lock.withLock({ keys }) else { throw DropError("The drop is over") }
        var cipher = keys.stream(stream.conn)
        var sealedBytes: Int64 = 0
        let buffer = UnsafeMutableRawPointer.allocate(byteCount: manifest.chunkSize, alignment: 16384)
        defer { buffer.deallocate() }
        var openFile = -1
        var fd: Int32 = -1
        defer { if fd >= 0 { close(fd) } }
        var spent = false

        while !isOver {
            // Room for this record and for the end marker after it.
            if cipher.count + 3 > cipher.limit || sealedBytes + Int64(manifest.chunkSize) > DropKeys.streamBytes { spent = true; break }
            guard let job = takeJob() else { break }
            let file = Int(job.file), chunk = Int(job.chunk)
            let length = manifest.chunkLength(file: file, chunk: chunk)
            if openFile != file {
                if fd >= 0 { close(fd) }
                fd = Darwin.open(scanned.sources[file], O_RDONLY)
                // A source that cannot be read is no fault of the link: it ends the drop.
                guard fd >= 0 else { let e = errnoError("Cannot open \(scanned.sources[file])"); fail(e); throw e }
                openFile = file
            }
            var got = 0
            let offset = Int64(chunk) * Int64(manifest.chunkSize)
            while got < length {
                let n = pread(fd, buffer + got, length - got, offset + Int64(got))
                if n > 0 { got += n } else if n < 0, errno == EINTR { continue } else {
                    let e = n == 0 ? DropError("\(manifest.entries[file].path) changed while it was being sent")
                                   : errnoError("Cannot read \(scanned.sources[file])")
                    fail(e)
                    throw e
                }
            }
            let record = try RecordHeader.seal(&cipher, file: UInt32(file), chunk: UInt32(chunk), bytes: buffer, count: length)
            sealedBytes += Int64(length)
            // Progress counts the chunk's own bytes, not the 44 around them.
            var skip = RecordHeader.sealedSize, left = length
            try socket.writeAll(record.header, record.ciphertext, record.tag, slice: 256 << 10) { [self] n in
                lock.withLock { stream.lastProgress = Date() }
                var n = n
                let s = min(skip, n)
                skip -= s
                n = min(n - s, left)
                left -= n
                if n > 0 { update { $0.doneBytes += Int64(n) } }
            }
            stream.chunks += 1
            streamCarried(stream.info, bytes: length)
            if chunk == manifest.chunkCount(file) - 1 { update { $0.doneFiles += 1 } }
        }
        if isOver { return false }
        let end = try RecordHeader.sealEnd(&cipher)
        try end.withUnsafeBytes { try socket.writeAll($0.baseAddress!, end.count) }
        return spent
    }
}
