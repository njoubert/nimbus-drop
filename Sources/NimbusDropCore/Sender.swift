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
    private var control: Socket!
    private var token = ""
    private var reconnected = false
    private let identity: Identity
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
    private var inboxError: Error?
    private var generation = 0

    /// One per live data connection, for the stall watch.
    private final class Stream {
        let socket: Socket
        var lastProgress = Date()
        /// Chunks written in full on this connection.
        var chunks = 0
        init(_ socket: Socket) { self.socket = socket }
    }
    private var live: [Stream] = []
    private var opened = 0

    /// Tests only: the protocol major to claim.
    var offerVersion = protocolVersion

    /// Tests only: fail the drop once this many chunks have been sent, as a dropped link would.
    var failAfterChunks: Int?
    private var chunksSent = 0

    /// `prescanned`: a drop already walked (and perhaps narrowed to some kinds of file), sent as
    /// it is instead of walking `urls` again.
    public init(urls: [URL], host: String, port: UInt16, peerName: String, identity: Identity,
                streams: Int = 8, chunkSize: Int = Scanner.defaultChunkSize, prescanned: ScannedDrop? = nil) {
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
        control = try Socket.connect(host: host, port: port)
        control.setNoDelay()
        track(control)
        try control.send(.offer, Offer(version: offerVersion, minor: protocolMinor, app: identity.appVersion, senderName: identity.name,
                                       senderID: identity.id, items: manifest.topLevelNames, fileCount: manifest.fileCount,
                                       totalBytes: manifest.totalBytes))
        setState(.waitingForAccept)
        listen(to: control)
        let answer = try nextFrame()
        switch answer.type {
        case .accept: break
        case .decline: finish(.declined(try decode(Reason.self, from: answer.body).message)); return
        default: throw DropError("Unexpected answer from \(peerName)")
        }

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
                token = plan.token
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
                    let sockets = try openStreams(token: plan.token)
                    let group = DispatchGroup()
                    for s in sockets {
                        group.enter()
                        Thread.detachNewThread { [self] in
                            carry(s, token: plan.token)
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
                    finish(.completed)
                    return
                case .plan: continue
                default: throw DropError("Unexpected answer from \(peerName)")
                }
            } catch let lost as DropError where lost.connection {
                // The conversation's own connection is gone (the other Mac changed networks,
                // slept, lost Wi-Fi). The drop is still wanted on both sides: get it back.
                if isOver { return }
                log("lost the control connection: \(lost.message)")
                reply = try reconnect(after: lost)
                reconnected = true
            }
        }
    }

    /// Tries for `Tuning.reconnectSeconds` to reach the receiver again and pick the drop up
    /// where it stands, looking the receiver's address up afresh before each attempt. Returns
    /// the receiver's new plan. Throws when the minute runs out.
    private func reconnect(after lost: DropError) throws -> (type: FrameType, body: Data) {
        guard !token.isEmpty else { throw lost }
        setState(.reconnecting)
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
            let fresh: Socket?
            do { fresh = try Socket.connect(host: h, port: p, timeout: min(Tuning.connectTimeout, 5)) } catch {
                fresh = nil
                log("reconnect attempt \(attempt) to \(h):\(p): \((error as? DropError)?.message ?? "\(error)")")
            }
            if let fresh {
                fresh.setNoDelay()
                replaceControl(control, with: fresh)
                control = fresh
                inbox.lock()
                frames = []
                inboxError = nil
                generation += 1
                inbox.unlock()
                if (try? fresh.send(.resume, Attach(token: token))) != nil {
                    listen(to: fresh)
                    // An answer, or the connection closing (a receiver that has given the drop
                    // up, or an older copy that does not know how to resume).
                    if let answer = try? nextFrame(within: max(2, Tuning.connectTimeout)), answer.type == .plan || answer.type == .complete {
                        note { $0.reconnects += 1 }
                        touch()
                        log("reconnected on attempt \(attempt); the receiver answered \(answer.type)")
                        return answer
                    }
                    log("reconnect attempt \(attempt) to \(h):\(p): connected, but no answer to resume")
                }
            }
            if isOver { break }
            Thread.sleep(forTimeInterval: 1)
        }
        if isOver { throw lost }
        throw DropError("Lost the connection to \(peerName) and could not get it back; send the drop again to continue it")
    }

    /// A drop that ends here for a reason of its own (a source file changed, the peer went
    /// silent) says so first, so the receiver stops at once instead of waiting out the minute it
    /// allows for a lost connection.
    override func fail(_ error: Error) {
        if !isOver, let control, let reason = error as? DropError, !reason.connection {
            try? control.send(.error, Reason(message: reason.message))
        }
        super.fail(error)
    }

    /// A long silence is treated as a lost connection: closing the control connection sends the
    /// drop into `reconnect`, which succeeds if the link has come back and gives up after its
    /// minute if the other Mac really is frozen.
    override func silence() {
        guard let control, !token.isEmpty, state != .reconnecting else { return super.silence() }
        log("no sign of life from \(peerName); treating the connection as lost")
        control.shutdown()
    }

    // MARK: The control connection

    /// Reads one control connection until it ends. After a reconnect the old connection's
    /// reader is still winding down; `generation` keeps its last words out of the new one's inbox.
    private func listen(to socket: Socket) {
        let mine = inbox.withLock { generation }
        Thread.detachNewThread { [self] in
            while true {
                do {
                    let frame = try socket.readFrame()
                    touch()
                    if frame.type == .error {
                        // The receiver's reason, said before it closes everything.
                        let reason = DropError(try decode(Reason.self, from: frame.body).message)
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
    private func openStreams(token: String) throws -> [Socket] {
        let wanted = min(streams, jobs.count)
        let started = Date()
        var last: Error = DropError("Cannot connect to \(peerName)")
        while !isOver {
            // No use opening data connections for a conversation that has lost its own.
            if let dead = inbox.withLock({ inboxError }) { throw dead }
            let (host, port) = lock.withLock { (self.host, self.port) }
            var sockets: [Socket] = []
            for _ in 0..<wanted {
                do {
                    let s = try Socket.connect(host: host, port: port)
                    track(s)
                    try s.send(.attach, Attach(token: token))
                    lock.withLock { opened += 1 }
                    sockets.append(s)
                } catch { last = error }
            }
            if !sockets.isEmpty { return sockets }
            guard Date().timeIntervalSince(started) < Tuning.connectRetrySeconds else { break }
            Thread.sleep(forTimeInterval: 0.5)
        }
        throw last
    }

    /// One of the round's data connections, and its replacements. A connection that fails is
    /// this round's loss, not the drop's: what it did not deliver is in the receiver's next
    /// answer. So that the drop does not limp on with fewer and fewer connections, a failed one
    /// is replaced at once, until the chunks run out or replacements stop getting anywhere.
    private func carry(_ first: Socket, token: String) {
        var socket = first
        var fruitless = 0
        while true {
            let stream = Stream(socket)
            lock.withLock { live.append(stream) }
            update { $0.connections += 1 }
            var failed = false
            do { try runStream(stream) } catch {
                failed = true
                log("a data connection failed after \(stream.chunks) chunks: \((error as? DropError)?.message ?? "\(error)")")
                note { $0.connectionFailures += 1 }
                socket.shutdown()
            }
            lock.withLock { live.removeAll { $0 === stream } }
            untrack(socket)
            update { $0.connections -= 1 }
            fruitless = stream.chunks == 0 ? fruitless + 1 : 0
            guard failed, !isOver, fruitless < 3, jobLock.withLock({ nextJob < jobs.count }) else { return }
            if inbox.withLock({ inboxError }) != nil { return }
            let (host, port) = lock.withLock { (self.host, self.port) }
            guard let next = try? Socket.connect(host: host, port: port) else { return }
            track(next)
            guard (try? next.send(.attach, Attach(token: token))) != nil else { next.shutdown(); untrack(next); return }
            lock.withLock { opened += 1 }
            socket = next
        }
    }

    /// Closes any data connection that has moved nothing for `Tuning.stallSeconds`. Its thread
    /// then fails, and its chunks go out again on another connection.
    private func watchStreams() {
        while !state.isFinal {
            let now = Date()
            for s in lock.withLock({ live }) where now.timeIntervalSince(lock.withLock { s.lastProgress }) > Tuning.stallSeconds {
                log("a data connection has moved nothing for \(Int(Tuning.stallSeconds)) s; closing it")
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

    private func runStream(_ stream: Stream) throws {
        let socket = stream.socket
        let manifest = scanned.manifest
        let buffer = UnsafeMutableRawPointer.allocate(byteCount: ChunkHeader.size + manifest.chunkSize, alignment: 16384)
        defer { buffer.deallocate() }
        var openFile = -1
        var fd: Int32 = -1
        defer { if fd >= 0 { close(fd) } }

        while !isOver, let job = takeJob() {
            let file = Int(job.file), chunk = Int(job.chunk)
            let length = manifest.chunkLength(file: file, chunk: chunk)
            if openFile != file {
                if fd >= 0 { close(fd) }
                fd = open(scanned.sources[file], O_RDONLY)
                // A source that cannot be read is no fault of the link: it ends the drop.
                guard fd >= 0 else { let e = errnoError("Cannot open \(scanned.sources[file])"); fail(e); throw e }
                openFile = file
            }
            var got = 0
            let offset = Int64(chunk) * Int64(manifest.chunkSize)
            while got < length {
                let n = pread(fd, buffer + ChunkHeader.size + got, length - got, offset + Int64(got))
                if n > 0 { got += n } else if n < 0, errno == EINTR { continue } else {
                    let e = n == 0 ? DropError("\(manifest.entries[file].path) changed while it was being sent")
                                   : errnoError("Cannot read \(scanned.sources[file])")
                    fail(e)
                    throw e
                }
            }
            ChunkHeader.seal(buffer, file: UInt32(file), chunk: UInt32(chunk), length: length)
            var counted = -ChunkHeader.size
            try socket.writeAll(buffer, ChunkHeader.size + length, slice: 256 << 10) { [self] n in
                counted += n
                lock.withLock { stream.lastProgress = Date() }
                if counted > 0 {
                    let add = Int64(counted)
                    counted = 0
                    update { $0.doneBytes += add }
                }
            }
            stream.chunks += 1
            if chunk == manifest.chunkCount(file) - 1 { update { $0.doneFiles += 1 } }
        }
        if isOver { return }
        ChunkHeader.seal(buffer, file: ChunkHeader.endMarker, chunk: 0, length: 0)
        try socket.writeAll(buffer, ChunkHeader.size)
    }
}
