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
/// it all. Only the control connection going away, or a long silence, ends a drop early.
public final class SendSession: Transfer, @unchecked Sendable {
    private let urls: [URL]
    private let host: String
    private let port: UInt16
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

    /// One per live data connection, for the stall watch.
    private final class Stream {
        let socket: Socket
        var lastProgress = Date()
        init(_ socket: Socket) { self.socket = socket }
    }
    private var live: [Stream] = []
    private var opened = 0

    /// Tests only: the protocol major to claim.
    var offerVersion = protocolVersion

    /// Tests only: fail the drop once this many chunks have been sent, as a dropped link would.
    var failAfterChunks: Int?
    private var chunksSent = 0

    public init(urls: [URL], host: String, port: UInt16, peerName: String, identity: Identity,
                streams: Int = 8, chunkSize: Int = Scanner.defaultChunkSize) {
        self.urls = urls
        self.host = host
        self.port = port
        self.identity = identity
        self.streams = max(1, min(32, streams))
        self.chunkSize = chunkSize
        super.init(direction: .send, state: .scanning, peerName: peerName, peerAddress: host)
        setItems(urls.map(\.lastPathComponent))
    }

    public func start() {
        Thread.detachNewThread { [self] in
            do { try run() } catch { fail(error) }
        }
    }

    private func run() throws {
        scanned = try Scanner.scan(urls, chunkSize: chunkSize) { [self] in isOver }
        let manifest = scanned.manifest
        setItems(manifest.topLevelNames)
        update { $0.totalBytes = manifest.totalBytes; $0.totalFiles = manifest.fileCount }
        if isOver { return }

        setState(.connecting)
        let control = try Socket.connect(host: host, port: port)
        control.setNoDelay()
        track(control)
        try control.send(.offer, Offer(version: offerVersion, minor: protocolMinor, app: identity.appVersion, senderName: identity.name, senderID: identity.id,
                                       items: manifest.topLevelNames, fileCount: manifest.fileCount,
                                       totalBytes: manifest.totalBytes))
        setState(.waitingForAccept)
        Thread.detachNewThread { [self] in readControl(control) }
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
        while true {
            let plan = try decode(Plan.self, from: reply.body)
            buildJobs(manifest, plan, first: first)
            first = false
            note { $0.rounds += 1 }
            setState(.transferring)
            if !jobs.isEmpty {
                let sockets = try openStreams(token: plan.token)
                let group = DispatchGroup()
                for s in sockets {
                    group.enter()
                    Thread.detachNewThread { [self] in
                        let stream = Stream(s)
                        lock.withLock { live.append(stream) }
                        update { $0.connections += 1 }
                        // A stream that fails is this round's loss, not the drop's: what it did
                        // not deliver is in the receiver's next answer.
                        do { try runStream(stream) } catch {
                            note { $0.connectionFailures += 1 }
                            s.shutdown()
                        }
                        lock.withLock { live.removeAll { $0 === stream } }
                        untrack(s)
                        update { $0.connections -= 1 }
                        group.leave()
                    }
                }
                group.wait()
            }
            if isOver { return }
            setState(.finishing)
            try control.send(.done, Done(streams: lock.withLock { opened }))
            reply = try nextFrame()
            switch reply.type {
            case .complete:
                update { $0.doneBytes = $0.totalBytes; $0.doneFiles = $0.totalFiles }
                finish(.completed)
                return
            case .plan: continue
            default: throw DropError("Unexpected answer from \(peerName)")
            }
        }
    }

    // MARK: The control connection

    private func readControl(_ control: Socket) {
        while true {
            do {
                let frame = try control.readFrame()
                touch()
                if frame.type == .error {
                    // The receiver's reason, said before it closes everything.
                    let reason = DropError(try decode(Reason.self, from: frame.body).message)
                    post(error: reason)
                    fail(reason)
                    return
                }
                inbox.lock()
                frames.append(frame)
                inbox.broadcast()
                inbox.unlock()
                if frame.type == .complete || frame.type == .decline { return }
            } catch {
                post(error: error)
                fail(error)
                return
            }
        }
    }

    private func post(error: Error) {
        inbox.lock()
        if inboxError == nil { inboxError = error }
        inbox.broadcast()
        inbox.unlock()
    }

    private func nextFrame() throws -> (type: FrameType, body: Data) {
        inbox.lock()
        defer { inbox.unlock() }
        while frames.isEmpty {
            if let inboxError { throw inboxError }
            if isOver { throw DropError("Cancelled") }
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

    /// Closes any data connection that has moved nothing for `Tuning.stallSeconds`. Its thread
    /// then fails, and its chunks go out again on another connection.
    private func watchStreams() {
        while !state.isFinal {
            let now = Date()
            for s in lock.withLock({ live }) where now.timeIntervalSince(lock.withLock { s.lastProgress }) > Tuning.stallSeconds {
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

    private func takeJob() -> Job? {
        jobLock.lock()
        defer { jobLock.unlock() }
        guard nextJob < jobs.count else { return nil }
        if let limit = failAfterChunks, chunksSent >= limit {
            DispatchQueue.global().async { self.fail(DropError("Stopped by the test")) }
            return nil
        }
        chunksSent += 1
        nextJob += 1
        return jobs[nextJob - 1]
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
            if chunk == manifest.chunkCount(file) - 1 { update { $0.doneFiles += 1 } }
        }
        if isOver { return }
        ChunkHeader.seal(buffer, file: ChunkHeader.endMarker, chunk: 0, length: 0)
        try socket.writeAll(buffer, ChunkHeader.size)
    }
}
