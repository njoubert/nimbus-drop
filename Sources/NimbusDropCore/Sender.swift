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
        try control.send(.offer, Offer(version: protocolVersion, senderName: identity.name, senderID: identity.id,
                                       items: manifest.topLevelNames, fileCount: manifest.fileCount,
                                       totalBytes: manifest.totalBytes))
        setState(.waitingForAccept)
        let answer = try control.readFrame()
        switch answer.type {
        case .accept: break
        case .decline: finish(.declined(try decode(Reason.self, from: answer.body).message)); return
        case .error: throw DropError(try decode(Reason.self, from: answer.body).message)
        default: throw DropError("Unexpected answer from the other Mac")
        }

        try control.send(.manifest, manifest)
        let reply = try control.readFrame()
        if reply.type == .error { throw DropError(try decode(Reason.self, from: reply.body).message) }
        guard reply.type == .plan else { throw DropError("Unexpected answer from the other Mac") }
        let plan = try decode(Plan.self, from: reply.body)
        buildJobs(manifest, plan)

        setState(.transferring)
        let count = min(streams, jobs.count)
        var sockets: [Socket] = []
        for _ in 0..<count {
            let s = try Socket.connect(host: host, port: port)
            track(s)
            try s.send(.attach, Attach(token: plan.token))
            sockets.append(s)
        }
        let group = DispatchGroup()
        for s in sockets {
            group.enter()
            Thread.detachNewThread { [self] in
                defer { group.leave() }
                do { try runStream(s) } catch {
                    // When the receiver stops a drop it says why on the control connection and
                    // then closes everything; give that message a moment to win over this
                    // stream's "connection lost".
                    Thread.sleep(forTimeInterval: 0.3)
                    fail(error)
                }
            }
        }
        // Once every stream has written its end marker, say so; the receiver then finishes up
        // and answers on the control connection, which this thread is reading meanwhile.
        DispatchQueue.global().async { [self] in
            group.wait()
            guard !isOver else { return }
            setState(.finishing)
            do { try control.send(.done, Done(streams: count)) } catch { fail(error) }
        }
        let final = try control.readFrame()
        switch final.type {
        case .complete:
            update { $0.doneBytes = $0.totalBytes; $0.doneFiles = $0.totalFiles }
            finish(.completed)
        case .error: throw DropError(try decode(Reason.self, from: final.body).message)
        default: throw DropError("Unexpected answer from the other Mac")
        }
    }

    /// Every chunk the receiver does not already hold, in manifest order.
    private func buildJobs(_ manifest: Manifest, _ plan: Plan) {
        let complete = Set(plan.completeFiles)
        var partial: [Int: Set<Int>] = [:]
        for p in plan.partialFiles { partial[p.file] = Set(p.chunks) }
        var resumed: Int64 = 0
        var filesDone = 0
        for (i, e) in manifest.entries.enumerated() where e.kind == .file {
            let n = manifest.chunkCount(i)
            if n == 0 || complete.contains(i) {
                resumed += e.size
                filesDone += 1
                continue
            }
            let have = partial[i] ?? []
            for c in 0..<n {
                if have.contains(c) { resumed += Int64(manifest.chunkLength(file: i, chunk: c)) }
                else { jobs.append(Job(file: Int32(i), chunk: Int32(c))) }
            }
        }
        update { $0.resumedBytes = resumed; $0.doneBytes = resumed; $0.doneFiles = filesDone }
    }

    private func takeJob() -> Job? {
        jobLock.lock()
        defer { jobLock.unlock() }
        if let limit = failAfterChunks, chunksSent >= limit { return nil }
        guard nextJob < jobs.count else { return nil }
        chunksSent += 1
        nextJob += 1
        return jobs[nextJob - 1]
    }

    private func runStream(_ socket: Socket) throws {
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
                guard fd >= 0 else { throw errnoError("Cannot open \(scanned.sources[file])") }
                openFile = file
            }
            var got = 0
            let offset = Int64(chunk) * Int64(manifest.chunkSize)
            while got < length {
                let n = pread(fd, buffer + ChunkHeader.size + got, length - got, offset + Int64(got))
                if n > 0 { got += n }
                else if n == 0 { throw DropError("\(manifest.entries[file].path) changed while it was being sent") }
                else if errno != EINTR { throw errnoError("Cannot read \(scanned.sources[file])") }
            }
            ChunkHeader(file: UInt32(file), chunk: UInt32(chunk), length: UInt32(length),
                        crc: checksum(buffer + ChunkHeader.size, length)).write(to: buffer)
            var counted = -ChunkHeader.size
            try socket.writeAll(buffer, ChunkHeader.size + length, slice: 1 << 20) { [self] n in
                counted += n
                if counted > 0 {
                    let add = Int64(counted)
                    counted = 0
                    update { $0.doneBytes += add }
                }
            }
            if chunk == manifest.chunkCount(file) - 1 { update { $0.doneFiles += 1 } }
        }
        if let limit = failAfterChunks, jobLock.withLock({ chunksSent >= limit }) {
            throw DropError("Stopped by the test")
        }
        if isOver { return }
        ChunkHeader(file: ChunkHeader.endMarker, chunk: 0, length: 0, crc: 0).write(to: buffer)
        try socket.writeAll(buffer, ChunkHeader.size)
    }
}
