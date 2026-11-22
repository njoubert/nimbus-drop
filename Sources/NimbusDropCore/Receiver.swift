// Copyright (C) 2026 Niels Joubert
// SPDX-License-Identifier: GPL-3.0-or-later
import Darwin
import Foundation

/// Accepts connections from senders. Each new drop is handed to `onOffer` as a `ReceiveSession`
/// that waits for `accept(destination:)` or `decline()`; nothing is written before that.
public final class DropListener: @unchecked Sendable {
    public let port: UInt16
    public let identity: Identity
    /// Called on a background thread for every incoming offer.
    public var onOffer: (@Sendable (ReceiveSession) -> Void)?

    private let fd: Int32
    private let lock = NSLock()
    private var stopped = false
    private var sessions: [String: ReceiveSession] = [:]

    /// Listens on `preferredPort`, or on any free port when that one is taken (0 asks for any).
    public init(identity: Identity, preferredPort: UInt16 = defaultPort) throws {
        self.identity = identity
        if let got = try? Socket.listen(port: preferredPort) {
            (fd, port) = got
        } else {
            (fd, port) = try Socket.listen(port: 0)
        }
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
                Thread.detachNewThread { [self] in serve(socket) }
            }
        }
    }

    /// Stops taking new drops. Drops already under way carry on.
    public func stop() { lock.withLock { stopped = true } }

    private func serve(_ socket: Socket) {
        // Bonjour resolution opens a connection and closes it again; anything that does not
        // speak within ten seconds is not a sender.
        socket.setReadTimeout(10)
        guard let first = try? socket.readFrame() else { return }
        socket.setReadTimeout(0)
        switch first.type {
        case .offer:
            guard let offer = try? decode(Offer.self, from: first.body) else { return }
            socket.setNoDelay()
            let session = ReceiveSession(control: socket, offer: offer, listener: self)
            session.run()
        case .attach:
            guard let attach = try? decode(Attach.self, from: first.body),
                  let session = lock.withLock({ sessions[attach.token] }) else { return }
            session.runStream(socket)
        default:
            return
        }
    }

    func register(_ session: ReceiveSession, token: String) { lock.withLock { sessions[token] = session } }
    func unregister(token: String) { lock.withLock { sessions[token] = nil } }
}

/// One incoming drop: first a question for the person at this Mac, then the transfer.
public final class ReceiveSession: Transfer, @unchecked Sendable {
    public let senderID: String
    /// What the sender says it is sending, for the prompt.
    public let offeredFiles: Int
    public let offeredBytes: Int64

    /// Called once if the sender gives up while this Mac is still deciding.
    public var onWithdrawn: (@Sendable () -> Void)?

    private let control: Socket
    private weak var listener: DropListener?
    private let version: Int

    private enum Decision { case accept(URL), decline(String) }
    private var decision: Decision?

    private var manifest: Manifest!
    private var ledger: Ledger!
    private var itemsRoot: URL!
    private let streamsCondition = NSCondition()
    private var streamsEnded = 0

    init(control: Socket, offer: Offer, listener: DropListener) {
        self.control = control
        self.listener = listener
        senderID = offer.senderID
        offeredFiles = offer.fileCount
        offeredBytes = offer.totalBytes
        version = offer.version
        super.init(direction: .receive, state: .waitingForAccept, peerName: offer.senderName, peerAddress: control.peerAddress)
        setItems(offer.items)
        update { $0.totalBytes = offer.totalBytes; $0.totalFiles = offer.fileCount }
        track(control)
    }

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
    }

    private func conduct() throws {
        guard version == protocolVersion else {
            try control.send(.decline, Reason(message: "\(listener?.identity.name ?? "The other Mac") runs a different version of Nimbus Drop"))
            finish(.declined("The sender runs a different version of Nimbus Drop"))
            return
        }
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
            if control.waitReadable(milliseconds: 200) {
                let message = (try? control.readFrame()).flatMap { $0.type == .error ? try? decode(Reason.self, from: $0.body).message : nil }
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

        try control.send(.accept, Empty())
        let frame = try control.readFrame()
        guard frame.type == .manifest else { throw DropError("Unexpected message from the sender") }
        manifest = try decode(Manifest.self, from: frame.body)
        try manifest.validate()
        setItems(manifest.topLevelNames)
        update { $0.totalBytes = manifest.totalBytes; $0.totalFiles = manifest.fileCount }

        // Everything is built inside one partial folder in the destination (so the final move
        // is a rename on the same volume), named after the drop's key so a re-send finds it.
        let key = manifest.key(senderID: senderID)
        let label = String((manifest.topLevelNames.first ?? "Drop").prefix(80))
        let partial = destination.appendingPathComponent("\(label).\(key.prefix(12)).nimbusdrop-partial", isDirectory: true)
        itemsRoot = partial.appendingPathComponent("items", isDirectory: true)
        do { try FileManager.default.createDirectory(at: itemsRoot, withIntermediateDirectories: true) }
        catch { throw DropError("Cannot write to \(destination.path): \(error.localizedDescription)") }
        try prepareTree()
        ledger = try Ledger(url: partial.appendingPathComponent("ledger"), manifest: manifest, root: itemsRoot)

        let empties = manifest.entries.indices.filter { manifest.entries[$0].kind == .file && manifest.chunkCount($0) == 0 }.count
        update { $0.resumedBytes = ledger.doneBytes; $0.doneBytes = ledger.doneBytes; $0.doneFiles = ledger.doneFiles + empties }
        let needed = manifest.totalBytes - ledger.doneBytes
        if let free = try? destination.resourceValues(forKeys: [.volumeAvailableCapacityForImportantUsageKey]).volumeAvailableCapacityForImportantUsage,
           free < needed {
            throw DropError("Not enough space on \(listener.identity.name): \(Format.bytes(needed)) needed, \(Format.bytes(free)) free")
        }

        let token = UUID().uuidString
        listener.register(self, token: token)
        defer { listener.unregister(token: token) }
        try control.send(.plan, ledger.plan(token: token))
        setState(.transferring)

        let next = try control.readFrame()
        if next.type == .error { throw DropError(try decode(Reason.self, from: next.body).message) }
        guard next.type == .done else { throw DropError("Unexpected message from the sender") }
        let expected = try decode(Done.self, from: next.body).streams

        // The sender wrote every end marker before it said done; the stream threads here may
        // still be writing their last chunks to disk.
        streamsCondition.lock()
        let deadline = Date().addingTimeInterval(120)
        while streamsEnded < expected, !isOver, streamsCondition.wait(until: deadline) {}
        let ended = streamsEnded
        streamsCondition.unlock()
        if isOver { return }
        guard ended >= expected, ledger.isComplete else { throw DropError("The drop arrived incomplete") }

        setState(.finishing)
        let saved = try finalize(partial: partial, destination: destination)
        setSaved(saved)
        update { $0.doneBytes = $0.totalBytes; $0.doneFiles = $0.totalFiles }
        try? control.send(.complete, Complete(saved: saved.map(\.lastPathComponent)))
        finish(.completed)
    }

    /// Folders, symlinks and empty files, before any data. Existing ones (a resume) are left.
    private func prepareTree() throws {
        for e in manifest.entries {
            let path = itemsRoot.appendingPathComponent(e.path).path
            switch e.kind {
            case .directory:
                guard mkdir(path, 0o700) == 0 || errno == EEXIST else { throw errnoError("Cannot create \(e.path)") }
            case .symlink:
                guard symlink(e.link ?? "", path) == 0 || errno == EEXIST else { throw errnoError("Cannot create the link \(e.path)") }
            case .file where e.size == 0:
                let fd = open(path, O_WRONLY | O_CREAT | O_NOFOLLOW, 0o600)
                guard fd >= 0 else { throw errnoError("Cannot create \(e.path)") }
                close(fd)
            case .file:
                break
            }
        }
    }

    /// One data connection: read a chunk, check it, write it where it belongs, note it.
    func runStream(_ socket: Socket) {
        track(socket)
        do { try receive(socket) } catch {
            if !isOver { try? control.send(.error, Reason(message: (error as? DropError)?.message ?? error.localizedDescription)) }
            fail(error)
        }
        streamsCondition.lock()
        streamsCondition.broadcast()
        streamsCondition.unlock()
    }

    private func receive(_ socket: Socket) throws {
        let buffer = UnsafeMutableRawPointer.allocate(byteCount: manifest.chunkSize, alignment: 16384)
        defer { buffer.deallocate() }
        var headerBytes = [UInt8](repeating: 0, count: ChunkHeader.size)
        var openFile = -1
        var fd: Int32 = -1
        defer { if fd >= 0 { close(fd) } }

        while true {
            try headerBytes.withUnsafeMutableBytes { try socket.readExactly($0.baseAddress!, ChunkHeader.size) }
            let header = headerBytes.withUnsafeBytes { ChunkHeader(from: $0.baseAddress!) }
            if header.file == ChunkHeader.endMarker {
                streamsCondition.lock()
                streamsEnded += 1
                streamsCondition.unlock()
                return
            }
            let file = Int(header.file), chunk = Int(header.chunk), length = Int(header.length)
            guard file < manifest.entries.count, chunk < manifest.chunkCount(file),
                  length == manifest.chunkLength(file: file, chunk: chunk) else {
                throw DropError("The sender sent a chunk that is not in the drop")
            }
            try socket.readExactly(buffer, length) { [self] n in update { $0.doneBytes += Int64(n) } }
            guard checksum(buffer, length) == header.crc else {
                throw DropError("A chunk of \(manifest.entries[file].path) arrived damaged; send the drop again to continue it")
            }
            if openFile != file {
                if fd >= 0 { close(fd) }
                fd = open(itemsRoot.appendingPathComponent(manifest.entries[file].path).path, O_WRONLY | O_CREAT | O_NOFOLLOW, 0o600)
                guard fd >= 0 else { throw errnoError("Cannot create \(manifest.entries[file].path)") }
                openFile = file
            }
            var wrote = 0
            let offset = Int64(chunk) * Int64(manifest.chunkSize)
            while wrote < length {
                let n = pwrite(fd, buffer + wrote, length - wrote, offset + Int64(wrote))
                if n > 0 { wrote += n }
                else if errno != EINTR { throw errnoError("Cannot write \(manifest.entries[file].path)") }
            }
            if try ledger.record(file: file, chunk: chunk) { update { $0.doneFiles += 1 } }
        }
    }

    /// Modes and times, deepest first; then each top-level item moves into the destination.
    private func finalize(partial: URL, destination: URL) throws -> [URL] {
        for e in manifest.entries.reversed() where e.kind != .symlink {
            let path = itemsRoot.appendingPathComponent(e.path).path
            var times = [timespec(tv_sec: 0, tv_nsec: Int(UTIME_OMIT)),
                         timespec(tv_sec: Int(e.mtime), tv_nsec: Int((e.mtime - e.mtime.rounded(.down)) * 1e9))]
            utimensat(AT_FDCWD, path, &times, AT_SYMLINK_NOFOLLOW)
            // The owner keeps access to what they were just sent, whatever the mode was.
            chmod(path, mode_t(e.mode & 0o777) | (e.kind == .directory ? 0o700 : 0o600))
        }
        var saved: [URL] = []
        let fm = FileManager.default
        for e in manifest.entries where !e.path.contains("/") {
            let name = Naming.unique(e.path, isDirectory: e.kind == .directory) {
                fm.fileExists(atPath: destination.appendingPathComponent($0).path)
            }
            let target = destination.appendingPathComponent(name)
            guard rename(itemsRoot.appendingPathComponent(e.path).path, target.path) == 0 else {
                throw errnoError("Cannot move \(e.path) into \(destination.path)")
            }
            saved.append(target)
        }
        try? fm.removeItem(at: partial)
        return saved
    }
}
