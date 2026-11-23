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
    private var holders: [String: ReceiveSession] = [:]
    private var completed: [String: (answer: Complete, at: Date)] = [:]

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
        case .hello:
            try? socket.send(.hello, Hello(name: identity.name, id: identity.id, version: protocolVersion, minor: protocolMinor, app: identity.appVersion))
        case .resume:
            guard let resume = try? decode(Attach.self, from: first.body) else { return }
            // A drop that finished while its sender was out of reach: say so again.
            if let done = lock.withLock({ completed[resume.token]?.answer }) {
                try? socket.send(.complete, done)
                return
            }
            guard let session = lock.withLock({ sessions[resume.token] }) else { return }
            socket.setNoDelay()
            session.resume(on: socket)
        case .attach:
            guard let attach = try? decode(Attach.self, from: first.body),
                  let session = lock.withLock({ sessions[attach.token] }) else { return }
            session.runStream(socket)
        default:
            return
        }
    }

    /// Keeps a finished drop's answer for a few minutes, for a sender whose connection was lost
    /// before it heard.
    func remember(completed token: String, _ answer: Complete) {
        lock.withLock {
            let now = Date()
            completed = completed.filter { now.timeIntervalSince($0.value.at) < 300 }
            completed[token] = (answer, now)
        }
    }

    func register(_ session: ReceiveSession, token: String) { lock.withLock { sessions[token] = session } }

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
        earlier.fail(DropError("The sender started this drop again"))
        earlier.waitUntilOver()
    }

    func release(_ partial: String, by session: ReceiveSession) {
        lock.withLock { if holders[partial] === session { holders[partial] = nil } }
    }
    func unregister(token: String) { lock.withLock { sessions[token] = nil } }
}

/// One incoming drop: first a question for the person at this Mac, then the transfer.
///
/// The transfer runs in rounds (see `SendSession`): a data connection that is lost or carries a
/// damaged chunk is closed and what it did not deliver is asked for again, on the same accepted
/// drop, without asking the person twice.
public final class ReceiveSession: Transfer, @unchecked Sendable {
    public let senderID: String
    /// What the sender says it is sending, for the prompt.
    public let offeredFiles: Int
    public let offeredBytes: Int64
    /// The sender's app version and protocol version ("0.3.1", "2.0"), as it stated them.
    public let senderAppVersion: String
    public let senderProtocol: String

    /// Called once if the sender gives up while this Mac is still deciding.
    public var onWithdrawn: (@Sendable () -> Void)?

    /// The connection the conversation is on. Replaced when the sender reconnects.
    private var control: Socket
    /// A connection the sender has opened to pick the drop up again, waiting to be taken.
    private var incoming: Socket?
    private weak var listener: DropListener?
    private let version: Int

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

    init(control: Socket, offer: Offer, listener: DropListener) {
        self.control = control
        self.listener = listener
        senderID = offer.senderID
        offeredFiles = offer.fileCount
        offeredBytes = offer.totalBytes
        version = offer.version
        senderAppVersion = offer.app ?? "an older version"
        senderProtocol = "\(offer.version)" + (offer.minor.map { ".\($0)" } ?? "")
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
        streams.lock()
        conducted = true
        streams.broadcast()
        streams.unlock()
    }

    /// A long silence is treated as a lost connection (see `SendSession.silence`): the drop is
    /// held open for the sender to come back to, rather than ended.
    override func silence() {
        guard ledger != nil, state == .transferring else { return super.silence() }
        control.shutdown()
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
    func resume(on socket: Socket) {
        streams.lock()
        incoming?.shutdown()
        incoming = socket
        let old = control
        streams.broadcast()
        streams.unlock()
        old.shutdown()
    }

    /// The control connection is gone. Holds the drop open for `Tuning.reconnectSeconds`, with
    /// everything written so far kept, until the sender reconnects; then answers with what is
    /// here. Throws when nobody comes.
    private func awaitSender(token: String, after lost: Error) throws {
        while true {
            if isOver { throw lost }
            setState(.reconnecting)
            // Whatever is wrong with the old connection (gone, or it delivered a damaged
            // message), it is finished: closing it is how the sender learns to reconnect.
            control.shutdown()
            streams.lock()
            for s in active { s.shutdown() }
            let deadline = Date().addingTimeInterval(Tuning.reconnectSeconds)
            while incoming == nil, !isOver, streams.wait(until: min(deadline, Date().addingTimeInterval(0.2))) || Date() < deadline {}
            let fresh = incoming
            incoming = nil
            streams.unlock()
            if isOver { throw lost }
            guard let fresh else {
                throw DropError("Lost the connection to \(peerName) and it did not come back; send the drop again to continue it")
            }
            replaceControl(control, with: fresh)
            control = fresh
            setPeerAddress(fresh.peerAddress)
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
                try control.send(.plan, ledger.plan(token: token))
                setState(.transferring)
                return
            } catch { continue }   // lost again already: wait again
        }
    }

    private func conduct() throws {
        // The major decides; a different minor is by definition something both sides can ignore.
        guard version == protocolVersion else {
            let mine = listener?.identity
            try control.send(.decline, Reason(message: "\(mine?.name ?? "The other Mac") runs Nimbus Drop \(mine?.appVersion ?? "?") (protocol \(protocolVersionText)) "
                + "and cannot take a drop from protocol \(senderProtocol). Update Nimbus Drop on both Macs."))
            finish(.declined("\(peerName) runs Nimbus Drop \(senderAppVersion) (protocol \(senderProtocol)); this Mac speaks protocol \(protocolVersionText). Update Nimbus Drop on both Macs."))
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
        listener.claim(partial.path, for: self)
        defer { listener.release(partial.path, by: self) }
        itemsRoot = partial.appendingPathComponent("items", isDirectory: true)
        do { try FileManager.default.createDirectory(at: itemsRoot, withIntermediateDirectories: true) }
        catch { throw DropError("Cannot write to \(destination.path): \(error.localizedDescription)") }
        try prepareTree()
        ledger = try Ledger(url: partial.appendingPathComponent("ledger"), manifest: manifest, root: itemsRoot)

        let empties = manifest.entries.indices.filter { manifest.entries[$0].kind == .file && manifest.chunkCount($0) == 0 }.count
        update { $0.resumedBytes = ledger.doneBytes; $0.doneBytes = ledger.doneBytes; $0.doneFiles = ledger.doneFiles + empties }
        roundStartBytes = ledger.doneBytes
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
        startWatchdog()

        // Rounds. The sender writes what it was asked for and says done; if connections died or
        // chunks arrived damaged along the way, something is missing, and the answer is a new
        // plan rather than a failure. It ends when everything is here, or when round after
        // round delivers nothing.
        var idle = 0
        while true {
            let next: (type: FrameType, body: Data)
            do { next = try control.readFrame() } catch {
                // The conversation's connection is gone. The drop was accepted and is partly
                // here: wait for the sender to come back rather than ending it.
                try awaitSender(token: token, after: error)
                continue
            }
            touch()
            if next.type == .error { throw DropError(try decode(Reason.self, from: next.body).message) }
            guard next.type == .done else { throw DropError("Unexpected message from \(peerName)") }
            let roundStart = lock.withLock { roundStartBytes }
            settle(opened: try decode(Done.self, from: next.body).streams)
            if isOver { return }
            if ledger.isComplete { break }
            idle = ledger.doneBytes > roundStart ? 0 : idle + 1
            guard idle < Tuning.idleRounds else { throw DropError("The drop arrived incomplete; send it again to continue it") }
            note { $0.rounds += 1 }
            let have = ledger.doneBytes
            lock.withLock { roundStartBytes = have }
            update { $0.doneBytes = have }
            do { try control.send(.plan, ledger.plan(token: token)) } catch {
                try awaitSender(token: token, after: error)
            }
        }

        setState(.finishing)
        let saved = try finalize(partial: partial, destination: destination)
        setSaved(saved)
        update { $0.doneBytes = $0.totalBytes; $0.doneFiles = $0.totalFiles }
        let complete = Complete(saved: saved.map(\.lastPathComponent))
        try? control.send(.complete, complete)
        // A sender that lost the connection meanwhile will come back asking; it is told then.
        listener.remember(completed: token, complete)
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
    ///
    /// Trouble with the connection (it closed, it stalled, what it carried is damaged) ends this
    /// connection only; the chunks it did not deliver are asked for again. Trouble with the disk
    /// ends the drop.
    func runStream(_ socket: Socket) {
        track(socket)
        streams.lock()
        active.append(socket)
        streams.unlock()
        update { $0.connections += 1 }
        do { try receive(socket) } catch let fault as StreamFault {
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
        streams.broadcast()
        streams.unlock()
    }

    private enum StreamFault: Error { case lost, damaged }

    private func receive(_ socket: Socket) throws {
        let buffer = UnsafeMutableRawPointer.allocate(byteCount: manifest.chunkSize, alignment: 16384)
        defer { buffer.deallocate() }
        var headerBytes = [UInt8](repeating: 0, count: ChunkHeader.size)
        var openFile = -1
        var fd: Int32 = -1
        defer { if fd >= 0 { close(fd) } }

        while true {
            do { try headerBytes.withUnsafeMutableBytes { try socket.readExactly($0.baseAddress!, ChunkHeader.size) } }
            catch { throw StreamFault.lost }
            let header = headerBytes.withUnsafeBytes { ChunkHeader(from: $0.baseAddress!) }
            if header.file == ChunkHeader.endMarker {
                guard header.length == 0, headerBytes.withUnsafeBytes({ header.verifies(head: $0.baseAddress!, payload: $0.baseAddress!) }) else {
                    throw StreamFault.damaged
                }
                return
            }
            // A header that makes no sense is taken for damage: its length cannot be trusted,
            // so neither can anything after it on this connection.
            let file = Int(header.file), chunk = Int(header.chunk), length = Int(header.length)
            guard file < manifest.entries.count, chunk < manifest.chunkCount(file),
                  length == manifest.chunkLength(file: file, chunk: chunk) else { throw StreamFault.damaged }
            do { try socket.readExactly(buffer, length) { [self] n in update { $0.doneBytes += Int64(n) } } }
            catch { throw StreamFault.lost }
            guard headerBytes.withUnsafeBytes({ header.verifies(head: $0.baseAddress!, payload: buffer) }) else {
                throw StreamFault.damaged
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
