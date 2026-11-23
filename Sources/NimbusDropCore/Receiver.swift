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
    private var strangers = 0
    private var turnedAway = Set<String>()
    private var _localOnly = true
    /// Take connections only from the local network (the default). Off: from anything that can reach the port.
    public var localOnly: Bool {
        get { lock.withLock { _localOnly } }
        set { lock.withLock { _localOnly = newValue; turnedAway = [] } }
    }
    /// Tests only: decides which addresses are let in, in place of the subnet rule.
    var allows: ((String) -> Bool)?
    private var waiting: [(session: ReceiveSession?, address: String)] = []
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

    /// Whether a connection from this address is taken at all. By default only the local
    /// network: this Mac itself and addresses on the same subnet as one of its interfaces.
    /// Anything else is closed before a byte of it is read.
    private func admits(_ address: String) -> Bool {
        if let allows { return allows(address) }
        return !localOnly || LocalNetwork.isLocal(address, among: LocalNetwork.current())
    }

    private func serve(_ socket: Socket) {
        let from = socket.peerAddress
        guard admits(from) else {
            // Said once per address: a scanner knocking every second should not fill the log.
            if lock.withLock({ turnedAway.insert(from).inserted }) {
                DropLog.write("turned away a connection from \(from): not on the local network (Settings › Receiving)", .warn)
            }
            socket.shutdown()
            return
        }
        // Bonjour resolution opens a connection and closes it again; anything that does not
        // speak within ten seconds is not a sender.
        // Until it has said what it is, a connection is a stranger: a bounded number of them, a
        // small first frame, and ten seconds in all to send it (not ten per byte).
        guard lock.withLock({ () -> Bool in
            guard strangers < Tuning.strangers else { return false }
            strangers += 1
            return true
        }) else { return }
        let arrived = Locked(false)
        DispatchQueue.global().asyncAfter(deadline: .now() + Tuning.strangerSeconds) { if !arrived.withLock({ $0 }) { socket.shutdown() } }
        socket.setReadTimeout(10)
        let first = try? socket.readFrame(limit: firstFrameBytes)
        arrived.withLock { $0 = true }
        lock.withLock { strangers -= 1 }
        // Closed here and now: the deadline above still holds the socket for its ten seconds.
        guard let first else { socket.shutdown(); return }
        socket.setReadTimeout(0)
        switch first.type {
        case .offer:
            guard let offer = try? decode(Offer.self, from: first.body) else { return }
            socket.setNoDelay()
            let session = ReceiveSession(control: socket, offer: offer, listener: self)
            // No more questions on screen than a person can read, and no more than two from
            // one address: the rest are declined without being shown.
            let room = lock.withLock { () -> Bool in
                waiting = waiting.filter { $0.session?.state == .waitingForAccept }
                guard waiting.count < Tuning.pendingOffers,
                      waiting.filter({ $0.address == from }).count < Tuning.pendingOffersPerAddress else { return false }
                waiting.append((session, from))
                return true
            }
            guard room else {
                DropLog.write("declined an offer from \(from) unseen: too many are waiting for an answer already", .warn)
                try? socket.send(.decline, Reason(message: "\(identity.name) has too many drops waiting for an answer"))
                return
            }
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
        DropLog.write("\(earlier.tag) superseded: the sender offered the same drop again", .warn)
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

    init(control: Socket, offer: Offer, listener: DropListener) {
        self.control = control
        self.listener = listener
        senderID = offer.senderID
        offeredFiles = offer.fileCount
        offeredBytes = offer.totalBytes
        version = offer.version
        senderAppVersion = Sanitize.label(offer.app ?? "an older version", limit: 24)
        senderProtocol = "\(offer.version)" + (offer.minor.map { ".\($0)" } ?? "")
        offered = offer
        // The name is whatever the sender says it is; only the address is known. Both are shown.
        super.init(direction: .receive, state: .waitingForAccept, peerName: Sanitize.label(offer.senderName, limit: 64),
                   peerAddress: control.peerAddress)
        setItems(offer.items.prefix(1000).map { Sanitize.label($0, limit: 255) })
        log("offer from \(peerName) at \(control.peerAddress) (Nimbus Drop \(senderAppVersion), protocol \(senderProtocol)): “\(items.prefix(20).joined(separator: "”, “"))”, \(offer.fileCount) files, \(offer.totalBytes) bytes")
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
        log("no sign of life from \(peerName); treating the connection as lost", .warn)
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
            log("lost the control connection: \((lost as? DropError)?.message ?? "\(lost)"); holding the drop for \(Int(Tuning.reconnectSeconds)) s", .warn)
            setState(.reconnecting)
            // Whatever is wrong with the old connection (gone, or it delivered a damaged
            // message), it is finished: closing it is how the sender learns to reconnect.
            control.shutdown()
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
            replaceControl(control, with: fresh)
            control = fresh
            setPeerAddress(fresh.peerAddress)
            log("the sender is back, from \(fresh.peerAddress)")
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
                let message = (try? control.readFrame(limit: firstFrameBytes)).flatMap { $0.type == .error ? (try? decode(Reason.self, from: $0.body).message).map { Sanitize.label($0, limit: 300) } : nil }
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

        log("accepted, saving to \(destination.path)")
        try control.send(.accept, Empty())
        let frame = try control.readFrame()
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
            do { try control.send(.plan, ledger.plan(token: token)) } catch {
                try awaitSender(token: token, after: error)
            }
        }

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
    func runStream(_ socket: Socket) {
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
        do { try receive(socket) } catch let fault as StreamFault {
            log(fault == .damaged ? "a chunk arrived damaged from \(from); closing that connection" : "a data connection from \(from) was lost", .warn)
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
                fd = -1
                fd = try treeLock.withLock { try tree.openFile(manifest.entries[file].path) }
                openFile = file
            }
            var wrote = 0
            let offset = Int64(chunk) * Int64(manifest.chunkSize)
            while wrote < length {
                let n = pwrite(fd, buffer + wrote, length - wrote, offset + Int64(wrote))
                if n > 0 { wrote += n }
                else if errno != EINTR { throw errnoError("Cannot write \(manifest.entries[file].path)") }
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
            guard rename(itemsRoot.appendingPathComponent(e.path).path, target.path) == 0 else {
                throw errnoError("Cannot move \(e.path) into \(destination.path)")
            }
            saved.append(target)
        }
        try? fm.removeItem(at: partial)
        return saved
    }
}
