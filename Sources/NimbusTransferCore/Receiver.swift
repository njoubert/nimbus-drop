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
    package override func withdrawn(_ error: DropError) {
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
