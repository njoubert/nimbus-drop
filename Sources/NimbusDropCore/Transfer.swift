// Copyright (C) 2026 Niels Joubert
// SPDX-License-Identifier: GPL-3.0-or-later
import Foundation

/// Who this Mac says it is: the name others see and an id that stays the same across launches
/// (it is what lets a re-sent drop be recognised, and how a Mac leaves itself out of its own list).
public struct Identity: Equatable, Sendable {
    public var name: String
    public var id: String
    /// The app's version, for the other side to show; "dev" for a bare binary.
    public var appVersion: String
    public init(name: String, id: String, appVersion: String = "dev") {
        self.name = name
        self.id = id
        self.appVersion = appVersion
    }
}

public enum TransferState: Equatable, Sendable {
    case scanning
    case connecting
    /// Sender: the other person has not answered yet. Receiver: this Mac has not answered yet.
    case waitingForAccept
    case transferring
    /// The connection carrying the conversation was lost mid-drop; the sender is trying to get
    /// it back and the receiver is waiting for it, for up to a minute. Nothing is asked again.
    case reconnecting
    /// Every byte has arrived; the receiver is setting times and moving the items into place.
    case finishing
    case completed
    case declined(String)
    case failed(String)
    case cancelled

    public var isFinal: Bool {
        switch self {
        case .completed, .declined, .failed, .cancelled: return true
        default: return false
        }
    }
}

public struct TransferProgress: Equatable, Sendable {
    public var totalBytes: Int64 = 0
    /// Includes `resumedBytes`.
    public var doneBytes: Int64 = 0
    /// Bytes an earlier attempt had already delivered.
    public var resumedBytes: Int64 = 0
    public var totalFiles = 0
    public var doneFiles = 0
    /// Data connections open right now.
    public var connections = 0

    public var fraction: Double { totalBytes > 0 ? min(1, Double(doneBytes) / Double(totalBytes)) : (doneFiles >= totalFiles ? 1 : 0) }
}

/// What went wrong along the way without stopping the drop.
public struct TransferStats: Equatable, Sendable {
    /// Times the sender was told what is still missing and sent it: 1 for a drop with no trouble.
    public var rounds = 0
    /// Data connections that died or were closed for stalling.
    public var connectionFailures = 0
    /// Chunks (or their headers) that arrived damaged and were thrown away.
    public var damagedChunks = 0
    /// Times the whole drop lost its connection and got it back.
    public var reconnects = 0
    /// Chunks sent (a sender) or received intact and written (a receiver), retransmissions included.
    public var chunks = 0
    /// Attempts to reconnect, whether or not they got through.
    public var reconnectAttempts = 0
    /// Symlinks in the drop that pointed outside it and were not recreated (a receiver).
    public var skippedLinks = 0
    /// Chunks that had to be sent a second time (the first copy was lost with its connection or
    /// arrived damaged). The measure of what trouble cost: everything else went once.
    public var retransmittedChunks = 0

    public init(rounds: Int = 0, connectionFailures: Int = 0, damagedChunks: Int = 0, reconnects: Int = 0, retransmittedChunks: Int = 0,
                skippedLinks: Int = 0) {
        self.skippedLinks = skippedLinks
        self.rounds = rounds; self.connectionFailures = connectionFailures
        self.damagedChunks = damagedChunks; self.reconnects = reconnects
        self.retransmittedChunks = retransmittedChunks
    }
}

/// One data connection of a drop, as the Internals panel shows it.
public struct StreamInfo: Sendable, Identifiable {
    public var id: Int
    /// The other end, "192.168.1.143:51234".
    public var remote: String
    public var chunks = 0
    public var bytes: Int64 = 0
    public var opened = Date()
    public var lastActivity = Date()
}

/// One drop, in either direction. Thread-safe: the engine's threads write it, the UI polls it.
public class Transfer: @unchecked Sendable, Identifiable {
    public enum Direction: Sendable { case send, receive }

    public let id = UUID()
    public let direction: Direction
    public let startedAt = Date()

    let lock = NSLock()
    private var _state: TransferState
    private var _progress = TransferProgress()
    private var _peerName: String
    private var _peerAddress: String
    private var _items: [String] = []
    private var _savedURLs: [URL] = []
    private var _finishedAt: Date?
    private var _transferStartedAt: Date?
    private var sockets: [Socket] = []
    private var _stats = TransferStats()
    private var _streams: [Int: StreamInfo] = [:]
    private var nextStream = 0
    private var lastActivity = Date()
    var cancelRequested = false

    /// Called on an engine thread whenever the state changes.
    public var onChange: (@Sendable () -> Void)?

    init(direction: Direction, state: TransferState, peerName: String, peerAddress: String) {
        self.direction = direction
        _state = state
        _peerName = peerName
        _peerAddress = peerAddress
    }

    public var state: TransferState { lock.withLock { _state } }
    public var progress: TransferProgress { lock.withLock { _progress } }
    public var peerName: String { lock.withLock { _peerName } }
    public var peerAddress: String { lock.withLock { _peerAddress } }
    /// The top-level names in the drop.
    public var items: [String] { lock.withLock { _items } }
    /// Receiver only, once completed: where each top-level item ended up.
    public var savedURLs: [URL] { lock.withLock { _savedURLs } }
    public var finishedAt: Date? { lock.withLock { _finishedAt } }
    public var stats: TransferStats { lock.withLock { _stats } }
    /// The data connections open right now, oldest first.
    public var dataConnections: [StreamInfo] { lock.withLock { _streams.values.sorted { $0.id < $1.id } } }

    /// A data connection has opened; the number it is known by.
    func streamOpened(remote: String) -> Int {
        lock.withLock {
            nextStream += 1
            _streams[nextStream] = StreamInfo(id: nextStream, remote: remote)
            return nextStream
        }
    }

    /// A whole chunk went over (or came in on) that connection.
    func streamCarried(_ id: Int, bytes: Int) {
        lock.withLock {
            _streams[id]?.chunks += 1
            _streams[id]?.bytes += Int64(bytes)
            _streams[id]?.lastActivity = Date()
            _stats.chunks += 1
        }
    }

    func streamClosed(_ id: Int) { lock.withLock { _streams[id] = nil } }
    /// When bytes started moving (after the scan and the other side's answer).
    public var transferStartedAt: Date? { lock.withLock { _transferStartedAt } }

    /// "Christmas 2026", "a.jpg and 3 more".
    public var title: String {
        let names = items
        guard let first = names.first else { return "…" }
        return names.count == 1 ? first : "\(first) and \(names.count - 1) more"
    }

    // MARK: For the engine

    /// "[3F9A2C send]": which drop a log line is about.
    var tag: String { "[\(id.uuidString.prefix(6)) \(direction == .send ? "send" : "recv")]" }

    func log(_ message: @autoclosure () -> String, _ level: LogLevel = .info) {
        DropLog.write("\(tag) \(message())", level)
    }

    func setState(_ new: TransferState) {
        lock.lock()
        guard !_state.isFinal else { lock.unlock(); return }
        let changed = _state != new
        _state = new
        if new == .transferring, _transferStartedAt == nil { _transferStartedAt = Date() }
        if new.isFinal { _finishedAt = Date() }
        let p = _progress, s = _stats
        lock.unlock()
        if changed {
            log("\(new)" + (new.isFinal || new == .reconnecting
                ? "  (\(p.doneBytes) of \(p.totalBytes) bytes, \(p.doneFiles) of \(p.totalFiles) files; rounds \(s.rounds), connections lost \(s.connectionFailures), damaged chunks \(s.damagedChunks), reconnects \(s.reconnects) in \(s.reconnectAttempts) attempts, chunks \(s.chunks) of which retransmitted \(s.retransmittedChunks))"
                : ""), { if case .failed = new { return .error }; return new == .reconnecting ? .warn : .info }())
        }
        onChange?()
    }

    /// Changes the progress, which also counts as a sign of life.
    func update(_ body: (inout TransferProgress) -> Void) {
        lock.lock()
        body(&_progress)
        lastActivity = Date()
        lock.unlock()
    }

    func note(_ body: (inout TransferStats) -> Void) { lock.withLock { body(&_stats) } }

    /// A message arrived, or something else showed the other side is there.
    func touch() { lock.withLock { lastActivity = Date() } }

    var idleSeconds: Double { lock.withLock { Date().timeIntervalSince(lastActivity) } }

    /// Gives the drop up when nothing has moved and nothing has been said for too long. TCP's
    /// own timeouts catch a peer that is gone; they do not catch one that is there and frozen
    /// (a stopped process, a full disk that blocks, a middlebox that swallows everything).
    func startWatchdog() {
        Thread.detachNewThread { [weak self] in
            while let self, !self.state.isFinal {
                let state = self.state
                // While the receiver puts a large drop in place the sender hears nothing; allow for it.
                let limit = Tuning.stallSeconds * (state == .finishing ? 10 : 3)
                if state == .transferring || (state == .finishing && self.direction == .send), self.idleSeconds > limit {
                    self.touch()
                    self.silence()
                }
                Thread.sleep(forTimeInterval: min(0.25, Tuning.stallSeconds / 8))
            }
        }
    }

    /// Nothing has moved and nothing has been said for too long. The sessions take it as a lost
    /// connection and try to get it back; this is what is left when they cannot.
    func silence() {
        log("no sign of life from \(peerName) for too long; giving up", .error)
        fail(DropError("\(peerName) stopped responding; send the drop again to continue it"))
    }

    func setItems(_ items: [String]) { lock.withLock { _items = items } }
    func setPeerAddress(_ address: String) { lock.withLock { _peerAddress = address } }

    /// A new control connection takes the old one's place (first in the list, where `cancel`
    /// looks for it); the old one is closed.
    func replaceControl(_ old: Socket, with new: Socket) {
        lock.lock()
        sockets.removeAll { $0 === old }
        sockets.insert(new, at: 0)
        let dead = _state.isFinal || cancelRequested
        lock.unlock()
        old.shutdown()
        if dead { new.shutdown() }
    }
    func setSaved(_ urls: [URL]) { lock.withLock { _savedURLs = urls } }

    func untrack(_ socket: Socket) { lock.withLock { sockets.removeAll { $0 === socket } } }

    func track(_ socket: Socket) {
        lock.lock()
        sockets.append(socket)
        let dead = _state.isFinal || cancelRequested
        lock.unlock()
        if dead { socket.shutdown() }
    }

    /// Ends the transfer in `state` (the first ending wins) and unblocks every thread working on it.
    func finish(_ state: TransferState) {
        setState(state)
        let all = lock.withLock { sockets }
        if state != .completed { for s in all { s.shutdown() } }
    }

    func fail(_ error: Error) {
        let cancelled = lock.withLock { cancelRequested }
        finish(cancelled ? .cancelled : .failed((error as? DropError)?.message ?? error.localizedDescription))
    }

    var isOver: Bool { lock.withLock { _state.isFinal || cancelRequested } }

    /// Stops the transfer. What has arrived stays in the receiver's partial folder, so sending
    /// the same drop again continues it.
    public func cancel() {
        lock.lock()
        cancelRequested = true
        let control = sockets.first
        lock.unlock()
        // Best effort, so the other side can say who stopped it rather than "connection lost".
        if let control, !state.isFinal {
            DispatchQueue.global().async { try? control.send(.error, Reason(message: "Cancelled on the other Mac")) }
            DispatchQueue.global().asyncAfter(deadline: .now() + 0.3) { self.finish(.cancelled) }
        } else {
            finish(.cancelled)
        }
    }
}
