// Copyright (C) 2026 Niels Joubert
// SPDX-License-Identifier: GPL-3.0-or-later
import Foundation

/// Who this Mac says it is: the name others see and an id that stays the same across launches
/// (it is what lets a re-sent drop be recognised, and how a Mac leaves itself out of its own list).
public struct Identity: Equatable, Sendable {
    public var name: String
    public var id: String
    public init(name: String, id: String) {
        self.name = name
        self.id = id
    }
}

public enum TransferState: Equatable, Sendable {
    case scanning
    case connecting
    /// Sender: the other person has not answered yet. Receiver: this Mac has not answered yet.
    case waitingForAccept
    case transferring
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

    public var fraction: Double { totalBytes > 0 ? min(1, Double(doneBytes) / Double(totalBytes)) : (doneFiles >= totalFiles ? 1 : 0) }
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
    /// When bytes started moving (after the scan and the other side's answer).
    public var transferStartedAt: Date? { lock.withLock { _transferStartedAt } }

    /// "Christmas 2026", "a.jpg and 3 more".
    public var title: String {
        let names = items
        guard let first = names.first else { return "…" }
        return names.count == 1 ? first : "\(first) and \(names.count - 1) more"
    }

    // MARK: For the engine

    func setState(_ new: TransferState) {
        lock.lock()
        guard !_state.isFinal else { lock.unlock(); return }
        _state = new
        if new == .transferring, _transferStartedAt == nil { _transferStartedAt = Date() }
        if new.isFinal { _finishedAt = Date() }
        lock.unlock()
        onChange?()
    }

    func update(_ body: (inout TransferProgress) -> Void) {
        lock.lock()
        body(&_progress)
        lock.unlock()
    }

    func setItems(_ items: [String]) { lock.withLock { _items = items } }
    func setSaved(_ urls: [URL]) { lock.withLock { _savedURLs = urls } }

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
