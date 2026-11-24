// Copyright (C) 2026 Niels Joubert
// SPDX-License-Identifier: GPL-3.0-or-later
import Foundation
import NimbusBase
import NimbusCrypto
import NimbusNet

/// One pairing at a time on a Mac, in either role, and the rationing of requests from others.
package final class PairingGate: @unchecked Sendable {
    private let lock = NSLock()
    private weak var current: PairingSession?
    private var quietUntil = Date.distantPast
    private var quiet = 0.0

    /// Takes the gate for `session`; false when another pairing holds it.
    func begin(_ session: PairingSession) -> Bool {
        lock.withLock {
            if let c = current, c !== session, !c.state.isFinal { return false }
            current = session
            return true
        }
    }

    package var active: PairingSession? { lock.withLock { current.flatMap { $0.state.isFinal ? nil : $0 } } }

    /// A request from someone else was refused, failed or was abandoned: none is shown for a
    /// while, and for longer each time. A success ends that.
    package func requestEnded(well: Bool) {
        lock.withLock {
            if well { quiet = 0; quietUntil = .distantPast; return }
            quiet = quiet == 0 ? Tuning.pairQuietSeconds : min(Tuning.pairQuietLongest, quiet * 2)
            quietUntil = Date().addingTimeInterval(quiet)
        }
    }

    package var quietSecondsLeft: Double { lock.withLock { max(0, quietUntil.timeIntervalSinceNow) } }

    /// Keys this Mac's own person has just started a pairing with, and when. A request from
    /// one of them is one that was asked for, and the pause does not apply to it.
    private var asked: [PublicKey: Date] = [:]

    func asked(_ key: PublicKey) {
        lock.withLock {
            let now = Date()
            asked = asked.filter { now.timeIntervalSince($0.value) < Tuning.pairSeconds }
            if asked.count < 64 { asked[key] = now }
        }
    }

    package func expects(_ key: PublicKey) -> Bool {
        lock.withLock { asked[key].map { Date().timeIntervalSince($0) < Tuning.pairSeconds } ?? false }
    }
}

/// A pairing between this Mac and one other, from either end.
///
/// One transaction, every part of it fixed once set: one connection and its handshake hash, one
/// commitment, one value from each side, one pair of codes, one deadline. Each message is taken
/// once and only in order; anything else ends it. What is stored at the end is the key of this
/// connection's handshake and the answers given in this transaction.
///
/// A Mac stores the pairing only when its own person has typed the right code AND the other Mac
/// has said that its person did too.
public final class PairingSession: @unchecked Sendable, Identifiable {
    public enum State: Equatable, Sendable {
        case connecting
        /// The person at the other Mac (an initiator) or at this one (a responder) has been
        /// asked whether to pair at all.
        case asking
        /// Read `mine` out; type theirs. For a pairing by identity number `mine` is empty.
        case codes(mine: String, triesLeft: Int)
        /// This side's code was right; waiting to hear the same from the other.
        case confirming
        case paired(KnownMac)
        case failed(String)

        public var isFinal: Bool {
            switch self {
            case .paired, .failed: return true
            default: return false
            }
        }
    }

    public let id = UUID()
    /// This Mac started it.
    public let initiator: Bool
    /// By identity number instead of spoken codes.
    public let byNumber: Bool

    private let lock = NSCondition()
    private var _state: State = .connecting
    private var _peerName: String
    private var _peerAddress: String
    private var _peerKey: PublicKey?
    private var _standing: KeyStanding = .unknown
    private var _clash: NameClash?
    private let trust: Trust
    private let identity: Identity
    private var channel: Channel?
    private var socket: Socket?
    private var theirs: SecureHello?
    /// The transaction itself: what each message and each entry means. Everything a pairing's
    /// security rests on is decided there (`PairingMachine`, in the crypto module, which has no
    /// I/O in it); this class is the connection, the person and the clock around it.
    private var machine: PairingMachine?
    private var go: Bool?
    private var replacing: PublicKey?
    private var localName: String?
    private var deadline = Date.distantFuture
    private let dialDelay = Tuning.pairDialDelay
    /// A responder's request, when it ends: whether it went well (for the rationing).
    package var onEnd: ((Bool) -> Void)?

    public var onChange: (@Sendable () -> Void)?

    public var state: State { lock.withLock { _state } }
    public var peerName: String { lock.withLock { _peerName } }
    public var peerAddress: String { lock.withLock { _peerAddress } }
    public var peerKey: PublicKey? { lock.withLock { _peerKey } }
    /// What the other Mac's key was to this Mac before the pairing: `.renew` means it is the
    /// same Mac as before.
    public var standing: KeyStanding { lock.withLock { _standing } }
    /// Set when the other Mac's name is that of a Mac this one already knows under another key.
    public var clash: NameClash? { lock.withLock { _clash } }
    /// This Mac's code, from the moment the codes exist to the end: a window shows it for as
    /// long as the other person still has to type it, which is after this Mac's own entry.
    public var myCode: String { lock.withLock { machine?.mine ?? "" } }
    /// The other Mac has said its person typed this Mac's code. Good for choosing what a
    /// window shows next and for nothing else: anyone at the other end can say it.
    public var otherTyped: Bool { lock.withLock { machine?.remoteRight ?? false } }
    public var secondsLeft: Double { lock.withLock { max(0, deadline.timeIntervalSinceNow) } }
    /// The other Mac turned the request away because it is not showing requests for a while:
    /// for how many seconds, as it said. Starting the pairing from that Mac goes through.
    public var pausedFor: Double? { lock.withLock { _pausedFor } }
    private var _pausedFor: Double?

    // MARK: Starting

    /// An initiator. `expect`: the key the other Mac proved when it was probed; if it proves
    /// another now, the pairing stops. `replacing`: a Known Mac this one takes the place of,
    /// when the person has said so.
    public init(host: String, port: UInt16, peerName: String, identity: Identity, trust: Trust, expect: PublicKey? = nil,
                replacing: PublicKey? = nil, name: String? = nil, byNumber: Bool = false) {
        initiator = true
        self.byNumber = byNumber
        self.trust = trust
        self.identity = identity
        self.replacing = replacing
        localName = name
        _peerName = peerName
        _peerAddress = host
        _peerKey = expect
        Thread.detachNewThread { [self] in
            do { try initiate(host: host, port: port, expect: expect) } catch { end(.failed((error as? DropError)?.message ?? "\(error)")) }
        }
    }

    /// A responder: the handshake and the hellos are done, and the other Mac is about to ask.
    package init(channel: Channel, hello: SecureHello, identity: Identity, trust: Trust) {
        initiator = false
        byNumber = hello.purpose == .verify
        self.trust = trust
        self.identity = identity
        self.channel = channel
        socket = channel.socket
        theirs = hello
        _peerName = Sanitize.label(hello.name, limit: 64)
        _peerAddress = channel.socket.peerAddress
        _peerKey = channel.remote
        _standing = trust.standing(of: channel.remote)
        _clash = trust.nameClash(hello.name, key: channel.remote)
    }

    private func set(_ new: State) {
        lock.lock()
        guard !_state.isFinal else { lock.unlock(); return }
        _state = new
        lock.broadcast()
        lock.unlock()
        onChange?()
    }

    private func end(_ final: State) {
        lock.lock()
        guard !_state.isFinal else { lock.unlock(); return }
        _state = final
        let s = socket
        lock.broadcast()
        lock.unlock()
        var well = false
        if case .paired = final { well = true }
        if case .failed(let why) = final { DropLog.write("pairing with \(peerName) at \(peerAddress) ended: \(why)", .warn) }
        // The last word may still be on its way out; give it a moment before closing.
        DispatchQueue.global().asyncAfter(deadline: .now() + (well ? 1 : 0.3)) { s?.shutdown() }
        onEnd?(well)
        onChange?()
    }

    private func hello() -> SecureHello {
        SecureHello(minor: protocolMinor, app: identity.appVersion, name: identity.name, remaining: trust.remaining,
                    paired: _peerKey.map { trust.standing(of: $0).isPaired } ?? false, purpose: byNumber ? .verify : .pair)
    }

    // MARK: The person's part

    /// A responder's person chose to pair. `replacing`: the Known Mac this one takes the place
    /// of, when they said so; `name`: what to call it here.
    public func proceed(replacing: PublicKey? = nil, name: String? = nil) {
        lock.lock()
        if go == nil { go = true; self.replacing = replacing; localName = name }
        lock.broadcast()
        lock.unlock()
    }

    /// "Not expecting this", or Cancel.
    public func refuse() {
        lock.lock()
        if go == nil { go = false }
        let c = channel
        lock.broadcast()
        lock.unlock()
        if !state.isFinal { try? c?.send(.pairFailed, Reason(message: "The other person stopped the pairing")) }
        end(.failed("Stopped"))
    }

    /// What the person typed: the other Mac's code, or its identity number. A third wrong entry
    /// ends the pairing. The code this is compared with was fixed when the values were
    /// exchanged; a retry is a retry of typing, not a new chance for anyone.
    public func submit(_ typed: String) {
        let digits = PublicKey.digits(typed)
        lock.lock()
        guard case .codes = _state, var m = machine else { lock.unlock(); return }
        let effects = m.step(.typed(digits))
        machine = m
        let c = channel
        lock.unlock()
        for effect in effects {
            switch effect {
            case .confirming: set(.confirming)
            case .send(.paired, _):
                do { try c?.send(.paired, Empty()) } catch { end(.failed("The connection was lost")); return }
            case .send:
                try? c?.send(.pairFailed, Reason(message: "The codes did not match on the other Mac"))
            case .codes(let mine, let left): set(.codes(mine: mine, triesLeft: left))
            case .store: store()
            case .fail(let why):
                DropLog.write("pairing with \(peerName): three wrong entries; stopped", .warn)
                end(.failed(text(why)))
            case .otherTyped: break
            }
        }
    }

    /// The machine said both are true: this Mac's person typed the right code and the other
    /// Mac said its person did. The key stored is the one this connection's handshake proved.
    private func store() {
        lock.lock()
        let ready = !_state.isFinal
        let key = _peerKey, hello = theirs, replacing = replacing, name = localName
        lock.unlock()
        guard ready, let key, let hello else { return }
        do {
            let mac = try trust.store(pairing: key, announced: hello.name, method: byNumber ? "identity number" : "codes", remaining: hello.remaining,
                                      replacing: replacing, name: name)
            end(.paired(mac))
        } catch { end(.failed((error as? DropError)?.message ?? "\(error)")) }
    }

    /// What a person reads when the machine ends the pairing.
    private func text(_ why: PairingMachine.Failure) -> String {
        switch why {
        case .didNotKeep: return "The other Mac did not keep to the pairing. Nothing was paired."
        case .damaged: return DropError.damagedMessage.message
        case .malformed: return "Malformed message from the other Mac"
        case .wrongCode:
            return byNumber ? "That is not this Mac's identity number. Nothing was paired."
                            : "The codes do not match. Something may be between the two Macs. Nothing was paired."
        case .theirsFailed:
            return byNumber ? "The other Mac did not accept this Mac's identity number. Nothing was paired."
                            : "The codes did not match on \(peerName). Something may be between the two Macs. Nothing was paired."
        case .timedOut: return "The codes ran out of time. Nothing was paired."
        }
    }

    // MARK: The exchange

    private func initiate(host: String, port: UInt16, expect: PublicKey?) throws {
        guard trust.gate.begin(self) else { throw DropError("This Mac is in the middle of another pairing") }
        if dialDelay > 0 { Thread.sleep(forTimeInterval: dialDelay) }
        let s = try Socket.connect(host: host, port: port)
        s.setNoDelay()
        s.setReadTimeout(Int(Tuning.connectTimeout.rounded(.up)))
        lock.withLock { socket = s }
        let trust = trust
        let c = try Channel.initiate(s, keys: trust.keyPair, expect: expect, expectName: peerName) { key in
            guard trust.standing(of: key).mayPair else {
                _ = trust.noteRefused(key)
                throw DropError("That Mac's identity was given up or has run out, and cannot be paired. It needs a new one (Reset Identity there).")
            }
        }
        lock.withLock { channel = c; _peerKey = c.remote; _standing = trust.standing(of: c.remote) }
        // This Mac's person has asked for a pairing with this key: a request from it in the
        // next two minutes is one they are expecting.
        trust.gate.asked(c.remote)
        try c.send(.hello, hello())
        let reply = try c.read()
        guard reply.type == .hello else { throw DropError("Unexpected answer from \(peerName)") }
        let h = try decode(SecureHello.self, from: reply.body)
        lock.withLock { theirs = h; _clash = trust.nameClash(h.name, key: c.remote) }
        try c.send(.pairRequest, Empty())
        deadline = Date().addingTimeInterval(Tuning.pairSeconds)
        set(.asking)
        // Their person has two minutes to say yes.
        s.setReadTimeout(Int(Tuning.pairSeconds.rounded(.up)) + 2)
        let answer = try c.read()
        switch answer.type {
        case .pairGo: break
        case .busy:
            let reason = try? decode(Reason.self, from: answer.body)
            // A number from another machine: held to what a pause can be before anything shows it.
            if let p = reason?.pause, p.isFinite, p > 0 { lock.withLock { _pausedFor = min(p, 600) } }
            throw DropError(Sanitize.label(reason?.message ?? "\(peerName) is busy", limit: 200))
        case .pairFailed: throw DropError("\(peerName) declined to pair")
        default: throw DropError("Unexpected answer from \(peerName)")
        }
        try exchange(c, as: .initiator)
    }

    /// A responder's side, on the listener's thread, once the request has reached the front of
    /// the queue and been shown.
    package func respond() {
        do {
            guard let c = channel, let s = socket else { throw DropError.notAuthentic }
            // Wait for the person here, while noticing the other side giving up.
            deadline = Date().addingTimeInterval(Tuning.pairSeconds)
            set(.asking)
            var decided: Bool?
            while decided == nil {
                if state.isFinal { return }
                if Date() > deadline { throw DropError("Nobody answered in time") }
                if s.waitReadable(milliseconds: 200) { throw DropError("\(peerName) gave up") }
                decided = lock.withLock { go }
            }
            guard decided == true else { return }
            guard trust.gate.begin(self) else {
                try? c.send(.busy, Reason(message: "\(identity.name) is in the middle of another pairing"))
                throw DropError("This Mac is in the middle of another pairing")
            }
            s.setReadTimeout(Int(Tuning.connectTimeout.rounded(.up)))
            try c.send(.pairGo, Empty())
            try exchange(c, as: .responder)
        } catch {
            if !state.isFinal { try? channel?.send(.pairFailed, Reason(message: "The pairing was stopped")) }
            end(.failed((error as? DropError)?.message ?? "\(error)"))
        }
    }

    /// The exchange, from the moment both people have agreed to pair until it ends: every
    /// message that arrives is handed to the machine, and what the machine says is done. Until
    /// the codes are up a message is waited for; after that the only things the other side may
    /// still say are "my person typed it right" and "it failed", and the codes have a deadline.
    private func exchange(_ c: Channel, as role: PairingMachine.Role) throws {
        // The identity number costs thousands of hashes; it is worked out only when it is used.
        let m = PairingMachine(role: role, byNumber: byNumber, h: c.h, theirNumber: byNumber ? c.remote.identityNumber : "")
        lock.withLock { machine = m }
        try perform(step(.begin), on: c)
        var polling = false
        while !state.isFinal {
            let codesUp = lock.withLock { machine?.phase == .codes }
            if codesUp {
                if !polling { c.socket.setReadTimeout(Int(Tuning.connectTimeout.rounded(.up))); polling = true }
                if Date() > deadline { try perform(step(.timeout), on: c) }
                guard c.socket.waitReadable(milliseconds: 200) else { continue }
            }
            let frame: (type: FrameType, body: Data)
            do { frame = try c.read() } catch {
                if state.isFinal { return }
                if codesUp { throw DropError("The connection was lost before the pairing finished") }
                throw error
            }
            let event: PairingMachine.Event
            switch frame.type {
            case .commit: event = .received(.commit, value: (try? decode(PairValue.self, from: frame.body))?.value)
            case .nonce: event = .received(.nonce, value: (try? decode(PairValue.self, from: frame.body))?.value)
            case .reveal: event = .received(.reveal, value: (try? decode(PairValue.self, from: frame.body))?.value)
            case .paired: event = .received(.paired, value: nil)
            case .pairFailed: event = .received(.failed, value: nil)
            default: event = .received(.other, value: nil)
            }
            try perform(step(event), on: c)
        }
    }

    private func step(_ event: PairingMachine.Event) -> [PairingMachine.Effect] {
        lock.withLock {
            guard var m = machine else { return [] }
            defer { machine = m }
            return m.step(event)
        }
    }

    /// Does what the machine said, on the thread that reads the connection. A failure is
    /// thrown, and ends the pairing where `initiate` and `respond` catch it.
    private func perform(_ effects: [PairingMachine.Effect], on c: Channel) throws {
        for effect in effects {
            switch effect {
            case .send(let message, let value):
                switch message {
                case .commit: try c.send(.commit, PairValue(value: value ?? Data()))
                case .nonce: try c.send(.nonce, PairValue(value: value ?? Data()))
                case .reveal: try c.send(.reveal, PairValue(value: value ?? Data()))
                case .paired: try c.send(.paired, Empty())
                case .failed, .other: try? c.send(.pairFailed, Reason(message: "The pairing was stopped"))
                }
            case .codes(let mine, let left):
                // The codes are computed once; nothing after this point can change what is expected.
                lock.withLock { deadline = Date().addingTimeInterval(Tuning.pairSeconds) }
                set(.codes(mine: mine, triesLeft: left))
            case .confirming: set(.confirming)
            case .otherTyped: onChange?()
            case .store: store()
            case .fail(.damaged): throw DropError.damagedMessage
            case .fail(let why): throw DropError(text(why))
            }
        }
    }

    /// A responder's request that is not going to be shown: say why and hang up. Not a failure
    /// that counts against anyone.
    package func turnAway(_ message: String, pause: Double? = nil) {
        try? lock.withLock({ channel })?.send(.busy, Reason(message: message, pause: pause))
        lock.lock()
        _state = .failed(message)
        let s = socket
        lock.unlock()
        DispatchQueue.global().asyncAfter(deadline: .now() + 0.3) { s?.shutdown() }
    }

    /// Whether the other side has hung up or sent something (it should be silent while it waits).
    package var channelClosed: Bool { lock.withLock({ socket })?.waitReadable(milliseconds: 0) ?? true }

    /// Ends the pairing from outside (the key was retired meanwhile, the app is quitting).
    public func cancel(_ why: String = "Stopped") {
        if !state.isFinal { try? lock.withLock({ channel })?.send(.pairFailed, Reason(message: "The pairing was stopped")) }
        end(.failed(why))
    }
}

/// The security core's knobs: how long a pairing may take and how requests are rationed.
extension Tuning {
    /// Tests only: how long a pairing this Mac starts waits before it connects, as a slow
    /// machine would.
    package nonisolated(unsafe) static var pairDialDelay: Double = 0
    /// How long a pairing's codes live, and how long a request waits for the person.
    package nonisolated(unsafe) static var pairSeconds: Double = 120
    /// After a request to pair is refused, fails or is abandoned, none is shown for this long;
    /// doubled each time up to `pairQuietLongest`, and back to nothing after a success.
    package nonisolated(unsafe) static var pairQuietSeconds: Double = 10
    package nonisolated(unsafe) static var pairQuietLongest: Double = 600
}
