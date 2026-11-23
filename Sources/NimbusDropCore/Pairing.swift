// Copyright (C) 2026 Niels Joubert
// SPDX-License-Identifier: GPL-3.0-or-later
import Foundation

/// The two six-digit codes of a pairing, from what both ends saw.
///
/// ```
/// S → R   commit = SHA-256("nimbus-drop pair commit v1" ‖ h ‖ Ns)      Ns: 32 random bytes
/// R → S   Nr                                                             made after commit arrives
/// S → R   Ns                                                             checked against commit
/// codes   = KDF(Ns ‖ Nr, "nimbus-drop pair codes v1" ‖ h, 16)
/// ```
/// `h` is the handshake hash, which covers both static keys: someone in the middle holds two
/// sessions with two different `h`, and for the codes of the two to agree would have to steer a
/// value it cannot see (the sender's is inside the commitment; the receiver's does not exist
/// until the commitment has arrived). Hearing the codes read out tells it nothing it does not
/// already have.
enum PairCodes {
    static func commitment(h: Data, ns: Data) -> Data { Crypto.sha256(Data("nimbus-drop pair commit v1".utf8) + h + ns) }

    /// (the code the receiver shows and the sender types, the code the sender shows and the receiver types)
    static func codes(h: Data, ns: Data, nr: Data) -> (receiver: String, sender: String) {
        let out = Crypto.kdf(ns + nr, Data("nimbus-drop pair codes v1".utf8) + h, 16)
        func six(_ d: Data) -> String {
            var v: UInt64 = 0
            for b in d { v = v << 8 | UInt64(b) }
            return String(format: "%06llu", v % 1_000_000)
        }
        return (six(out.prefix(8)), six(out.suffix(8)))
    }
}

/// One pairing at a time on a Mac, in either role, and the rationing of requests from others.
final class PairingGate: @unchecked Sendable {
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

    var active: PairingSession? { lock.withLock { current.flatMap { $0.state.isFinal ? nil : $0 } } }

    /// A request from someone else was refused, failed or was abandoned: none is shown for a
    /// while, and for longer each time. A success ends that.
    func requestEnded(well: Bool) {
        lock.withLock {
            if well { quiet = 0; quietUntil = .distantPast; return }
            quiet = quiet == 0 ? Tuning.pairQuietSeconds : min(Tuning.pairQuietLongest, quiet * 2)
            quietUntil = Date().addingTimeInterval(quiet)
        }
    }

    var quietSecondsLeft: Double { lock.withLock { max(0, quietUntil.timeIntervalSinceNow) } }
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
    private var expected = ""
    private var tries = 3
    private var localRight = false
    private var remoteRight = false
    private var go: Bool?
    private var replacing: PublicKey?
    private var localName: String?
    private var deadline = Date.distantFuture
    /// A responder's request, when it ends: whether it went well (for the rationing).
    var onEnd: ((Bool) -> Void)?

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
    public var secondsLeft: Double { lock.withLock { max(0, deadline.timeIntervalSinceNow) } }

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
    init(channel: Channel, hello: SecureHello, identity: Identity, trust: Trust) {
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
        guard case .codes(let mine, _) = _state, !localRight else { lock.unlock(); return }
        let right = Crypto.same(Data(digits.utf8), Data(expected.utf8))
        if !right { tries -= 1 }
        let left = tries
        let c = channel
        if right { localRight = true }
        lock.unlock()
        if right {
            set(.confirming)
            do { try c?.send(.paired, Empty()) } catch { end(.failed("The connection was lost")); return }
            finishIfBoth()
        } else if left <= 0 {
            DropLog.write("pairing with \(peerName): three wrong entries; stopped", .warn)
            try? c?.send(.pairFailed, Reason(message: "The codes did not match on the other Mac"))
            end(.failed(byNumber ? "That is not this Mac's identity number. Nothing was paired." : "The codes do not match. Something may be between the two Macs. Nothing was paired."))
        } else {
            set(.codes(mine: mine, triesLeft: left))
        }
    }

    private func finishIfBoth() {
        lock.lock()
        let ready = localRight && remoteRight && !_state.isFinal
        let key = _peerKey, hello = theirs, replacing = replacing, name = localName
        lock.unlock()
        guard ready, let key, let hello else { return }
        do {
            let mac = try trust.store(pairing: key, announced: hello.name, method: byNumber ? "identity number" : "codes", remaining: hello.remaining,
                                      replacing: replacing, name: name)
            end(.paired(mac))
        } catch { end(.failed((error as? DropError)?.message ?? "\(error)")) }
    }

    // MARK: The exchange

    private func initiate(host: String, port: UInt16, expect: PublicKey?) throws {
        guard trust.gate.begin(self) else { throw DropError("This Mac is in the middle of another pairing") }
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
        case .busy: throw DropError(Sanitize.label((try? decode(Reason.self, from: answer.body).message) ?? "\(peerName) is busy", limit: 200))
        case .pairFailed: throw DropError("\(peerName) declined to pair")
        default: throw DropError("Unexpected answer from \(peerName)")
        }
        if byNumber {
            beginCodes(mine: "", expecting: c.remote.identityNumber)
        } else {
            let ns = Crypto.random(32)
            try c.send(.commit, PairValue(value: PairCodes.commitment(h: c.h, ns: ns)))
            let nr = try expectValue(c, .nonce)
            try c.send(.reveal, PairValue(value: ns))
            let codes = PairCodes.codes(h: c.h, ns: ns, nr: nr)
            beginCodes(mine: codes.sender, expecting: codes.receiver)
        }
        try awaitTheirs(c)
    }

    /// A responder's side, on the listener's thread, once the request has reached the front of
    /// the queue and been shown.
    func respond() {
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
            if byNumber {
                beginCodes(mine: "", expecting: c.remote.identityNumber)
            } else {
                let commit = try expectValue(c, .commit)
                // Made only now: the other side has committed and cannot choose its value to suit this one.
                let nr = Crypto.random(32)
                try c.send(.nonce, PairValue(value: nr))
                let ns = try expectValue(c, .reveal)
                guard Crypto.same(PairCodes.commitment(h: c.h, ns: ns), commit) else {
                    throw DropError("The other Mac did not keep to the pairing. Nothing was paired.")
                }
                let codes = PairCodes.codes(h: c.h, ns: ns, nr: nr)
                beginCodes(mine: codes.receiver, expecting: codes.sender)
            }
            try awaitTheirs(c)
        } catch {
            if !state.isFinal { try? channel?.send(.pairFailed, Reason(message: "The pairing was stopped")) }
            end(.failed((error as? DropError)?.message ?? "\(error)"))
        }
    }

    /// One value of the exchange: exactly this type, exactly once, 32 bytes.
    private func expectValue(_ c: Channel, _ type: FrameType) throws -> Data {
        let frame = try c.read()
        guard frame.type == type else { throw DropError("The other Mac did not keep to the pairing. Nothing was paired.") }
        let v = try decode(PairValue.self, from: frame.body).value
        guard v.count == 32 else { throw DropError.damagedMessage }
        return v
    }

    /// The codes are computed here, once; nothing after this point can change what is expected.
    private func beginCodes(mine: String, expecting: String) {
        lock.lock()
        expected = expecting
        tries = 3
        deadline = Date().addingTimeInterval(Tuning.pairSeconds)
        lock.unlock()
        set(.codes(mine: mine, triesLeft: 3))
    }

    /// After the codes are up: the only messages the other side may still send are "my person
    /// typed it right" and "it failed". Either ends this reading.
    private func awaitTheirs(_ c: Channel) throws {
        c.socket.setReadTimeout(Int(Tuning.connectTimeout.rounded(.up)))
        while !state.isFinal {
            if Date() > deadline, !lock.withLock({ localRight && remoteRight }) { throw DropError("The codes ran out of time. Nothing was paired.") }
            guard c.socket.waitReadable(milliseconds: 200) else { continue }
            let frame: (type: FrameType, body: Data)
            do { frame = try c.read() } catch {
                if state.isFinal { return }
                throw DropError("The connection was lost before the pairing finished")
            }
            switch frame.type {
            case .paired:
                let again = lock.withLock { () -> Bool in defer { remoteRight = true }; return remoteRight }
                guard !again else { throw DropError("The other Mac did not keep to the pairing. Nothing was paired.") }
                finishIfBoth()
                // Nothing more is expected; wait for this side's own person.
                while !state.isFinal {
                    if Date() > deadline { throw DropError("The codes ran out of time. Nothing was paired.") }
                    Thread.sleep(forTimeInterval: 0.1)
                }
                return
            case .pairFailed:
                throw DropError(byNumber ? "The other Mac did not accept this Mac's identity number. Nothing was paired."
                                         : "The codes did not match on \(peerName). Something may be between the two Macs. Nothing was paired.")
            default:
                throw DropError("The other Mac did not keep to the pairing. Nothing was paired.")
            }
        }
    }

    /// A responder's request that is not going to be shown: say why and hang up. Not a failure
    /// that counts against anyone.
    func turnAway(_ message: String) {
        try? lock.withLock({ channel })?.send(.busy, Reason(message: message))
        lock.lock()
        _state = .failed(message)
        let s = socket
        lock.unlock()
        DispatchQueue.global().asyncAfter(deadline: .now() + 0.3) { s?.shutdown() }
    }

    /// Whether the other side has hung up or sent something (it should be silent while it waits).
    var channelClosed: Bool { lock.withLock({ socket })?.waitReadable(milliseconds: 0) ?? true }

    /// Ends the pairing from outside (the key was retired meanwhile, the app is quitting).
    public func cancel(_ why: String = "Stopped") {
        if !state.isFinal { try? lock.withLock({ channel })?.send(.pairFailed, Reason(message: "The pairing was stopped")) }
        end(.failed(why))
    }
}
