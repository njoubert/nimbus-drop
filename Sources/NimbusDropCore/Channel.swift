// Copyright (C) 2026 Niels Joubert
// SPDX-License-Identifier: GPL-3.0-or-later
import Darwin
import Foundation

/// What a connection is for; said in the encrypted hello, so nobody on the path learns it.
enum Purpose: String, Codable {
    /// Send a drop. Both sides must hold a current pairing.
    case drop
    /// Pair, with two spoken codes.
    case pair
    /// Pair, by entering each other's identity numbers.
    case verify
    /// Pick a drop up again after its control connection was lost.
    case resume
    /// "The key that proved this session is retired."
    case retire
    /// Measure the link: a drop's records each way, with no file at either end (protocol 3.1).
    case speed
}

/// The first message inside the encrypted channel, each way.
struct SecureHello: Codable {
    var minor: Int
    var app: String
    var name: String
    /// Seconds the sender's key has left. A duration and not a date: two Macs on a network with
    /// no time server need not agree what day it is.
    var remaining: Double
    /// Whether the sender holds a current pairing with the key it is talking to.
    var paired: Bool
    var purpose: Purpose?
}

/// How every connection begins, in the clear: five bytes saying what it is, then (for a control
/// connection) the protocol majors this side speaks. Nothing else is said before the handshake.
enum Opening {
    static let control = Data("NDROP".utf8)
    static let data = Data("NDATA".utf8)
    /// The majors this copy speaks. (A variable so that a test can claim more.)
    nonisolated(unsafe) static var majors: [UInt8] = [UInt8(protocolVersion)]

    static func mine(_ majors: [UInt8] = Opening.majors) -> Data { control + Data([UInt8(majors.count)]) + Data(majors) }

    /// Reads the rest of a control opening whose first five bytes have been read; returns the
    /// whole opening as sent (it goes into the handshake's prologue) and the majors.
    static func readRest(_ socket: Socket) throws -> (bytes: Data, majors: [UInt8]) {
        var count: UInt8 = 0
        try socket.readExactly(&count, 1)
        guard count >= 1, count <= 16 else { throw DropError.damagedMessage }
        var list = [UInt8](repeating: 0, count: Int(count))
        try list.withUnsafeMutableBytes { try socket.readExactly($0.baseAddress!, Int(count)) }
        return (control + Data([count]) + Data(list), list)
    }

    static func readKind(_ socket: Socket) throws -> Data {
        var kind = [UInt8](repeating: 0, count: 5)
        try kind.withUnsafeMutableBytes { try socket.readExactly($0.baseAddress!, 5) }
        return Data(kind)
    }
}

extension DropError {
    /// The Mac that answered is not the one this drop was meant for. Nothing was said to it.
    static func wrongKey(_ name: String) -> DropError {
        var e = DropError("That is not \(name): the Mac that answered could not prove it is the one you paired with. Nothing was sent.")
        e.identity = true
        return e
    }
    /// A drop needs a pairing first; the app starts one.
    static func notPaired(_ message: String) -> DropError {
        var e = DropError(message)
        e.needsPairing = true
        return e
    }
}

/// A control connection after the handshake: both ends proved, everything sealed.
///
/// A frame on the wire is `[u16 length][u16 length, bits inverted]` and then one Noise transport
/// message of that length. The repeated length catches an accident (a flipped bit in a bare
/// length leaves a reader waiting for bytes that never come); the seal catches everything else.
/// The plaintext is `[u8 type][u8 flags][u32 total length, in a first fragment only]` and bytes;
/// a message too long for one Noise message (65,535 bytes) goes as consecutive fragments.
final class Channel: @unchecked Sendable {
    let socket: Socket
    /// The other end's static key, proved by the handshake.
    let remote: PublicKey
    /// The handshake hash: what both ends saw. Pairing codes and resume proofs are bound to it.
    let h: Data
    /// The third output of the handshake's Split: the root of a drop's data keys.
    let master: Data
    private var sending: CipherState
    private var receiving: CipherState
    private let writeLock = NSLock()
    /// The largest message this side will reassemble. One fragment until a drop is accepted.
    var limit = Channel.fragment

    static let fragment = 65519
    private static let firstBody = fragment - 6
    private static let nextBody = fragment - 2

    private init(socket: Socket, noise: Noise) throws {
        guard let remote = noise.remoteStatic else { throw DropError.notAuthentic }
        self.socket = socket
        self.remote = remote
        h = noise.h
        (sending, receiving, master) = try noise.split()
    }

    // MARK: Raw frames

    static func write(_ socket: Socket, _ body: Data) throws {
        guard body.count <= 65535 else { throw DropError.damagedMessage }
        let n = UInt16(body.count)
        var out = Data([UInt8(n >> 8), UInt8(n & 0xff), UInt8(~n >> 8), UInt8(~n & 0xff)])
        out.append(body)
        try out.withUnsafeBytes { try socket.writeAll($0.baseAddress!, out.count) }
    }

    static func read(_ socket: Socket, limit: Int = 65535) throws -> Data {
        var head = [UInt8](repeating: 0, count: 4)
        try head.withUnsafeMutableBytes { try socket.readExactly($0.baseAddress!, 4) }
        let n = UInt16(head[0]) << 8 | UInt16(head[1]), check = UInt16(head[2]) << 8 | UInt16(head[3])
        guard n == ~check, Int(n) <= limit else { throw DropError.damagedMessage }
        var body = Data(count: Int(n))
        if n > 0 { try body.withUnsafeMutableBytes { try socket.readExactly($0.baseAddress!, Int(n)) } }
        return body
    }

    // MARK: Handshakes

    /// What both sides mix into the handshake before anything else: the protocol's name and
    /// major, and both openings byte for byte as they crossed the wire. An opening altered on
    /// the way leaves the two ends hashing different things, and the handshake fails.
    static func prologue(initiator: Data, responder: Data) -> Data {
        Data("nimbus-drop/\(protocolVersion)".utf8) + initiator + responder
    }

    /// The initiator's side, up to and including message 2: the responder's key is proved and
    /// nothing about this side has been said. `majors` is what the responder speaks.
    private static func begin(_ socket: Socket, keys: KeyPair, ephemeral: KeyPair? = nil) throws -> Noise {
        let mine = Opening.mine()
        try mine.withUnsafeBytes { try socket.writeAll($0.baseAddress!, mine.count) }
        guard try Opening.readKind(socket) == Opening.control else { throw DropError("That is not Nimbus Drop 0.3 or later") }
        let theirs = try Opening.readRest(socket)
        guard theirs.majors.contains(UInt8(protocolVersion)) else {
            throw DropError("The other Mac speaks protocol \(theirs.majors.map(String.init).joined(separator: ", ")); this one speaks \(protocolVersion). Update Nimbus Drop on both.")
        }
        let noise = Noise(initiator: true, prologue: prologue(initiator: mine, responder: theirs.bytes), s: keys, ephemeral: ephemeral)
        try write(socket, try noise.write())
        guard try noise.read(try read(socket, limit: 1024)).isEmpty else { throw DropError.damagedMessage }
        return noise
    }

    /// Asks whatever listens there to prove who it is, and hangs up: opening, Noise messages 1
    /// and 2. The answer is a key that the other end holds; this side has revealed nothing.
    static func probe(host: String, port: UInt16, timeout: TimeInterval = 3) throws -> PublicKey {
        let socket = try Socket.connect(host: host, port: port, timeout: timeout)
        socket.setReadTimeout(Int(timeout.rounded(.up)))
        defer { socket.shutdown() }
        // A throwaway key: a probe says nothing about this Mac.
        let noise = try begin(socket, keys: KeyPair())
        guard let key = noise.remoteStatic else { throw DropError.notAuthentic }
        return key
    }

    /// Connects as the initiator. `expect`: the key the responder must prove; if it proves
    /// another, this side stops before sending its own key or anything else. `check` is asked
    /// about the responder's key at the same point and may refuse it (a retired key).
    /// `ephemeral`: tests only (the vectors fix it).
    static func initiate(_ socket: Socket, keys: KeyPair, expect: PublicKey?, expectName: String = "the Mac you chose", ephemeral: KeyPair? = nil,
                         check: (PublicKey) throws -> Void = { _ in }) throws -> Channel {
        let noise = try begin(socket, keys: keys, ephemeral: ephemeral)
        guard let theirs = noise.remoteStatic else { throw DropError.notAuthentic }
        if let expect, expect != theirs { throw DropError.wrongKey(expectName) }
        try check(theirs)
        try write(socket, try noise.write())
        return try Channel(socket: socket, noise: noise)
    }

    /// The responder's side, after the first five bytes ("NDROP") have been read.
    static func respond(_ socket: Socket, keys: KeyPair, ephemeral: KeyPair? = nil) throws -> Channel {
        let theirs = try Opening.readRest(socket)
        let mine = Opening.mine()
        try mine.withUnsafeBytes { try socket.writeAll($0.baseAddress!, mine.count) }
        guard theirs.majors.contains(UInt8(protocolVersion)) else { throw DropError.damagedMessage }
        let noise = Noise(initiator: false, prologue: prologue(initiator: theirs.bytes, responder: mine), s: keys, ephemeral: ephemeral)
        // A handshake message carries the handshake and nothing else: a payload ends it.
        guard try noise.read(try read(socket, limit: 1024)).isEmpty else { throw DropError.damagedMessage }
        try write(socket, try noise.write())
        guard try noise.read(try read(socket, limit: 1024)).isEmpty else { throw DropError.damagedMessage }
        return try Channel(socket: socket, noise: noise)
    }

    /// Connects, proves both ends and exchanges hellos, as `trust`'s Mac. For tools and tests
    /// that speak the protocol by hand; the sessions have their own, stricter, versions.
    static func dial(host: String, port: UInt16, trust: Trust, name: String, purpose: Purpose?, paired: Bool? = nil) throws -> (channel: Channel, hello: SecureHello) {
        let socket = try Socket.connect(host: host, port: port)
        socket.setReadTimeout(10)
        let channel = try Channel.initiate(socket, keys: trust.keyPair, expect: nil)
        try channel.send(.hello, SecureHello(minor: protocolMinor, app: "test", name: name, remaining: trust.remaining,
                                             paired: paired ?? trust.standing(of: channel.remote).isPaired, purpose: purpose))
        let reply = try channel.read()
        guard reply.type == .hello else { throw DropError.damagedMessage }
        return (channel, try decode(SecureHello.self, from: reply.body))
    }

    // MARK: Messages

    func send<T: Encodable>(_ type: FrameType, _ value: T) throws { try send(type, body: try JSONEncoder().encode(value)) }

    /// A message whose body is already bytes.
    func send(_ type: FrameType, body: Data) throws {
        writeLock.lock()
        defer { writeLock.unlock() }
        var offset = 0, first = true
        repeat {
            let room = first ? Channel.firstBody : Channel.nextBody
            let piece = body[offset..<min(body.count, offset + room)]
            offset += piece.count
            var plain = Data([type.rawValue, offset < body.count ? 1 : 0])
            if first { plain.append(Crypto.be32(UInt32(body.count))) }
            plain.append(piece)
            try Channel.write(socket, try sending.seal(plain))
            first = false
        } while offset < body.count
    }

    /// The next message. Read by one thread at a time. A message longer than `limit` is refused
    /// on its first fragment, before anything is set aside for it.
    func read() throws -> (type: FrameType, body: Data) {
        let head = try receiving.open(try Channel.read(socket))
        guard head.count >= 6, let type = FrameType(rawValue: head[head.startIndex]) else { throw DropError.damagedMessage }
        let total = Int(UInt32(bigEndian: head.dropFirst(2).prefix(4).withUnsafeBytes { $0.loadUnaligned(as: UInt32.self) }))
        var body = Data(head.dropFirst(6))
        var more = head[head.startIndex + 1] & 1 == 1
        guard total <= limit, body.count <= total, more == (body.count < total) else {
            throw DropError(total > limit ? "A message from the other Mac was larger than it is allowed to send" : "A message from the other Mac arrived damaged", connection: total <= limit)
        }
        if more { body.reserveCapacity(total) }
        while more {
            let next = try receiving.open(try Channel.read(socket))
            guard next.count >= 2, next[next.startIndex] == type.rawValue else { throw DropError.damagedMessage }
            body.append(next.dropFirst(2))
            more = next[next.startIndex + 1] & 1 == 1
            guard body.count <= total, more == (body.count < total) else { throw DropError.damagedMessage }
        }
        return (type, body)
    }
}

/// The keys of one drop, all derived from the handshake's `master`. One master per drop: a
/// reconnect proves the same two Macs again and gives the control channel new keys, and changes
/// nothing here, so data connections that outlive a control connection keep working.
struct DropKeys {
    let sessionID: Data
    private let master: Data
    let attachKey: Data
    let resumeKey: Data

    /// At most this many bytes and this many seals under one stream key; then the sender moves
    /// to a new connection, and so to a new key. Far inside what the cipher allows.
    nonisolated(unsafe) static var streamBytes: Int64 = 1 << 38
    static let streamSeals: UInt64 = 1 << 24

    init(master: Data) {
        self.master = master
        sessionID = Crypto.kdf(master, "nimbus-drop session id v1", 16)
        attachKey = Crypto.kdf(master, "nimbus-drop attach v1", 32)
        resumeKey = Crypto.kdf(master, "nimbus-drop resume v1", 32)
    }

    /// The key of data connection number `conn`. A number is used once in a drop, so a key is too.
    func stream(_ conn: UInt64) -> CipherState {
        CipherState(key: Crypto.kdf(master, Data("nimbus-drop stream v1".utf8) + Crypto.be64(conn), 32), limit: DropKeys.streamSeals)
    }

    func attachTag(conn: UInt64, challenge: Data) -> Data {
        Crypto.hmac(attachKey, sessionID + Crypto.be64(conn) + challenge).prefix(16)
    }

    static func resumeProof(_ resumeKey: Data, _ label: String, h: Data) -> Data { Crypto.hmac(resumeKey, Data(label.utf8) + h) }
}

/// The twelve bytes sealed before every chunk on a data connection: which file, which chunk,
/// how long. Sealed by themselves and opened before the chunk is read, so nobody watching can
/// tell where one file ends, and a damaged length is caught at once.
struct RecordHeader {
    static let size = 12
    static let sealedSize = 28
    static let endMarker = UInt32.max
    var file: UInt32
    var chunk: UInt32
    var length: UInt32

    var bytes: Data { Crypto.be32(file) + Crypto.be32(chunk) + Crypto.be32(length) }

    init(file: UInt32, chunk: UInt32, length: UInt32) { self.file = file; self.chunk = chunk; self.length = length }

    /// A whole record as it goes on the wire: the header sealed by itself, then the chunk sealed
    /// with the header as associated data. Two seals, two counts.
    static func seal(_ cipher: inout CipherState, file: UInt32, chunk: UInt32, bytes: UnsafeRawPointer, count: Int) throws -> (header: Data, ciphertext: Data, tag: Data) {
        let header = RecordHeader(file: file, chunk: chunk, length: UInt32(count)).bytes
        let sealedHeader = try cipher.seal(header)
        let body = try cipher.seal(bytes: bytes, count: count, ad: header)
        return (sealedHeader, body.ciphertext, body.tag)
    }

    /// What ends a data connection: exactly this header, sealed, and nothing after it.
    static func sealEnd(_ cipher: inout CipherState) throws -> Data {
        try cipher.seal(RecordHeader(file: endMarker, chunk: 0, length: 0).bytes)
    }

    init?(_ data: Data) {
        guard data.count == RecordHeader.size else { return nil }
        let v = data.withUnsafeBytes { p in (0..<3).map { UInt32(bigEndian: p.loadUnaligned(fromByteOffset: $0 * 4, as: UInt32.self)) } }
        file = v[0]; chunk = v[1]; length = v[2]
    }
}
