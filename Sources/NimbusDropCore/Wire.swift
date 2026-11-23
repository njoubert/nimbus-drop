// Copyright (C) 2026 Niels Joubert
// SPDX-License-Identifier: GPL-3.0-or-later
import Darwin
import Foundation

/// The one error type the engine throws; its message is what the user reads.
public struct DropError: Error, CustomStringConvertible, LocalizedError, Equatable {
    public let message: String
    /// The link's fault rather than anybody's decision: the connection closed, timed out, could
    /// not be made, or carried a damaged message. These are what a drop tries to reconnect after.
    var connection = false
    public init(_ message: String) { self.message = message }
    init(_ message: String, connection: Bool) { self.message = message; self.connection = connection }
    public static func == (a: DropError, b: DropError) -> Bool { a.message == b.message }
    public var description: String { message }
    public var errorDescription: String? { message }
}

func errnoError(_ what: String) -> DropError {
    DropError("\(what): \(String(cString: strerror(errno)))")
}

/// The protocol's version, in two parts.
///
/// **Major** changes when two copies can no longer exchange a drop: a frame's layout, a message's
/// meaning, the chunk header. A receiver declines an offer whose major is not its own, and says
/// which versions are involved. **Minor** changes when something is added that an older copy can
/// ignore (a new optional field, which JSON decoding skips): copies whose majors match work
/// together whatever their minors.
///
/// The app's version changes far more often than either and is carried beside them, for people
/// to read: it never decides compatibility.
///
/// What may never change, because it is how any two versions find out that they differ: the
/// control frame layout (`Socket.send`), and the `version` field of `Offer` and `Hello`.
public let protocolVersion = 2
public let protocolMinor = 1

/// "2.0".
public var protocolVersionText: String { "\(protocolVersion).\(protocolMinor)" }

/// The port the listener asks for first, so a peer can also be reached by address alone. A
/// second copy on the same Mac (or anything else holding it) falls back to an ephemeral port;
/// Bonjour carries whichever it got.
public let defaultPort: UInt16 = 47823

/// The engine's patience, in one place so the tests can shorten it.
enum Tuning {
    /// A data connection that moves nothing for this long is closed and its chunks are sent
    /// again on another. A drop with no sign of life for three times this long is given up.
    nonisolated(unsafe) static var stallSeconds: Double = 60
    /// How long a sender keeps trying to open data connections when none will open.
    nonisolated(unsafe) static var connectRetrySeconds: Double = 30
    nonisolated(unsafe) static var connectTimeout: Double = 10
    /// Repair rounds in a row that deliver nothing before the receiver gives up.
    nonisolated(unsafe) static var idleRounds = 5
    /// How long both sides hold a drop open after the connection that carries the conversation
    /// is lost: the sender trying to reconnect, the receiver waiting for it.
    nonisolated(unsafe) static var reconnectSeconds: Double = 60
    /// How long a receiver waits for connections the sender says it opened but that never arrived.
    nonisolated(unsafe) static var settleSeconds: Double = 1
}

/// A blocking TCP socket. One thread reads it, one writes it; `shutdown()` from any other thread
/// unblocks both, which is how a transfer is cancelled. The descriptor closes with the object.
final class Socket: @unchecked Sendable {
    let fd: Int32
    private let writeLock = NSLock()

    init(fd: Int32) {
        self.fd = fd
        var one: Int32 = 1
        setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &one, socklen_t(MemoryLayout<Int32>.size))
        // A peer that vanishes (cable pulled, lid closed) must not leave a thread blocked for
        // ever: keepalive covers an idle read, the retransmit limit a stalled write.
        setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &one, socklen_t(MemoryLayout<Int32>.size))
        var idle: Int32 = 10, interval: Int32 = 5, count: Int32 = 3, drop: Int32 = 30
        setsockopt(fd, IPPROTO_TCP, TCP_KEEPALIVE, &idle, socklen_t(MemoryLayout<Int32>.size))
        setsockopt(fd, IPPROTO_TCP, TCP_KEEPINTVL, &interval, socklen_t(MemoryLayout<Int32>.size))
        setsockopt(fd, IPPROTO_TCP, TCP_KEEPCNT, &count, socklen_t(MemoryLayout<Int32>.size))
        setsockopt(fd, IPPROTO_TCP, TCP_RXT_CONNDROPTIME, &drop, socklen_t(MemoryLayout<Int32>.size))
    }

    deinit { Darwin.close(fd) }

    /// Unblocks any thread reading or writing this socket; both then fail.
    func shutdown() { _ = Darwin.shutdown(fd, SHUT_RDWR) }

    func setNoDelay() {
        var one: Int32 = 1
        setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, socklen_t(MemoryLayout<Int32>.size))
    }

    /// Seconds a read may block; 0 clears it.
    func setReadTimeout(_ seconds: Int) {
        var tv = timeval(tv_sec: seconds, tv_usec: 0)
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, socklen_t(MemoryLayout<timeval>.size))
    }

    func readExactly(_ buffer: UnsafeMutableRawPointer, _ count: Int, progress: ((Int) -> Void)? = nil) throws {
        var got = 0
        while got < count {
            let n = Darwin.read(fd, buffer + got, count - got)
            if n > 0 {
                got += n
                progress?(n)
            } else if n == 0 {
                throw DropError("The connection closed", connection: true)
            } else if errno != EINTR {
                throw DropError("Connection lost: \(String(cString: strerror(errno)))", connection: true)
            }
        }
    }

    /// Writes everything, at most `slice` bytes per call so `progress` moves on a slow link.
    func writeAll(_ buffer: UnsafeRawPointer, _ count: Int, slice: Int = .max, progress: ((Int) -> Void)? = nil) throws {
        var sent = 0
        while sent < count {
            let n = Darwin.write(fd, buffer + sent, min(slice, count - sent))
            if n > 0 {
                sent += n
                progress?(n)
            } else if n < 0, errno != EINTR {
                throw DropError("Connection lost: \(String(cString: strerror(errno)))", connection: true)
            }
        }
    }

    /// Whether something (data or a hang-up) is waiting to be read within `milliseconds`.
    func waitReadable(milliseconds: Int32) -> Bool {
        var p = pollfd(fd: fd, events: Int16(POLLIN), revents: 0)
        return poll(&p, 1, milliseconds) > 0
    }

    /// The other end's address, numeric, without a port.
    var peerAddress: String {
        var storage = sockaddr_storage()
        var len = socklen_t(MemoryLayout<sockaddr_storage>.size)
        let ok = withUnsafeMutablePointer(to: &storage) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { getpeername(fd, $0, &len) }
        }
        guard ok == 0 else { return "?" }
        var host = [CChar](repeating: 0, count: Int(NI_MAXHOST))
        let rc = withUnsafePointer(to: &storage) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                getnameinfo($0, len, &host, socklen_t(host.count), nil, 0, NI_NUMERICHOST)
            }
        }
        guard rc == 0 else { return "?" }
        var text = String(cString: host)
        // A dual-stack listener sees IPv4 peers as ::ffff:a.b.c.d.
        if text.hasPrefix("::ffff:") { text.removeFirst(7) }
        return text
    }

    // MARK: Connecting and listening

    static func connect(host: String, port: UInt16, timeout: TimeInterval = Tuning.connectTimeout) throws -> Socket {
        var hints = addrinfo()
        hints.ai_socktype = SOCK_STREAM
        var list: UnsafeMutablePointer<addrinfo>?
        let rc = getaddrinfo(host, String(port), &hints, &list)
        guard rc == 0, let first = list else {
            throw DropError("Cannot resolve \(host): \(String(cString: gai_strerror(rc)))", connection: true)
        }
        defer { freeaddrinfo(list) }
        var last = DropError("Cannot connect to \(host)", connection: true)
        var next: UnsafeMutablePointer<addrinfo>? = first
        while let ai = next {
            next = ai.pointee.ai_next
            let fd = socket(ai.pointee.ai_family, ai.pointee.ai_socktype, ai.pointee.ai_protocol)
            if fd < 0 { continue }
            let flags = fcntl(fd, F_GETFL)
            _ = fcntl(fd, F_SETFL, flags | O_NONBLOCK)
            var result = Darwin.connect(fd, ai.pointee.ai_addr, ai.pointee.ai_addrlen)
            if result != 0, errno == EINPROGRESS {
                var p = pollfd(fd: fd, events: Int16(POLLOUT), revents: 0)
                if poll(&p, 1, Int32(timeout * 1000)) > 0 {
                    var err: Int32 = 0
                    var len = socklen_t(MemoryLayout<Int32>.size)
                    getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &len)
                    errno = err
                    result = err == 0 ? 0 : -1
                } else {
                    errno = ETIMEDOUT
                    result = -1
                }
            }
            if result == 0 {
                _ = fcntl(fd, F_SETFL, flags)
                return Socket(fd: fd)
            }
            last = DropError("Cannot connect to \(host): \(String(cString: strerror(errno)))", connection: true)
            Darwin.close(fd)
        }
        throw last
    }

    /// A dual-stack listening socket and the port it got. `port` 0 asks for any free one.
    static func listen(port: UInt16) throws -> (fd: Int32, port: UInt16) {
        let fd = socket(AF_INET6, SOCK_STREAM, 0)
        guard fd >= 0 else { throw errnoError("socket") }
        var off: Int32 = 0, on: Int32 = 1
        setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &off, socklen_t(MemoryLayout<Int32>.size))
        setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, socklen_t(MemoryLayout<Int32>.size))
        var addr = sockaddr_in6()
        addr.sin6_len = UInt8(MemoryLayout<sockaddr_in6>.size)
        addr.sin6_family = sa_family_t(AF_INET6)
        addr.sin6_port = port.bigEndian
        addr.sin6_addr = in6addr_any
        let bound = withUnsafePointer(to: &addr) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { bind(fd, $0, socklen_t(MemoryLayout<sockaddr_in6>.size)) }
        }
        guard bound == 0, Darwin.listen(fd, 64) == 0 else {
            let e = errnoError("Cannot listen on port \(port)")
            Darwin.close(fd)
            throw e
        }
        var got = sockaddr_in6()
        var len = socklen_t(MemoryLayout<sockaddr_in6>.size)
        _ = withUnsafeMutablePointer(to: &got) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { getsockname(fd, $0, &len) }
        }
        return (fd, UInt16(bigEndian: got.sin6_port))
    }

    // MARK: Control frames

    /// `[u32 length][u32 CRC of the length][u8 type][JSON][u32 CRC of type + JSON]`, big-endian;
    /// the length counts the type byte and the JSON. Both checksums exist because TCP's own is
    /// weak: a flipped bit in a manifest is a wrong file name or size, and a flipped bit in a
    /// length would leave the reader waiting for bytes that are never coming.
    func send<T: Encodable>(_ type: FrameType, _ value: T) throws {
        let json = try JSONEncoder().encode(value)
        var frame = Data(capacity: json.count + 13)
        var length = UInt32(json.count + 1).bigEndian
        var lengthCRC = withUnsafeBytes(of: &length) { checksum($0.baseAddress!, 4) }.bigEndian
        withUnsafeBytes(of: &length) { frame.append(contentsOf: $0) }
        withUnsafeBytes(of: &lengthCRC) { frame.append(contentsOf: $0) }
        frame.append(type.rawValue)
        frame.append(json)
        var bodyCRC = frame.withUnsafeBytes { checksum($0.baseAddress! + 8, json.count + 1) }.bigEndian
        withUnsafeBytes(of: &bodyCRC) { frame.append(contentsOf: $0) }
        writeLock.lock()
        defer { writeLock.unlock() }
        try frame.withUnsafeBytes { try writeAll($0.baseAddress!, frame.count) }
    }

    func readFrame() throws -> (type: FrameType, body: Data) {
        var head = [UInt8](repeating: 0, count: 8)
        try head.withUnsafeMutableBytes { try readExactly($0.baseAddress!, 8) }
        let (length, lengthCRC) = head.withUnsafeBytes {
            (UInt32(bigEndian: $0.loadUnaligned(fromByteOffset: 0, as: UInt32.self)),
             UInt32(bigEndian: $0.loadUnaligned(fromByteOffset: 4, as: UInt32.self)))
        }
        let count = Int(length)
        guard head.withUnsafeBytes({ checksum($0.baseAddress!, 4) }) == lengthCRC, count >= 1, count <= maxFrameBytes else {
            throw DropError.damagedMessage
        }
        var data = Data(count: count + 4)
        try data.withUnsafeMutableBytes { (raw: UnsafeMutableRawBufferPointer) in try readExactly(raw.baseAddress!, count + 4) }
        let ok = data.withUnsafeBytes { (raw: UnsafeRawBufferPointer) in
            checksum(raw.baseAddress!, count) == UInt32(bigEndian: raw.loadUnaligned(fromByteOffset: count, as: UInt32.self))
        }
        guard ok, let type = FrameType(rawValue: data[0]) else { throw DropError.damagedMessage }
        return (type, data.subdata(in: 1..<count))
    }
}

extension DropError {
    /// Either a damaged message or something that is not Nimbus Drop at all.
    static let damagedMessage = DropError("A message from the other Mac arrived damaged", connection: true)
}

/// The largest control frame accepted: a manifest of about two million files.
let maxFrameBytes = 512 << 20

enum FrameType: UInt8 {
    case offer = 1, accept, decline, manifest, plan, done, complete, error, attach, hello, resume
}

func decode<T: Decodable>(_ type: T.Type, from body: Data) throws -> T {
    do { return try JSONDecoder().decode(type, from: body) } catch { throw DropError("Malformed message from the other Mac") }
}

// MARK: Messages

/// What the sender proposes; enough for the receiving person to decide.
struct Offer: Codable {
    /// The sender's protocol major, minor, and app version (the last two absent before 2.0).
    var version: Int
    var minor: Int?
    var app: String?
    var senderName: String
    var senderID: String
    /// The top-level names being sent.
    var items: [String]
    var fileCount: Int
    var totalBytes: Int64
}

struct Empty: Codable {}

/// "Who is there?" and its answer: how a Mac added by address gets its name.
struct Hello: Codable { var name: String; var id: String; var version: Int; var minor: Int?; var app: String? }

struct Reason: Codable { var message: String }

/// The receiver's answer to a manifest: what it already holds from an earlier attempt, and the
/// token every data stream must present.
struct Plan: Codable {
    struct Partial: Codable { var file: Int; var chunks: [Int] }
    var token: String
    var completeFiles: [Int]
    var partialFiles: [Partial]
}

/// "Every chunk I had to send has been written." `streams` is how many data connections the
/// sender has opened in all, so the receiver knows how many to wait for.
struct Done: Codable { var streams: Int }

struct Complete: Codable { var saved: [String] }

struct Attach: Codable { var token: String }

/// The 16 bytes before every chunk on a data stream, big-endian. `file == endMarker` ends the
/// stream. The CRC covers the first twelve bytes and then the chunk, so a flipped bit in an index
/// cannot put good bytes in the wrong place.
struct ChunkHeader {
    static let size = 16
    static let endMarker = UInt32.max
    var file: UInt32
    var chunk: UInt32
    var length: UInt32
    var crc: UInt32

    func write(to p: UnsafeMutableRawPointer) {
        p.storeBytes(of: file.bigEndian, toByteOffset: 0, as: UInt32.self)
        p.storeBytes(of: chunk.bigEndian, toByteOffset: 4, as: UInt32.self)
        p.storeBytes(of: length.bigEndian, toByteOffset: 8, as: UInt32.self)
        p.storeBytes(of: crc.bigEndian, toByteOffset: 12, as: UInt32.self)
    }

    init(file: UInt32, chunk: UInt32, length: UInt32, crc: UInt32 = 0) {
        self.file = file; self.chunk = chunk; self.length = length; self.crc = crc
    }

    /// Writes the header at `p`, followed by `length` bytes already in place, and seals both.
    static func seal(_ p: UnsafeMutableRawPointer, file: UInt32, chunk: UInt32, length: Int) {
        ChunkHeader(file: file, chunk: chunk, length: UInt32(length)).write(to: p)
        let crc = checksum(p + size, length, seed: checksum(p, 12))
        p.storeBytes(of: crc.bigEndian, toByteOffset: 12, as: UInt32.self)
    }

    /// Whether the header at `head` and the `length` bytes at `payload` are what was sealed.
    func verifies(head: UnsafeRawPointer, payload: UnsafeRawPointer) -> Bool {
        checksum(payload, Int(length), seed: checksum(head, 12)) == crc
    }

    init(from p: UnsafeRawPointer) {
        file = UInt32(bigEndian: p.loadUnaligned(fromByteOffset: 0, as: UInt32.self))
        chunk = UInt32(bigEndian: p.loadUnaligned(fromByteOffset: 4, as: UInt32.self))
        length = UInt32(bigEndian: p.loadUnaligned(fromByteOffset: 8, as: UInt32.self))
        crc = UInt32(bigEndian: p.loadUnaligned(fromByteOffset: 12, as: UInt32.self))
    }
}
