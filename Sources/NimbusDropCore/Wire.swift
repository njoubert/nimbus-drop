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
    /// The two Macs are not paired (or no longer are): pair, then send again.
    public var needsPairing = false
    /// The Mac that answered is not the one that was meant.
    public var identity = false
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
/// **Major** changes when two copies can no longer exchange a drop. Every connection opens by
/// listing the majors each side speaks, and those openings are bound into the handshake, so the
/// choice cannot be altered on the way. **Minor** changes when something is added that an older
/// copy can ignore (a new optional field, which JSON decoding skips); it travels inside the
/// encrypted hello.
///
/// Protocol 3 is encrypted and authenticated end to end and has nothing in common with 2 on the
/// wire. It does not read, answer or recognise protocol 2 (decided 2026-11-22: it ran on four
/// Macs, all the owner's).
public let protocolVersion = 3
public let protocolMinor = 1

/// "3.0".
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
    /// How long a connection has to say what it is, in all.
    nonisolated(unsafe) static var strangerSeconds: Double = 10
    /// Connections that have not yet said what they are, at once; more are closed on arrival.
    nonisolated(unsafe) static var strangers = 64
    /// Of which from one address. At either limit the oldest gives way to the newcomer.
    nonisolated(unsafe) static var strangersPerAddress = 8
    /// New connections a second from one address, under `arrivalsPerSecond` from all. A Mac
    /// sending several drops at once on 32 connections each opens well over a hundred in a second.
    nonisolated(unsafe) static var arrivalsPerAddress = 200
    /// Of `unattachedPerDrop`, from one address.
    nonisolated(unsafe) static var unattachedPerAddress = 4
    /// Tests only: how long a pairing this Mac starts waits before it connects, as a slow
    /// machine would.
    nonisolated(unsafe) static var pairDialDelay: Double = 0
    /// After a speed test from a key is answered (run, or declined): no other from that key
    /// for this long.
    nonisolated(unsafe) static var speedPauseSeconds: Double = 10
    /// Connections from one paired key that have not yet said what they came for.
    nonisolated(unsafe) static var pairedWaiting = 8
    /// Offers waiting for the person's answer at once, in all and from one address; more are
    /// declined, so that nobody can bury the screen in panels.
    nonisolated(unsafe) static var pendingOffers = 6
    nonisolated(unsafe) static var pendingOffersPerAddress = 2
    /// Connections that have completed a handshake with a key nobody here has paired, at once.
    nonisolated(unsafe) static var unpaired = 8
    /// New connections taken per second, whoever they are from. A handshake costs this Mac a
    /// key generation and two key agreements, about a seventh of a millisecond: this many a
    /// second is under a tenth of one core. (It was 50 at first, and a test showed fifty
    /// strangers arriving in one second then kept a paired Mac out for the rest of it.)
    nonisolated(unsafe) static var arrivalsPerSecond = 500
    /// Requests to pair that may wait behind the one on screen.
    nonisolated(unsafe) static var pairRequestsWaiting = 4
    /// How long a pairing's codes live, and how long a request waits for the person.
    nonisolated(unsafe) static var pairSeconds: Double = 120
    /// After a request to pair is refused, fails or is abandoned, none is shown for this long;
    /// doubled each time up to `pairQuietLongest`, and back to nothing after a success.
    nonisolated(unsafe) static var pairQuietSeconds: Double = 10
    nonisolated(unsafe) static var pairQuietLongest: Double = 600
    /// Data connections that have not yet proved they belong to a drop: this many per drop in
    /// progress, and this long to prove it.
    nonisolated(unsafe) static var unattachedPerDrop = 16
    nonisolated(unsafe) static var attachSeconds: Double = 5
    /// Bytes of control messages being reassembled at once, across every drop.
    nonisolated(unsafe) static var controlBudget = 1 << 30
    /// Data connections one drop may have open.
    nonisolated(unsafe) static var streamsPerDrop = 64
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

    /// The name of this Mac's interface the connection leaves by ("en0", "bridge0"), found
    /// by the local address it has. Nil when it cannot be told.
    var localInterface: String? {
        var storage = sockaddr_storage()
        var len = socklen_t(MemoryLayout<sockaddr_storage>.size)
        guard withUnsafeMutablePointer(to: &storage, { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { getsockname(fd, $0, &len) } }) == 0 else { return nil }
        func text(_ sa: UnsafePointer<sockaddr>, _ n: socklen_t) -> String? {
            var host = [CChar](repeating: 0, count: Int(NI_MAXHOST))
            guard getnameinfo(sa, n, &host, socklen_t(host.count), nil, 0, NI_NUMERICHOST) == 0 else { return nil }
            // "fe80::1%en0" and "::ffff:192.168.1.5" both come down to the address itself.
            return String(cString: host).split(separator: "%").first.map { $0.replacingOccurrences(of: "::ffff:", with: "") }
        }
        guard let mine = withUnsafePointer(to: &storage, { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { text($0, len) } }) else { return nil }
        var list: UnsafeMutablePointer<ifaddrs>?
        guard getifaddrs(&list) == 0 else { return nil }
        defer { freeifaddrs(list) }
        var next = list
        while let ifa = next {
            next = ifa.pointee.ifa_next
            guard let sa = ifa.pointee.ifa_addr, sa.pointee.sa_family == sa_family_t(AF_INET) || sa.pointee.sa_family == sa_family_t(AF_INET6) else { continue }
            if text(sa, socklen_t(sa.pointee.sa_len)) == mine { return String(cString: ifa.pointee.ifa_name) }
        }
        return nil
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

    /// Writes three buffers as one stream of bytes with `writev`, at most `slice` bytes per
    /// call so that `progress` moves on a slow link. For a sealed header, a sealed chunk and its
    /// tag: no copy to join them and no small packet between them.
    func writeAll(_ a: Data, _ b: Data, _ c: Data, slice: Int = .max, progress: ((Int) -> Void)? = nil) throws {
        try a.withUnsafeBytes { pa in
            try b.withUnsafeBytes { pb in
                try c.withUnsafeBytes { pc in
                    var parts = [pa, pb, pc].filter { $0.count > 0 }.map { (base: $0.baseAddress!, left: $0.count) }
                    while !parts.isEmpty {
                        var room = slice
                        var iov: [iovec] = []
                        for p in parts where room > 0 {
                            let n = min(p.left, room)
                            iov.append(iovec(iov_base: UnsafeMutableRawPointer(mutating: p.base), iov_len: n))
                            room -= n
                        }
                        let n = writev(fd, iov, Int32(iov.count))
                        if n < 0 {
                            if errno == EINTR { continue }
                            throw DropError("Connection lost: \(String(cString: strerror(errno)))", connection: true)
                        }
                        progress?(n)
                        var done = n
                        while done > 0, let first = parts.first {
                            if done >= first.left { done -= first.left; parts.removeFirst() } else {
                                parts[0] = (first.base + done, first.left - done)
                                done = 0
                            }
                        }
                    }
                }
            }
        }
    }
}

extension DropError {
    /// Either a damaged message or something that is not Nimbus Drop at all.
    static let damagedMessage = DropError("A message from the other Mac arrived damaged", connection: true)
}

/// The largest control message ever reassembled: a manifest of about two million files.
let maxFrameBytes = 512 << 20

enum FrameType: UInt8 {
    case offer = 1, accept, decline, manifest, plan, done, complete, error, hello, resume, resumed
    case pairRequest = 32, pairGo, commit, nonce, reveal, paired, pairFailed, busy
    case retire = 48, retired
    case speed = 64, speedGo, speedUpDone, speedCount, speedDown, speedDone
}

func decode<T: Decodable>(_ type: T.Type, from body: Data) throws -> T {
    do { return try JSONDecoder().decode(type, from: body) } catch { throw DropError("Malformed message from the other Mac") }
}

// MARK: Messages

/// What the sender proposes; enough for the receiving person to decide. Who the sender is came
/// with the handshake and the hello, not from here.
struct Offer: Codable {
    /// The top-level names being sent.
    var items: [String]
    var fileCount: Int
    var totalBytes: Int64
}

struct Empty: Codable {}

struct Reason: Codable {
    var message: String
    /// With `busy` to a request to pair: the seconds for which requests nobody here asked for
    /// are not being shown. The asking Mac's tile says to start the pairing from this one.
    var pause: Double?
}

/// The receiver's answer to a manifest: what it already holds from an earlier attempt.
struct Plan: Codable {
    struct Partial: Codable { var file: Int; var chunks: [Int] }
    var completeFiles: [Int]
    var partialFiles: [Partial]
}

/// "Every chunk I had to send has been written." `streams` is how many data connections the
/// sender has opened in all, so the receiver knows how many to wait for.
struct Done: Codable {
    var streams: Int
    /// Chunks the sender has sent more than once so far.
    var resent: Int?
}

struct Complete: Codable { var saved: [String] }

/// "This is the drop with that session id, and here is proof that I hold its keys": an HMAC
/// under the drop's resume key over the new connection's handshake hash.
struct Resume: Codable { var session: Data; var proof: Data }
struct Resumed: Codable { var proof: Data }

/// A value in the pairing exchange: the commitment, or one of the two random values.
struct PairValue: Codable { var value: Data }
