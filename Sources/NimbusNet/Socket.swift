// Copyright (C) 2026 Niels Joubert
// SPDX-License-Identifier: GPL-3.0-or-later
import Darwin
import Foundation
import NimbusBase

/// The port the listener asks for first, so a peer can also be reached by address alone. A
/// second copy on the same Mac (or anything else holding it) falls back to an ephemeral port;
/// Bonjour carries whichever it got.
public let defaultPort: UInt16 = 47823

/// A blocking TCP socket. One thread reads it, one writes it; `shutdown()` from any other thread
/// unblocks both, which is how a transfer is cancelled. The descriptor closes with the object.
package final class Socket: @unchecked Sendable {
    let fd: Int32
    private let writeLock = NSLock()

    package init(fd: Int32) {
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
    package func shutdown() { _ = Darwin.shutdown(fd, SHUT_RDWR) }

    package func setNoDelay() {
        var one: Int32 = 1
        setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, socklen_t(MemoryLayout<Int32>.size))
    }

    /// Seconds a read may block; 0 clears it.
    package func setReadTimeout(_ seconds: Int) {
        var tv = timeval(tv_sec: seconds, tv_usec: 0)
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, socklen_t(MemoryLayout<timeval>.size))
    }

    package func readExactly(_ buffer: UnsafeMutableRawPointer, _ count: Int, progress: ((Int) -> Void)? = nil) throws {
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
    package func writeAll(_ buffer: UnsafeRawPointer, _ count: Int, slice: Int = .max, progress: ((Int) -> Void)? = nil) throws {
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
    package func waitReadable(milliseconds: Int32) -> Bool {
        var p = pollfd(fd: fd, events: Int16(POLLIN), revents: 0)
        return poll(&p, 1, milliseconds) > 0
    }

    /// The name of this Mac's interface the connection leaves by ("en0", "bridge0"), found
    /// by the local address it has. Nil when it cannot be told.
    package var localInterface: String? {
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
    package var peerAddress: String {
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

    package static func connect(host: String, port: UInt16, timeout: TimeInterval = Tuning.connectTimeout) throws -> Socket {
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
    package static func listen(port: UInt16) throws -> (fd: Int32, port: UInt16) {
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
    package func writeAll(_ a: Data, _ b: Data, _ c: Data, slice: Int = .max, progress: ((Int) -> Void)? = nil) throws {
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
    package static let damagedMessage = DropError("A message from the other Mac arrived damaged", connection: true)
}

extension Tuning {
    package nonisolated(unsafe) static var connectTimeout: Double = 10
}
