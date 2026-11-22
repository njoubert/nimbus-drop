// Copyright (C) 2026 Niels Joubert
// SPDX-License-Identifier: GPL-3.0-or-later
import Darwin
import Foundation

/// A TCP proxy that misbehaves on cue, for testing what a protocol does when the network turns
/// bad. A client connects to `port`; the proxy connects on to the target and carries bytes both
/// ways, subject to `Conditions` that a test changes while the traffic flows: at a time, or
/// once a number of bytes has passed, so a run repeats exactly.
///
/// What it can and cannot imitate. It sits above TCP, so it handles byte streams, not packets:
///
/// - **Bandwidth** (`bytesPerSecond`): real. A token bucket shared by every connection.
/// - **Connection drops** (`kill`, `refuseNew`): real. The sockets are closed under the traffic.
/// - **Stalls** (`blackhole`): real. Bytes stop moving and nothing is closed, which is what a
///   frozen peer or a link that swallows everything looks like.
/// - **Corruption** (`corruptEvery`, `plantFlip`): real, and worse than a network usually
///   manages, because it happens after TCP's checksum has been satisfied. This is the case an
///   end-to-end checksum exists for.
/// - **Packet loss** (`loss`): imitated. TCP hides loss from the application; what gets through
///   is delay (a retransmission timeout per lost segment) and the throughput that follows from
///   it. The proxy charges that delay per lost segment. Real per-packet loss, with TCP's own
///   congestion response, needs the kernel (`dnctl`/`pfctl`, root).
///
/// It knows nothing about Nimbus Drop. Connections are numbered in the order they arrive;
/// `Scope.control` is the first and `Scope.data` the rest, which is how a drop opens them.
public final class ChaosProxy: @unchecked Sendable {

    public enum Scope: Sendable { case all, control, data }

    public struct Conditions: Sendable {
        /// The link's capacity, shared by all connections in both directions; nil is unlimited.
        public var bytesPerSecond: Int?
        /// The chance that any one 1460-byte segment is "lost", 0…1.
        public var loss: Double = 0
        /// What each lost segment costs: about a retransmission timeout.
        public var lossPenalty: Double = 0.2
        /// Flip one bit in roughly every this many bytes heading to the target; nil is never.
        public var corruptEvery: Int?
        public var corruptScope: Scope = .data
        /// Carry nothing, close nothing.
        public var blackhole = false
        /// Close new connections as soon as they arrive.
        public var refuseNew = false
        public init() {}
    }

    public struct Stats: Sendable {
        public var connections = 0
        public var bytesToTarget: Int64 = 0
        public var bytesToClient: Int64 = 0
        public var bitsFlipped = 0
        public var segmentsLost = 0
        public var connectionsKilled = 0
        public var connectionsRefused = 0
    }

    public let port: UInt16
    private let targetHost: String
    private let targetPort: UInt16
    private let listenFD: Int32

    private let lock = NSLock()
    private var conditions = Conditions()
    private var _stats = Stats()
    private var connections: [Connection] = []
    private var stopped = false
    private var rng: UInt64
    private var tokens: Double = 0
    private var lastRefill = Date()
    private var untilNextFlip: Int?
    private var byteTriggers: [(at: Int64, action: @Sendable (ChaosProxy) -> Void)] = []
    private var plantedFlips: [(connection: Int, offset: Int64, bit: Int?)] = []

    private final class Connection {
        let index: Int
        let client: Int32
        let target: Int32
        var toTarget: Int64 = 0
        var open = 2
        var dead = false
        init(index: Int, client: Int32, target: Int32) { self.index = index; self.client = client; self.target = target }
    }

    /// Listens on `listenPort` (0: any free port) and forwards to the target. `seed` fixes every
    /// random choice (which segments are lost, where bits flip).
    public init(targetHost: String = "127.0.0.1", targetPort: UInt16, listenPort: UInt16 = 0, seed: UInt64 = 1) throws {
        self.targetHost = targetHost
        self.targetPort = targetPort
        rng = seed &+ 0x9E37_79B9_7F4A_7C15
        let fd = socket(AF_INET6, SOCK_STREAM, 0)
        guard fd >= 0 else { throw ChaosError("socket: \(String(cString: strerror(errno)))") }
        var off: Int32 = 0, on: Int32 = 1
        setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &off, 4)
        setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, 4)
        var addr = sockaddr_in6()
        addr.sin6_len = UInt8(MemoryLayout<sockaddr_in6>.size)
        addr.sin6_family = sa_family_t(AF_INET6)
        addr.sin6_port = listenPort.bigEndian
        addr.sin6_addr = in6addr_any
        let bound = withUnsafePointer(to: &addr) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { bind(fd, $0, socklen_t(MemoryLayout<sockaddr_in6>.size)) }
        }
        guard bound == 0, listen(fd, 64) == 0 else {
            let e = ChaosError("cannot listen on \(listenPort): \(String(cString: strerror(errno)))")
            close(fd)
            throw e
        }
        var got = sockaddr_in6()
        var len = socklen_t(MemoryLayout<sockaddr_in6>.size)
        _ = withUnsafeMutablePointer(to: &got) { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { getsockname(fd, $0, &len) } }
        listenFD = fd
        port = UInt16(bigEndian: got.sin6_port)
    }

    deinit { close(listenFD) }

    // MARK: Scripting

    public var stats: Stats { lock.withLock { _stats } }
    public var current: Conditions { lock.withLock { conditions } }

    /// Changes the conditions, now.
    public func set(_ change: (inout Conditions) -> Void) {
        lock.lock()
        let before = conditions.bytesPerSecond
        change(&conditions)
        if conditions.bytesPerSecond != before { tokens = 0; lastRefill = Date() }
        if conditions.corruptEvery == nil { untilNextFlip = nil }
        lock.unlock()
    }

    /// Runs `action` once this many bytes in total have been carried toward the target.
    public func whenForwarded(bytes: Int64, _ action: @escaping @Sendable (ChaosProxy) -> Void) {
        lock.withLock { byteTriggers.append((bytes, action)) }
    }

    /// Runs `action` this long from now.
    public func after(seconds: Double, _ action: @escaping @Sendable (ChaosProxy) -> Void) {
        DispatchQueue.global().asyncAfter(deadline: .now() + seconds) { [weak self] in
            guard let self, !self.lock.withLock({ self.stopped }) else { return }
            action(self)
        }
    }

    /// Flips one bit of the byte at `offset` in what connection number `connection` sends to
    /// the target: damage at an exact place (a length field, a chunk index). `bit` picks which
    /// bit, 0 the lowest; nil leaves it to the seed.
    public func plantFlip(connection: Int, offset: Int64, bit: Int? = nil) {
        lock.withLock { plantedFlips.append((connection, offset, bit)) }
    }

    /// Closes connections under the traffic, as a dropped link or a reset would. Returns how many.
    @discardableResult
    public func kill(_ scope: Scope = .all) -> Int {
        let victims = lock.withLock { connections.filter { !$0.dead && matches(scope, $0.index) } }
        for c in victims { drop(c) }
        return victims.count
    }

    /// Closes one data connection, the oldest still open.
    @discardableResult
    public func killOneData() -> Bool {
        guard let c = lock.withLock({ connections.first { !$0.dead && $0.index > 0 } }) else { return false }
        drop(c)
        return true
    }

    public var openConnections: Int { lock.withLock { connections.filter { !$0.dead }.count } }

    private func matches(_ scope: Scope, _ index: Int) -> Bool {
        switch scope {
        case .all: return true
        case .control: return index == 0
        case .data: return index > 0
        }
    }

    private func drop(_ c: Connection) {
        lock.lock()
        let was = c.dead
        c.dead = true
        if !was { _stats.connectionsKilled += 1 }
        lock.unlock()
        guard !was else { return }
        shutdown(c.client, SHUT_RDWR)
        shutdown(c.target, SHUT_RDWR)
    }

    // MARK: Running

    public func start() {
        Thread.detachNewThread { [self] in
            while !lock.withLock({ stopped }) {
                var p = pollfd(fd: listenFD, events: Int16(POLLIN), revents: 0)
                guard poll(&p, 1, 100) > 0 else { continue }
                let client = accept(listenFD, nil, nil)
                guard client >= 0 else { continue }
                if lock.withLock({ conditions.refuseNew }) {
                    lock.withLock { _stats.connectionsRefused += 1 }
                    close(client)
                    continue
                }
                guard let target = connectToTarget() else { close(client); continue }
                for fd in [client, target] {
                    var one: Int32 = 1
                    setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &one, 4)
                    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, 4)
                }
                lock.lock()
                let c = Connection(index: _stats.connections, client: client, target: target)
                _stats.connections += 1
                connections.append(c)
                lock.unlock()
                Thread.detachNewThread { [self] in pump(c, from: client, to: target, towardTarget: true) }
                Thread.detachNewThread { [self] in pump(c, from: target, to: client, towardTarget: false) }
            }
        }
    }

    /// Stops accepting and closes everything.
    public func stop() {
        lock.withLock { stopped = true }
        kill(.all)
    }

    private func connectToTarget() -> Int32? {
        var hints = addrinfo()
        hints.ai_socktype = SOCK_STREAM
        var list: UnsafeMutablePointer<addrinfo>?
        guard getaddrinfo(targetHost, String(targetPort), &hints, &list) == 0 else { return nil }
        defer { freeaddrinfo(list) }
        var next = list
        while let ai = next {
            next = ai.pointee.ai_next
            let fd = socket(ai.pointee.ai_family, ai.pointee.ai_socktype, ai.pointee.ai_protocol)
            if fd < 0 { continue }
            if connect(fd, ai.pointee.ai_addr, ai.pointee.ai_addrlen) == 0 { return fd }
            close(fd)
        }
        return nil
    }

    private func pump(_ c: Connection, from: Int32, to: Int32, towardTarget: Bool) {
        let capacity = 16 << 10
        let buffer = UnsafeMutablePointer<UInt8>.allocate(capacity: capacity)
        defer { buffer.deallocate() }
        var clean = false
        loop: while true {
            // Small reads under a low cap, so the bucket meters smoothly rather than in bursts.
            let rate = lock.withLock { conditions.bytesPerSecond }
            let want = rate.map { max(256, min(capacity, $0 / 20)) } ?? capacity
            let n = read(from, buffer, want)
            if n < 0, errno == EINTR { continue }
            // A link that swallows everything swallows the news that a connection closed, too:
            // neither bytes nor an end of stream get across until it lifts.
            while lock.withLock({ conditions.blackhole && !c.dead && !stopped }) { usleep(20_000) }
            if n == 0 { clean = true; break }
            if n < 0 || lock.withLock({ c.dead }) { break }
            let wait = charge(n)
            if wait > 0 { Thread.sleep(forTimeInterval: wait) }
            if towardTarget { damage(c, buffer, n) }

            var sent = 0
            while sent < n {
                let w = write(to, buffer + sent, n - sent)
                if w > 0 { sent += w } else if w < 0, errno == EINTR { continue } else { break loop }
            }
            fire(c, n, towardTarget)
        }
        if clean {
            shutdown(to, SHUT_WR)   // pass the end of the stream on, let the other direction finish
        } else {
            drop(c)
        }
        lock.lock()
        c.open -= 1
        let last = c.open == 0
        if last { c.dead = true }
        lock.unlock()
        if last {
            close(c.client)
            close(c.target)
        }
    }

    /// The delay `n` bytes owe: their place in the token bucket, plus a timeout per lost segment.
    private func charge(_ n: Int) -> Double {
        lock.lock()
        defer { lock.unlock() }
        var wait = 0.0
        if let rate = conditions.bytesPerSecond, rate > 0 {
            let now = Date()
            tokens = min(Double(rate) / 10, tokens + now.timeIntervalSince(lastRefill) * Double(rate))
            lastRefill = now
            tokens -= Double(n)
            if tokens < 0 { wait = -tokens / Double(rate) }
        }
        if conditions.loss > 0 {
            var lost = 0
            for _ in 0..<max(1, (n + 1459) / 1460) where random() < conditions.loss { lost += 1 }
            _stats.segmentsLost += lost
            wait += Double(lost) * conditions.lossPenalty
        }
        return wait
    }

    private func damage(_ c: Connection, _ buffer: UnsafeMutablePointer<UInt8>, _ n: Int) {
        lock.lock()
        defer { lock.unlock() }
        let start = c.toTarget
        plantedFlips.removeAll { flip in
            guard flip.connection == c.index, flip.offset >= start, flip.offset < start + Int64(n) else { return false }
            buffer[Int(flip.offset - start)] ^= 1 << UInt8(flip.bit ?? Int(next() % 8))
            _stats.bitsFlipped += 1
            return true
        }
        guard let every = conditions.corruptEvery, every > 0, matches(conditions.corruptScope, c.index) else { return }
        var left = untilNextFlip ?? Int(next() % UInt64(every)) + 1
        var at = 0
        while left <= n - at {
            at += left
            buffer[at - 1] ^= 1 << UInt8(next() % 8)
            _stats.bitsFlipped += 1
            left = every / 2 + Int(next() % UInt64(every)) + 1   // every, give or take half
        }
        untilNextFlip = left - (n - at)
    }

    private func fire(_ c: Connection, _ n: Int, _ towardTarget: Bool) {
        lock.lock()
        if towardTarget {
            c.toTarget += Int64(n)
            _stats.bytesToTarget += Int64(n)
        } else {
            _stats.bytesToClient += Int64(n)
        }
        let total = _stats.bytesToTarget
        let due = byteTriggers.filter { $0.at <= total }
        byteTriggers.removeAll { $0.at <= total }
        lock.unlock()
        for t in due { t.action(self) }
    }

    // SplitMix64: small, seedable, good enough to decide which segment is unlucky.
    private func next() -> UInt64 {
        rng &+= 0x9E37_79B9_7F4A_7C15
        var z = rng
        z = (z ^ (z >> 30)) &* 0xBF58_476D_1CE4_E5B9
        z = (z ^ (z >> 27)) &* 0x94D0_49BB_1331_11EB
        return z ^ (z >> 31)
    }

    private func random() -> Double { Double(next() >> 11) / Double(1 << 53) }
}

public struct ChaosError: Error, CustomStringConvertible {
    public let description: String
    public init(_ description: String) { self.description = description }
}
