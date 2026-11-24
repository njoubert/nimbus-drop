// Copyright (C) 2026 Niels Joubert
// SPDX-License-Identifier: GPL-3.0-or-later
import Foundation

/// What a speed test found: bytes carried each way, and over how long, as counted by the end
/// that received them.
public struct SpeedResult: Equatable, Sendable {
    public var upBytes: Int64 = 0
    public var upSeconds: Double = 0
    public var downBytes: Int64 = 0
    public var downSeconds: Double = 0
    public var streams = 0
    /// Bytes a second from this Mac to the other, and back.
    public var upRate: Double { upSeconds > 0 ? Double(upBytes) / upSeconds : 0 }
    public var downRate: Double { downSeconds > 0 ? Double(downBytes) / downSeconds : 0 }
}

struct SpeedAsk: Codable { var seconds: Double; var streams: Int }
struct SpeedCount: Codable { var bytes: Int64; var seconds: Double }

/// The data path of a speed test, the same at both ends: a drop's records, with nothing read
/// from a file and nothing written to one (the plan's Addendum B).
enum SpeedWire {
    static let chunk = Scanner.defaultChunkSize
    /// The most a Mac will grant, whatever is asked.
    static let longest = 30.0
    static let mostStreams = 32

    /// Bytes received and when, across the connections of one direction.
    final class Meter: @unchecked Sendable {
        private let lock = NSLock()
        private var _bytes: Int64 = 0
        private var first: Date?
        private var last: Date?

        func add(_ n: Int) {
            lock.withLock {
                let now = Date()
                if first == nil { first = now }
                last = now
                _bytes += Int64(n)
            }
        }
        /// The clock starts when the first connection begins to read, not at its first record.
        func began() { lock.withLock { if first == nil { first = Date() } } }
        var bytes: Int64 { lock.withLock { _bytes } }
        var seconds: Double { lock.withLock { first.flatMap { f in last.map { $0.timeIntervalSince(f) } } ?? 0 } }
    }

    /// Sends records on one connection until `until` or `over`, then the end marker. Returns
    /// the bytes sent (not counting the 44 around each chunk).
    @discardableResult
    static func send(_ socket: Socket, cipher: inout CipherState, until: Date, over: () -> Bool, sent: (Int) -> Void = { _ in }) throws -> Int64 {
        let buffer = UnsafeMutableRawPointer.allocate(byteCount: chunk, alignment: 16384)
        defer { buffer.deallocate() }
        // Not zeros: what is sealed should look like what a drop seals.
        arc4random_buf(buffer, chunk)
        var counter: UInt32 = 0
        var total: Int64 = 0
        while Date() < until, !over(), cipher.count + 3 <= cipher.limit {
            let record = try RecordHeader.seal(&cipher, file: 0, chunk: counter, bytes: buffer, count: chunk)
            try socket.writeAll(record.header, record.ciphertext, record.tag, slice: 256 << 10)
            counter &+= 1
            total += Int64(chunk)
            sent(chunk)
        }
        let end = try RecordHeader.sealEnd(&cipher)
        try end.withUnsafeBytes { try socket.writeAll($0.baseAddress!, end.count) }
        return total
    }

    /// Reads records on one connection until the end marker, opening each and throwing it
    /// away. A record that does not open, or that is not a speed test's, ends the connection.
    static func receive(_ socket: Socket, cipher: inout CipherState, meter: Meter, over: () -> Bool) throws {
        let buffer = UnsafeMutableRawPointer.allocate(byteCount: chunk + 16, alignment: 16384)
        defer { buffer.deallocate() }
        var sealedHeader = Data(count: RecordHeader.sealedSize)
        meter.began()
        while !over() {
            try sealedHeader.withUnsafeMutableBytes { try socket.readExactly($0.baseAddress!, RecordHeader.sealedSize) }
            guard let headerBytes = try? cipher.open(sealedHeader), let header = RecordHeader(headerBytes) else { throw DropError.damagedMessage }
            if header.file == RecordHeader.endMarker {
                guard header.chunk == 0, header.length == 0 else { throw DropError.damagedMessage }
                return
            }
            let length = Int(header.length)
            guard header.file == 0, length > 0, length <= chunk else { throw DropError.damagedMessage }
            try socket.readExactly(buffer, length + 16)
            guard let plain = try? cipher.open(bytes: buffer, count: length, ad: headerBytes), plain.count == length else { throw DropError.damagedMessage }
            meter.add(length)
        }
    }
}

/// A speed test, from the Mac that asks for it: how fast this Mac and a paired one can carry
/// a drop's records between them, each way, with no disk at either end.
public final class SpeedTest: Transfer, @unchecked Sendable {
    private let host: String
    private let port: UInt16
    private let identity: Identity
    private let trust: Trust
    private let expect: PublicKey?
    private let seconds: Double
    private let streams: Int
    private var _result = SpeedResult()
    private var _phase = ""

    /// What has been measured so far; whole once the test has completed.
    public var result: SpeedResult { lock.withLock { _result } }
    /// "to macstudio", "from macstudio": what is being measured now.
    public var phase: String { lock.withLock { _phase } }
    public var secondsEachWay: Double { seconds }

    /// `expect`: the key the other Mac must prove. Nil: whoever answers, provided it is paired.
    public init(host: String, port: UInt16, peerName: String, identity: Identity, trust: Trust, expect: PublicKey? = nil, seconds: Double = 5, streams: Int = 8) {
        self.host = host
        self.port = port
        self.identity = identity
        self.trust = trust
        self.expect = expect
        self.seconds = max(1, min(SpeedWire.longest, seconds))
        self.streams = max(1, min(SpeedWire.mostStreams, streams))
        super.init(direction: .send, state: .connecting, peerName: peerName, peerAddress: host)
        setItems(["Speed test"])
    }

    public func start() {
        Thread.detachNewThread { [self] in
            do { try run() } catch { fail(error) }
        }
    }

    private func run() throws {
        log("speed test with \(peerName) at \(host):\(port): \(Int(seconds)) s each way, \(streams) connections")
        let socket = try Socket.connect(host: host, port: port)
        socket.setNoDelay()
        socket.setReadTimeout(Int(Tuning.connectTimeout.rounded(.up)))
        track(socket)
        let trust = trust, name = peerName
        let control = try Channel.initiate(socket, keys: trust.keyPair, expect: expect, expectName: name) { theirs in
            guard trust.standing(of: theirs).isPaired else { throw DropError.notPaired("This Mac is not paired with \(name)") }
        }
        setPeerKey(control.remote)
        try control.send(.hello, SecureHello(minor: protocolMinor, app: identity.appVersion, name: identity.name, remaining: trust.remaining,
                                             paired: true, purpose: .speed))
        // A copy from before the speed test does not know the purpose and hangs up here.
        guard let reply = try? control.read(), reply.type == .hello else {
            throw DropError("\(peerName) did not answer a speed test; it may need a newer Nimbus Drop")
        }
        guard try decode(SecureHello.self, from: reply.body).paired else {
            trust.notePairingGone(control.remote)
            throw DropError.notPaired("\(peerName) no longer has this Mac paired; pair again")
        }
        trust.track(self, key: control.remote)
        try control.send(.speed, SpeedAsk(seconds: seconds, streams: streams))
        let answer = try control.read()
        if answer.type == .busy { throw DropError(Sanitize.label((try? decode(Reason.self, from: answer.body).message) ?? "\(peerName) is busy", limit: 200)) }
        guard answer.type == .speedGo else { throw DropError("Unexpected answer from \(peerName)") }
        let granted = try decode(SpeedAsk.self, from: answer.body)
        // Numbers from another machine: held to what was asked for before they are used.
        let time = max(1, min(seconds, granted.seconds.isFinite ? granted.seconds : seconds))
        let n = max(1, min(streams, granted.streams))
        let keys = DropKeys(master: control.master)

        // Every connection of both directions, before anything is timed.
        var up: [(Socket, UInt64)] = [], down: [(Socket, UInt64)] = []
        for conn in 1...(2 * n) {
            let s = try attach(keys, conn: UInt64(conn))
            if conn <= n { up.append((s, UInt64(conn))) } else { down.append((s, UInt64(conn))) }
        }
        update { $0.connections = n; $0.totalBytes = 0 }
        setState(.transferring)
        lock.withLock { _result.streams = n; _phase = "to \(name)" }
        socket.setReadTimeout(Int(time.rounded(.up)) + 15)

        // Up: this Mac sends; the other counts.
        let until = Date().addingTimeInterval(time)
        let failure = Locked<Error?>(nil)
        var group = DispatchGroup()
        for (s, conn) in up {
            group.enter()
            Thread.detachNewThread { [self] in
                defer { group.leave() }
                var cipher = keys.stream(conn)
                do { try SpeedWire.send(s, cipher: &cipher, until: until, over: { self.isOver }, sent: { n in self.update { $0.doneBytes += Int64(n) } }) }
                catch { failure.withLock { $0 = $0 ?? error } }
            }
        }
        group.wait()
        if isOver { return }
        if let error = failure.withLock({ $0 }) { throw error }
        try control.send(.speedUpDone, Empty())
        let counted = try control.read()
        guard counted.type == .speedCount else { throw DropError("Unexpected answer from \(peerName)") }
        let count = try decode(SpeedCount.self, from: counted.body)
        guard count.bytes >= 0, count.seconds.isFinite, count.seconds >= 0 else { throw DropError("Unexpected answer from \(peerName)") }
        lock.withLock { _result.upBytes = count.bytes; _result.upSeconds = count.seconds; _phase = "from \(name)" }
        log("to \(peerName): \(Format.bytes(count.bytes)) in \(String(format: "%.2f", count.seconds)) s = \(Format.bitRate(result.upRate))")

        // Down: the other Mac sends on connections of their own; this one counts.
        let meter = SpeedWire.Meter()
        group = DispatchGroup()
        for (s, conn) in down {
            s.setReadTimeout(Int(time.rounded(.up)) + 10)
            group.enter()
            Thread.detachNewThread { [self] in
                defer { group.leave() }
                var cipher = keys.stream(conn)
                do { try SpeedWire.receive(s, cipher: &cipher, meter: meter, over: { self.isOver }) }
                catch { failure.withLock { $0 = $0 ?? error } }
                update { $0.doneBytes = meter.bytes }
            }
        }
        update { $0.doneBytes = 0 }
        try control.send(.speedDown, Empty())
        group.wait()
        if isOver { return }
        if let error = failure.withLock({ $0 }) { throw error }
        let done = try control.read()
        guard done.type == .speedDone else { throw DropError("Unexpected answer from \(peerName)") }
        lock.withLock { _result.downBytes = meter.bytes; _result.downSeconds = meter.seconds; _phase = "" }
        log("from \(peerName): \(Format.bytes(meter.bytes)) in \(String(format: "%.2f", meter.seconds)) s = \(Format.bitRate(result.downRate))")
        finish(.completed)
    }

    /// As a drop attaches a data connection: the other Mac's challenge, answered under a key
    /// only the two of them hold.
    private func attach(_ keys: DropKeys, conn: UInt64) throws -> Socket {
        let s = try Socket.connect(host: host, port: port)
        track(s)
        s.setNoDelay()
        s.setReadTimeout(Int(Tuning.attachSeconds.rounded(.up)))
        try Opening.data.withUnsafeBytes { try s.writeAll($0.baseAddress!, Opening.data.count) }
        var challenge = Data(count: 16)
        try challenge.withUnsafeMutableBytes { try s.readExactly($0.baseAddress!, 16) }
        let message = keys.sessionID + Crypto.be64(conn) + keys.attachTag(conn: conn, challenge: challenge)
        try message.withUnsafeBytes { try s.writeAll($0.baseAddress!, message.count) }
        s.setReadTimeout(0)
        return s
    }
}

/// A session that data connections attach to: a drop being received, or a speed test.
protocol DataSession: AnyObject {
    var peerKey: PublicKey? { get }
    func claim(conn: UInt64, tag: Data, challenge: Data) -> Bool
    func runStream(_ socket: Socket, conn: UInt64)
}

/// A speed test, at the Mac that was asked. It takes what the tester sends and throws it
/// away, then sends for as long as it granted. Nothing is written and nobody is asked.
final class SpeedResponder: Transfer, DataSession, @unchecked Sendable {
    private let control: Channel
    private weak var listener: DropListener?
    private var keys: DropKeys?
    private var claimed = Set<UInt64>()
    private let seconds: Double
    private let streams: Int
    private let up = SpeedWire.Meter()
    private let phase = NSCondition()
    private var upOpen = 0, upDone = 0, downOpen = 0, downDone = 0
    private var sendUntil: Date?
    private var sentBytes: Int64 = 0

    init(channel: Channel, ask: SpeedAsk, mac: KnownMac, listener: DropListener) {
        control = channel
        self.listener = listener
        // Whatever was asked for, this is what a Mac gives.
        seconds = max(1, min(SpeedWire.longest, ask.seconds.isFinite ? ask.seconds : 1))
        streams = max(1, min(SpeedWire.mostStreams, ask.streams))
        keys = DropKeys(master: channel.master)
        super.init(direction: .receive, state: .transferring, peerName: mac.name, peerAddress: channel.socket.peerAddress)
        setPeerKey(channel.remote)
        setItems(["Speed test"])
        track(channel.socket)
        listener.trust.track(self, key: channel.remote)
    }

    override func withdrawn(_ error: DropError) {
        lock.withLock { keys = nil }
        super.withdrawn(error)
        phase.lock(); phase.broadcast(); phase.unlock()
    }

    func claim(conn: UInt64, tag: Data, challenge: Data) -> Bool {
        lock.withLock {
            guard let keys, !cancelRequested, conn >= 1, conn <= UInt64(2 * streams),
                  Crypto.same(tag, keys.attachTag(conn: conn, challenge: challenge)), claimed.insert(conn).inserted else { return false }
            return true
        }
    }

    /// One data connection, on the listener's thread for it. The first `streams` numbers are
    /// read from; the rest wait for the tester's word and are then written to.
    func runStream(_ socket: Socket, conn: UInt64) {
        track(socket)
        defer { socket.shutdown(); untrack(socket) }
        guard var cipher = lock.withLock({ keys })?.stream(conn) else { return }
        if conn <= UInt64(streams) {
            phase.withLock { upOpen += 1 }
            socket.setReadTimeout(Int(seconds.rounded(.up)) + 10)
            try? SpeedWire.receive(socket, cipher: &cipher, meter: up, over: { self.isOver })
            phase.lock(); upDone += 1; phase.broadcast(); phase.unlock()
        } else {
            phase.lock()
            downOpen += 1
            let patience = Date().addingTimeInterval(2 * seconds + 15)
            while sendUntil == nil, !isOver, Date() < patience { phase.wait(until: Date().addingTimeInterval(0.2)) }
            let until = sendUntil
            phase.unlock()
            var sent: Int64 = 0
            if let until, !isOver { sent = (try? SpeedWire.send(socket, cipher: &cipher, until: until, over: { self.isOver })) ?? 0 }
            phase.lock(); downDone += 1; sentBytes += sent; phase.broadcast(); phase.unlock()
            // Leave the end marker time to arrive before the socket is closed behind it.
            Thread.sleep(forTimeInterval: 0.2)
        }
    }

    /// The conversation, on the listener's thread for the control connection.
    func run() {
        guard let listener, let keys = lock.withLock({ keys }) else { return }
        log("speed test asked for by \(peerName) at \(peerAddress): \(Int(seconds)) s each way, \(streams) connections")
        listener.register(self, id: keys.sessionID)
        defer { listener.unregister(id: keys.sessionID) }
        // An absolute limit on the whole, whatever the tester does or stops doing.
        let deadline = Deadline(control.socket, seconds: 2 * seconds + 20)
        defer { deadline.cancel() }
        do {
            try control.send(.speedGo, SpeedAsk(seconds: seconds, streams: streams))
            guard try control.read().type == .speedUpDone else { throw DropError("Unexpected message from \(peerName)") }
            // The last records may still be on their way in.
            phase.lock()
            let settled = Date().addingTimeInterval(3)
            while upDone < upOpen, !isOver, phase.wait(until: settled) {}
            phase.unlock()
            try control.send(.speedCount, SpeedCount(bytes: up.bytes, seconds: up.seconds))
            log("from \(peerName): \(Format.bytes(up.bytes)) in \(String(format: "%.2f", up.seconds)) s = \(Format.bitRate(up.seconds > 0 ? Double(up.bytes) / up.seconds : 0))")
            guard try control.read().type == .speedDown else { throw DropError("Unexpected message from \(peerName)") }
            phase.lock()
            sendUntil = Date().addingTimeInterval(seconds)
            phase.broadcast()
            let finished = Date().addingTimeInterval(seconds + 10)
            while downDone < downOpen, !isOver, phase.wait(until: finished) {}
            let sent = sentBytes
            phase.unlock()
            try control.send(.speedDone, SpeedCount(bytes: sent, seconds: seconds))
            log("to \(peerName): \(Format.bytes(sent)) sent in \(Int(seconds)) s")
            Thread.sleep(forTimeInterval: 0.2)
            finish(.completed)
        } catch {
            fail(error)
        }
        phase.lock(); phase.broadcast(); phase.unlock()
    }
}
