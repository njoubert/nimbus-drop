// Copyright (C) 2026 Niels Joubert
// SPDX-License-Identifier: GPL-3.0-or-later
import dnssd
import Foundation
import Network

public let bonjourType = "_nimbusdrop._tcp"

/// Announces this Mac on the local network for as long as the object lives. The TXT record
/// carries the name, the protocol major and `i`, a random value made at launch by which a Mac
/// recognises its own record. No key, no tag, nothing lasting: Bonjour says where a Mac is, and
/// only a handshake says who it is.
public final class Advertiser {
    private var ref: DNSServiceRef?

    public init(identity: Identity, port: UInt16) throws {
        var txt = [UInt8]()
        for (key, value) in [("i", identity.id), ("name", identity.name), ("v", "\(protocolVersion)")] {
            let pair = Array("\(key)=\(value)".utf8.prefix(255))
            txt.append(UInt8(pair.count))
            txt.append(contentsOf: pair)
        }
        let err = DNSServiceRegister(&ref, 0, 0, identity.name, bonjourType, nil, nil, port.bigEndian,
                                     UInt16(txt.count), txt, nil, nil)
        guard err == kDNSServiceErr_NoError else { throw DropError("Cannot announce this Mac on the network (Bonjour error \(err))") }
    }

    deinit { if let ref { DNSServiceRefDeallocate(ref) } }
}

/// Another Mac running Nimbus Drop with receiving on.
public struct Peer: Identifiable, Equatable, Sendable {
    public var id: String
    public var name: String
    /// The IPv4 address the service resolved to, once it has.
    public var address: String?
    public var port: UInt16?
    /// The protocol major it announces; a different one cannot exchange drops with this copy.
    public var version: Int?
    public var minor: Int?
    /// Its app version, to show.
    public var appVersion: String?

    /// "2.0", or "?" when it has not said.
    public var protocolText: String { version.map { "\($0)" + (minor.map { ".\($0)" } ?? "") } ?? "?" }
    /// Added by address rather than found by Bonjour.
    public var isManual = false
    /// A Mac added by address that did not answer the last time it was asked.
    public var unreachable = false
    /// The key the Mac at this address proved it holds, when it was last asked. Everything a
    /// window says about who a Mac is comes from this and from nothing the Mac announces.
    public var key: PublicKey?
    /// It was asked and could not prove any key (not Nimbus Drop 0.3, or not answering).
    public var unproved = false

    public init(id: String, name: String, address: String? = nil, port: UInt16? = nil, version: Int? = protocolVersion) {
        self.id = id; self.name = name; self.address = address; self.port = port; self.version = version
    }

    public var isCompatible: Bool { version == nil || version == protocolVersion }
}

public enum Probe {
    /// Asks whatever listens at `host:port` to prove who it is, and hangs up. This side says
    /// nothing about itself. The answer is a key; what that key is to this Mac is `Trust`'s to say.
    public static func identify(host: String, port: UInt16 = defaultPort, timeout: TimeInterval = 3) throws -> PublicKey {
        try Channel.probe(host: host, port: port, timeout: timeout)
    }

    /// For a Mac added by address, where there is no Bonjour record to give a name: a full
    /// handshake and an exchange of hellos, then nothing. This Mac's key is shown to it.
    public static func hello(host: String, port: UInt16 = defaultPort, identity: Identity, trust: Trust, timeout: TimeInterval = 3) throws -> Peer {
        let socket = try Socket.connect(host: host, port: port, timeout: timeout)
        socket.setReadTimeout(Int(timeout.rounded(.up)))
        defer { socket.shutdown() }
        let channel = try Channel.initiate(socket, keys: trust.keyPair, expect: nil)
        try channel.send(.hello, SecureHello(minor: protocolMinor, app: identity.appVersion, name: identity.name, remaining: trust.remaining,
                                             paired: trust.standing(of: channel.remote).isPaired, purpose: nil))
        let reply = try channel.read()
        guard reply.type == .hello else { throw DropError("\(host) is not running Nimbus Drop") }
        let hello = try decode(SecureHello.self, from: reply.body)
        var peer = Peer(id: "manual:\(host):\(port)", name: Sanitize.label(hello.name, limit: 64), address: host, port: port, version: protocolVersion)
        peer.minor = hello.minor
        peer.appVersion = Sanitize.label(hello.app, limit: 24)
        peer.key = channel.remote
        return peer
    }
}

/// Probes addresses for the app, within limits: forged Bonjour records could otherwise drive
/// any amount of it. At most four at once, an address at most once in thirty seconds, results
/// for at most 256 addresses.
public final class Prober: @unchecked Sendable {
    private let lock = NSLock()
    private var results: [String: (key: PublicKey?, at: Date)] = [:]
    private var inFlight = Set<String>()
    private let slots = DispatchSemaphore(value: 4)
    private let queue = DispatchQueue(label: "nimbusdrop.prober", attributes: .concurrent)

    public init() {}

    /// The key last proved at that address, if it has been asked.
    public func known(host: String, port: UInt16) -> (key: PublicKey?, at: Date)? { lock.withLock { results["\(host):\(port)"] } }

    /// Asks, unless it was asked within the last thirty seconds (`fresh` insists). `completion`
    /// is called on a background queue, with nil when no key was proved.
    public func identify(host: String, port: UInt16, fresh: Bool = false, completion: @escaping @Sendable (PublicKey?) -> Void) {
        let name = "\(host):\(port)"
        let go = lock.withLock { () -> Bool in
            if inFlight.contains(name) { return false }
            if !fresh, let r = results[name], Date().timeIntervalSince(r.at) < 30 { return false }
            inFlight.insert(name)
            return true
        }
        guard go else { if let r = known(host: host, port: port) { completion(r.key) }; return }
        queue.async { [self] in
            slots.wait()
            let key = try? Probe.identify(host: host, port: port)
            slots.signal()
            lock.withLock {
                inFlight.remove(name)
                if results.count >= 256, results[name] == nil, let oldest = results.min(by: { $0.value.at < $1.value.at }) { results[oldest.key] = nil }
                results[name] = (key, Date())
            }
            completion(key)
        }
    }
}

/// Who is on the network, worked out from what Bonjour reports. Pure, so the rules that were
/// learned the hard way have tests: a result that loses its TXT record is still the Mac it was.
struct PeerTable {
    struct Seen { var key: String; var txt: [String: String]? }
    private var identities: [String: (instance: String, name: String, version: Int?, minor: Int?)] = [:]
    private(set) var peers: [String: Peer] = [:]
    /// The browse result each peer was last seen under.
    private(set) var keys: [String: String] = [:]

    /// Takes a full set of browse results. Returns the peers that need their address looked up
    /// (new, or seen under a different result) and whether any result came without its TXT
    /// record, which calls for a fresh browse.
    ///
    /// A peer is one browse result, whatever it says about itself: two records claiming to be
    /// the same Mac are two tiles, and neither can move or replace the other. `i` in the record
    /// serves only for this Mac to leave its own record out.
    mutating func apply(_ results: [Seen], selfID: String) -> (resolve: [String], missingTXT: Bool) {
        var seen = Set<String>(), resolve: [String] = [], missingTXT = false
        for r in results {
            if let txt = r.txt, txt["name"] != nil || txt["v"] != nil || txt["i"] != nil {
                // "3", or "2.2" from a copy that still speaks protocol 2.
                let v = (txt["v"] ?? "").split(separator: ".").map { Int($0) }
                identities[r.key] = (String((txt["i"] ?? txt["id"] ?? "").prefix(64)), Sanitize.label(txt["name"] ?? "?", limit: 64), v.first ?? nil,
                                     v.count > 1 ? v[1] : nil)
            } else {
                missingTXT = true
            }
            guard let who = identities[r.key], who.instance != selfID else { continue }
            let id = r.key
            seen.insert(id)
            let moved = keys[id] != r.key
            keys[id] = r.key
            var peer = peers[id] ?? Peer(id: id, name: who.name)
            peer.name = who.name
            peer.version = who.version
            peer.minor = who.minor
            peers[id] = peer
            if moved || peer.address == nil { resolve.append(id) }
        }
        let present = Set(results.map(\.key))
        identities = identities.filter { present.contains($0.key) }
        for id in peers.keys where !seen.contains(id) { peers[id] = nil; keys[id] = nil }
        return (resolve, missingTXT)
    }

    /// What the Mac at a peer's address proved when asked (nil: nothing).
    mutating func setKey(_ id: String, key: PublicKey?) {
        peers[id]?.key = key
        peers[id]?.unproved = key == nil
    }

    mutating func setAddress(_ id: String, address: String, port: UInt16) {
        // A Mac at another address has to prove itself again.
        if peers[id]?.address != address || peers[id]?.port != port { peers[id]?.key = nil; peers[id]?.unproved = false }
        peers[id]?.address = address
        peers[id]?.port = port
    }

    /// Every address is looked up again at the next results (the network changed).
    mutating func forgetWhereTheyWere() { keys = [:] }
}

/// Watches the local network for receivers and resolves each to an address and port.
/// Everything is delivered on the main queue.
public final class PeerBrowser: @unchecked Sendable {
    private let selfID: String
    private var browser: NWBrowser?
    private var endpoints: [String: NWEndpoint] = [:]
    /// The interfaces each peer was found on, and the same by browse result.
    private var interfaces: [String: [NWInterface]] = [:]
    private var reachedOn: [String: [NWInterface]] = [:]
    private var table = PeerTable()
    private var resolving: [String: NWConnection] = [:]
    private var restartPending = false
    private var lastRestart = Date.distantPast
    private var stopped = false
    private var recheck: Timer?
    /// Asks each address found to prove who it is.
    public let prober = Prober()

    public var onChange: (([Peer]) -> Void)?
    /// What the browser is told, line by line, for `--watch-peers`.
    public var onTrace: ((String) -> Void)?
    /// Why browsing is not working (Local Network access denied, say), or nil.
    public private(set) var problem: String?

    public init(selfID: String) { self.selfID = selfID }

    public var peers: [Peer] { table.peers.values.sorted { $0.name.localizedStandardCompare($1.name) == .orderedAscending } }

    public func start() {
        stopped = false
        // A Mac's key changes under an address that does not: it was reset, or it ran out and
        // was made anew, with the app running throughout. Nothing Bonjour reports changes then,
        // so every address is asked again as time passes. Without this a Mac that reset its
        // identity stayed "Identity not accepted" at the others until one of the two was
        // restarted (found by the owner, 2026-11-23).
        recheck?.invalidate()
        let t = Timer(timeInterval: 30, repeats: true) { [weak self] _ in self?.probeAll() }
        RunLoop.main.add(t, forMode: .common)
        recheck = t
        let b = NWBrowser(for: .bonjourWithTXTRecord(type: bonjourType, domain: nil), using: NWParameters())
        b.browseResultsChangedHandler = { [weak self, weak b] results, _ in
            guard let self, let b, self.browser === b else { return }
            self.update(results)
        }
        b.stateUpdateHandler = { [weak self, weak b] state in
            guard let self, let b, self.browser === b else { return }
            onTrace?("browser state: \(state)")
            switch state {
            case .failed(let e):
                // A failed browser stays failed; the network changing under it is the usual cause.
                DropLog.write("discovery: the browser failed: \(e)", .error)
                problem = "\(e.localizedDescription)"
                restartSoon()
            case .waiting(let e): problem = "\(e.localizedDescription)"
            default: problem = nil
            }
            onChange?(peers)
        }
        b.start(queue: .main)
        browser = b
    }

    /// Starts browsing afresh, keeping who is known until the new results say otherwise.
    private func restartSoon() {
        guard !restartPending, !stopped else { return }
        restartPending = true
        let wait = max(1, 5 - Date().timeIntervalSince(lastRestart))
        DispatchQueue.main.asyncAfter(deadline: .now() + wait) { [weak self] in
            guard let self, !stopped else { return }
            restartPending = false
            lastRestart = Date()
            onTrace?("restarting the browser")
            DropLog.write("discovery: browsing afresh (a result came without its TXT record, or the browser failed)", .debug)
            browser?.cancel()
            table.forgetWhereTheyWere()
            start()
        }
    }

    public func stop() {
        stopped = true
        recheck?.invalidate()
        recheck = nil
        browser?.cancel()
        browser = nil
        for c in resolving.values { c.cancel() }
        resolving = [:]
    }

    private func update(_ results: Set<NWBrowser.Result>) {
        onTrace?("results changed: \(results.count)")
        var byKey: [String: NWEndpoint] = [:]
        let seen = results.map { r -> PeerTable.Seen in
            onTrace?("result \(r.endpoint) txt=\(r.metadata) interfaces=\(r.interfaces.map(\.name))")
            let key = "\(r.endpoint)"
            byKey[key] = r.endpoint
            reachedOn[key] = r.interfaces
            var txt: [String: String]?
            if case .bonjour(let record) = r.metadata { txt = record.dictionary }
            return PeerTable.Seen(key: key, txt: txt)
        }
        // When an interface goes away (Wi-Fi off with Ethernet still up, checked 2026-11-22)
        // macOS reports every result again with its TXT record gone. The table keeps who they
        // were; a fresh browse fetches the records back.
        let outcome = table.apply(seen, selfID: selfID)
        endpoints = [:]
        interfaces = [:]
        for (id, key) in table.keys { endpoints[id] = byKey[key]; interfaces[id] = reachedOn[key] }
        reachedOn = reachedOn.filter { byKey[$0.key] != nil }
        for id in resolving.keys where table.peers[id] == nil {
            resolving[id]?.cancel()
            resolving[id] = nil
        }
        for id in outcome.resolve { resolve(id) }
        if outcome.missingTXT { restartSoon() }
        onChange?(peers)
    }

    /// Looks the peer's address and port up afresh; `completion` gets the peer as it then stands
    /// (without an address when it could not be reached). The port changes whenever the other
    /// copy restarts, so a send resolves first.
    public func resolve(_ id: String, completion: ((Peer?) -> Void)? = nil) { resolve(id, anyInterface: false, completion: completion) }

    /// The interface to reach a Mac on, when it is found on several: a Thunderbolt Bridge
    /// before anything else. Left to macOS, a Mac cabled by Thunderbolt and also on Ethernet or
    /// Wi-Fi is resolved to whichever comes first in the service order, usually not the
    /// Thunderbolt one: the owner's first speed test in the app measured 300 Mbit/s over a
    /// USB Ethernet adapter with a 37 Gbit/s cable beside it (2026-11-23). Nil: let macOS choose.
    static func preferred(_ interfaces: [NWInterface]) -> NWInterface? {
        interfaces.count > 1 ? interfaces.first { $0.name.hasPrefix("bridge") } : nil
    }

    private func resolve(_ id: String, anyInterface: Bool, completion: ((Peer?) -> Void)?) {
        guard let endpoint = endpoints[id] else { completion?(nil); return }
        resolving[id]?.cancel()
        // IPv4, so the address shown is the one people recognise; the listener is dual-stack.
        let parameters = NWParameters.tcp
        (parameters.defaultProtocolStack.internetProtocol as? NWProtocolIP.Options)?.version = .v4
        let chosen = anyInterface ? nil : Self.preferred(interfaces[id] ?? [])
        parameters.requiredInterface = chosen
        let connection = NWConnection(to: endpoint, using: parameters)
        resolving[id] = connection
        var finished = false
        let finish: (Peer?) -> Void = { [weak self] peer in
            guard !finished else { return }
            finished = true
            connection.cancel()
            if let self, self.resolving[id] === connection { self.resolving[id] = nil }
            completion?(peer)
        }
        connection.stateUpdateHandler = { [weak self] state in
            guard let self else { return }
            switch state {
            case .ready:
                if case .hostPort(let host, let port)? = connection.currentPath?.remoteEndpoint, table.peers[id] != nil {
                    table.setAddress(id, address: Self.text(host), port: port.rawValue)
                    onChange?(peers)
                    if table.peers[id]?.isCompatible == true { probe(id) }
                }
                finish(table.peers[id])
            case .failed, .cancelled:
                // The interface that was preferred did not answer: any will do.
                if chosen != nil, !finished {
                    finished = true
                    connection.cancel()
                    resolve(id, anyInterface: true, completion: completion)
                    return
                }
                finish(table.peers[id].map { var p = $0; p.address = nil; p.port = nil; return p })
            default:
                break
            }
        }
        connection.start(queue: .main)
        DispatchQueue.main.asyncAfter(deadline: .now() + (chosen != nil ? 2 : 5)) { [weak self] in
            if chosen != nil, !finished {
                finished = true
                connection.cancel()
                self?.resolve(id, anyInterface: true, completion: completion)
                return
            }
            finish(self?.table.peers[id].map { var p = $0; p.address = nil; p.port = nil; return p })
        }
    }

    /// Asks the Mac at a peer's address to prove its key; the answer arrives as a change.
    public func probe(_ id: String, fresh: Bool = false) {
        guard let peer = table.peers[id], let address = peer.address, let port = peer.port else { return }
        prober.identify(host: address, port: port, fresh: fresh) { [weak self] key in
            DispatchQueue.main.async {
                guard let self, self.table.peers[id]?.address == address, self.table.peers[id]?.port == port else { return }
                self.table.setKey(id, key: key)
                self.onChange?(self.peers)
            }
        }
    }

    /// Asks every address again (trust changed, or time has passed).
    public func probeAll() { for id in table.peers.keys { probe(id, fresh: true) } }

    private static func text(_ host: NWEndpoint.Host) -> String {
        switch host {
        case .ipv4(let a): return a.rawValue.map(String.init).joined(separator: ".")
        case .ipv6(let a):
            var bytes = [UInt8](a.rawValue)
            var out = [CChar](repeating: 0, count: Int(INET6_ADDRSTRLEN))
            inet_ntop(AF_INET6, &bytes, &out, socklen_t(out.count))
            let scope = a.interface.map { "%\($0.name)" } ?? ""
            return String(cString: out) + scope
        case .name(let n, _): return n
        @unknown default: return "\(host)"
        }
    }
}
