// Copyright (C) 2026 Niels Joubert
// SPDX-License-Identifier: GPL-3.0-or-later
import dnssd
import Foundation
import Network

public let bonjourType = "_nimbusdrop._tcp"

/// Announces this Mac on the local network for as long as the object lives. The TXT record
/// carries the name and the id; the service's port is the listener's.
public final class Advertiser {
    private var ref: DNSServiceRef?

    public init(identity: Identity, port: UInt16) throws {
        var txt = [UInt8]()
        for (key, value) in [("id", identity.id), ("name", identity.name), ("v", protocolVersionText), ("app", identity.appVersion)] {
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

    public init(id: String, name: String, address: String? = nil, port: UInt16? = nil, version: Int? = protocolVersion) {
        self.id = id; self.name = name; self.address = address; self.port = port; self.version = version
    }

    public var isCompatible: Bool { version == nil || version == protocolVersion }
}

public enum Probe {
    /// Asks whatever listens at `host:port` who it is. For Macs added by address, where there
    /// is no Bonjour record to say.
    public static func hello(host: String, port: UInt16 = defaultPort, timeout: TimeInterval = 3) throws -> Peer {
        let socket = try Socket.connect(host: host, port: port, timeout: timeout)
        socket.setReadTimeout(Int(timeout.rounded(.up)))
        try socket.send(.hello, Empty())
        let reply = try socket.readFrame()
        guard reply.type == .hello else { throw DropError("\(host) is not running Nimbus Drop") }
        let hello = try decode(Hello.self, from: reply.body)
        var peer = Peer(id: hello.id, name: hello.name, address: host, port: port, version: hello.version)
        peer.minor = hello.minor
        peer.appVersion = hello.app
        return peer
    }
}

/// Who is on the network, worked out from what Bonjour reports. Pure, so the rules that were
/// learned the hard way have tests: a result that loses its TXT record is still the Mac it was.
struct PeerTable {
    struct Seen { var key: String; var txt: [String: String]? }
    private var identities: [String: (id: String, name: String, version: Int?, minor: Int?, app: String?)] = [:]
    private(set) var peers: [String: Peer] = [:]
    /// The browse result each peer was last seen under.
    private(set) var keys: [String: String] = [:]

    /// Takes a full set of browse results. Returns the peers that need their address looked up
    /// (new, or seen under a different result) and whether any result came without its TXT
    /// record, which calls for a fresh browse.
    mutating func apply(_ results: [Seen], selfID: String) -> (resolve: [String], missingTXT: Bool) {
        var seen = Set<String>(), resolve: [String] = [], missingTXT = false
        for r in results {
            if let txt = r.txt, let id = txt["id"] {
                // "2.0", or a bare "2" from before minors existed.
                let v = (txt["v"] ?? "").split(separator: ".").map { Int($0) }
                identities[r.key] = (id, txt["name"] ?? "?", v.first ?? nil, v.count > 1 ? v[1] : nil, txt["app"])
            } else {
                missingTXT = true
            }
            guard let who = identities[r.key], who.id != selfID else { continue }
            seen.insert(who.id)
            let moved = keys[who.id] != r.key
            keys[who.id] = r.key
            var peer = peers[who.id] ?? Peer(id: who.id, name: who.name)
            peer.name = who.name
            peer.version = who.version
            peer.minor = who.minor
            peer.appVersion = who.app
            peers[who.id] = peer
            if moved || peer.address == nil { resolve.append(who.id) }
        }
        let present = Set(results.map(\.key))
        identities = identities.filter { present.contains($0.key) }
        for id in peers.keys where !seen.contains(id) { peers[id] = nil; keys[id] = nil }
        return (resolve, missingTXT)
    }

    mutating func setAddress(_ id: String, address: String, port: UInt16) {
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
    private var table = PeerTable()
    private var resolving: [String: NWConnection] = [:]
    private var restartPending = false
    private var lastRestart = Date.distantPast
    private var stopped = false

    public var onChange: (([Peer]) -> Void)?
    /// What the browser is told, line by line, for `--watch-peers`.
    public var onTrace: ((String) -> Void)?
    /// Why browsing is not working (Local Network access denied, say), or nil.
    public private(set) var problem: String?

    public init(selfID: String) { self.selfID = selfID }

    public var peers: [Peer] { table.peers.values.sorted { $0.name.localizedStandardCompare($1.name) == .orderedAscending } }

    public func start() {
        stopped = false
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
            browser?.cancel()
            table.forgetWhereTheyWere()
            start()
        }
    }

    public func stop() {
        stopped = true
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
            var txt: [String: String]?
            if case .bonjour(let record) = r.metadata { txt = record.dictionary }
            return PeerTable.Seen(key: key, txt: txt)
        }
        // When an interface goes away (Wi-Fi off with Ethernet still up, checked 2026-11-22)
        // macOS reports every result again with its TXT record gone. The table keeps who they
        // were; a fresh browse fetches the records back.
        let outcome = table.apply(seen, selfID: selfID)
        endpoints = [:]
        for (id, key) in table.keys { endpoints[id] = byKey[key] }
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
    public func resolve(_ id: String, completion: ((Peer?) -> Void)? = nil) {
        guard let endpoint = endpoints[id] else { completion?(nil); return }
        resolving[id]?.cancel()
        // IPv4, so the address shown is the one people recognise; the listener is dual-stack.
        let parameters = NWParameters.tcp
        (parameters.defaultProtocolStack.internetProtocol as? NWProtocolIP.Options)?.version = .v4
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
                }
                finish(table.peers[id])
            case .failed, .cancelled:
                finish(table.peers[id].map { var p = $0; p.address = nil; p.port = nil; return p })
            default:
                break
            }
        }
        connection.start(queue: .main)
        DispatchQueue.main.asyncAfter(deadline: .now() + 5) { [weak self] in
            finish(self?.table.peers[id].map { var p = $0; p.address = nil; p.port = nil; return p })
        }
    }

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
