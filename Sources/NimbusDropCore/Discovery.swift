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
        for (key, value) in [("id", identity.id), ("name", identity.name), ("v", String(protocolVersion))] {
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

    public init(id: String, name: String, address: String? = nil, port: UInt16? = nil) {
        self.id = id; self.name = name; self.address = address; self.port = port
    }
}

/// Watches the local network for receivers and resolves each to an address and port.
/// Everything is delivered on the main queue.
public final class PeerBrowser: @unchecked Sendable {
    private let selfID: String
    private var browser: NWBrowser?
    private var endpoints: [String: NWEndpoint] = [:]
    private var known: [String: Peer] = [:]
    private var resolving: [String: NWConnection] = [:]

    public var onChange: (([Peer]) -> Void)?
    /// Why browsing is not working (Local Network access denied, say), or nil.
    public private(set) var problem: String?

    public init(selfID: String) { self.selfID = selfID }

    public var peers: [Peer] { known.values.sorted { $0.name.localizedStandardCompare($1.name) == .orderedAscending } }

    public func start() {
        let b = NWBrowser(for: .bonjourWithTXTRecord(type: bonjourType, domain: nil), using: NWParameters())
        b.browseResultsChangedHandler = { [weak self] results, _ in self?.update(results) }
        b.stateUpdateHandler = { [weak self] state in
            guard let self else { return }
            switch state {
            case .failed(let e), .waiting(let e): problem = "\(e.localizedDescription)"
            default: problem = nil
            }
            onChange?(peers)
        }
        b.start(queue: .main)
        browser = b
    }

    public func stop() {
        browser?.cancel()
        browser = nil
        for c in resolving.values { c.cancel() }
        resolving = [:]
    }

    private func update(_ results: Set<NWBrowser.Result>) {
        var seen = Set<String>()
        for r in results {
            guard case .bonjour(let txt) = r.metadata, let id = txt["id"], id != selfID else { continue }
            seen.insert(id)
            let name = txt["name"] ?? "?"
            let changed = endpoints[id] != r.endpoint
            endpoints[id] = r.endpoint
            if known[id] == nil { known[id] = Peer(id: id, name: name) }
            known[id]?.name = name
            if changed || known[id]?.address == nil { resolve(id) }
        }
        for id in known.keys where !seen.contains(id) {
            known[id] = nil
            endpoints[id] = nil
            resolving[id]?.cancel()
            resolving[id] = nil
        }
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
                if case .hostPort(let host, let port)? = connection.currentPath?.remoteEndpoint, known[id] != nil {
                    known[id]?.address = Self.text(host)
                    known[id]?.port = port.rawValue
                    onChange?(peers)
                }
                finish(known[id])
            case .failed, .cancelled:
                finish(known[id].map { Peer(id: $0.id, name: $0.name) })
            default:
                break
            }
        }
        connection.start(queue: .main)
        DispatchQueue.main.asyncAfter(deadline: .now() + 5) { [weak self] in
            finish(self?.known[id].map { Peer(id: $0.id, name: $0.name) })
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
