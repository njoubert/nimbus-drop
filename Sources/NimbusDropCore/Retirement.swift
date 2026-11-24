// Copyright (C) 2026 Niels Joubert
// SPDX-License-Identifier: GPL-3.0-or-later
import Foundation

/// Reset Identity: tell the Macs this one is paired with that its key is retired, while the key
/// still exists to prove the telling; then replace it.
///
/// The notice names no successor. The new key is never vouched for by the old one, which may be
/// in someone else's hands; it earns trust the only way any key does, from two people.
public enum Retirement {
    /// Where a Known Mac can be reached right now.
    public typealias Reach = @Sendable (PublicKey) -> (host: String, port: UInt16)?

    /// Sends `retire` to each Mac that can be found, proving `old`; returns those that
    /// acknowledged. Takes at most `seconds` in all, whatever the network does.
    static func tell(_ peers: [KnownMac], old: KeyPair, identity: Identity, remaining: Double, reach: Reach, seconds: Double) -> Set<PublicKey> {
        let told = Locked(Set<PublicKey>())
        let group = DispatchGroup()
        var sockets: [Socket] = []
        let socketLock = NSLock()
        for mac in peers {
            guard let where_ = reach(mac.key) else { continue }
            group.enter()
            Thread.detachNewThread {
                defer { group.leave() }
                guard let socket = try? Socket.connect(host: where_.host, port: where_.port, timeout: min(seconds, 5)) else { return }
                socketLock.withLock { sockets.append(socket) }
                socket.setReadTimeout(Int(seconds.rounded(.up)))
                guard let channel = try? Channel.initiate(socket, keys: old, expect: mac.key),
                      (try? channel.send(.hello, SecureHello(minor: protocolMinor, app: identity.appVersion, name: identity.name, remaining: remaining,
                                                             paired: true, purpose: .retire))) != nil,
                      let hello = try? channel.read(), hello.type == .hello,
                      (try? channel.send(.retire, Empty())) != nil,
                      let answer = try? channel.read(), answer.type == .retired else { socket.shutdown(); return }
                told.withLock { _ = $0.insert(mac.key) }
                socket.shutdown()
            }
        }
        if group.wait(timeout: .now() + seconds) == .timedOut { socketLock.withLock { for s in sockets { s.shutdown() } } }
        return told.withLock { $0 }
    }
}

extension Trust {
    /// Reset Identity, whole: tells every paired Mac that can be reached, for at most `seconds`
    /// in all, then makes a new key and destroys the old one whatever the outcome. Returns the
    /// pair-again list, each Mac marked with whether it was told.
    @discardableResult
    public func reset(identity: Identity, reach: Retirement.Reach, seconds: Double = 10) -> [Renewal] {
        let (old, peers) = beginReset()
        DropLog.write("identity: resetting; telling \(peers.count) paired Macs that \(old.publicKey.tag) is retired", .warn)
        let told = Retirement.tell(peers, old: old, identity: identity, remaining: remaining, reach: reach, seconds: seconds)
        completeReset(told: told)
        for mac in peers {
            DropLog.write("identity: \(mac.name) was \(told.contains(mac.key) ? "told" : "NOT reached; it still trusts the old identity until it is paired again or that identity's end date")", told.contains(mac.key) ? .info : .warn)
        }
        return again
    }

    /// Tests, and nothing else: two stores that hold a pairing with each other, as if two people
    /// had just exchanged codes.
    static func paired(_ aName: String = "sender", _ bName: String = "receiver") -> (Trust, Trust) {
        let a = Trust.inMemory(), b = Trust.inMemory()
        a.adopt(b, as: bName)
        b.adopt(a, as: aName)
        return (a, b)
    }

    func adopt(_ other: Trust, as name: String) {
        // swiftlint:disable:next force_try
        try! store(pairing: other.publicKey, announced: name, method: "codes", remaining: other.remaining)
    }
}
