// Copyright (C) 2026 Niels Joubert
// SPDX-License-Identifier: GPL-3.0-or-later
import Darwin
import Foundation
import SystemConfiguration

/// This Mac's name and addresses, as the other side will see them.
public enum LocalHost {
    /// The Bonjour host name without ".local" ("macbookpro"): what `ssh` and Finder's sidebar use.
    public static var name: String {
        if let n = SCDynamicStoreCopyLocalHostName(nil) as String?, !n.isEmpty { return n }
        let h = ProcessInfo.processInfo.hostName
        return h.hasSuffix(".local") ? String(h.dropLast(6)) : h
    }

    public struct Address: Equatable, Sendable {
        public var interface: String
        public var address: String
        public init(interface: String, address: String) {
            self.interface = interface
            self.address = address
        }
    }

    /// The IPv4 addresses of every interface that is up, loopback and link-local left out.
    public static var addresses: [Address] {
        var list: UnsafeMutablePointer<ifaddrs>?
        guard getifaddrs(&list) == 0 else { return [] }
        defer { freeifaddrs(list) }
        var out: [Address] = []
        var next = list
        while let ifa = next {
            next = ifa.pointee.ifa_next
            let flags = Int32(ifa.pointee.ifa_flags)
            guard let sa = ifa.pointee.ifa_addr, sa.pointee.sa_family == sa_family_t(AF_INET),
                  flags & IFF_UP != 0, flags & IFF_RUNNING != 0, flags & IFF_LOOPBACK == 0 else { continue }
            var host = [CChar](repeating: 0, count: Int(NI_MAXHOST))
            guard getnameinfo(sa, socklen_t(sa.pointee.sa_len), &host, socklen_t(host.count), nil, 0, NI_NUMERICHOST) == 0 else { continue }
            let text = String(cString: host)
            if text.hasPrefix("169.254.") { continue }
            out.append(Address(interface: String(cString: ifa.pointee.ifa_name), address: text))
        }
        return out
    }
}

/// Which addresses count as "this network": the ones on the same subnet as one of this Mac's
/// own interfaces. It is what "receive only from the local network" goes by.
public enum LocalNetwork {
    /// One of this Mac's addresses and its netmask, as bytes (4 for IPv4, 16 for IPv6).
    public struct Net: Equatable, Sendable {
        public var address: [UInt8]
        public var mask: [UInt8]
        public init(address: [UInt8], mask: [UInt8]) {
            self.address = address
            self.mask = mask
        }
    }

    /// The subnets of every interface that is up.
    public static func current() -> [Net] {
        var list: UnsafeMutablePointer<ifaddrs>?
        guard getifaddrs(&list) == 0 else { return [] }
        defer { freeifaddrs(list) }
        var out: [Net] = []
        var next = list
        while let ifa = next {
            next = ifa.pointee.ifa_next
            guard Int32(ifa.pointee.ifa_flags) & IFF_UP != 0, let sa = ifa.pointee.ifa_addr, let nm = ifa.pointee.ifa_netmask,
                  let address = bytes(sa), let mask = bytes(nm, family: sa.pointee.sa_family), address.count == mask.count else { continue }
            out.append(Net(address: address, mask: mask))
        }
        return out
    }

    private static func bytes(_ sa: UnsafeMutablePointer<sockaddr>, family: sa_family_t? = nil) -> [UInt8]? {
        switch Int32(family ?? sa.pointee.sa_family) {
        case AF_INET:
            return sa.withMemoryRebound(to: sockaddr_in.self, capacity: 1) { withUnsafeBytes(of: $0.pointee.sin_addr) { Array($0) } }
        case AF_INET6:
            return sa.withMemoryRebound(to: sockaddr_in6.self, capacity: 1) { withUnsafeBytes(of: $0.pointee.sin6_addr) { Array($0) } }
        default:
            return nil
        }
    }

    /// "192.168.1.20", "fe80::1%en0" as bytes; nil for anything that is not an address.
    public static func parse(_ text: String) -> [UInt8]? {
        let plain = String(text.split(separator: "%").first ?? "")
        var v4 = in_addr(), v6 = in6_addr()
        if inet_pton(AF_INET, plain, &v4) == 1 { return withUnsafeBytes(of: v4) { Array($0) } }
        if inet_pton(AF_INET6, plain, &v6) == 1 { return withUnsafeBytes(of: v6) { Array($0) } }
        return nil
    }

    /// Whether `peer` is this Mac itself, a link-local neighbour, or on the same subnet as one
    /// of `nets`. An address that cannot be read is not local.
    public static func isLocal(_ peer: String, among nets: [Net]) -> Bool {
        guard let p = parse(peer) else { return false }
        if p.count == 4 {
            if p[0] == 127 || (p[0] == 169 && p[1] == 254) { return true }
        } else {
            if p == [UInt8](repeating: 0, count: 15) + [1] { return true }          // ::1
            if p[0] == 0xFE && p[1] & 0xC0 == 0x80 { return true }                    // fe80::/10
        }
        return nets.contains { net in
            net.address.count == p.count && net.mask.contains { $0 != 0 }
                && zip(zip(p, net.address), net.mask).allSatisfy { $0.0 & $1 == $0.1 & $1 }
        }
    }
}

/// The mark macOS puts on files that came from somewhere else, so that Gatekeeper asks before
/// an app or a script among them is run for the first time. AirDrop and browsers set it; a drop
/// is no different. Photos and documents open as usual.
enum Quarantine {
    static let attribute = "com.apple.quarantine"

    /// The attribute's value for files received now, made by macOS itself (so that it is in
    /// the form the system expects, and known to its record of quarantined files): a scratch
    /// file is marked through the system's API and what it wrote is read back. If that cannot
    /// be done, the same form written by hand.
    static func value() -> [UInt8] {
        let scratch = FileManager.default.temporaryDirectory.appendingPathComponent("nimbusdrop-quarantine-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: scratch) }
        if FileManager.default.createFile(atPath: scratch.path, contents: nil) {
            var values = URLResourceValues()
            values.quarantineProperties = ["LSQuarantineAgentName": "Nimbus Drop", "LSQuarantineType": "LSQuarantineTypeOtherDownload"]
            var url = scratch
            if (try? url.setResourceValues(values)) != nil {
                var buffer = [UInt8](repeating: 0, count: 512)
                let n = getxattr(scratch.path, attribute, &buffer, buffer.count, 0, 0)
                if n > 0 { return Array(buffer.prefix(n)) }
            }
        }
        return Array(String(format: "0081;%08x;Nimbus\\x20Drop;", Int(Date().timeIntervalSince1970)).utf8)
    }
}
