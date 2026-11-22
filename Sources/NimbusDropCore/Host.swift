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
