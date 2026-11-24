// Copyright (C) 2026 Niels Joubert
// SPDX-License-Identifier: GPL-3.0-or-later
import Foundation
import SystemConfiguration

/// What macOS calls a network interface ("Thunderbolt Bridge", "Wi-Fi", "USB 10/100/1000 LAN")
/// for its BSD name ("bridge0", "en0", "en13"): which cable a speed test went over, in words a
/// person recognises from System Settings.
enum LinkName {
    static func display(_ bsd: String) -> String {
        let all = SCNetworkInterfaceCopyAll() as? [SCNetworkInterface] ?? []
        for interface in all where (SCNetworkInterfaceGetBSDName(interface) as String?) == bsd {
            if let name = SCNetworkInterfaceGetLocalizedDisplayName(interface) as String? { return "\(name) (\(bsd))" }
        }
        return bsd
    }
}
