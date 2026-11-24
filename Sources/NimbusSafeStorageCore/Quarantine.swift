// Copyright (C) 2026 Niels Joubert
// SPDX-License-Identifier: GPL-3.0-or-later
import Darwin
import Foundation
import NimbusBase

/// The mark macOS puts on files that came from somewhere else, so that Gatekeeper asks before
/// an app or a script among them is run for the first time. AirDrop and browsers set it; a drop
/// is no different. Photos and documents open as usual.
package enum Quarantine {
    static let attribute = "com.apple.quarantine"

    /// The attribute's value for files received now, made by macOS itself (so that it is in
    /// the form the system expects, and known to its record of quarantined files): a scratch
    /// file is marked through the system's API and what it wrote is read back. If that cannot
    /// be done, the same form written by hand.
    package static func value() -> [UInt8] {
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
