// Copyright (C) 2026 Niels Joubert
// SPDX-License-Identifier: GPL-3.0-or-later
import Foundation

public enum Format {
    /// "31.2 GB", decimal units as Finder shows them.
    public static func bytes(_ n: Int64) -> String {
        let units = ["bytes", "KB", "MB", "GB", "TB"]
        var value = Double(n), unit = 0
        while value >= 1000, unit < units.count - 1 { value /= 1000; unit += 1 }
        if unit == 0 { return n == 1 ? "1 byte" : "\(n) bytes" }
        return String(format: value >= 100 ? "%.0f %@" : (value >= 10 ? "%.1f %@" : "%.2f %@"), value, units[unit])
    }

    /// "812 MB/s".
    public static func rate(_ bytesPerSecond: Double) -> String { bytes(Int64(max(0, bytesPerSecond))) + "/s" }

    /// "0:31", "12:05", "1:02:09".
    public static func duration(_ seconds: Double) -> String {
        let s = Int(max(0, seconds.rounded()))
        return s >= 3600 ? String(format: "%d:%02d:%02d", s / 3600, s / 60 % 60, s % 60) : String(format: "%d:%02d", s / 60, s % 60)
    }

    /// "1 file", "1,204 files".
    public static func files(_ n: Int) -> String {
        let f = NumberFormatter()
        f.numberStyle = .decimal
        return "\(f.string(from: NSNumber(value: n)) ?? "\(n)") \(n == 1 ? "file" : "files")"
    }
}
