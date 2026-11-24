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
    public static func rate(_ bytesPerSecond: Double) -> String { bytes(Int64(whole(bytesPerSecond, atMost: 9e18))) + "/s" }

    /// A whole number from one that may be anything: never negative, never past `atMost`, and
    /// not-a-number is nothing. What is shown is computed from counts and times, some of them
    /// another Mac's: a rate that is next to nothing makes "time left" a number no integer
    /// holds, and turning that into one traps (a crash, for showing a row).
    static func whole(_ x: Double, atMost: Double) -> Int { x.isNaN ? 0 : Int(min(max(0, x.rounded()), atMost)) }

    /// A hundred thousand years of seconds: more than any time shown means anything.
    static let longest = 3.2e12

    /// A network rate in bits: "940 Mbps", "1.24 Gbps", "640 kbps".
    public static func bitRate(_ bytesPerSecond: Double) -> String {
        let units = ["bps", "kbps", "Mbps", "Gbps"]
        var value = max(0, bytesPerSecond) * 8, unit = 0
        while value >= 1000, unit < units.count - 1 { value /= 1000; unit += 1 }
        return String(format: value >= 100 || unit == 0 ? "%.0f %@" : (value >= 10 ? "%.1f %@" : "%.2f %@"), value, units[unit])
    }

    /// "1 connection", "8 connections".
    public static func connections(_ n: Int) -> String { "\(n) \(n == 1 ? "connection" : "connections")" }

    /// "0:31", "12:05", "1:02:09".
    public static func duration(_ seconds: Double) -> String {
        let s = whole(seconds, atMost: longest)
        return s >= 3600 ? String(format: "%d:%02d:%02d", s / 3600, s / 60 % 60, s % 60) : String(format: "%d:%02d", s / 60, s % 60)
    }

    /// How long a key lasts: "90 days", "1 week", "1 hour".
    public static func lifetime(_ seconds: Double) -> String {
        let s = whole(seconds, atMost: longest)
        func say(_ n: Int, _ unit: String) -> String { "\(n) \(unit)\(n == 1 ? "" : "s")" }
        if s % (7 * 86400) == 0, s / (7 * 86400) == 1 { return "1 week" }
        if s >= 86400 { return say(s / 86400, "day") }
        if s >= 3600 { return say(s / 3600, "hour") }
        return say(max(1, s / 60), "minute")
    }

    /// "1 file", "1,204 files".
    public static func files(_ n: Int) -> String {
        let f = NumberFormatter()
        f.numberStyle = .decimal
        return "\(f.string(from: NSNumber(value: n)) ?? "\(n)") \(n == 1 ? "file" : "files")"
    }
}
