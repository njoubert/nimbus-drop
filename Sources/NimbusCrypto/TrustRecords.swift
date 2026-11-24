// Copyright (C) 2026 Niels Joubert
// SPDX-License-Identifier: GPL-3.0-or-later
import Foundation
import NimbusBase

/// A Mac this one has paired with.
public struct KnownMac: Codable, Identifiable, Equatable, Sendable {
    public var key: PublicKey
    /// What the person here calls it; unique among the Known Macs. A Mac cannot rename itself
    /// into something misleading, because this is what is shown, not what it announces.
    public var name: String
    /// What it has called itself.
    public var announced: [String]
    public var pairedAt: Date
    /// "codes" or "identity number".
    public var method: String
    /// When its key ends: a reading of this Mac's elapsed-time counter, and a calendar date.
    /// Whichever comes first ends it. Never moved later.
    var endsElapsed: Double
    public var endsWall: Date
    public var lastSeen: Date?
    /// The highest protocol major it has proved; a lower one from it is refused afterwards.
    public var major: Int
    /// Times another key has used its name.
    public var impostors = 0
    public var lastImpostor: String?

    public var id: Data { key.raw }
}

/// A key that is never to be trusted again, and why.
public struct Tombstone: Codable, Equatable, Sendable {
    public var key: PublicKey
    public var name: String
    public var at: Date
    /// "retired" (it said so), "replaced" (the person paired its successor), "expired".
    public var reason: String
    /// Times it has been presented since.
    public var attempts = 0
}

/// A Mac that was paired with a key this Mac no longer has (it reset, or its key ran out). It
/// is not trusted; it is remembered so that pairing again can say it is the same Mac.
public struct Renewal: Codable, Equatable, Identifiable, Sendable {
    public var key: PublicKey
    public var name: String
    /// After a reset: whether it acknowledged being told. Nil after an ordinary expiry.
    public var told: Bool?
    /// When its own key ends, after which the entry is dropped.
    var endsElapsed: Double
    public var endsWall: Date
    public var pairedAgain = false
    public var id: Data { key.raw }
}

/// An unknown key is using the name of a Mac this one knows.
public struct NameClash: Equatable, Sendable {
    /// What that Mac is called here.
    public var name: String
    public var key: PublicKey
    public var pairedAt: Date?
    /// Its key has run out, so a new key under its name was to be expected.
    public var expected: Bool
    /// It is paired now (as opposed to waiting to be paired again).
    public var paired: Bool

    public init(name: String, key: PublicKey, pairedAt: Date?, expected: Bool, paired: Bool) {
        self.name = name; self.key = key; self.pairedAt = pairedAt; self.expected = expected; self.paired = paired
    }
}

/// What a key is to this Mac.
public enum KeyStanding: Equatable, Sendable {
    case mine
    /// Paired, and within its dates.
    case paired(KnownMac)
    /// Paired once; its key has reached its end. Refused, and cannot be paired again.
    case expired(KnownMac)
    /// Given up or replaced. Refused, and cannot be paired again.
    case retired(Tombstone)
    /// Known from before this Mac's own key changed; needs pairing again.
    case renew(Renewal)
    case unknown

    public var isPaired: Bool { if case .paired = self { return true }; return false }
    /// Whether a pairing with this key may be started at all.
    public var mayPair: Bool {
        switch self {
        case .unknown, .renew, .paired: return true
        case .mine, .expired, .retired: return false
        }
    }
}

/// The three clocks, read once. The calendar can be set by anyone who controls a time server,
/// so lifetimes are counted on `continuous`, which runs through sleep and cannot be set.
package struct ClockReading: Equatable, Sendable {
    /// Changes at every boot.
    package var boot: String
    /// Seconds since boot, sleep included.
    package var continuous: Double
    package var wall: Date

    package init(boot: String, continuous: Double, wall: Date) {
        self.boot = boot; self.continuous = continuous; self.wall = wall
    }
}
