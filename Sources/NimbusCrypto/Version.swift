// Copyright (C) 2026 Niels Joubert
// SPDX-License-Identifier: GPL-3.0-or-later
import Foundation
import NimbusBase

/// The protocol's version, in two parts.
///
/// **Major** changes when two copies can no longer exchange a drop. Every connection opens by
/// listing the majors each side speaks, and those openings are bound into the handshake, so the
/// choice cannot be altered on the way. **Minor** changes when something is added that an older
/// copy can ignore (a new optional field, which JSON decoding skips); it travels inside the
/// encrypted hello.
///
/// Protocol 3 is encrypted and authenticated end to end and has nothing in common with 2 on the
/// wire. It does not read, answer or recognise protocol 2 (decided 2026-11-22: it ran on four
/// Macs, all the owner's).
public let protocolVersion = 3
public let protocolMinor = 1

/// "3.0".
public var protocolVersionText: String { "\(protocolVersion).\(protocolMinor)" }

extension Noise {
    /// What both sides mix into the handshake before anything else: the protocol's name and
    /// major, and both openings byte for byte as they crossed the wire. An opening altered on
    /// the way leaves the two ends hashing different things, and the handshake fails.
    package static func prologue(initiator: Data, responder: Data) -> Data {
        Data("nimbus-drop/\(protocolVersion)".utf8) + initiator + responder
    }
}
