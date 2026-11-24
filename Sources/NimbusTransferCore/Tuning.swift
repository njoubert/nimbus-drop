// Copyright (C) 2026 Niels Joubert
// SPDX-License-Identifier: GPL-3.0-or-later
import Foundation
import NimbusBase
import NimbusCrypto
import NimbusNet
import NimbusSafeStorageCore
import NimbusSecurityCore

/// The engine's patience and its admission limits, in one place so the tests can shorten them.
extension Tuning {
    /// A data connection that moves nothing for this long is closed and its chunks are sent
    /// again on another. A drop with no sign of life for three times this long is given up.
    package nonisolated(unsafe) static var stallSeconds: Double = 60
    /// How long a sender keeps trying to open data connections when none will open.
    package nonisolated(unsafe) static var connectRetrySeconds: Double = 30
    /// Repair rounds in a row that deliver nothing before the receiver gives up.
    package nonisolated(unsafe) static var idleRounds = 5
    /// How long both sides hold a drop open after the connection that carries the conversation
    /// is lost: the sender trying to reconnect, the receiver waiting for it.
    package nonisolated(unsafe) static var reconnectSeconds: Double = 60
    /// How long a connection has to say what it is, in all.
    package nonisolated(unsafe) static var strangerSeconds: Double = 10
    /// Connections that have not yet said what they are, at once; more are closed on arrival.
    package nonisolated(unsafe) static var strangers = 64
    /// Of which from one address. At either limit the oldest gives way to the newcomer.
    package nonisolated(unsafe) static var strangersPerAddress = 8
    /// New connections a second from one address, under `arrivalsPerSecond` from all. A Mac
    /// sending several drops at once on 32 connections each opens well over a hundred in a second.
    package nonisolated(unsafe) static var arrivalsPerAddress = 200
    /// Of `unattachedPerDrop`, from one address.
    package nonisolated(unsafe) static var unattachedPerAddress = 4
    /// After a speed test from a key is answered (run, or declined): no other from that key
    /// for this long.
    package nonisolated(unsafe) static var speedPauseSeconds: Double = 10
    /// Connections from one paired key that have not yet said what they came for.
    package nonisolated(unsafe) static var pairedWaiting = 8
    /// Offers waiting for the person's answer at once, in all and from one address; more are
    /// declined, so that nobody can bury the screen in panels.
    package nonisolated(unsafe) static var pendingOffers = 6
    package nonisolated(unsafe) static var pendingOffersPerAddress = 2
    /// Connections that have completed a handshake with a key nobody here has paired, at once.
    package nonisolated(unsafe) static var unpaired = 8
    /// New connections taken per second, whoever they are from. A handshake costs this Mac a
    /// key generation and two key agreements, about a seventh of a millisecond: this many a
    /// second is under a tenth of one core. (It was 50 at first, and a test showed fifty
    /// strangers arriving in one second then kept a paired Mac out for the rest of it.)
    package nonisolated(unsafe) static var arrivalsPerSecond = 500
    /// Requests to pair that may wait behind the one on screen.
    package nonisolated(unsafe) static var pairRequestsWaiting = 4
    /// Data connections that have not yet proved they belong to a drop: this many per drop in
    /// progress, and this long to prove it.
    package nonisolated(unsafe) static var unattachedPerDrop = 16
    package nonisolated(unsafe) static var attachSeconds: Double = 5
    /// Bytes of control messages being reassembled at once, across every drop.
    package nonisolated(unsafe) static var controlBudget = 1 << 30
    /// Data connections one drop may have open.
    package nonisolated(unsafe) static var streamsPerDrop = 64
    /// How long a receiver waits for connections the sender says it opened but that never arrived.
    package nonisolated(unsafe) static var settleSeconds: Double = 1
    /// How long a sender that was accepted may be silent before its manifest, or in the
    /// middle of it. Room for the manifest is held meanwhile out of what all drops share
    /// (`controlBudget`), so a sender that says nothing must not hold it for ever. A minute:
    /// the largest manifest there can be (two million entries) took its sender under three
    /// seconds to encode before the first byte of it went (a debug build, 2026-11-24). It is a
    /// limit on silence, not on the whole: a manifest that keeps coming is waited for.
    package nonisolated(unsafe) static var manifestSeconds: Double = 60
}
