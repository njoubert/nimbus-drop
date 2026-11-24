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
    /// Of which from one address. Anyone can make a key, so this pool is kept as the pool of
    /// connections that have proved nothing is: at either limit the oldest that has asked for
    /// nothing gives way to the newcomer. Two is what one Mac needs (a pairing can only be one
    /// at a time, and a second connection may be asking who is here); four addresses would be
    /// needed to hold every place, and even then the one that has waited longest gives way.
    /// A connection whose request to pair has been read keeps its place for as long as it
    /// lasts, so this is also the most requests one address can have waiting for a person.
    package nonisolated(unsafe) static var unpairedPerAddress = 2
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
    /// How long a finished drop's answer is kept, with the one key of the drop that is still
    /// needed (to know that whoever asks "did it arrive?" is its sender), for a sender whose
    /// connection was lost before it heard. After that, neither is here any more.
    package nonisolated(unsafe) static var completedSeconds: Double = 300
}
