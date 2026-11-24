// Copyright (C) 2026 Niels Joubert
// SPDX-License-Identifier: GPL-3.0-or-later
import Foundation
import NimbusBase
import NimbusCrypto
import NimbusNet
import NimbusSafeStorageCore
import NimbusSecurityCore

// MARK: Messages

/// What the sender proposes; enough for the receiving person to decide. Who the sender is came
/// with the handshake and the hello, not from here.
struct Offer: Codable {
    /// The top-level names being sent.
    var items: [String]
    var fileCount: Int
    var totalBytes: Int64
}

/// "Every chunk I had to send has been written." `streams` is how many data connections the
/// sender has opened in all, so the receiver knows how many to wait for.
struct Done: Codable {
    var streams: Int
    /// Chunks the sender has sent more than once so far.
    var resent: Int?
}

struct Complete: Codable { var saved: [String] }

/// "This is the drop with that session id, and here is proof that I hold its keys": an HMAC
/// under the drop's resume key over the new connection's handshake hash.
struct Resume: Codable { var session: Data; var proof: Data }
struct Resumed: Codable { var proof: Data }
