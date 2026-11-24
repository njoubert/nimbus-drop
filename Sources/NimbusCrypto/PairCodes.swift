// Copyright (C) 2026 Niels Joubert
// SPDX-License-Identifier: GPL-3.0-or-later
import Foundation
import NimbusBase

/// The two six-digit codes of a pairing, from what both ends saw.
///
/// ```
/// S → R   commit = SHA-256("nimbus-drop pair commit v1" ‖ h ‖ Ns)      Ns: 32 random bytes
/// R → S   Nr                                                             made after commit arrives
/// S → R   Ns                                                             checked against commit
/// codes   = KDF(Ns ‖ Nr, "nimbus-drop pair codes v1" ‖ h, 16)
/// ```
/// `h` is the handshake hash, which covers both static keys: someone in the middle holds two
/// sessions with two different `h`, and for the codes of the two to agree would have to steer a
/// value it cannot see (the sender's is inside the commitment; the receiver's does not exist
/// until the commitment has arrived). Hearing the codes read out tells it nothing it does not
/// already have.
package enum PairCodes {
    package static func commitment(h: Data, ns: Data) -> Data { Crypto.sha256(Data("nimbus-drop pair commit v1".utf8) + h + ns) }

    /// (the code the receiver shows and the sender types, the code the sender shows and the receiver types)
    package static func codes(h: Data, ns: Data, nr: Data) -> (receiver: String, sender: String) {
        let out = Crypto.kdf(ns + nr, Data("nimbus-drop pair codes v1".utf8) + h, 16)
        func six(_ d: Data) -> String {
            var v: UInt64 = 0
            for b in d { v = v << 8 | UInt64(b) }
            return String(format: "%06llu", v % 1_000_000)
        }
        return (six(out.prefix(8)), six(out.suffix(8)))
    }
}
