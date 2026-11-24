// Copyright (C) 2026 Niels Joubert
// SPDX-License-Identifier: GPL-3.0-or-later
import Foundation
import NimbusBase
import NimbusCrypto
import NimbusNet

/// The largest control message ever reassembled: a manifest of about two million files.
package let maxFrameBytes = 512 << 20

package enum FrameType: UInt8 {
    case offer = 1, accept, decline, manifest, plan, done, complete, error, hello, resume, resumed
    case pairRequest = 32, pairGo, commit, nonce, reveal, paired, pairFailed, busy
    case retire = 48, retired
    case speed = 64, speedGo, speedUpDone, speedCount, speedDown, speedDone
}

package func decode<T: Decodable>(_ type: T.Type, from body: Data) throws -> T {
    do { return try JSONDecoder().decode(type, from: body) } catch { throw DropError("Malformed message from the other Mac") }
}

package struct Empty: Codable { package init() {} }

package struct Reason: Codable {
    package var message: String
    /// With `busy` to a request to pair: the seconds for which requests nobody here asked for
    /// are not being shown. The asking Mac's tile says to start the pairing from this one.
    var pause: Double?

    package init(message: String, pause: Double? = nil) { self.message = message; self.pause = pause }
}

/// A value in the pairing exchange: the commitment, or one of the two random values.
package struct PairValue: Codable {
    package var value: Data
    package init(value: Data) { self.value = value }
}
