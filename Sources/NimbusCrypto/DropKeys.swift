// Copyright (C) 2026 Niels Joubert
// SPDX-License-Identifier: GPL-3.0-or-later
import Foundation
import NimbusBase

/// The keys of one drop, all derived from the handshake's `master`. One master per drop: a
/// reconnect proves the same two Macs again and gives the control channel new keys, and changes
/// nothing here, so data connections that outlive a control connection keep working.
package struct DropKeys {
    package let sessionID: Data
    private let master: Data
    let attachKey: Data
    package let resumeKey: Data

    /// At most this many bytes and this many seals under one stream key; then the sender moves
    /// to a new connection, and so to a new key. Far inside what the cipher allows.
    package nonisolated(unsafe) static var streamBytes: Int64 = 1 << 38
    static let streamSeals: UInt64 = 1 << 24

    package init(master: Data) {
        self.master = master
        sessionID = Crypto.kdf(master, "nimbus-drop session id v1", 16)
        attachKey = Crypto.kdf(master, "nimbus-drop attach v1", 32)
        resumeKey = Crypto.kdf(master, "nimbus-drop resume v1", 32)
    }

    /// The key of data connection number `conn`. A number is used once in a drop, so a key is too.
    package func stream(_ conn: UInt64) -> CipherState {
        CipherState(key: Crypto.kdf(master, Data("nimbus-drop stream v1".utf8) + Crypto.be64(conn), 32), limit: DropKeys.streamSeals)
    }

    package func attachTag(conn: UInt64, challenge: Data) -> Data {
        Crypto.hmac(attachKey, sessionID + Crypto.be64(conn) + challenge).prefix(16)
    }

    package static func resumeProof(_ resumeKey: Data, _ label: String, h: Data) -> Data { Crypto.hmac(resumeKey, Data(label.utf8) + h) }
}

/// The twelve bytes sealed before every chunk on a data connection: which file, which chunk,
/// how long. Sealed by themselves and opened before the chunk is read, so nobody watching can
/// tell where one file ends, and a damaged length is caught at once.
package struct RecordHeader {
    static let size = 12
    package static let sealedSize = 28
    package static let endMarker = UInt32.max
    package var file: UInt32
    package var chunk: UInt32
    package var length: UInt32

    var bytes: Data { Crypto.be32(file) + Crypto.be32(chunk) + Crypto.be32(length) }

    package init(file: UInt32, chunk: UInt32, length: UInt32) { self.file = file; self.chunk = chunk; self.length = length }

    /// A whole record as it goes on the wire: the header sealed by itself, then the chunk sealed
    /// with the header as associated data. Two seals, two counts.
    package static func seal(_ cipher: inout CipherState, file: UInt32, chunk: UInt32, bytes: UnsafeRawPointer, count: Int) throws -> (header: Data, ciphertext: Data, tag: Data) {
        let header = RecordHeader(file: file, chunk: chunk, length: UInt32(count)).bytes
        let sealedHeader = try cipher.seal(header)
        let body = try cipher.seal(bytes: bytes, count: count, ad: header)
        return (sealedHeader, body.ciphertext, body.tag)
    }

    /// What ends a data connection: exactly this header, sealed, and nothing after it.
    package static func sealEnd(_ cipher: inout CipherState) throws -> Data {
        try cipher.seal(RecordHeader(file: endMarker, chunk: 0, length: 0).bytes)
    }

    package init?(_ data: Data) {
        guard data.count == RecordHeader.size else { return nil }
        let v = data.withUnsafeBytes { p in (0..<3).map { UInt32(bigEndian: p.loadUnaligned(fromByteOffset: $0 * 4, as: UInt32.self)) } }
        file = v[0]; chunk = v[1]; length = v[2]
    }
}
