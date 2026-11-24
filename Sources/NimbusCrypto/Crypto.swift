// Copyright (C) 2026 Niels Joubert
// SPDX-License-Identifier: GPL-3.0-or-later
import CryptoKit
import Foundation
import NimbusBase

/// The cryptographic pieces of protocol 3, and nothing that touches a socket or a file.
///
/// What is standard: X25519, AES-256-GCM, SHA-256, HKDF and HMAC from CryptoKit, and the Noise
/// handshake `Noise_XX_25519_AESGCM_SHA256` (revision 34 of the specification), implemented here
/// and checked against published vectors (`CryptoTests`). What is ours: the third output taken
/// from Noise's final Split (`master`), every key derived from it, the pairing codes, and the
/// record format. `docs/plans/secure-drops-plan.html` is the specification; a change here that
/// is not a change there is a bug in one of them.
package enum Crypto {
    /// `KDF(key, info, n)`: HKDF-SHA-256 with an empty salt. Every derivation of our own uses
    /// this; Noise's own HKDF (`Noise.hkdf`) has different conventions and is used only inside
    /// the handshake.
    static func kdf(_ key: Data, _ info: Data, _ count: Int) -> Data {
        HKDF<SHA256>.deriveKey(inputKeyMaterial: SymmetricKey(data: key), salt: Data(), info: info, outputByteCount: count)
            .withUnsafeBytes { Data($0) }
    }

    static func kdf(_ key: Data, _ label: String, _ count: Int) -> Data { kdf(key, Data(label.utf8), count) }

    static func hmac(_ key: Data, _ message: Data) -> Data {
        Data(HMAC<SHA256>.authenticationCode(for: message, using: SymmetricKey(data: key)))
    }

    static func sha256(_ data: Data) -> Data { Data(SHA256.hash(data: data)) }

    package static func random(_ count: Int) -> Data {
        var bytes = [UInt8](repeating: 0, count: count)
        guard SecRandomCopyBytes(kSecRandomDefault, count, &bytes) == errSecSuccess else { fatalError("the system has no random bytes") }
        return Data(bytes)
    }

    /// Compares without stopping at the first difference.
    package static func same(_ a: Data, _ b: Data) -> Bool {
        guard a.count == b.count else { return false }
        var diff: UInt8 = 0
        for (x, y) in zip(a, b) { diff |= x ^ y }
        return diff == 0
    }

    package static func be64(_ v: UInt64) -> Data { withUnsafeBytes(of: v.bigEndian) { Data($0) } }
    package static func be32(_ v: UInt32) -> Data { withUnsafeBytes(of: v.bigEndian) { Data($0) } }
}

/// A Mac's identity as the rest of the world sees it: an X25519 public key in canonical form.
///
/// X25519 takes more than one encoding for the same key: the top bit of the last byte is
/// ignored, and values at or above the field prime wrap. Such an encoding is refused here,
/// before any lookup, tag or number is computed from it, so that a key on record is found again
/// when it is presented. (A handful of distinct canonical encodings still behave alike in a key
/// agreement; to this protocol each is a different, unknown key.)
public struct PublicKey: Hashable, Sendable, Codable, CustomStringConvertible {
    public let raw: Data

    public init?(_ raw: Data) {
        guard raw.count == 32 else { return nil }
        let b = [UInt8](raw)
        guard b[31] & 0x80 == 0 else { return nil }
        // 2^255 - 19, little-endian: ed ff … ff 7f.
        if b[31] == 0x7f, b[1..<31].allSatisfy({ $0 == 0xff }), b[0] >= 0xed { return nil }
        self.raw = Data(b)
    }

    public init(from decoder: Decoder) throws {
        let data = try decoder.singleValueContainer().decode(Data.self)
        guard let key = PublicKey(data) else { throw DropError("A stored key is not a valid key") }
        self = key
    }

    public func encode(to encoder: Encoder) throws {
        var c = encoder.singleValueContainer()
        try c.encode(raw)
    }

    /// "7F3K-92QD-M4TX-81WC": 80 bits of a hash of the key, for lists and logs. A label; never
    /// the basis for a decision and never sent in a Bonjour record.
    public var tag: String {
        let digest = Crypto.sha256(Data("nimbus-drop key tag v1".utf8) + raw).prefix(10)
        let alphabet = Array("0123456789ABCDEFGHJKMNPQRSTVWXYZ")
        var out = "", acc: UInt32 = 0, bits = 0
        for byte in digest {
            acc = acc << 8 | UInt32(byte)
            bits += 8
            while bits >= 5 {
                out.append(alphabet[Int(acc >> UInt32(bits - 5)) & 31])
                bits -= 5
            }
        }
        var grouped = ""
        for (i, c) in out.enumerated() {
            if i > 0, i % 4 == 0 { grouped.append("-") }
            grouped.append(c)
        }
        return grouped
    }

    /// Thirty digits that stand for the key, to be read over a phone or pasted into a message
    /// and typed into the other Mac, which does the comparing. As Signal derives each half of a
    /// safety number: `H0 = label ‖ key`, `Hi = SHA-512(Hi-1 ‖ key)` 5200 times, then six
    /// 5-byte integers of the result, each modulo 100000.
    public var identityNumber: String {
        var h = Data("nimbus-drop identity number v1".utf8) + raw
        for _ in 0..<5200 { h = Data(SHA512.hash(data: h + raw)) }
        var out = ""
        for group in 0..<6 {
            var v: UInt64 = 0
            for byte in h[(group * 5)..<(group * 5 + 5)] { v = v << 8 | UInt64(byte) }
            out += String(format: "%05llu", v % 100_000)
        }
        return out
    }

    /// "30517 84926 11370 65208 49913 07754".
    public static func grouped(_ number: String) -> String {
        var out = ""
        for (i, c) in number.enumerated() {
            if i > 0, i % 5 == 0 { out.append(" ") }
            out.append(c)
        }
        return out
    }

    /// The digits of whatever a person typed or pasted.
    public static func digits(_ text: String) -> String { String(text.unicodeScalars.filter { $0.value >= 48 && $0.value <= 57 }.map(Character.init)) }

    public var description: String { tag }

    /// A key nobody holds the other half of: for made-up data (the windows rendered for a
    /// screenshot) and for tests. The secret is made and dropped here.
    public static func madeUp() -> PublicKey { KeyPair().publicKey }
}

/// Secret bytes: a key, or what keys are made from (`master`, a drop's resume key). Any part
/// of the engine may hold one and hand it back to this module; only this module can read it,
/// and this module does no I/O. So a secret cannot be written to a socket, a file or the log
/// by code that merely has it: there is nothing in it that code can reach. It says nothing of
/// itself when printed or dumped.
package struct Secret: Sendable, CustomStringConvertible, CustomDebugStringConvertible, CustomReflectable {
    let bytes: Data
    init(_ bytes: Data) { self.bytes = bytes }
    package var description: String { "<secret>" }
    package var debugDescription: String { "<secret>" }
    package var customMirror: Mirror { Mirror(self, children: [:]) }
}

/// A static key pair. The private half never leaves this module: other modules can hold a
/// `KeyPair` and hand it to a handshake, and cannot read it. The one way out is the trust
/// file's plaintext (`TrustCore.encoded`), which goes to be sealed and stored.
///
/// `package`, not `public`: nothing outside the engine can so much as name it.
package struct KeyPair: Sendable {
    let secret: Curve25519.KeyAgreement.PrivateKey
    package let publicKey: PublicKey

    package init() {
        // A fresh key is canonical except, about once in 2^250, by value; make another then.
        while true {
            let k = Curve25519.KeyAgreement.PrivateKey()
            if let p = PublicKey(k.publicKey.rawRepresentation) { secret = k; publicKey = p; return }
        }
    }

    /// From stored bytes. Within this module only: the trust core reads the file.
    init?(raw: Data) {
        guard let k = try? Curve25519.KeyAgreement.PrivateKey(rawRepresentation: raw),
              let p = PublicKey(k.publicKey.rawRepresentation) else { return nil }
        secret = k
        publicKey = p
    }

    /// The private key's bytes. Within this module only.
    var raw: Data { secret.rawRepresentation }

    /// X25519. A result of all zeros (a key of low order) is refused.
    func agree(with other: Data) throws -> Data {
        guard let theirs = try? Curve25519.KeyAgreement.PublicKey(rawRepresentation: other),
              let shared = try? secret.sharedSecretFromKeyAgreement(with: theirs) else { throw DropError.notAuthentic }
        let bytes = shared.withUnsafeBytes { Data($0) }
        guard bytes.contains(where: { $0 != 0 }) else { throw DropError.notAuthentic }
        return bytes
    }
}

extension DropError {
    /// Something that should have been sealed by the other Mac's keys was not. Never a reason to
    /// carry on with that connection; said the same way whatever exactly failed.
    package static let notAuthentic = DropError("The other Mac could not prove what it sent", connection: true)
}

/// AES-256-GCM with a nonce that is a counter: four zero bytes, then the count, big-endian
/// (Noise's convention). A key and count pair is used once: the count only rises, and `limit`
/// ends the key's life long before the count or the cipher's own limits could be reached.
package struct CipherState {
    private let key: SymmetricKey
    package private(set) var count: UInt64 = 0
    /// Seals or opens allowed under this key.
    package let limit: UInt64

    init(key: Data, limit: UInt64 = 1 << 24) {
        self.key = SymmetricKey(data: key)
        self.limit = limit
    }

    var exhausted: Bool { count >= limit }

    private func nonce(_ n: UInt64) -> AES.GCM.Nonce {
        // Twelve bytes are always a valid nonce.
        // swiftlint:disable:next force_try
        try! AES.GCM.Nonce(data: Data(count: 4) + Crypto.be64(n))
    }

    /// The ciphertext followed by the 16-byte tag.
    package mutating func seal(_ plaintext: Data, ad: Data = Data()) throws -> Data {
        guard count < limit else { throw DropError("A key reached the end of its life", connection: true) }
        let box = try AES.GCM.seal(plaintext, using: key, nonce: nonce(count), authenticating: ad)
        count += 1
        return box.ciphertext + box.tag
    }

    package mutating func open(_ sealed: Data, ad: Data = Data()) throws -> Data {
        guard count < limit else { throw DropError("A key reached the end of its life", connection: true) }
        guard sealed.count >= 16 else { throw DropError.notAuthentic }
        let split = sealed.index(sealed.endIndex, offsetBy: -16)
        guard let box = try? AES.GCM.SealedBox(nonce: nonce(count), ciphertext: sealed[sealed.startIndex..<split], tag: sealed[split...]),
              let plain = try? AES.GCM.open(box, using: key, authenticating: ad) else { throw DropError.notAuthentic }
        count += 1
        return plain
    }

    /// For a chunk: seals bytes that are already in a buffer, without first copying them into a
    /// `Data`. Returns the ciphertext and the tag separately, to go out in one `writev`.
    package mutating func seal(bytes: UnsafeRawPointer, count length: Int, ad: Data) throws -> (ciphertext: Data, tag: Data) {
        guard count < limit else { throw DropError("A key reached the end of its life", connection: true) }
        let plain = Data(bytesNoCopy: UnsafeMutableRawPointer(mutating: bytes), count: length, deallocator: .none)
        let box = try AES.GCM.seal(plain, using: key, nonce: nonce(count), authenticating: ad)
        count += 1
        return (box.ciphertext, box.tag)
    }

    /// For a chunk: opens `length` bytes of ciphertext followed by a 16-byte tag, in a buffer.
    /// The plaintext is a new buffer nothing else has seen; it exists only if the tag held.
    package mutating func open(bytes: UnsafeRawPointer, count length: Int, ad: Data) throws -> Data {
        guard count < limit else { throw DropError("A key reached the end of its life", connection: true) }
        let cipher = Data(bytesNoCopy: UnsafeMutableRawPointer(mutating: bytes), count: length, deallocator: .none)
        let tag = Data(bytesNoCopy: UnsafeMutableRawPointer(mutating: bytes + length), count: 16, deallocator: .none)
        guard let box = try? AES.GCM.SealedBox(nonce: nonce(count), ciphertext: cipher, tag: tag),
              let plain = try? AES.GCM.open(box, using: key, authenticating: ad) else { throw DropError.notAuthentic }
        count += 1
        return plain
    }
}

/// `Noise_XX_25519_AESGCM_SHA256`.
///
/// ```
/// -> e
/// <- e, ee, s, es
/// -> s, se
/// ```
/// After message 2 the initiator knows the responder's static key and that the responder holds
/// it; after message 3 the responder knows the same of the initiator. `split()` then gives the
/// two transport keys of standard Noise and, as this protocol's one extension, a third output of
/// the same HKDF: the drop's `master`.
package final class Noise {
    static let name = Data("Noise_XX_25519_AESGCM_SHA256".utf8)

    /// Noise's HKDF: `ck` is the HMAC key, the outputs are chained with a counter byte.
    static func hkdf(_ ck: Data, _ ikm: Data, _ outputs: Int) -> [Data] {
        let temp = Crypto.hmac(ck, ikm)
        var out: [Data] = []
        var last = Data()
        for i in 1...outputs {
            last = Crypto.hmac(temp, last + Data([UInt8(i)]))
            out.append(last)
        }
        return out
    }

    private let initiator: Bool
    private let s: KeyPair
    private var e: KeyPair?
    private var re: Data?
    /// The other side's static key, once it has been read and (by the DH that follows it in the
    /// same message) proved.
    package private(set) var remoteStatic: PublicKey?
    private var ck: Data
    package private(set) var h: Data
    private var cipher: CipherState?
    private var step = 0

    /// `ephemeral`: tests only (the published vectors fix it).
    package init(initiator: Bool, prologue: Data, s: KeyPair, ephemeral: KeyPair? = nil) {
        self.initiator = initiator
        self.s = s
        e = ephemeral
        // The name is under 32 bytes, so h starts as the name padded with zeros.
        h = Noise.name + Data(count: 32 - Noise.name.count)
        ck = h
        mixHash(prologue)
    }

    private func mixHash(_ data: Data) { h = Crypto.sha256(h + data) }

    private func mixKey(_ ikm: Data) {
        let out = Noise.hkdf(ck, ikm, 2)
        ck = out[0]
        cipher = CipherState(key: out[1])
    }

    private func encryptAndHash(_ plain: Data) throws -> Data {
        guard cipher != nil else { mixHash(plain); return plain }
        let sealed = try cipher!.seal(plain, ad: h)
        mixHash(sealed)
        return sealed
    }

    private func decryptAndHash(_ data: Data) throws -> Data {
        guard cipher != nil else { mixHash(data); return data }
        let plain = try cipher!.open(data, ad: h)
        mixHash(data)
        return plain
    }

    var isComplete: Bool { step == 3 }

    /// The next message this side sends. Throws when it is not this side's turn.
    package func write(payload: Data = Data()) throws -> Data {
        guard step < 3, (step % 2 == 0) == initiator else { throw DropError.notAuthentic }
        var out = Data()
        switch step {
        case 0:
            let mine = e ?? KeyPair()
            e = mine
            out += mine.publicKey.raw
            mixHash(mine.publicKey.raw)
        case 1:
            guard let re else { throw DropError.notAuthentic }
            let mine = e ?? KeyPair()
            e = mine
            out += mine.publicKey.raw
            mixHash(mine.publicKey.raw)
            mixKey(try mine.agree(with: re))
            out += try encryptAndHash(s.publicKey.raw)
            mixKey(try s.agree(with: re))
        default:
            guard let re else { throw DropError.notAuthentic }
            out += try encryptAndHash(s.publicKey.raw)
            mixKey(try s.agree(with: re))
        }
        out += try encryptAndHash(payload)
        step += 1
        return out
    }

    /// Takes the other side's next message; returns its payload.
    package func read(_ message: Data) throws -> Data {
        guard step < 3, (step % 2 == 0) != initiator else { throw DropError.notAuthentic }
        var rest = message[...]
        func take(_ n: Int) throws -> Data {
            guard rest.count >= n else { throw DropError.notAuthentic }
            defer { rest = rest.dropFirst(n) }
            return Data(rest.prefix(n))
        }
        switch step {
        case 0:
            let theirs = try take(32)
            re = theirs
            mixHash(theirs)
        case 1:
            guard let e else { throw DropError.notAuthentic }
            let theirs = try take(32)
            re = theirs
            mixHash(theirs)
            mixKey(try e.agree(with: theirs))
            guard let key = PublicKey(try decryptAndHash(try take(48))) else { throw DropError.notAuthentic }
            mixKey(try e.agree(with: key.raw))
            remoteStatic = key
        default:
            guard let e else { throw DropError.notAuthentic }
            guard let key = PublicKey(try decryptAndHash(try take(48))) else { throw DropError.notAuthentic }
            mixKey(try e.agree(with: key.raw))
            remoteStatic = key
        }
        let payload = try decryptAndHash(Data(rest))
        step += 1
        return payload
    }

    /// The two transport keys (this side's sending one first) and the master. The chaining key
    /// is gone afterwards.
    package func split() throws -> (send: CipherState, receive: CipherState, master: Secret) {
        guard step == 3 else { throw DropError.notAuthentic }
        let out = Noise.hkdf(ck, Data(), 3)
        ck = Data()
        let first = CipherState(key: out[0]), second = CipherState(key: out[1])
        return initiator ? (first, second, Secret(out[2])) : (second, first, Secret(out[2]))
    }
}
