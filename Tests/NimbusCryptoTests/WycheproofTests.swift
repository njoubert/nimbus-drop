// Copyright (C) 2026 Niels Joubert
// SPDX-License-Identifier: GPL-3.0-or-later
import Foundation
import XCTest
@testable import NimbusCrypto

/// X25519 as this project wraps it, against Project Wycheproof's vectors (`Vectors/README.md`).
///
/// The curve arithmetic is CryptoKit's and is not ours to test. What is ours is what is done
/// with the inputs it accepts and the outputs it gives: a key agreement whose result is all
/// zeros (the other side sent a point of low order, so the "shared secret" is one anybody
/// knows) is refused, and a public key has exactly one encoding. The vectors are the cases an
/// implementation gets wrong: low-order points, the twist, non-canonical encodings, edge
/// values of the scalar. 518 of them.
final class WycheproofTests: XCTestCase {
    struct File: Decodable {
        struct Group: Decodable {
            struct Test: Decodable {
                let tcId: Int
                let flags: [String]
                let `public`: String
                let `private`: String
                let shared: String
                let result: String
            }
            let curve: String
            let tests: [Test]
        }
        let algorithm: String
        let numberOfTests: Int
        let testGroups: [Group]
    }

    static func bytes(_ hex: String) -> Data {
        var out = Data(), rest = hex[...]
        while rest.count >= 2 {
            out.append(UInt8(rest.prefix(2), radix: 16)!)
            rest = rest.dropFirst(2)
        }
        return out
    }

    /// Whether 32 little-endian bytes are a number below 2^255 - 19 (which also means the top
    /// bit is clear).
    static func belowThePrime(_ raw: Data) -> Bool {
        let prime: [UInt8] = [0xed] + [UInt8](repeating: 0xff, count: 30) + [0x7f]
        let value = [UInt8](raw)
        guard value.count == 32 else { return false }
        for i in (0..<32).reversed() where value[i] != prime[i] { return value[i] < prime[i] }
        return false
    }

    func testKeyAgreementAgainstWycheproof() throws {
        let url = URL(fileURLWithPath: #filePath).deletingLastPathComponent().appendingPathComponent("Vectors/x25519_test.json")
        let file = try JSONDecoder().decode(File.self, from: Data(contentsOf: url))
        XCTAssertEqual(file.algorithm, "XDH")
        let tests = file.testGroups.filter { $0.curve == "curve25519" }.flatMap(\.tests)
        XCTAssertEqual(tests.count, file.numberOfTests)
        XCTAssertGreaterThan(tests.count, 500)
        var refused = 0, oneEncoding = 0
        for t in tests {
            let theirs = Self.bytes(t.public), shared = Self.bytes(t.shared)
            guard let pair = KeyPair(raw: Self.bytes(t.private)) else { XCTFail("vector \(t.tcId): the private key was not taken"); continue }
            if shared.allSatisfy({ $0 == 0 }) {
                // A point of low order: whatever the private key, the result is zero. (On this
                // macOS CryptoKit refuses these itself: taking the check out of `KeyPair.agree`
                // changes nothing here, which is why it has no line in scripts/mutate.py. It
                // stays as the second of two, for a system whose CryptoKit does not.)
                XCTAssertThrowsError(try pair.agree(with: theirs), "vector \(t.tcId) (\(t.flags)): an all-zero shared secret was accepted")
                XCTAssertTrue(t.flags.contains("LowOrderPublic") || t.flags.contains("ZeroSharedSecret"), "vector \(t.tcId)")
                refused += 1
            } else {
                XCTAssertEqual(try pair.agree(with: theirs), shared, "vector \(t.tcId) (\(t.flags))")
            }
            // One key, one encoding: the top bit set, or a value at or above the field prime,
            // is the same key written another way, and is not taken as a Mac's identity. Judged
            // here by the number itself (the vectors flag only some of them as non-canonical).
            let canonical = Self.belowThePrime(theirs)
            XCTAssertEqual(PublicKey(theirs) != nil, canonical, "vector \(t.tcId) (\(t.flags)): \(t.public)")
            if t.flags.contains("NonCanonicalPublic") { XCTAssertNil(PublicKey(theirs), "vector \(t.tcId)") }
            if !canonical { oneEncoding += 1 }
        }
        XCTAssertEqual(refused, 31, "the vectors with a zero shared secret")
        XCTAssertEqual(oneEncoding, 29, "the vectors whose public key is written a second way")
    }
}
