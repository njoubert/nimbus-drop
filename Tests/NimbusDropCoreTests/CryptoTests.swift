// Copyright (C) 2026 Niels Joubert
// SPDX-License-Identifier: GPL-3.0-or-later
import CryptoKit
import Foundation
import XCTest
@testable import NimbusDropCore

func hex(_ s: String) -> Data {
    var d = Data(), i = s.startIndex
    while i < s.endIndex { let j = s.index(i, offsetBy: 2); d.append(UInt8(s[i..<j], radix: 16)!); i = j }
    return d
}

extension Data { var hex: String { map { String(format: "%02x", $0) }.joined() } }

/// The cryptographic core against answers that were not produced by it.
final class CryptoTests: XCTestCase {
    /// `Noise_XX_25519_AESGCM_SHA256` from the snow project's published vectors
    /// (github.com/mcginty/snow, tests/vectors/snow.txt): three handshake messages and two
    /// transport messages, with fixed keys.
    func testTheHandshakeMatchesThePublishedNoiseVector() throws {
        let prologue = hex("5468657265206973206e6f20726967687420616e642077726f6e672e2054686572652773206f6e6c792066756e20616e6420626f72696e672e")
        let a = Noise(initiator: true, prologue: prologue, s: KeyPair(raw: hex("67a147237ca2e511a5328abf44fc049e725d23ac193f1d5e8da60d543670cd39"))!, ephemeral: KeyPair(raw: hex("b4dbfea92d1afb2ce4a508bd5e014d21ee95ced8d12346d226985d40b2da95e7"))!)
        let b = Noise(initiator: false, prologue: prologue, s: KeyPair(raw: hex("0e64a9143ba4c2bb79a25cd1c12575a9da949b52338b32fe1208e4b598c9acc0"))!, ephemeral: KeyPair(raw: hex("c3142e465cafd8356330d7f910146c5428a524e723df165d76a2d5a697aa7e6d"))!)
        let messages: [(String, String)] = [
            ("09f6721fa79e976f05d523c07e4818bfad6903108a05734e3163cec30442fcf5", "c8a324f41408be37f760130b5a8f2c4e9c92bab229e9b78007aa43b7c7656b3409f6721fa79e976f05d523c07e4818bfad6903108a05734e3163cec30442fcf5"),
            ("af62581a26fc31c4b722c1f04d73d845eb6daf35bcd64fc805a46a74bd747d90", "4e935a4c1dccaf91b78062590be1e790f984eeff2ab9a219e491387a99dbfe53b9ea4a0a1b78a30056a0615ef4cfcc5d5bcfa087abd07df701c08b2410ab385c490a43cd853a15a1d1e8162c25b78d362ff84afd1f02e0d0e8d25ada33fe5f8e8856cc49e9a896c1c10616508f52387ca29d35a037c7d1c968a45d07daf01667"),
            ("bae081c11b0a050d08a48d4a2dd387bd927e18d12c1f2758ae712ec4e3948dc8", "72eb5f83ef7773b38886a657b2216368f76f51e90855aaec0c9cd65c7750c531b3ef8a9261065b9b73009e698c3e0e1e7153c64e842d877db5f0953c2a43f12bdee99b360ebc11ee64a2989bf8f486a45267753caf35ad5900224e9b04c4b5b2"),
            ("062b027afab93baa74c7cdc1ac71b3486636bed142caec9f70f4dd672dbe120d", "9953df9aa4294b12364dd6896de6e705564a5583c67ed86f0b985054d63f4381bdb99faa8633893643d6ee3ba987344f"),
            ("3000ff396f68e4d00ac10c97a4c14e5901e3245dc29f9a801427babd59bfc2a3", "d9ea28203c96f5ac9024541d8f05e5e9bbfedccf701d2a2130ddeada49446a546d03c3ed440558782120b95e537a229e"),
        ]
        XCTAssertEqual(try a.write(payload: hex(messages[0].0)).hex, messages[0].1)
        XCTAssertEqual(try b.read(hex(messages[0].1)).hex, messages[0].0)
        XCTAssertEqual(try b.write(payload: hex(messages[1].0)).hex, messages[1].1)
        XCTAssertEqual(try a.read(hex(messages[1].1)).hex, messages[1].0)
        XCTAssertEqual(try a.write(payload: hex(messages[2].0)).hex, messages[2].1)
        XCTAssertEqual(try b.read(hex(messages[2].1)).hex, messages[2].0)
        XCTAssertEqual(a.h, b.h)
        XCTAssertEqual(a.remoteStatic, KeyPair(raw: hex("0e64a9143ba4c2bb79a25cd1c12575a9da949b52338b32fe1208e4b598c9acc0"))!.publicKey)
        XCTAssertEqual(b.remoteStatic, KeyPair(raw: hex("67a147237ca2e511a5328abf44fc049e725d23ac193f1d5e8da60d543670cd39"))!.publicKey)
        var (aSend, aReceive, aMaster) = try a.split()
        var (bSend, bReceive, bMaster) = try b.split()
        XCTAssertEqual(try bSend.seal(hex(messages[3].0)).hex, messages[3].1)
        XCTAssertEqual(try aReceive.open(hex(messages[3].1)).hex, messages[3].0)
        XCTAssertEqual(try aSend.seal(hex(messages[4].0)).hex, messages[4].1)
        XCTAssertEqual(try bReceive.open(hex(messages[4].1)).hex, messages[4].0)
        XCTAssertEqual(aMaster, bMaster)
        XCTAssertEqual(aMaster.count, 32)
    }
}
