// Copyright (C) 2026 Niels Joubert
// SPDX-License-Identifier: GPL-3.0-or-later
import Darwin
import Foundation
import XCTest
@testable import NimbusBase
@testable import NimbusCrypto
@testable import NimbusDiscovery
@testable import NimbusDropCore
@testable import NimbusNet
@testable import NimbusSafeStorageCore
@testable import NimbusSecurityCore
@testable import NimbusTransferCore

/// Protocol 3 against a second implementation: `scripts/vectors.py`, written from the
/// specification in Python with another crypto library. What that script printed is below. A
/// difference here means one of the two implementations is not the specification.
final class VectorTests: XCTestCase {
    static let json = #"""
{
 "initiator_static": "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20",
 "initiator_ephemeral": "2122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f40",
 "responder_static": "4142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f60",
 "responder_ephemeral": "6162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f80",
 "initiator_public": "07a37cbc142093c8b755dc1b10e86cb426374ad16aa853ed0bdfc0b2b86d1c7c",
 "responder_public": "64b101b1d0be5a8704bd078f9895001fc03e8e9f9522f188dd128d9846d48466",
 "opening": "4e44524f500103",
 "prologue": "6e696d6275732d64726f702f334e44524f5001034e44524f500103",
 "handshake_frames": [
  "0020ffdf5869aff450549732cbaaed5e5df9b30a6da31cb0e5742bad5ad4a1a768f1a67b",
  "0060ff9f244fe3b963e899dd295baffce248d3530f3a9a7479ba063002680ebfe7adad4935aa6a8e508b0e5ea84343218663011a2e80eee8c38279f8f6a581a30de7fc7a57c8ec0fef5b57320664aa482d865b753ec7dc0d0db86bd9424eee93f735f0e7",
  "0040ffbf5dca9067f7af2b40c82e71d975a7e206f9b9cb3dc86df8d3688bb3a976de1fa15d4384835741d450cfca441aa51e5f4643ca60a46c5a6a80f32bce0d8fff8a89"
 ],
 "h": "9215f3cc01011b03dabe5d4f4ebb601a0594688414f28abe5e5bc28bc6706df2",
 "master": "c5034ac815bc251eba9ec0786926ca8e5c05e81ef8cbbed9cda1b51c16a98aa0",
 "control_body": "7b226974656d73223a5b2261225d2c2266696c65436f756e74223a312c22746f74616c4279746573223a357d",
 "control_frame_initiator": "0042ffbdfe0301d79b6535905cf9b83b5759a99101179f325f400ef5b9b35ed4e370b0df3dab323dfc7e3e6c810c78b2eace567964204c8736b0e2b9bd406ade342a112fa76a",
 "control_frame_responder": "0042ffbdb6957b9a758f2d05a872ae5af184df472b27708ccf1e5b80057e096e0d5cb98b0cb1bd286fc616fce8c36cc872785793a95e759f720d273b27071bbd5221d5fa122f",
 "session_id": "44122539a38757cbcf973c933b33749e",
 "attach_key": "2ece86e3151d273c89bfc6096f7fd28c56553215bdb19b3c9792439ad0fc3dfa",
 "resume_key": "049c63f03c7a0c7672642c3d313f08676150e41e218f80da23b6bc09fe8601ee",
 "stream_key_1": "ca591ce1365b028d4eff1f70aae2f59c00e0d9e22c1c19488d485be278344894",
 "stream_key_2": "dc9e92c2a43ee49ce19a590bc14e9d56224786f37d9742b86eec4dda4d13629b",
 "challenge": "a0a1a2a3a4a5a6a7a8a9aaabacadaeaf",
 "attach_7": "44122539a38757cbcf973c933b33749e0000000000000007ea9b5fd08cad3a8444505bddbc9164f9",
 "later_h": "f26233eea9b390176b2b38d19b94b181a051037900b3dc0c3dfd4492f6cdf893",
 "resume_proof": "3cf55372f60e0e378aacd2259b58f2e4533283cca717c139062d331bedf6ce39",
 "resumed_proof": "5bf453422bcfdd339c11559b1ea6e28b5227ba4026fced9e29f5d7d08ed80771",
 "record": "1c9f78934927e353195ee3aa3375138411e3dad98f3023b8be6ac6432dd74dca5d9812608647cec55fe54038b39fd6203f",
 "end_marker": "63f3d7a128a096a9811cbc731f3590c28146484d19e6d70efb933ee5",
 "ns": "1111111111111111111111111111111111111111111111111111111111111111",
 "nr": "2222222222222222222222222222222222222222222222222222222222222222",
 "commit": "964d0d99aa5dab8bcee9d8109aa177dee98b8b3f38aa182b717bcd5bee17fc18",
 "code_receiver": "759656",
 "code_sender": "893228",
 "initiator_tag": "JQ4T-VVPP-YJXG-1MBP",
 "initiator_number": "026813055260262255759972532711",
 "responder_tag": "A12Y-C0Y9-SPTJ-E2G7",
 "responder_number": "293699792116939100601602599741"
}
"""#

    var v: [String: Any] = [:]
    func s(_ key: String) -> String { v[key] as? String ?? "" }
    func d(_ key: String) -> Data { hex(s(key)) }

    override func setUpWithError() throws {
        v = try XCTUnwrap(try JSONSerialization.jsonObject(with: Data(VectorTests.json.utf8)) as? [String: Any])
    }

    /// Two connected sockets with something in between that writes down what each end sent.
    func tappedPair() throws -> (a: Socket, b: Socket, sent: () -> (byA: Data, byB: Data)) {
        var one = [Int32](repeating: 0, count: 2), two = [Int32](repeating: 0, count: 2)
        XCTAssertEqual(socketpair(AF_UNIX, SOCK_STREAM, 0, &one), 0)
        XCTAssertEqual(socketpair(AF_UNIX, SOCK_STREAM, 0, &two), 0)
        let a = Socket(fd: one[0]), tapA = Socket(fd: one[1]), tapB = Socket(fd: two[0]), b = Socket(fd: two[1])
        let byA = Locked(Data()), byB = Locked(Data())
        func pump(_ from: Socket, _ to: Socket, _ log: Locked<Data>) {
            Thread.detachNewThread {
                var buffer = [UInt8](repeating: 0, count: 65536)
                while true {
                    let n = read(from.fd, &buffer, buffer.count)
                    guard n > 0 else { to.shutdown(); return }
                    log.withLock { $0.append(contentsOf: buffer[0..<n]) }
                    guard (try? buffer.withUnsafeBytes { try to.writeAll($0.baseAddress!, n) }) != nil else { return }
                }
            }
        }
        pump(tapA, tapB, byA)
        pump(tapB, tapA, byB)
        return (a, b, { (byA.withLock { $0 }, byB.withLock { $0 }) })
    }

    func testEveryByteOfAConnectionIsWhatTheSecondImplementationSays() throws {
        let (a, b, sent) = try tappedPair()
        let si = try XCTUnwrap(KeyPair(raw: d("initiator_static"))), sr = try XCTUnwrap(KeyPair(raw: d("responder_static")))
        XCTAssertEqual(si.publicKey.raw, d("initiator_public"))
        XCTAssertEqual(sr.publicKey.raw, d("responder_public"))
        let responder = Locked<Channel?>(nil)
        let done = DispatchSemaphore(value: 0)
        Thread.detachNewThread { [self] in
            if (try? Opening.readKind(b)) == Opening.control {
                responder.withLock { $0 = try? Channel.respond(b, keys: sr, ephemeral: KeyPair(raw: d("responder_ephemeral"))) }
            }
            done.signal()
        }
        let initiator = try Channel.initiate(a, keys: si, expect: sr.publicKey, ephemeral: KeyPair(raw: d("initiator_ephemeral")))
        XCTAssertEqual(done.wait(timeout: .now() + 5), .success)
        let other = try XCTUnwrap(responder.withLock { $0 })
        XCTAssertEqual(initiator.h, d("h"))
        XCTAssertEqual(other.h, d("h"))
        XCTAssertEqual(initiator.master, d("master"), "the third output of Split, which the published Noise vectors do not cover")
        XCTAssertEqual(other.master, d("master"))
        XCTAssertEqual(other.remote, si.publicKey)

        // One control message each way, with a body whose bytes are fixed.
        try initiator.send(.offer, body: d("control_body"))
        try other.send(.offer, body: d("control_body"))
        XCTAssertEqual(try other.read().body, d("control_body"))
        XCTAssertEqual(try initiator.read().body, d("control_body"))

        let frames = try XCTUnwrap(v["handshake_frames"] as? [String]).map { hex($0) }
        let wire = sent()
        XCTAssertEqual(wire.byA.hex, (d("opening") + frames[0] + frames[2] + d("control_frame_initiator")).hex, "everything the initiator put on the wire")
        XCTAssertEqual(wire.byB.hex, (d("opening") + frames[1] + d("control_frame_responder")).hex, "and everything the responder did")
        XCTAssertEqual(Channel.prologue(initiator: d("opening"), responder: d("opening")), d("prologue"))
    }

    func testTheDropsKeys() throws {
        let keys = DropKeys(master: d("master"))
        XCTAssertEqual(keys.sessionID, d("session_id"))
        XCTAssertEqual(keys.attachKey, d("attach_key"))
        XCTAssertEqual(keys.resumeKey, d("resume_key"))
        XCTAssertEqual((keys.sessionID + Crypto.be64(7) + keys.attachTag(conn: 7, challenge: d("challenge"))).hex, s("attach_7"))
        XCTAssertEqual(DropKeys.resumeProof(keys.resumeKey, "resume", h: d("later_h")), d("resume_proof"))
        XCTAssertEqual(DropKeys.resumeProof(keys.resumeKey, "resumed", h: d("later_h")), d("resumed_proof"))
    }

    func testARecordAndTheEndMarker() throws {
        let keys = DropKeys(master: d("master"))
        var cipher = keys.stream(1)
        let payload = Data("hello".utf8)
        let record = try payload.withUnsafeBytes { try RecordHeader.seal(&cipher, file: 3, chunk: 9, bytes: $0.baseAddress!, count: 5) }
        XCTAssertEqual((record.header + record.ciphertext + record.tag).hex, s("record"))
        XCTAssertEqual(try RecordHeader.sealEnd(&cipher).hex, s("end_marker"))
        // The same bytes open under the same key and no other.
        var reader = keys.stream(1)
        let header = try reader.open(d("record").prefix(RecordHeader.sealedSize))
        XCTAssertEqual(RecordHeader(header)?.chunk, 9)
        XCTAssertEqual(try reader.open(d("record").dropFirst(RecordHeader.sealedSize), ad: header), payload)
        var other = keys.stream(2)
        XCTAssertThrowsError(try other.open(d("record").prefix(RecordHeader.sealedSize)), "another connection's key")
        var replay = keys.stream(1)
        _ = try replay.open(d("record").prefix(RecordHeader.sealedSize))
        XCTAssertThrowsError(try replay.open(d("record").prefix(RecordHeader.sealedSize)), "the same record a second time: the counter has moved on")
    }

    func testPairingCodesAndIdentities() throws {
        XCTAssertEqual(PairCodes.commitment(h: d("h"), ns: d("ns")), d("commit"))
        let codes = PairCodes.codes(h: d("h"), ns: d("ns"), nr: d("nr"))
        XCTAssertEqual(codes.receiver, s("code_receiver"))
        XCTAssertEqual(codes.sender, s("code_sender"))
        let i = try XCTUnwrap(PublicKey(d("initiator_public"))), r = try XCTUnwrap(PublicKey(d("responder_public")))
        XCTAssertEqual(i.tag, s("initiator_tag"))
        XCTAssertEqual(r.tag, s("responder_tag"))
        XCTAssertEqual(i.identityNumber, s("initiator_number"))
        XCTAssertEqual(r.identityNumber, s("responder_number"))
    }
}
