// Copyright (C) 2026 Niels Joubert
// SPDX-License-Identifier: GPL-3.0-or-later
import Foundation
import XCTest
@testable import NimbusBase
@testable import NimbusCrypto
@testable import NimbusDropCore
@testable import NimbusNet
@testable import NimbusSafeStorageCore
@testable import NimbusSecurityCore
@testable import NimbusTransferCore

/// The secrets must not flow. Key bytes are kept inside `NimbusCrypto` by the compiler
/// (`scripts/test-capabilities.py`) and kept out of what says things by a lint
/// (`scripts/check-layers.py`). This is the same claim tested from the other end: everything
/// two Macs do with each other, with every log line recorded at every level, and then a search
/// of the record for the keys themselves and for anything shaped like one.
final class SecretsTests: XCTestCase {
    override func setUp() { Tuning.pairQuietSeconds = 0.3; Tuning.speedPauseSeconds = 0 }
    override func tearDown() { Tuning.pairQuietSeconds = 10; Tuning.speedPauseSeconds = 10; DropLog.sink = nil }

    func testNothingSecretIsEverLogged() throws {
        let lines = Locked<[String]>([])
        DropLog.sink = { _, line in lines.withLock { $0.append(line) } }

        // Two Macs pair with codes.
        let a = try TestMac("macbookpro"), b = try TestMac("dads-imac")
        b.onRequest = { $0.proceed() }
        let mine = a.pair(with: b)
        XCTAssertTrue(until { !b.requests.withLock { $0 }.isEmpty })
        let theirs = try XCTUnwrap(b.requests.withLock { $0.last })
        let codeA = try XCTUnwrap(mine.code()), codeB = try XCTUnwrap(theirs.code())
        mine.submit(codeB)
        theirs.submit(codeA)
        XCTAssertTrue(until { mine.isPaired && theirs.isPaired })
        // What must not appear: this Mac's and that Mac's private keys, as they were then.
        var secrets = [a.trust.keyPair.raw, b.trust.keyPair.raw]

        // A drop of a folder, accepted.
        let fm = FileManager.default
        let root = fm.temporaryDirectory.appendingPathComponent("nimbus-secrets-\(UUID().uuidString)", isDirectory: true)
        defer { try? fm.removeItem(at: root) }
        let src = root.appendingPathComponent("Photos", isDirectory: true), dst = root.appendingPathComponent("dst", isDirectory: true)
        try fm.createDirectory(at: src.appendingPathComponent("sub"), withIntermediateDirectories: true)
        try fm.createDirectory(at: dst, withIntermediateDirectories: true)
        for (name, size) in [("one.bin", 300_000), ("sub/two.bin", 70_000), ("empty", 0)] {
            try Data((0..<size).map { UInt8(truncatingIfNeeded: $0 &* 31) }).write(to: src.appendingPathComponent(name))
        }
        let send = SendSession(urls: [src], host: "127.0.0.1", port: b.port, peerName: "dads-imac", identity: a.identity, trust: a.trust, expect: b.key, streams: 3, chunkSize: 65536)
        send.start()
        XCTAssertTrue(until { b.offers.withLock { $0.count == 1 } })
        b.offers.withLock { $0[0] }.accept(destination: dst)
        XCTAssertTrue(until(30) { send.state.isFinal })
        XCTAssertEqual(send.state, .completed)

        // A speed test, allowed.
        b.listener.onSpeedTest = { $0.accept() }
        let speed = SpeedTest(host: "127.0.0.1", port: b.port, peerName: "dads-imac", identity: a.identity, trust: a.trust, expect: b.key, seconds: 1, streams: 2)
        speed.start()
        XCTAssertTrue(until(30) { speed.state.isFinal })

        // And a reset of this Mac's identity, which tells the other and makes a new key.
        let port = b.port, oldKey = a.key
        a.trust.reset(identity: a.identity, reach: { _ in ("127.0.0.1", port) }, seconds: 5)
        secrets.append(a.trust.keyPair.raw)
        XCTAssertTrue(until { !b.trust.standing(of: oldKey).isPaired }, "the other Mac was told of the reset")
        Thread.sleep(forTimeInterval: 0.3)

        let record = lines.withLock { $0 }
        XCTAssertGreaterThan(record.count, 40, "the log was not being recorded: \(record.count) lines")
        XCTAssertTrue(record.contains { $0.contains("paired with") } && record.contains { $0.contains("summary:") }, "the record is not of what this test did")
        // File paths are not secrets, and a temporary folder's path is long and made of the
        // same letters as base64: taken out before looking for the shape of a key.
        let places = [root.path, "/private" + root.path, fm.temporaryDirectory.path, "/private" + fm.temporaryDirectory.path]
        for logged in record {
            let line = places.reduce(logged) { $0.replacingOccurrences(of: $1, with: "<tmp>") }
            for secret in secrets {
                let hex = secret.map { String(format: "%02x", $0) }.joined()
                XCTAssertFalse(line.lowercased().contains(hex), "a private key, in hex: \(line.prefix(120))")
                XCTAssertFalse(line.contains(secret.base64EncodedString()), "a private key, in base64: \(line.prefix(120))")
                XCTAssertFalse(line.lowercased().contains(hex.prefix(24)), "the start of a private key: \(line.prefix(120))")
            }
            // Anything shaped like key material at all: forty hex digits or forty-three of
            // base64 in a row. (A partial folder's name has 32 hex digits of a hash of the
            // manifest, which is not a secret and is shorter; key tags are 16 characters.)
            XCTAssertNil(line.range(of: "[0-9a-fA-F]{40,}", options: .regularExpression), "forty hex digits in a row: \(line.prefix(160))")
            XCTAssertNil(line.range(of: "[A-Za-z0-9+/]{43,}", options: .regularExpression), "forty-three base64 characters in a row: \(line.prefix(160))")
        }
    }

    /// What is said to the OTHER Mac when something goes wrong here: a reason, and nothing
    /// about this Mac's disk. (A reason is a `Reason(message:)` on the control connection.)
    func testAKeyAndItsBytesNeverDescribeThemselves() {
        let pair = KeyPair()
        let said = "\(pair) \(String(describing: pair)) \(String(reflecting: pair.publicKey)) \(pair.publicKey)"
        let hex = pair.raw.map { String(format: "%02x", $0) }.joined()
        XCTAssertFalse(said.lowercased().contains(hex.prefix(16)), "a key pair prints its private half: \(said)")
        XCTAssertFalse(said.contains(pair.raw.base64EncodedString().prefix(12)))
        var core = TrustCore(fresh: ClockReading(boot: "b", continuous: 1, wall: Date()), lifetime: 3600)
        _ = core.tick(ClockReading(boot: "b", continuous: 2, wall: Date()))
        let dumped = "\(core.sessions) \(core.known) \(core.tombstones) \(core.again)"
        XCTAssertFalse(dumped.lowercased().contains(core.pair.raw.map { String(format: "%02x", $0) }.joined().prefix(16)))
    }
}
