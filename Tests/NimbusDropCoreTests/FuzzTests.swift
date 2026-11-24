// Copyright (C) 2026 Niels Joubert
// SPDX-License-Identifier: GPL-3.0-or-later
import Foundation
import XCTest
@testable import NimbusBase
@testable import NimbusCrypto
@testable import NimbusDropCore
@testable import NimbusSafeStorageCore
@testable import NimbusSecurityCore

/// Seeded fuzzers for what is parsed and what is computed from numbers that are not this
/// Mac's own. (This toolchain has no libFuzzer for macOS: `-sanitize=fuzzer` is refused. So
/// the generation is here, with a seed that is printed, and `swift test --sanitize=address`
/// and `--sanitize=thread` run the same inputs under the sanitizers.) Swift traps on overflow
/// and on a float that no integer holds, and a trap is a crash: for each of these, not
/// crashing is the first property, and what must hold of whatever was accepted is the second.
/// `ReviewTests` has the three that speak the wire (openings, sealed messages, records).
final class FuzzTests: XCTestCase {
    struct SplitMix: RandomNumberGenerator {
        var state: UInt64
        init(seed: UInt64) { state = seed }
        mutating func next() -> UInt64 {
            state &+= 0x9E37_79B9_7F4A_7C15
            var z = state
            z = (z ^ (z >> 30)) &* 0xBF58_476D_1CE4_E5B9
            z = (z ^ (z >> 27)) &* 0x94D0_49BB_1331_11EB
            return z ^ (z >> 31)
        }
    }

    /// Fixed seeds, and one from the clock so that every run also looks somewhere new.
    static var seeds: [UInt64] { [1, 2, 3, 0xF0220, UInt64(Date().timeIntervalSince1970 * 1000)] }

    static let nastyInts: [Int64] = [0, 1, -1, 4095, 4096, 4097, 1 << 20, 1 << 31, (1 << 32) - 1, 1 << 32, 1 << 50, (1 << 50) + 1, 1 << 60, .max, .min, .max - 1]
    static let nastyDoubles: [Double] = [0, -0.0, 1, -1, 0.1, 1e-300, 1e11, -1e11, 1e300, -1e300, .infinity, -.infinity, .nan, .greatestFiniteMagnitude, .leastNonzeroMagnitude,
                                         9.3e18, 1.9e19]
    static let nastyNames = ["", ".", "..", "/", "a/", "/a", "a//b", "a/./b", "a/../b", "../a", "a\u{0}b", "A", "a", "Maße", "Masse", "e\u{301}", "\u{e9}",
                             String(repeating: "n", count: 255), String(repeating: "n", count: 256), "a\u{202E}fdp.exe", " ", "con", "a\nb", "💣", "a\u{200B}",
                             "x.nimbusdrop-partial", "items", "ledger"]

    static func pick<T>(_ from: [T], _ rng: inout SplitMix) -> T { from[Int(rng.next() % UInt64(from.count))] }

    // MARK: The manifest

    /// A manifest is another Mac's text and numbers. Whatever it holds, `validate` answers
    /// (it does not trap), and what it lets through has arithmetic that holds together.
    func testManifestsOfHostileNumbersAndNames() throws {
        var accepted = 0, refused = 0
        for seed in Self.seeds {
            var rng = SplitMix(seed: seed)
            for round in 0..<3000 {
                var entries: [Manifest.Entry] = []
                var folders = ["top"]
                entries.append(.init(path: "top", kind: .directory))
                for i in 0..<Int(rng.next() % 12) {
                    let hostile = rng.next() % 4 == 0
                    let parent = Self.pick(folders, &rng)
                    let name = hostile ? Self.pick(Self.nastyNames, &rng) : "f\(i)"
                    let path = rng.next() % 9 == 0 ? name : parent + "/" + name
                    switch rng.next() % 4 {
                    case 0:
                        entries.append(.init(path: path, kind: .directory, mtime: hostile ? Self.pick(Self.nastyDoubles, &rng) : 1e9))
                        if !hostile { folders.append(path) }
                    case 1:
                        entries.append(.init(path: path, kind: .symlink, link: hostile ? Self.pick(Self.nastyNames + [String(repeating: "l", count: 5000)], &rng) : "f0"))
                    default:
                        entries.append(.init(path: path, kind: .file, size: rng.next() % 3 == 0 ? Self.pick(Self.nastyInts, &rng) : Int64(rng.next() % 100_000),
                                             mtime: rng.next() % 5 == 0 ? Self.pick(Self.nastyDoubles, &rng) : 1e9, mode: UInt16(truncatingIfNeeded: rng.next())))
                    }
                }
                let chunkSize = rng.next() % 3 == 0 ? Int(truncatingIfNeeded: Self.pick(Self.nastyInts, &rng)) : 4096 << Int(rng.next() % 12)
                let manifest = Manifest(chunkSize: chunkSize, entries: entries)
                // Through JSON too, as it arrives: a number JSON cannot say is refused there.
                guard let data = try? JSONEncoder().encode(manifest), let decoded = try? JSONDecoder().decode(Manifest.self, from: data) else { refused += 1; continue }
                guard (try? decoded.validate()) != nil else { refused += 1; continue }
                accepted += 1
                let why = "seed \(seed), round \(round)"
                // What was let through: sizes that add up, chunks that tile each file exactly.
                XCTAssertGreaterThanOrEqual(decoded.totalBytes, 0, why)
                XCTAssertLessThanOrEqual(decoded.totalBytes, Manifest.maxTotalBytes, why)
                for (i, e) in decoded.entries.enumerated() where e.kind == .file {
                    let n = decoded.chunkCount(i)
                    XCTAssertLessThan(n, Int(UInt32.max), why)
                    guard n > 0 else { XCTAssertEqual(e.size, 0, why); continue }
                    let last = decoded.chunkLength(file: i, chunk: n - 1), first = decoded.chunkLength(file: i, chunk: 0)
                    XCTAssertTrue(last > 0 && last <= decoded.chunkSize && first <= decoded.chunkSize, why)
                    XCTAssertEqual(Int64(n - 1) * Int64(decoded.chunkSize) + Int64(last), e.size, why)
                }
                // And names that are one name each, as text: no two entries fold together.
                XCTAssertEqual(Set(decoded.entries.map { Manifest.folded($0.path) }).count, decoded.entries.count, why)
                _ = decoded.key(senderID: "aa")
            }
        }
        XCTAssertGreaterThan(accepted, 500, "the fuzzer made nothing acceptable: it is testing the refusals only")
        XCTAssertGreaterThan(refused, 500)
    }

    // MARK: The ledger file

    /// The resume ledger is a file in the partial folder, and whatever is in it (a torn write,
    /// another drop's, noise), opening it answers, counts no more than the drop holds, and
    /// offers the sender to skip only chunks that exist.
    func testLedgerFilesOfAnything() throws {
        let fm = FileManager.default
        for seed in Self.seeds {
            var rng = SplitMix(seed: seed)
            for round in 0..<60 {
                let root = fm.temporaryDirectory.appendingPathComponent("nimbus-fuzz-ledger-\(UUID().uuidString)", isDirectory: true)
                defer { try? fm.removeItem(at: root) }
                let items = root.appendingPathComponent("items", isDirectory: true)
                try fm.createDirectory(at: items, withIntermediateDirectories: true)
                let chunk = 4096
                let sizes: [Int64] = (0..<4).map { _ in Int64(rng.next() % UInt64(5 * chunk)) }
                let manifest = Manifest(chunkSize: chunk, entries: [.init(path: "d", kind: .directory)] + sizes.enumerated().map { .init(path: "d/f\($0.offset)", kind: .file, size: $0.element) })
                try manifest.validate()
                let tree = try SafeTree(root: items)
                try tree.makeDirectory("d")
                // Some of the files are there, of some length; one is something else altogether.
                for i in 0..<4 where rng.next() % 3 != 0 {
                    let url = items.appendingPathComponent("d/f\(i)")
                    if rng.next() % 7 == 0 { try fm.createDirectory(at: url, withIntermediateDirectories: true); continue }
                    try Data(count: Int(rng.next() % UInt64(6 * chunk))).write(to: url)
                }
                var bytes = Data()
                for _ in 0..<Int(rng.next() % 200) {
                    switch rng.next() % 4 {
                    case 0: bytes.append(contentsOf: (0..<8).map { _ in UInt8(truncatingIfNeeded: rng.next()) })
                    case 1: bytes.append(contentsOf: [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF])
                    default:
                        var f = UInt32(rng.next() % 7).bigEndian, c = UInt32(rng.next() % 7).bigEndian
                        withUnsafeBytes(of: &f) { bytes.append(contentsOf: $0) }
                        withUnsafeBytes(of: &c) { bytes.append(contentsOf: $0) }
                    }
                }
                bytes.append(contentsOf: (0..<Int(rng.next() % 8)).map { _ in UInt8(truncatingIfNeeded: rng.next()) })   // a torn tail
                let url = root.appendingPathComponent("ledger")
                try bytes.write(to: url)

                let why = "seed \(seed), round \(round)"
                guard let ledger = try? Ledger(url: url, manifest: manifest, tree: tree) else { continue }
                XCTAssertGreaterThanOrEqual(ledger.doneBytes, 0, why)
                XCTAssertLessThanOrEqual(ledger.doneBytes, manifest.totalBytes, why)
                let plan = ledger.plan()
                for file in plan.completeFiles {
                    XCTAssertTrue(file > 0 && file < manifest.entries.count && manifest.entries[file].kind == .file, why)
                    // A file the ledger calls complete is there, and long enough to be.
                    XCTAssertGreaterThanOrEqual(tree.fileSize(manifest.entries[file].path) ?? -1, manifest.entries[file].size, why)
                }
                for partial in plan.partialFiles {
                    XCTAssertTrue(partial.file > 0 && partial.file < manifest.entries.count, why)
                    XCTAssertEqual(Set(partial.chunks).count, partial.chunks.count, why)
                    for c in partial.chunks { XCTAssertTrue(c >= 0 && c < manifest.chunkCount(partial.file), why) }
                }
                XCTAssertEqual(ledger.isComplete, manifest.totalBytes == ledger.doneBytes, why)
                tree.release()
            }
        }
    }

    // MARK: The trust file's plaintext

    /// The trust file is sealed, so what opens is what this Mac wrote. This is the second line:
    /// whatever the plaintext holds, opening it and living with it does not crash. A store that
    /// crashed on its own file would be a Mac that cannot start.
    func testTrustFilesOfAnything() throws {
        let clock = ClockReading(boot: "b", continuous: 1000, wall: Date(timeIntervalSince1970: 1_800_000_000))
        var core = TrustCore(fresh: clock, lifetime: 30 * 86400)
        let other = PublicKey.madeUp()
        _ = try core.store(pairing: other, announced: "air", method: "codes", remaining: 86400, major: 3, replacing: nil, name: nil, wall: clock.wall)
        _ = core.retire(PublicKey.madeUp(), wall: clock.wall)
        let good = try XCTUnwrap(String(data: try core.encoded(), encoding: .utf8))
        let numbers = ["0", "-1", "1e300", "-1e300", "1e999", "9223372036854775807", "-9223372036854775808", "1.7976931348623157e308", "null", "\"x\"", "[]", "{}", "true", "0.0000001"]
        var opened = 0
        for seed in Self.seeds {
            var rng = SplitMix(seed: seed)
            for _ in 0..<1500 {
                var text = good
                for _ in 0..<(1 + Int(rng.next() % 3)) {
                    // Replace one number, or cut, or double a stretch.
                    let all = Array(text)
                    switch rng.next() % 3 {
                    case 0:
                        let starts = all.indices.filter { all[$0] == ":" && $0 + 1 < all.count && (all[$0 + 1].isNumber || all[$0 + 1] == "-") }
                        guard !starts.isEmpty else { continue }
                        let at = Self.pick(starts, &rng) + 1
                        var end = at
                        while end < all.count, !",}]".contains(all[end]) { end += 1 }
                        text = String(all[..<at]) + Self.pick(numbers, &rng) + String(all[end...])
                    case 1:
                        let at = Int(rng.next() % UInt64(all.count))
                        text = String(all[..<at]) + String(all[min(all.count, at + Int(rng.next() % 40))...])
                    default:
                        let at = Int(rng.next() % UInt64(all.count)), n = Int(rng.next() % 60)
                        text = String(all[..<at]) + String(all[at..<min(all.count, at + n)]) + String(all[at...])
                    }
                }
                guard var mutated = TrustCore(decoding: Data(text.utf8)) else { continue }
                opened += 1
                // Live with it: time passes, in steps and in leaps; keys are asked about; one is paired.
                for reading in [ClockReading(boot: "b", continuous: 1001, wall: clock.wall.addingTimeInterval(1)),
                                ClockReading(boot: "c", continuous: 5, wall: clock.wall.addingTimeInterval(-1e9)),
                                ClockReading(boot: "c", continuous: 1e12, wall: clock.wall.addingTimeInterval(1e12))] {
                    _ = mutated.tick(reading, waiting: [1])
                    _ = mutated.standing(of: other, wall: reading.wall)
                    _ = mutated.remaining(wall: reading.wall)
                    _ = mutated.nameClash("air", key: PublicKey.madeUp(), wall: reading.wall)
                    _ = mutated.noteRefused(other, wall: reading.wall)
                    _ = mutated.track(1, key: other)
                    _ = try? mutated.store(pairing: PublicKey.madeUp(), announced: "x", method: "codes", remaining: 1e300, major: 3, replacing: other, name: nil, wall: reading.wall)
                    _ = Format.lifetime(mutated.lifetime)
                }
                _ = try mutated.encoded()
            }
        }
        XCTAssertGreaterThan(opened, 300, "the fuzzer made nothing that opens: it is testing the refusals only")
    }

    // MARK: What is shown

    /// Numbers that are shown are computed from counts and times, some of them another Mac's.
    func testNumbersThatAreShownNeverTrap() {
        for x in Self.nastyDoubles {
            XCTAssertFalse(Format.duration(x).isEmpty, "\(x)")
            XCTAssertFalse(Format.lifetime(x).isEmpty, "\(x)")
            XCTAssertFalse(Format.rate(x).isEmpty, "\(x)")
            XCTAssertFalse(Format.bitRate(x).isEmpty, "\(x)")
            for y in Self.nastyDoubles { _ = Format.duration(x / y); _ = Format.rate(x / y); _ = Format.bitRate(x * y) }
        }
        for n in Self.nastyInts { XCTAssertFalse(Format.bytes(n).isEmpty); XCTAssertFalse(Format.files(Int(n)).isEmpty) }
        XCTAssertEqual(Format.duration(.infinity), Format.duration(Format.longest))
        XCTAssertEqual(Format.duration(.nan), "0:00")
        XCTAssertEqual(Format.duration(61), "1:01")
        XCTAssertEqual(Format.lifetime(90 * 86400), "90 days")
    }

    /// A label made from anything is one line, of bounded length, with nothing in it that
    /// cannot be seen or that moves what can.
    func testLabelsMadeFromAnything() {
        let pieces: [String] = ["a", "é", "e\u{301}", "\n", "\r", "\t", "\u{0}", "\u{1B}[31m", "\u{202E}", "\u{202D}", "\u{2066}", "\u{2069}", "\u{200B}", "\u{200E}", "\u{FEFF}", "\u{2028}",
                                "\u{2029}", "\u{00AD}", "\u{E0001}", "👨\u{200D}👩", " ", "/", "名", "\u{7F}", "\u{85}", "\u{61C}"]
        for seed in Self.seeds {
            var rng = SplitMix(seed: seed)
            for _ in 0..<4000 {
                let text = (0..<Int(rng.next() % 40)).map { _ in Self.pick(pieces, &rng) }.joined()
                let limit = 1 + Int(rng.next() % 30)
                let label = Sanitize.label(text, limit: limit)
                XCTAssertLessThanOrEqual(label.count, limit + 1)
                for scalar in label.unicodeScalars {
                    let c = scalar.properties.generalCategory
                    XCTAssertFalse(c == .control || c == .lineSeparator || c == .paragraphSeparator, "U+\(String(scalar.value, radix: 16)) in a label")
                    XCTAssertFalse(c == .format && scalar != "\u{200C}" && scalar != "\u{200D}", "U+\(String(scalar.value, radix: 16)) in a label")
                }
                // Folding a name for comparison is the same whether or not it was cleaned first.
                XCTAssertEqual(Trust.fold(text.replacingOccurrences(of: "\u{200B}", with: "")), Trust.fold(text))
            }
        }
    }
}
