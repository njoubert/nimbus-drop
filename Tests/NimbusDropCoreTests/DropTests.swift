// Copyright (C) 2026 Niels Joubert
// SPDX-License-Identifier: GPL-3.0-or-later
import Foundation
import XCTest
@testable import NimbusDropCore

/// Whole drops over loopback: a real listener, a real sender, real files in a temporary folder.
final class DropTests: XCTestCase {
    var root: URL!
    let sender = Identity(name: "sender", id: "sender-id")
    let receiver = Identity(name: "receiver", id: "receiver-id")
    /// Small, so a few hundred kilobytes make a many-chunk file.
    let chunk = 16 * 1024

    override func setUpWithError() throws {
        root = FileManager.default.temporaryDirectory.appendingPathComponent("nimbusdrop-tests-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
    }

    override func tearDownWithError() throws { try? FileManager.default.removeItem(at: root) }

    // MARK: Helpers

    func bytes(_ count: Int, seed: UInt64) -> Data {
        var state = seed &* 6364136223846793005 &+ 1442695040888963407
        var data = Data(count: count)
        data.withUnsafeMutableBytes { (raw: UnsafeMutableRawBufferPointer) in
            for i in 0..<count {
                state = state &* 6364136223846793005 &+ 1442695040888963407
                raw[i] = UInt8(truncatingIfNeeded: state >> 33)
            }
        }
        return data
    }

    /// A folder with everything the protocol distinguishes.
    @discardableResult
    func makeTree(_ name: String = "Photos") throws -> URL {
        let fm = FileManager.default
        let dir = root.appendingPathComponent("src/\(name)")
        try fm.createDirectory(at: dir.appendingPathComponent("sub/deeper"), withIntermediateDirectories: true)
        try fm.createDirectory(at: dir.appendingPathComponent("empty folder"), withIntermediateDirectories: true)
        try bytes(chunk * 20 + 123, seed: 1).write(to: dir.appendingPathComponent("big.bin"))
        try bytes(chunk, seed: 2).write(to: dir.appendingPathComponent("exactly-one-chunk.bin"))
        try bytes(7, seed: 3).write(to: dir.appendingPathComponent("sub/tiny.txt"))
        try Data().write(to: dir.appendingPathComponent("sub/empty.txt"))
        for i in 0..<40 { try bytes(100 + i * 37, seed: UInt64(10 + i)).write(to: dir.appendingPathComponent("sub/deeper/img\(i).jpg")) }
        try fm.createSymbolicLink(atPath: dir.appendingPathComponent("link").path, withDestinationPath: "sub/tiny.txt")
        try fm.setAttributes([.modificationDate: Date(timeIntervalSince1970: 1_600_000_000)], ofItemAtPath: dir.appendingPathComponent("big.bin").path)
        try fm.setAttributes([.posixPermissions: 0o755], ofItemAtPath: dir.appendingPathComponent("sub/tiny.txt").path)
        return dir
    }

    func destination(_ name: String = "dst") throws -> URL {
        let d = root.appendingPathComponent(name)
        try FileManager.default.createDirectory(at: d, withIntermediateDirectories: true)
        return d
    }

    /// A listener that answers every offer with `answer`.
    func listen(_ answer: @escaping @Sendable (ReceiveSession) -> Void) throws -> DropListener {
        let l = try DropListener(identity: receiver, preferredPort: 0)
        l.onOffer = answer
        l.start()
        return l
    }

    func wait(_ t: Transfer, timeout: TimeInterval = 30, file: StaticString = #filePath, line: UInt = #line) {
        let deadline = Date().addingTimeInterval(timeout)
        while !t.state.isFinal, Date() < deadline { Thread.sleep(forTimeInterval: 0.01) }
        XCTAssertTrue(t.state.isFinal, "still \(t.state)", file: file, line: line)
    }

    func send(_ urls: [URL], to l: DropListener, streams: Int = 4, failAfter: Int? = nil) -> SendSession {
        let s = SendSession(urls: urls, host: "127.0.0.1", port: l.port, peerName: "receiver", identity: sender,
                            streams: streams, chunkSize: chunk)
        s.failAfterChunks = failAfter
        s.start()
        return s
    }

    /// Path → what is there, for comparing two trees.
    func snapshot(_ dir: URL) throws -> [String: String] {
        var out: [String: String] = [:]
        let base = dir.path
        let e = FileManager.default.enumerator(atPath: base)!
        while let rel = e.nextObject() as? String {
            let path = base + "/" + rel
            var st = stat()
            lstat(path, &st)
            switch st.st_mode & S_IFMT {
            case S_IFDIR: out[rel] = "dir"
            case S_IFLNK: out[rel] = "link → " + (try FileManager.default.destinationOfSymbolicLink(atPath: path))
            default:
                let data = try Data(contentsOf: URL(fileURLWithPath: path))
                out[rel] = "file \(data.count) \(data.hashValue) mode \(String(st.st_mode & 0o777, radix: 8)) mtime \(st.st_mtimespec.tv_sec)"
            }
        }
        return out
    }

    // MARK: Drops

    func testAFolderArrivesIdentical() throws {
        let src = try makeTree()
        let dst = try destination()
        let l = try listen { $0.accept(destination: dst) }
        defer { l.stop() }
        let s = send([src], to: l)
        wait(s)
        XCTAssertEqual(s.state, .completed)
        XCTAssertEqual(try snapshot(dst.appendingPathComponent("Photos")), try snapshot(src))
        XCTAssertEqual(try FileManager.default.contentsOfDirectory(atPath: dst.path), ["Photos"], "the partial folder is gone")
        XCTAssertEqual(s.progress.doneBytes, s.progress.totalBytes)
        XCTAssertEqual(s.progress.doneFiles, s.progress.totalFiles)
    }

    func testLooseFilesAndOneStream() throws {
        let src = try makeTree()
        let dst = try destination()
        let l = try listen { $0.accept(destination: dst) }
        defer { l.stop() }
        let files = ["big.bin", "exactly-one-chunk.bin", "sub/empty.txt"].map { src.appendingPathComponent($0) }
        let s = send(files, to: l, streams: 1)
        wait(s)
        XCTAssertEqual(s.state, .completed)
        for f in files {
            XCTAssertEqual(try Data(contentsOf: dst.appendingPathComponent(f.lastPathComponent)), try Data(contentsOf: f))
        }
    }

    func testTheReceiverSeesWhoAndWhatBeforeAnswering() throws {
        let src = try makeTree()
        let dst = try destination()
        let seen = Box<ReceiveSession?>(nil)
        let l = try listen { seen.value = $0; $0.accept(destination: dst) }
        defer { l.stop() }
        let s = send([src], to: l)
        wait(s)
        let r = try XCTUnwrap(seen.value)
        wait(r)
        XCTAssertEqual(r.peerName, "sender")
        XCTAssertEqual(r.peerAddress, "127.0.0.1")
        XCTAssertEqual(r.items, ["Photos"])
        XCTAssertEqual(r.offeredFiles, 44)
        XCTAssertEqual(r.offeredBytes, s.progress.totalBytes)
        XCTAssertEqual(r.state, .completed)
        XCTAssertEqual(r.savedURLs.map(\.lastPathComponent), ["Photos"])
    }

    func testADeclinedDropWritesNothing() throws {
        let src = try makeTree()
        let dst = try destination()
        let l = try listen { $0.decline("No thanks") }
        defer { l.stop() }
        let s = send([src], to: l)
        wait(s)
        XCTAssertEqual(s.state, .declined("No thanks"))
        XCTAssertEqual(try FileManager.default.contentsOfDirectory(atPath: dst.path), [])
    }

    func testAnExistingNameIsKeptAndTheNewOneNumbered() throws {
        let src = try makeTree()
        let dst = try destination()
        let l = try listen { $0.accept(destination: dst) }
        defer { l.stop() }
        for _ in 0..<3 {
            let s = send([src, src.appendingPathComponent("big.bin")], to: l)
            wait(s)
            XCTAssertEqual(s.state, .completed)
        }
        XCTAssertEqual(try FileManager.default.contentsOfDirectory(atPath: dst.path).sorted(),
                       ["Photos", "Photos 2", "Photos 3", "big 2.bin", "big 3.bin", "big.bin"])
        XCTAssertEqual(try snapshot(dst.appendingPathComponent("Photos 3")), try snapshot(src))
    }

    func testAnInterruptedDropContinuesWhereItStopped() throws {
        let src = try makeTree()
        let dst = try destination()
        let l = try listen { $0.accept(destination: dst) }
        defer { l.stop() }

        let first = send([src], to: l, failAfter: 12)
        wait(first)
        guard case .failed = first.state else { return XCTFail("expected a failure, got \(first.state)") }
        let left = try FileManager.default.contentsOfDirectory(atPath: dst.path)
        XCTAssertEqual(left.count, 1)
        XCTAssertTrue(left[0].hasSuffix(".nimbusdrop-partial"), left[0])

        // The receiver's threads may still be noting the last chunks that arrived.
        Thread.sleep(forTimeInterval: 0.5)
        let second = send([src], to: l)
        wait(second)
        XCTAssertEqual(second.state, .completed)
        XCTAssertGreaterThan(second.progress.resumedBytes, 0, "nothing was reused")
        XCTAssertLessThan(second.progress.resumedBytes, second.progress.totalBytes)
        XCTAssertEqual(try snapshot(dst.appendingPathComponent("Photos")), try snapshot(src))
        XCTAssertEqual(try FileManager.default.contentsOfDirectory(atPath: dst.path), ["Photos"])
    }

    func testAResumeDoesNotTrustAFileThatWasDeleted() throws {
        let src = try makeTree()
        let dst = try destination()
        let l = try listen { $0.accept(destination: dst) }
        defer { l.stop() }
        let first = send([src], to: l, streams: 1, failAfter: 30)
        wait(first)
        Thread.sleep(forTimeInterval: 0.5)
        let partial = dst.appendingPathComponent(try FileManager.default.contentsOfDirectory(atPath: dst.path)[0])
        try FileManager.default.removeItem(at: partial.appendingPathComponent("items/Photos/big.bin"))
        let second = send([src], to: l)
        wait(second)
        XCTAssertEqual(second.state, .completed)
        XCTAssertEqual(try snapshot(dst.appendingPathComponent("Photos")), try snapshot(src))
    }

    func testAChangedFileStartsAFreshDrop() throws {
        let src = try makeTree()
        let dst = try destination()
        let l = try listen { $0.accept(destination: dst) }
        defer { l.stop() }
        wait(send([src], to: l, failAfter: 5))
        Thread.sleep(forTimeInterval: 0.3)
        try bytes(999, seed: 99).write(to: src.appendingPathComponent("sub/tiny.txt"))
        let second = send([src], to: l)
        wait(second)
        XCTAssertEqual(second.state, .completed)
        XCTAssertEqual(second.progress.resumedBytes, 0)
        XCTAssertEqual(try snapshot(dst.appendingPathComponent("Photos")), try snapshot(src))
    }

    func testCancellingTheSenderEndsBothSides() throws {
        let src = try makeTree()
        let seen = Box<ReceiveSession?>(nil)
        let l = try listen { seen.value = $0 }   // never answers
        defer { l.stop() }
        let s = send([src], to: l)
        while s.state != .waitingForAccept { Thread.sleep(forTimeInterval: 0.01) }
        while seen.value == nil { Thread.sleep(forTimeInterval: 0.01) }
        s.cancel()
        wait(s)
        XCTAssertEqual(s.state, .cancelled)
        let r = try XCTUnwrap(seen.value)
        wait(r)
        XCTAssertEqual(r.state, .failed("Cancelled on the other Mac"))
    }

    func testNothingListeningIsAnErrorNotAHang() throws {
        let src = try makeTree()
        let s = SendSession(urls: [src], host: "127.0.0.1", port: 1, peerName: "nobody", identity: sender)
        s.start()
        wait(s)
        guard case .failed(let why) = s.state else { return XCTFail("\(s.state)") }
        XCTAssertTrue(why.contains("Cannot connect"), why)
    }

    // MARK: The manifest

    func testAManifestThatReachesOutsideIsRefused() {
        func bad(_ entries: [Manifest.Entry], file: StaticString = #filePath, line: UInt = #line) {
            XCTAssertThrowsError(try Manifest(chunkSize: chunk, entries: entries).validate(), file: file, line: line)
        }
        bad([.init(path: "../escape", kind: .file)])
        bad([.init(path: "/etc/passwd", kind: .file)])
        bad([.init(path: "a", kind: .directory), .init(path: "a/../../b", kind: .file)])
        bad([.init(path: "a/b", kind: .file)])                                         // no such folder
        bad([.init(path: "a", kind: .symlink, link: "/etc"), .init(path: "a/passwd", kind: .file)])   // through a link
        bad([.init(path: "a", kind: .file), .init(path: "a", kind: .file)])
        bad([.init(path: "", kind: .file)])
        bad([])
        XCTAssertNoThrow(try Manifest(chunkSize: chunk, entries: [.init(path: "a", kind: .directory), .init(path: "a/b", kind: .file, size: 3)]).validate())
    }

    func testChunksCoverAFileExactly() {
        let m = Manifest(chunkSize: 100, entries: [.init(path: "a", kind: .file, size: 250), .init(path: "b", kind: .file, size: 0),
                                                   .init(path: "c", kind: .file, size: 100), .init(path: "d", kind: .directory)])
        XCTAssertEqual((0..<4).map(m.chunkCount), [3, 0, 1, 0])
        XCTAssertEqual((0..<3).map { m.chunkLength(file: 0, chunk: $0) }, [100, 100, 50])
        XCTAssertEqual(m.totalBytes, 350)
        XCTAssertEqual(m.fileCount, 3)
    }

    func testTheKeyFollowsContentAndSender() {
        let a = Manifest(chunkSize: 100, entries: [.init(path: "a", kind: .file, size: 250, mtime: 5)])
        var b = a
        b.entries[0].mtime = 6
        XCTAssertEqual(a.key(senderID: "x"), a.key(senderID: "x"))
        XCTAssertNotEqual(a.key(senderID: "x"), b.key(senderID: "x"))
        XCTAssertNotEqual(a.key(senderID: "x"), a.key(senderID: "y"))
    }

    func testKeepBothNames() {
        let taken: Set = ["Photos", "Photos 2", "a.jpg", ".hidden", "archive.tar.gz"]
        XCTAssertEqual(Naming.unique("New", isDirectory: true) { taken.contains($0) }, "New")
        XCTAssertEqual(Naming.unique("Photos", isDirectory: true) { taken.contains($0) }, "Photos 3")
        XCTAssertEqual(Naming.unique("a.jpg", isDirectory: false) { taken.contains($0) }, "a 2.jpg")
        XCTAssertEqual(Naming.unique(".hidden", isDirectory: false) { taken.contains($0) }, ".hidden 2")
        XCTAssertEqual(Naming.unique("archive.tar.gz", isDirectory: false) { taken.contains($0) }, "archive.tar 2.gz")
    }

    func testFormatting() {
        XCTAssertEqual(Format.bytes(1), "1 byte")
        XCTAssertEqual(Format.bytes(999), "999 bytes")
        XCTAssertEqual(Format.bytes(31_200_000_000), "31.2 GB")
        XCTAssertEqual(Format.bytes(812_000_000), "812 MB")
        XCTAssertEqual(Format.duration(31), "0:31")
        XCTAssertEqual(Format.duration(3729), "1:02:09")
        XCTAssertEqual(Format.files(1), "1 file")
        XCTAssertEqual(Format.files(1204), "1,204 files")
    }
}

final class Box<T>: @unchecked Sendable {
    private let lock = NSLock()
    private var _value: T
    init(_ value: T) { _value = value }
    var value: T {
        get { lock.withLock { _value } }
        set { lock.withLock { _value = newValue } }
    }
}
