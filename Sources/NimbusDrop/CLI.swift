// Copyright (C) 2026 Niels Joubert
// SPDX-License-Identifier: GPL-3.0-or-later
import Foundation
import NimbusDropCore
import NimbusUpdater

/// The engine without the app: for scripts, for a Mac reached over ssh, and for checking the
/// app against something that is not itself.
@MainActor
enum CLI {
    enum Command {
        case receive(dir: String, once: Bool)
        case send(target: String, paths: [String])
        case peers
        case watchPeers
        case print
        case checkUpdate
        case preflight(app: String)
    }

    /// Set by `--name`, `--port`, `--streams`, `--no-advertise`.
    static var name: String?
    static var port: UInt16?
    static var streams: Int?
    static var advertise = true

    static var identity: Identity {
        var i = Settings.identity
        if let name { i.name = name; i.id = "cli-" + name }
        return i
    }

    static func run(_ cmd: Command) -> Int32 {
        setvbuf(stdout, nil, _IOLBF, 0)
        switch cmd {
        case .print:
            Swift.print("name:      \(identity.name)")
            Swift.print("id:        \(identity.id)")
            for a in LocalHost.addresses { Swift.print("address:   \(a.address)  (\(a.interface))") }
            Swift.print("receiving: \(Settings.receiving ? "on" : "off")")
            Swift.print("streams:   \(Settings.streams)")
            Swift.print("login item: \(LoginItem.statusDescription)")
            return 0

        case .peers:
            let found = browse(seconds: 3) { _ in false }
            if found.isEmpty { Swift.print("no other Macs found") }
            for p in found { Swift.print("\(p.name)  \(p.address ?? "unresolved")\(p.port.map { ":\($0)" } ?? "")  [\(p.id)]") }
            return 0

        case .watchPeers:
            let browser = PeerBrowser(selfID: identity.id)
            browser.onTrace = { Swift.print("  \($0)") }
            browser.onChange = { peers in
                Swift.print("\(Date().formatted(date: .omitted, time: .standard))  " + (peers.isEmpty ? "nobody" : peers.map { "\($0.name) \($0.address ?? "unresolved")" }.joined(separator: ", ")))
            }
            browser.start()
            RunLoop.main.run()
            return 0

        case .receive(let dir, let once):
            let destination = URL(fileURLWithPath: dir, isDirectory: true)
            guard (try? destination.checkResourceIsReachable()) == true else { fputs("\(dir) does not exist\n", stderr); return 1 }
            let listener: DropListener
            do { listener = try DropListener(identity: identity, preferredPort: port ?? defaultPort) }
            catch { fputs("\(error)\n", stderr); return 1 }
            let advertiser = advertise ? try? Advertiser(identity: identity, port: listener.port) : nil
            let finished = DispatchSemaphore(value: 0)
            listener.onOffer = { session in
                Swift.print("\(session.peerName) (\(session.peerAddress)) sends \(session.title): \(Format.files(session.offeredFiles)), \(Format.bytes(session.offeredBytes))")
                session.accept(destination: destination)
                Thread.detachNewThread {
                    let code = watch(session)
                    for u in session.savedURLs { Swift.print("saved \(u.path)") }
                    if once { exit(code) }
                    finished.signal()
                }
            }
            listener.start()
            Swift.print("receiving as \(identity.name) on port \(listener.port)\(advertiser == nil ? " (not announced)" : ""), saving to \(destination.path)")
            withExtendedLifetime(advertiser) { RunLoop.main.run() }
            return 0

        case .send(let target, let paths):
            let urls = paths.map { URL(fileURLWithPath: $0) }
            for u in urls where (try? u.checkResourceIsReachable()) != true { fputs("\(u.path) does not exist\n", stderr); return 1 }
            var host = target, hostPort = port ?? defaultPort, peerName = target
            // host, host:port, or the name of a Mac found on the network.
            let parts = target.split(separator: ":")
            if parts.count == 2, let p = UInt16(parts[1]) {
                host = String(parts[0]); hostPort = p; peerName = host
            } else if !target.contains(".") {
                let found = browse(seconds: 5) { $0.contains { $0.name == target && $0.address != nil } }
                if let peer = found.first(where: { $0.name == target }), let a = peer.address, let p = peer.port {
                    host = a; hostPort = p
                }
            }
            let session = SendSession(urls: urls, host: host, port: hostPort, peerName: peerName, identity: identity,
                                      streams: streams ?? Settings.streams)
            session.start()
            return watch(session)

        case .checkUpdate:
            guard let current = Updates.runningVersion ?? Updates.installedVersion else {
                fputs("no version to compare against: \(Updates.appName) is not installed\n", stderr); return 1
            }
            let config = Updates.config(currentVersion: current)
            Swift.print("current: \(current)  (\(Updates.runningVersion != nil ? "this bundle" : "the installed copy"))")
            do {
                guard let release = try block({ try await Release.fetchLatest(config) }) else {
                    Swift.print("latest:  none the updater can read"); return 0
                }
                Swift.print("latest:  \(release.version)  [\(release.tag)]")
                if let asset = release.asset { Swift.print("asset:   \(asset.name)  (\(asset.size) bytes)") }
                else { Swift.print("asset:   none named \(config.assetPrefix)\(release.version.text).zip — invisible to the updater") }
                Swift.print(release.version > current
                    ? (release.asset != nil ? "→ an update is available" : "→ newer, but nothing installable is published")
                    : "→ up to date")
            } catch {
                fputs("error: \(error)\n", stderr); return 1
            }
            return 0

        case .preflight(let path):
            let plist = URL(fileURLWithPath: path).appendingPathComponent("Contents/Info.plist")
            let info = (try? Data(contentsOf: plist)).flatMap { try? PropertyListSerialization.propertyList(from: $0, format: nil) as? [String: Any] } ?? nil
            guard let short = info?["CFBundleShortVersionString"] as? String, let version = SemanticVersion(short) else {
                fputs("\(path) has no readable CFBundleShortVersionString\n", stderr); return 1
            }
            let report = block { await Preflight.run(app: URL(fileURLWithPath: path), config: Updates.config(currentVersion: version), releaseVersion: version) }
            for check in report.checks { Swift.print("\(check.ok ? "ok  " : "FAIL") \(check.name): \(check.detail)") }
            guard report.passed else {
                fputs("\nthis build would break auto-update for people who already have the app\n", stderr); return 1
            }
            Swift.print("\npreflight passed")
            return 0
        }
    }

    /// Browses until `enough` says so or `seconds` pass, turning the main run loop meanwhile.
    private static func browse(seconds: Double, until enough: @escaping ([Peer]) -> Bool) -> [Peer] {
        let browser = PeerBrowser(selfID: identity.id)
        browser.start()
        let deadline = Date().addingTimeInterval(seconds)
        while Date() < deadline, !enough(browser.peers) { RunLoop.main.run(until: Date().addingTimeInterval(0.1)) }
        let peers = browser.peers
        browser.stop()
        return peers
    }

    /// Prints a transfer's progress once a second until it ends; the exit code.
    nonisolated static func watch(_ t: Transfer) -> Int32 {
        var last = t.progress.doneBytes, lastState: TransferState?
        var lastTime = Date()
        while !t.state.isFinal {
            Thread.sleep(forTimeInterval: 1)
            let state = t.state, p = t.progress, now = Date()
            let fresh = state != lastState
            if fresh, !state.isFinal {
                lastState = state
                if state != .transferring { Swift.print("\(state)") }
                if state == .transferring, p.resumedBytes > 0 { Swift.print("continuing: \(Format.bytes(p.resumedBytes)) already there") }
            }
            if state == .transferring, fresh {
                // The first look after bytes start moving has no earlier figure to measure from.
            } else if state == .transferring {
                let rate = Double(p.doneBytes - last) / now.timeIntervalSince(lastTime)
                let trouble = t.stats
                Swift.print(String(format: "%3.0f%%  %@ / %@  %@ (%@)  %@  %d/%d files", p.fraction * 100, Format.bytes(p.doneBytes),
                                   Format.bytes(p.totalBytes), Format.bitRate(rate), Format.rate(rate), Format.connections(p.connections),
                                   p.doneFiles, p.totalFiles)
                    + (trouble.connectionFailures > 0 ? "  \(trouble.connectionFailures) lost\(trouble.damagedChunks > 0 ? " (\(trouble.damagedChunks) for damaged chunks)" : ""), round \(trouble.rounds)" : ""))
            }
            last = p.doneBytes; lastTime = now
        }
        let p = t.progress
        switch t.state {
        case .completed:
            let seconds = max(0.001, (t.finishedAt ?? Date()).timeIntervalSince(t.transferStartedAt ?? t.startedAt))
            let moved = p.totalBytes - p.resumedBytes
            let trouble = t.stats
            Swift.print("done: \(Format.files(p.totalFiles)), \(Format.bytes(moved)) in \(String(format: "%.1f", seconds)) s = \(Format.bitRate(Double(moved) / seconds)) (\(Format.rate(Double(moved) / seconds)))"
                + (trouble.connectionFailures > 0 ? "; got past \(trouble.connectionFailures) lost connections\(trouble.damagedChunks > 0 ? " (\(trouble.damagedChunks) for damaged chunks)" : "") in \(trouble.rounds) rounds" : ""))
            return 0
        case .declined(let why): Swift.print("declined: \(why)"); return 3
        case .failed(let why): Swift.print("failed: \(why)"); return 1
        default: Swift.print("cancelled"); return 1
        }
    }

    /// Runs an async call to its end from synchronous code, keeping the main run loop turning.
    private static func block<T: Sendable>(_ body: @escaping @Sendable () async throws -> T) throws -> T {
        let box = ResultBox<Result<T, Error>>()
        Task.detached {
            do { box.value = .success(try await body()) } catch { box.value = .failure(error) }
        }
        while box.value == nil { RunLoop.main.run(until: Date().addingTimeInterval(0.05)) }
        return try box.value!.get()
    }

    private static func block<T: Sendable>(_ body: @escaping @Sendable () async -> T) -> T {
        let box = ResultBox<T>()
        Task.detached { box.value = await body() }
        while box.value == nil { RunLoop.main.run(until: Date().addingTimeInterval(0.05)) }
        return box.value!
    }
}

private final class ResultBox<T>: @unchecked Sendable {
    private let lock = NSLock()
    private var _value: T?
    var value: T? {
        get { lock.withLock { _value } }
        set { lock.withLock { _value = newValue } }
    }
}
