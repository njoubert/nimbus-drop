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
        case pair(target: String, byNumber: Bool)
        case identity
        case known
        case forget(tag: String)
        case resetIdentity
        case speed(target: String)
        case keyLifetime(String)
        case watchPeers
        case print
        case checkUpdate
        case preflight(app: String)
    }

    /// Set by `--name`, `--port`, `--streams`, `--no-advertise`.
    static var name: String?
    static var port: UInt16?
    static var streams: Int?
    /// Set by `--seconds`: how long a speed test measures each direction.
    static var speedSeconds = 5.0
    static var advertise = true
    /// Set by `--any-network`: take drops from addresses beyond the local network too.
    static var anyNetwork = false
    /// Set by `--only`: the extensions to send.
    static var only: [String]?

    /// Set by `--unattended-from TAG` and `--max-bytes N`: take drops without asking, from the
    /// one paired key named, up to that many bytes each.
    static var unattendedFrom: String?
    static var maxBytes: Int64 = 100 << 30

    static var identity: Identity {
        var i = Settings.identity
        if let name { i.name = name }
        return i
    }

    /// The command line's own identity, never the app's: a folder per `--name` (or "default"),
    /// so that a terminal and the app on one Mac are two Macs to each other, and two processes
    /// never share a trust file.
    static let trust: Trust = {
        let storage = EnclaveStorage.standard(bundleID: Settings.bundleID, name: name ?? "default")
        do { return try Trust(storage: storage) } catch TrustFault.damaged {
            fputs("this identity's stored file is damaged; it was set aside and a new identity made (the record of retired identities is lost)\n", stderr)
            // swiftlint:disable:next force_try
            return try! Trust.startFresh(storage: storage)
        } catch {
            fputs("cannot open this Mac's identity: \(error)\n", stderr)
            exit(1)
        }
    }()

    nonisolated(unsafe) private static let stdinLock = NSLock()
    /// One question at a time on the terminal, from whatever thread.
    nonisolated static func ask(_ prompt: String) -> String {
        stdinLock.lock()
        defer { stdinLock.unlock() }
        Swift.print(prompt, terminator: " ")
        fflush(stdout)
        return (readLine() ?? "").trimmingCharacters(in: .whitespaces)
    }

    /// Runs a pairing on the terminal: this side's code is printed, the other's is typed.
    nonisolated static func converse(_ p: PairingSession) -> Int32 {
        var shown: PairingSession.State?
        while true {
            let state = p.state
            if state != shown {
                shown = state
                switch state {
                case .connecting: break
                case .asking: if p.initiator { Swift.print("waiting for the person at \(p.peerName) to agree…") }
                case .codes(let mine, let left):
                    if let clash = p.clash, left == 3 {
                        Swift.print("NOTE: \(p.peerName) is not the \(clash.name) this Mac knows" + (clash.expected ? " (that one's key has run out, so a new one was expected)" : " (that one's key is still good: ask the person there why)"))
                    }
                    if case .renew = p.standing, left == 3 { Swift.print("this is the same Mac you paired with before") }
                    if p.byNumber {
                        if left < 3 { Swift.print("that is not its identity number; \(left) tries left") }
                        p.submit(ask("identity number of \(p.peerName):"))
                    } else {
                        if left < 3 { Swift.print("that is not the code this Mac expected; \(left) tries left. If it is what they read out, stop: something may be between the two Macs.") }
                        else { Swift.print("read this code out to the person at \(p.peerName):  \(mine.prefix(3)) \(mine.suffix(3))") }
                        p.submit(ask("the code they read to you:"))
                    }
                    shown = nil
                case .confirming: Swift.print("right; waiting for \(p.peerName) to say the same…")
                case .paired(let mac): Swift.print("paired with \(mac.name) (\(mac.key.tag)), good until \(mac.endsWall.formatted(date: .abbreviated, time: .shortened))"); return 0
                case .failed(let why): Swift.print("not paired: \(why)"); return 1
                }
            }
            Thread.sleep(forTimeInterval: 0.1)
        }
    }

    /// host, host:port, or the name of a Mac found on the network.
    private static func locate(_ target: String) -> (host: String, port: UInt16, name: String) {
        var host = target, hostPort = port ?? defaultPort, peerName = target
        let parts = target.split(separator: ":")
        if parts.count == 2, let p = UInt16(parts[1]) {
            host = String(parts[0]); hostPort = p; peerName = host
        } else if !target.contains(".") {
            let found = browse(seconds: 5) { $0.contains { $0.name == target && $0.address != nil } }
            if let peer = found.first(where: { $0.name == target }), let a = peer.address, let p = peer.port {
                host = a; hostPort = p
            }
        }
        return (host, hostPort, peerName)
    }

    /// Where a target is and whose key it must prove. A name means one Known Mac, and what is
    /// sent goes to the key that Mac is paired by, wherever on the network that key is proved.
    /// What a Mac announces itself as picks nothing: `--send air` used to go to whichever
    /// paired Mac answered under "air". An address means whoever is there, provided it proves
    /// a key this identity is paired with. Nil (and a line on stderr) when it cannot be found.
    private static func aim(_ target: String) -> (host: String, port: UInt16, name: String, expect: PublicKey?)? {
        let parts = target.split(separator: ":")
        if target.contains(".") || (parts.count == 2 && UInt16(parts[1]) != nil) {
            let (host, hostPort, peerName) = locate(target)
            return (host, hostPort, peerName, nil)
        }
        guard let mac = trust.knownMac(called: target) else {
            fputs("this identity is not paired with a Mac it calls “\(target)” (see --known). Pair first:  NimbusDrop\(name.map { " --name \($0)" } ?? "") --pair \(target)\n", stderr)
            return nil
        }
        let found = browse(seconds: 5) { $0.contains { $0.key == mac.key && $0.address != nil } }
        guard let peer = found.first(where: { $0.key == mac.key }), let a = peer.address, let p = peer.port else {
            fputs("\(mac.name) [\(mac.key.tag)] was not found on the network\n", stderr)
            return nil
        }
        return (a, p, mac.name, mac.key)
    }

    private static func describe(_ key: PublicKey?) -> String {
        guard let key else { return "not proved" }
        switch trust.standing(of: key) {
        case .mine: return "this Mac"
        case .paired(let m): return "paired as \(m.name)"
        case .expired(let m): return "was \(m.name); its key has run out"
        case .retired(let t): return "a retired identity of \(t.name)"
        case .renew(let r): return "pair again (was \(r.name))"
        case .unknown: return "new"
        }
    }

    static func run(_ cmd: Command) -> Int32 {
        setvbuf(stdout, nil, _IOLBF, 0)
        switch cmd {
        case .print:
            Swift.print("name:      \(identity.name)")
            Swift.print("key:       \(trust.publicKey.tag)  (good until \(trust.ends.formatted(date: .abbreviated, time: .shortened)))")
            for a in LocalHost.addresses { Swift.print("address:   \(a.address)  (\(a.interface))") }
            Swift.print("receiving: \(Settings.receiving ? "on" : "off")")
            Swift.print("streams:   \(Settings.streams)")
            Swift.print("login item: \(LoginItem.statusDescription)")
            return 0

        case .peers:
            let found = browse(seconds: 3) { _ in false }
            if found.isEmpty { Swift.print("no other Macs found") }
            for p in found {
                let key = p.address.flatMap { a in p.port.flatMap { try? Probe.identify(host: a, port: $0, timeout: 2) } }
                Swift.print("\(p.name)  \(p.address ?? "unresolved")\(p.port.map { ":\($0)" } ?? "")  \(p.isCompatible ? describe(key) : "needs an update (protocol \(p.protocolText))")\(key.map { "  [\($0.tag)]" } ?? "")")
            }
            return 0

        case .identity:
            Swift.print("name:            \(identity.name)")
            Swift.print("key:             \(trust.publicKey.tag)")
            Swift.print("identity number: \(PublicKey.grouped(trust.publicKey.identityNumber))")
            Swift.print("made:            \(trust.made.formatted(date: .abbreviated, time: .shortened))")
            Swift.print("good until:      \(trust.ends.formatted(date: .abbreviated, time: .shortened))  (keys last \(Format.lifetime(trust.lifetime)))")
            return 0

        case .known:
            if trust.known.isEmpty, trust.again.isEmpty { Swift.print("not paired with any Mac") }
            for m in trust.known {
                let state = trust.standing(of: m.key).isPaired ? "good until \(m.endsWall.formatted(date: .abbreviated, time: .shortened))" : "key has run out; pair again"
                Swift.print("\(m.name)  [\(m.key.tag)]  paired \(m.pairedAt.formatted(date: .abbreviated, time: .omitted)) by \(m.method); \(state)\(m.impostors > 0 ? "; another Mac used its name \(m.impostors) times" : "")")
            }
            for r in trust.again where !r.pairedAgain {
                Swift.print("\(r.name)  [\(r.key.tag)]  pair again\(r.told.map { $0 ? " (told of the reset)" : " (NOT reached: it still trusts the old identity)" } ?? "")")
            }
            return 0

        case .forget(let tag):
            guard let mac = trust.known.first(where: { $0.key.tag.replacingOccurrences(of: "-", with: "").hasPrefix(tag.uppercased().replacingOccurrences(of: "-", with: "")) }) else {
                fputs("no paired Mac has a key beginning \(tag)\n", stderr); return 1
            }
            let found = browse(seconds: 3) { $0.contains { $0.key == mac.key && $0.address != nil } }
            let place = found.first { $0.key == mac.key }.flatMap { p in p.address.flatMap { a in p.port.map { (host: a, port: $0) } } }
            let told = trust.forget(mac.key, telling: place, identity: identity)
            Swift.print("forgot \(mac.name)" + (told ? "; it was told" : "; it could not be told and will learn at its next drop"))
            return 0

        case .keyLifetime(let text):
            let choices: [String: Double] = ["1h": 3600, "1d": 86400, "1w": 7 * 86400, "30d": 30 * 86400, "90d": 90 * 86400]
            guard let seconds = choices[text] else { fputs("--key-lifetime takes one of 1h, 1d, 1w, 30d, 90d\n", stderr); return 1 }
            trust.setLifetime(seconds)
            Swift.print("keys last \(Format.lifetime(seconds)); this one is good until \(trust.ends.formatted(date: .abbreviated, time: .shortened))")
            return 0

        case .resetIdentity:
            let peers = trust.known
            Swift.print("resetting this identity; telling \(peers.count) paired Macs…")
            let found = peers.isEmpty ? [] : browse(seconds: 4) { _ in false }
            var where_: [PublicKey: (String, UInt16)] = [:]
            for p in found { if let a = p.address, let port = p.port, let key = try? Probe.identify(host: a, port: port, timeout: 2) { where_[key] = (a, port) } }
            let places = where_
            for r in trust.reset(identity: identity, reach: { places[$0].map { (host: $0.0, port: $0.1) } }) {
                Swift.print("\(r.name): \(r.told == true ? "told" : "NOT reached; it still trusts the old identity until you pair again, or until that identity's end date")")
            }
            Swift.print("new key: \(trust.publicKey.tag)")
            return 0

        case .pair(let target, let byNumber):
            let (host, hostPort, peerName) = locate(target)
            if byNumber { Swift.print("this Mac's identity number, for the other person: \(PublicKey.grouped(trust.publicKey.identityNumber))") }
            let p = PairingSession(host: host, port: hostPort, peerName: peerName, identity: identity, trust: trust, byNumber: byNumber)
            return converse(p)

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
            do { listener = try DropListener(identity: identity, trust: trust, preferredPort: port ?? defaultPort) }
            catch { fputs("\(error)\n", stderr); return 1 }
            listener.localOnly = !anyNetwork
            let unattended = unattendedFrom?.uppercased().replacingOccurrences(of: "-", with: "")
            let limit = maxBytes
            let busy = Locked<ReceiveSession?>(nil)
            let trust = trust
            let advertiser = advertise ? try? Advertiser(identity: identity, port: listener.port) : nil
            let finished = DispatchSemaphore(value: 0)
            listener.onSpeedTest = { test in
                // The standing grant covers the Mac it names for this too; anyone else is asked about.
                let tag = test.peerKey?.tag.replacingOccurrences(of: "-", with: "") ?? ""
                if let grant = unattended, tag == grant {
                    Swift.print("speed test from \(test.peerName): allowed unattended")
                    test.accept()
                    return
                }
                Thread.detachNewThread {
                    let yes = ["y", "yes"].contains(ask("\(test.peerName) (\(test.peerAddress)) asks to test the speed between the two Macs (\(Int(test.secondsEachWay)) s each way). allow? [y/N]").lowercased())
                    if yes { test.accept() } else { test.decline() }
                }
            }
            listener.onOffer = { session in
                Swift.print("\(session.peerName) [\(session.sender.key.tag)] (\(session.peerAddress)) wants to send \(session.title): \(Format.files(session.offeredFiles)), \(Format.bytes(session.offeredBytes))")
                if let grant = unattended {
                    // The one standing grant there is: this key, this folder, this much, one at a time.
                    // A drop that is only waiting for its sender to come back is not in the way:
                    // a sender that was killed offers the same drop afresh, and the engine ends
                    // the one that was waiting (found between two Macs, 2026-11-23).
                    let ok = session.sender.key.tag.replacingOccurrences(of: "-", with: "") == grant && session.offeredBytes <= limit && busy.withLock {
                        if let b = $0, b.state != .reconnecting { return false }
                        $0 = session; return true
                    }
                    guard ok else { Swift.print("declined: not covered by --unattended-from"); session.decline("Not accepted unattended"); return }
                } else {
                    guard ["y", "yes"].contains(ask("accept into \(destination.path)? [y/N]").lowercased()) else { session.decline(); return }
                }
                session.accept(destination: destination)
                Thread.detachNewThread {
                    let code = watch(session)
                    for u in session.savedURLs { Swift.print("saved \(u.path)") }
                    busy.withLock { if $0 === session { $0 = nil } }
                    if once { exit(code) }
                    finished.signal()
                }
            }
            listener.onPairRequest = { p in
                Swift.print("\(p.peerName) [\(p.peerKey?.tag ?? "?")] (\(p.peerAddress)) wants to pair\(p.byNumber ? " by identity number" : "")" + (p.clash.map { ". It is NOT the \($0.name) this Mac knows" } ?? ""))
                Thread.detachNewThread {
                    guard ["y", "yes"].contains(ask("pair? Go on only if someone you can hear is asking. [y/N]").lowercased()) else { p.refuse(); return }
                    if p.byNumber { Swift.print("this Mac's identity number, for the other person: \(PublicKey.grouped(trust.publicKey.identityNumber))") }
                    p.proceed()
                    _ = converse(p)
                }
            }
            listener.onRefusedIdentity = { name, address in Swift.print("WARNING: a retired identity of \(name) was used from \(address); someone may hold a copy of it") }
            listener.start()
            if unattended != nil {
                guard !anyNetwork else { fputs("--unattended-from cannot be combined with --any-network\n", stderr); return 1 }
                Swift.print("UNATTENDED: drops from the paired key \(unattendedFrom ?? "") are accepted without asking, up to \(Format.bytes(limit)) each, while this runs")
            }
            Swift.print("receiving as \(identity.name) [\(trust.publicKey.tag)] on port \(listener.port)\(advertiser == nil ? " (not announced)" : "")\(anyNetwork ? ", from any address" : ""), saving to \(destination.path)")
            withExtendedLifetime(advertiser) { RunLoop.main.run() }
            return 0

        case .send(let target, let paths):
            let urls = paths.map { URL(fileURLWithPath: $0) }
            for u in urls where (try? u.checkResourceIsReachable()) != true { fputs("\(u.path) does not exist\n", stderr); return 1 }
            guard let (host, hostPort, peerName, expect) = aim(target) else { return 1 }
            var prescanned: ScannedDrop?
            if let only {
                // --only jpg,cr3: the kinds those extensions belong to (so jpg brings .jpeg too).
                guard let scanned = try? Scanner.scan(urls) else { fputs("cannot read what was given\n", stderr); return 1 }
                let wanted = Set(only.map { FileKinds.id(forPath: "x." + $0.lowercased()) })
                prescanned = scanned.keeping(kinds: wanted)
                for kind in FileKinds.summarize(scanned.manifest) {
                    Swift.print("\(wanted.contains(kind.id) ? "send" : "skip")  \(kind.label) \(kind.extensions.map { "." + $0 }.joined(separator: " "))  \(Format.files(kind.files)), \(Format.bytes(kind.bytes))")
                }
            }
            let session = SendSession(urls: urls, host: host, port: hostPort, peerName: peerName, identity: identity, trust: trust,
                                      expect: expect, streams: streams ?? Settings.streams, prescanned: prescanned)
            session.start()
            let code = watch(session)
            if case .failed = session.state, session.needsPairing { Swift.print("pair first:  NimbusDrop\(name.map { " --name \($0)" } ?? "") --pair \(target)") }
            return code

        case .speed(let target):
            guard let (host, hostPort, peerName, expect) = aim(target) else { return 1 }
            let test = SpeedTest(host: host, port: hostPort, peerName: peerName, identity: identity, trust: trust, expect: expect,
                                 seconds: speedSeconds, streams: streams ?? Settings.streams)
            test.start()
            var said = "", waiting = false
            while !test.state.isFinal {
                Thread.sleep(forTimeInterval: 0.25)
                if test.state == .waitingForAccept, !waiting { waiting = true; Swift.print("waiting for the person at \(peerName) to allow it…") }
                let phase = test.phase
                if phase != said, !phase.isEmpty { said = phase; Swift.print("measuring \(phase)…") }
            }
            guard test.state == .completed else {
                if case .failed(let why) = test.state { Swift.print("failed: \(why)") }
                else if case .declined(let why) = test.state { Swift.print("declined: \(why)") }
                else { Swift.print("\(test.state)") }
                if test.needsPairing { Swift.print("pair first:  NimbusDrop\(name.map { " --name \($0)" } ?? "") --pair \(target)") }
                return 1
            }
            let r = test.result
            Swift.print("to \(peerName):    \(Format.bitRate(r.upRate))  (\(Format.bytes(r.upBytes)) in \(String(format: "%.1f", r.upSeconds)) s)")
            Swift.print("from \(peerName):  \(Format.bitRate(r.downRate))  (\(Format.bytes(r.downBytes)) in \(String(format: "%.1f", r.downSeconds)) s)")
            Swift.print("\(Format.connections(r.streams))" + (test.linkInterface.map { ", over \(LinkName.display($0))" } ?? ""))
            return 0

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
                + (trouble.retransmittedChunks > 0 ? "; \(trouble.retransmittedChunks) chunks retransmitted" : "")
                + (trouble.reconnects > 0 ? "; reconnected \(trouble.reconnects) time\(trouble.reconnects == 1 ? "" : "s")" : "")
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
