// Copyright (C) 2026 Niels Joubert
// SPDX-License-Identifier: GPL-3.0-or-later
import AppKit
import NimbusDropCore
@preconcurrency import UserNotifications

/// One line in the transfer list, as the menu and the window show it.
struct TransferRow: Identifiable, Equatable {
    var id: UUID
    var direction: Transfer.Direction
    var peerName: String
    var peerAddress: String
    var title: String
    var status: String
    var fraction: Double
    /// Still going (or waiting); can be cancelled.
    var isActive: Bool
    /// No meaningful fraction yet: scanning, connecting, waiting for an answer.
    var isIndeterminate: Bool
    var failed: Bool
    var canReveal: Bool
    /// A send that ended without arriving, and can be sent again to the same Mac.
    var canRetry = false

    /// "Christmas 2026 → macbookair" / "Christmas 2026 ← macstudio".
    var headline: String { "\(title) \(direction == .send ? "→" : "←") \(peerName)" }
}

/// "Which kinds of file do you want to send?": a drop that has been read and holds several.
struct KindQuestion: Identifiable {
    let id = UUID()
    var urls: [URL]
    var peer: Peer
    var scanned: ScannedDrop
    var kinds: [FileKind]
    var title: String
}

/// Everything the app knows: who is nearby, what is moving, whether this Mac is receiving.
/// The menu and the window both draw from it.
@MainActor
final class AppModel: ObservableObject {
    let identity: Identity
    @Published var peers: [Peer] = []
    @Published var rows: [TransferRow] = []
    @Published var receiving: Bool
    @Published var addresses: [LocalHost.Address] = []
    /// Why this Mac cannot be found or cannot find others, when something is wrong.
    @Published var problem: String?
    /// Files dropped on the Dock icon, waiting for a Mac to be picked.
    @Published var pendingURLs: [URL] = []
    /// Macs added by address, as last heard from.
    @Published var manual: [Peer] = []
    @Published var streams = Settings.streams
    /// Destinations as a compact list (true) or a grid of tiles.
    @Published var listLayout = Settings.listLayout { didSet { if live { Settings.listLayout = listLayout } } }
    @Published var openAtLogin = LoginItem.isEnabled
    /// "0.2.0", when the updater has that version downloaded and ready to install.
    @Published var updateReady: String?
    var installUpdate: (() -> Void)?
    /// Files are being read before a send: "Reading “Christmas 2026”…".
    @Published var scanning: String?
    /// A drop with several kinds of file, waiting for the person to say which to send.
    @Published var kindQuestion: KindQuestion?
    /// Every drop that has ended, newest first, kept across launches.
    @Published var history: [HistoryEntry] = []
    private var historyStore: HistoryStore?
    /// A finished drop leaves the window this long after it ended; the History window keeps it.
    static let lingerSeconds: Double = 60
    /// The "add by address" field is showing.
    @Published var askingForAddress = false

    /// Everything that can be sent to: what Bonjour found, then the Macs added by address that
    /// Bonjour did not also find.
    var destinations: [Peer] {
        let found = Set(peers.map(\.id))
        return peers + manual.filter { !found.contains($0.id) }
    }

    /// Called after every change the status item cares about.
    var onChange: (() -> Void)?

    private var listener: DropListener?
    private var advertiser: Advertiser?
    private var browser: PeerBrowser?
    private var transfers: [Transfer] = []
    /// What each send was sending and to whom, for Retry.
    private var sends: [UUID: (urls: [URL], peer: Peer, kinds: Set<String>?)] = [:]
    private var scanTicket: UUID?
    private var meters: [UUID: RateMeter] = [:]
    private var announced = Set<UUID>()
    private var timer: Timer?
    private var activity: NSObjectProtocol?
    private struct Asking { var question: OfferPanel?; var chooser: NSOpenPanel? }
    /// The questions open right now, by drop.
    private var asking: [UUID: Asking] = [:]
    private let live: Bool

    init() {
        identity = Settings.identity
        receiving = Settings.receiving
        addresses = LocalHost.addresses
        live = true
    }

    /// Made-up contents for `--dump-window`; touches no network.
    init(demoPeers: [Peer], manual: [Peer], rows: [TransferRow], receiving: Bool = true, askingForAddress: Bool = false, listLayout: Bool = false) {
        identity = Identity(name: "macbookpro", id: "demo")
        self.receiving = receiving
        addresses = [LocalHost.Address(interface: "en0", address: "192.168.1.129")]
        peers = demoPeers
        self.manual = manual
        self.rows = rows
        self.askingForAddress = askingForAddress
        live = false
        self.listLayout = listLayout
    }

    // MARK: Lifecycle

    func start() {
        guard live else { return }
        let b = PeerBrowser(selfID: identity.id)
        b.onChange = { [weak self] peers in
            MainActor.assumeIsolated {
                guard let self else { return }
                self.logPeers(from: self.peers, to: peers)
                self.peers = peers
                self.updateProblem()
                self.onChange?()
            }
        }
        b.start()
        browser = b
        // Beside the preferences, under the bundle's own name, so the development copy keeps its own.
        let support = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
            .appendingPathComponent(Bundle.main.bundleIdentifier ?? "NimbusDrop", isDirectory: true)
        historyStore = HistoryStore(url: support.appendingPathComponent("history.json"))
        history = historyStore?.entries ?? []
        manual = Settings.manualDestinations.map(Self.placeholder)
        probeManual()
        applyReceiving()
        // Addresses change (Wi-Fi joins, a cable goes in) without anything telling us.
        let t = Timer(timeInterval: 5, repeats: true) { [weak self] _ in
            MainActor.assumeIsolated {
                guard let self else { return }
                let now = LocalHost.addresses
                if now != self.addresses {
                    DropLog.write("this Mac's addresses changed: \(now.map { "\($0.address) (\($0.interface))" }.joined(separator: ", "))")
                    self.addresses = now
                    self.onChange?()
                }
                self.probeManual()
            }
        }
        RunLoop.main.add(t, forMode: .common)
    }

    /// Who came, who went, whose address changed.
    private func logPeers(from old: [Peer], to new: [Peer]) {
        let before = Dictionary(uniqueKeysWithValues: old.map { ($0.id, $0) })
        let after = Dictionary(uniqueKeysWithValues: new.map { ($0.id, $0) })
        for p in new {
            let was = before[p.id]
            let place = "\(p.address ?? "address not known yet")\(p.port.map { ":\($0)" } ?? "")"
            if was == nil {
                DropLog.write("discovery: found \(p.name) at \(place) (Nimbus Drop \(p.appVersion ?? "?"), protocol \(p.protocolText))")
            } else if was?.address != p.address || was?.port != p.port {
                DropLog.write("discovery: \(p.name) is at \(place)")
            }
        }
        for p in old where after[p.id] == nil { DropLog.write("discovery: \(p.name) is gone") }
    }

    func stop() {
        for t in transfers where !t.state.isFinal { t.cancel() }
        advertiser = nil
        listener?.stop()
        browser?.stop()
    }

    func setReceiving(_ on: Bool) {
        receiving = on
        Settings.receiving = on
        applyReceiving()
        onChange?()
    }

    private var listenProblem: String?

    private func applyReceiving() {
        guard live else { return }
        advertiser = nil
        listener?.stop()
        listener = nil
        listenProblem = nil
        if !receiving { DropLog.write("receiving is off") }
        if receiving {
            do {
                let l = try DropListener(identity: identity)
                l.onOffer = { [weak self] session in
                    DispatchQueue.main.async { MainActor.assumeIsolated { self?.offered(session) } }
                }
                l.start()
                listener = l
                advertiser = try Advertiser(identity: identity, port: l.port)
                DropLog.write("receiving as \(identity.name) on port \(l.port); addresses \(LocalHost.addresses.map { "\($0.address) (\($0.interface))" }.joined(separator: ", "))")
            } catch {
                listenProblem = (error as? DropError)?.message ?? error.localizedDescription
                DropLog.write("cannot receive: \(listenProblem ?? "")")
            }
        }
        updateProblem()
    }

    private func updateProblem() {
        problem = listenProblem ?? browser?.problem.map { "Cannot look for other Macs: \($0). Check System Settings › Privacy & Security › Local Network." }
    }

    /// Something that quitting would interrupt; an offer nobody has answered yet does not count.
    var hasActiveTransfers: Bool {
        transfers.contains { !$0.state.isFinal && !($0.direction == .receive && $0.state == .waitingForAccept) }
    }

    // MARK: Sending

    /// Sends files and folders to a Mac. They are read first; if they hold more than one kind of
    /// file the person is asked which kinds to send (`kindQuestion`), unless `kinds` already says or `asking` is off (a retry).
    func send(_ urls: [URL], to peer: Peer, kinds: Set<String>? = nil, asking: Bool = true) {
        guard live, !urls.isEmpty else { return }
        pendingURLs = []
        let name = urls.count == 1 ? urls[0].lastPathComponent : "\(urls.count) items"
        scanning = "Reading “\(name)”…"
        let ticket = UUID()
        scanTicket = ticket
        DispatchQueue.global(qos: .userInitiated).async {
            let result = Result { try Scanner.scan(urls) }
            DispatchQueue.main.async {
                MainActor.assumeIsolated {
                    guard self.scanTicket == ticket else { return }
                    self.scanning = nil
                    switch result {
                    case .failure(let error):
                        let alert = NSAlert()
                        alert.messageText = "Cannot send “\(name)”"
                        alert.informativeText = (error as? DropError)?.message ?? error.localizedDescription
                        NSApp.activate(ignoringOtherApps: true)
                        alert.runModal()
                    case .success(let scanned):
                        let found = FileKinds.summarize(scanned.manifest)
                        if let kinds {
                            self.deliver(urls, scanned.keeping(kinds: kinds), kinds: kinds, to: peer)
                        } else if asking, found.count >= 2 {
                            AppDelegate.shared?.showWindow()
                            self.kindQuestion = KindQuestion(urls: urls, peer: peer, scanned: scanned, kinds: found, title: name)
                        } else {
                            self.deliver(urls, scanned, kinds: nil, to: peer)
                        }
                    }
                }
            }
        }
    }

    /// The answer to `kindQuestion`: these kinds (nil: everything), or nothing at all.
    func answer(_ question: KindQuestion, kinds: Set<String>?, send: Bool) {
        kindQuestion = nil
        guard send else { return }
        deliver(question.urls, kinds.map { question.scanned.keeping(kinds: $0) } ?? question.scanned, kinds: kinds, to: question.peer)
    }

    private func deliver(_ urls: [URL], _ scanned: ScannedDrop, kinds: Set<String>?, to peer: Peer) {
        guard let browser else { return }
        if peer.isManual, let address = peer.address {
            begin(urls, scanned, kinds: kinds, to: peer, host: address, port: peer.port ?? defaultPort)
            return
        }
        // The other copy's port changes when it restarts, so look it up again each time.
        browser.resolve(peer.id) { [weak self] resolved in
            MainActor.assumeIsolated {
                guard let self else { return }
                guard let address = resolved?.address ?? peer.address, let port = resolved?.port ?? peer.port else {
                    let alert = NSAlert()
                    alert.messageText = "Cannot reach \(peer.name)"
                    alert.informativeText = "It was found on the network but did not answer. Check that Nimbus Drop is still running there with receiving on."
                    NSApp.activate(ignoringOtherApps: true)
                    alert.runModal()
                    return
                }
                self.begin(urls, scanned, kinds: kinds, to: peer, host: address, port: port)
            }
        }
    }

    private func begin(_ urls: [URL], _ scanned: ScannedDrop, kinds: Set<String>?, to peer: Peer, host: String, port: UInt16) {
        let session = SendSession(urls: urls, host: host, port: port, peerName: peer.name,
                                  identity: identity, streams: Settings.streams, prescanned: scanned)
        DropLog.write("sending \(urls.map(\.path).joined(separator: ", ")) to \(peer.name)\(peer.isManual ? " (added by address)" : "")"
            + (kinds.map { "; only \($0.sorted().joined(separator: ", "))" } ?? ""))
        if !peer.isManual {
            // If the drop loses its connection, the engine asks where the Mac is now: one that
            // changed networks comes back under another address, and Bonjour knows it.
            let id = peer.id
            session.relocate = { [weak self] in
                let found = Located()
                let done = DispatchSemaphore(value: 0)
                DispatchQueue.main.async {
                    MainActor.assumeIsolated {
                        guard let browser = self?.browser else { done.signal(); return }
                        browser.resolve(id) { peer in
                            if let a = peer?.address, let p = peer?.port { found.value = (a, p) }
                            done.signal()
                        }
                    }
                }
                _ = done.wait(timeout: .now() + 6)
                return found.value
            }
        }
        sends[session.id] = (urls, peer, kinds)
        add(session)
        session.start()
    }

    /// Sends a drop that did not arrive once more, to the same Mac. What the first attempt
    /// delivered is still there, so it carries on from it; the other person is asked again.
    func retry(_ id: UUID) {
        guard let again = sends[id], let old = transfers.first(where: { $0.id == id }), old.state.isFinal else { return }
        transfers.removeAll { $0.id == id }
        meters[id] = nil
        sends[id] = nil
        // The Mac as it is known now (its address may have changed), or as it was.
        let peer = destinations.first { $0.id == again.peer.id } ?? again.peer
        // The same kinds of file as before; the files are read again, in case they changed.
        send(again.urls, to: peer, kinds: again.kinds, asking: false)
        refresh()
    }

    /// The Open panel for "send to this Mac", from the menu or a click on a tile.
    func chooseAndSend(to peer: Peer) {
        let p = NSOpenPanel()
        p.canChooseFiles = true
        p.canChooseDirectories = true
        p.allowsMultipleSelection = true
        p.message = "Choose files and folders to send to \(peer.name)\(peer.address.map { " (\($0))" } ?? "")."
        p.prompt = "Send"
        NSApp.activate(ignoringOtherApps: true)
        p.begin { [weak self] response in
            MainActor.assumeIsolated {
                if response == .OK { self?.send(p.urls, to: peer) }
            }
        }
    }

    // MARK: Macs added by address

    /// "192.168.1.20", "macstudio.local", "10.0.0.5:47900".
    nonisolated private static func parse(_ entry: String) -> (host: String, port: UInt16) {
        let parts = entry.split(separator: ":")
        if parts.count == 2, let port = UInt16(parts[1]) { return (String(parts[0]), port) }
        return (entry, defaultPort)
    }

    /// How a Mac added by address looks before it has said who it is.
    nonisolated private static func placeholder(_ entry: String) -> Peer {
        let (host, port) = parse(entry)
        var p = Peer(id: "manual:" + entry, name: host, address: host, port: port, version: nil)
        p.isManual = true
        p.unreachable = true
        return p
    }

    /// Adds a Mac by address and asks it who it is. Returns why not, when the entry is unusable.
    @discardableResult
    func addManual(_ text: String) -> String? {
        let entry = text.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !entry.isEmpty, !entry.contains(" "), !entry.contains("/") else { return "Enter an IP address or a host name." }
        var list = Settings.manualDestinations
        guard !list.contains(entry) else { return "\(entry) is already in the list." }
        list.append(entry)
        Settings.manualDestinations = list
        manual.append(Self.placeholder(entry))
        probeManual()
        return nil
    }

    func removeManual(_ peer: Peer) {
        guard let index = manual.firstIndex(where: { $0.id == peer.id }) else { return }
        manual.remove(at: index)
        var list = Settings.manualDestinations
        if index < list.count { list.remove(at: index) }
        Settings.manualDestinations = list
    }

    /// Asks each added Mac who it is, off the main thread; one that does not answer stays in
    /// the list, marked, and is asked again in a few seconds.
    private func probeManual() {
        guard live else { return }
        let entries = Settings.manualDestinations
        let own = identity.id
        DispatchQueue.global(qos: .utility).async {
            let answers = entries.map { entry -> Peer in
                let (host, port) = Self.parse(entry)
                guard var peer = try? Probe.hello(host: host, port: port, timeout: 2) else { return Self.placeholder(entry) }
                peer.isManual = true
                if peer.id == own { peer.name += " (this Mac)" }
                return peer
            }
            DispatchQueue.main.async {
                MainActor.assumeIsolated {
                    guard Settings.manualDestinations == entries, self.manual != answers else { return }
                    self.manual = answers
                }
            }
        }
    }

    // MARK: Settings the window shows

    func setStreams(_ n: Int) {
        Settings.streams = n
        streams = Settings.streams
    }

    func setOpenAtLogin(_ on: Bool) {
        do {
            try LoginItem.setEnabled(on)
            UserDefaults.standard.set(true, forKey: LoginItem.registeredDefaultsKey)
        } catch {
            let alert = NSAlert()
            alert.messageText = "Could not change Open at Login"
            alert.informativeText = error.localizedDescription
            alert.runModal()
        }
        openAtLogin = LoginItem.isEnabled
    }

    // MARK: Receiving

    /// Each incoming drop asks its own question, independently of any other: a small panel that
    /// says who is sending, what, how many files and how big, answered with Save to Downloads
    /// (one click), Save to… (then a folder chooser; cancelling that declines), or Decline. A second drop that arrives while the first is still being
    /// decided gets its own panel beside it, and they can be answered in any order.
    private func offered(_ session: ReceiveSession) {
        add(session)
        let id = session.id
        session.onWithdrawn = { [weak self] in
            DispatchQueue.main.async { MainActor.assumeIsolated { self?.withdraw(id) } }
        }
        let q = OfferPanel(session: session) { [weak self] answer in
            MainActor.assumeIsolated {
                guard let self else { return }
                self.asking[id]?.question = nil
                guard session.state == .waitingForAccept, answer != .decline else {
                    session.decline("\(self.identity.name) declined")
                    self.asking[id] = nil
                    return
                }
                if answer == .downloads, let downloads = FileManager.default.urls(for: .downloadsDirectory, in: .userDomainMask).first {
                    session.accept(destination: downloads)
                    self.asking[id] = nil
                } else {
                    self.askWhere(session)
                }
            }
        }
        let place = asking.count
        asking[id] = Asking(question: q, chooser: nil)
        NSApp.activate(ignoringOtherApps: true)
        NSSound(named: "Glass")?.play()
        q.show(cascade: place)
    }

    private func askWhere(_ session: ReceiveSession) {
        let id = session.id
        let p = NSOpenPanel()
        p.title = "Save “\(session.title)” from \(session.peerName)"
        p.canChooseFiles = false
        p.canChooseDirectories = true
        p.canCreateDirectories = true
        p.allowsMultipleSelection = false
        p.directoryURL = FileManager.default.urls(for: .downloadsDirectory, in: .userDomainMask).first
        p.message = "Where do you want to save “\(session.title)” (\(Format.files(session.offeredFiles)), \(Format.bytes(session.offeredBytes))) from \(session.peerName)?"
        p.prompt = "Save Here"
        p.level = .modalPanel
        asking[id] = Asking(question: nil, chooser: p)
        NSApp.activate(ignoringOtherApps: true)
        p.begin { [weak self] response in
            MainActor.assumeIsolated {
                guard let self else { return }
                if response == .OK, let url = p.url {
                    session.accept(destination: url)
                } else {
                    session.decline("\(self.identity.name) declined")
                }
                self.asking[id] = nil
            }
        }
        p.makeKeyAndOrderFront(nil)
    }

    /// The sender gave up while its question was open: take the question away. (An earlier
    /// version dismissed the panel but went on believing a question was open, and every later
    /// offer waited behind it: 2026-11-22.)
    private func withdraw(_ id: UUID) {
        guard let open = asking.removeValue(forKey: id) else { return }
        open.question?.dismiss()
        open.chooser?.cancel(nil)
    }

    /// Questions on screen right now, for `--print`-style checks and the tests of the future.
    var openQuestions: Int { asking.count }

    // MARK: The list

    private func add(_ t: Transfer) {
        transfers.insert(t, at: 0)
        meters[t.id] = RateMeter()
        t.onChange = { [weak self] in
            DispatchQueue.main.async { MainActor.assumeIsolated { self?.refresh() } }
        }
        refresh()
    }

    func cancel(_ id: UUID) { transfers.first { $0.id == id }?.cancel() }

    func remove(_ id: UUID) {
        guard let t = transfers.first(where: { $0.id == id }), t.state.isFinal else { return }
        transfers.removeAll { $0.id == id }
        meters[id] = nil
        sends[id] = nil
        refresh()
    }

    func clearFinished() {
        transfers.removeAll { $0.state.isFinal }
        sends = sends.filter { id, _ in transfers.contains { $0.id == id } }
        refresh()
    }

    func reveal(_ id: UUID) {
        guard let t = transfers.first(where: { $0.id == id }), !t.savedURLs.isEmpty else { return }
        NSWorkspace.shared.activateFileViewerSelecting(t.savedURLs)
    }

    /// The sum over everything moving, for the status item: nil when nothing is.
    var overallFraction: Double? {
        let moving = transfers.filter { $0.state == .transferring || $0.state == .finishing }
        guard !moving.isEmpty else { return nil }
        let total = moving.reduce(Int64(0)) { $0 + $1.progress.totalBytes }
        let done = moving.reduce(Int64(0)) { $0 + $1.progress.doneBytes }
        return total > 0 ? Double(done) / Double(total) : 0
    }

    private func refresh() {
        let now = Date()
        for t in transfers where t.state.isFinal && announced.insert(t.id).inserted {
            announce(t)
            record(t)
        }
        // A drop that ended a minute ago has been seen; it leaves the window. History has it.
        let stale = transfers.filter { t in t.finishedAt.map { now.timeIntervalSince($0) > Self.lingerSeconds } ?? false }
        if !stale.isEmpty {
            let ids = Set(stale.map(\.id))
            transfers.removeAll { ids.contains($0.id) }
            for id in ids { meters[id] = nil; sends[id] = nil }
        }
        rows = transfers.map { row(for: $0, now: now) }
        let active = transfers.contains { !$0.state.isFinal }

        // Poll while anything is listed: quickly while it moves, once a second while finished
        // drops wait out their minute. The Mac is held awake only while something moves.
        let interval = active ? 0.25 : 1.0
        if transfers.isEmpty {
            timer?.invalidate()
            timer = nil
        } else if timer == nil || timer?.timeInterval != interval {
            timer?.invalidate()
            let t = Timer(timeInterval: interval, repeats: true) { [weak self] _ in MainActor.assumeIsolated { self?.refresh() } }
            RunLoop.main.add(t, forMode: .common)
            timer = t
        }
        if active, activity == nil {
            activity = ProcessInfo.processInfo.beginActivity(options: [.userInitiated, .idleSystemSleepDisabled],
                                                             reason: "A drop is under way")
        } else if !active, let a = activity {
            ProcessInfo.processInfo.endActivity(a)
            activity = nil
        }
        onChange?()
    }

    /// Writes a drop that has ended into the history. An offer that was withdrawn before anyone
    /// here answered it never became a drop, and is left out.
    private func record(_ t: Transfer) {
        let outcome: HistoryEntry.Outcome
        var detail: String?
        switch t.state {
        case .completed: outcome = .completed
        case .declined(let why): outcome = .declined; detail = why
        case .failed(let why):
            if t.direction == .receive, t.transferStartedAt == nil { return }
            outcome = .failed; detail = why
        case .cancelled: outcome = .cancelled
        default: return
        }
        let p = t.progress
        let seconds = t.transferStartedAt.map { (t.finishedAt ?? Date()).timeIntervalSince($0) }
        var entry = HistoryEntry(date: t.finishedAt ?? Date(), sent: t.direction == .send, title: t.title, peerName: t.peerName,
                                 peerAddress: t.peerAddress, files: p.totalFiles, bytes: p.totalBytes, seconds: seconds,
                                 outcome: outcome, detail: detail, savedPaths: t.savedURLs.map(\.path))
        let stats = t.stats
        entry.rounds = stats.rounds
        entry.connectionsLost = stats.connectionFailures
        entry.damagedChunks = stats.damagedChunks
        entry.reconnects = stats.reconnects
        historyStore?.add(entry)
        history = historyStore?.entries ?? []
    }

    func clearHistory() {
        historyStore?.clear()
        history = []
    }

    private func row(for t: Transfer, now: Date) -> TransferRow {
        let state = t.state, p = t.progress
        var status = "", indeterminate = false, failed = false
        switch state {
        case .scanning: status = "Reading files…"; indeterminate = true
        case .connecting: status = "Connecting to \(t.peerAddress)…"; indeterminate = true
        case .waitingForAccept:
            status = t.direction == .send ? "Waiting for \(t.peerName) to accept…" : "Waiting for you to choose where to save it…"
            indeterminate = true
        case .transferring:
            let rate = meters[t.id]?.rate(bytes: p.doneBytes, now: now) ?? 0
            status = "\(Format.bytes(p.doneBytes)) of \(Format.bytes(p.totalBytes)) · \(Format.bitRate(rate)) · \(Format.connections(p.connections))"
            if rate > 0 { status += " · \(Format.duration(Double(p.totalBytes - p.doneBytes) / rate)) left" }
            let trouble = t.stats
            if trouble.connectionFailures > 0 || trouble.damagedChunks > 0 || trouble.reconnects > 0 { status += "\n" + Self.troubleText(trouble) }
        case .reconnecting:
            status = t.direction == .send ? "Lost the connection to \(t.peerName); trying to get it back…"
                                          : "Lost the connection to \(t.peerName); waiting for it to come back…"
            status += "\n\(Format.bytes(p.doneBytes)) of \(Format.bytes(p.totalBytes)) so far"
            indeterminate = true
        case .finishing: status = "Finishing…"; indeterminate = true
        case .completed:
            let seconds = max(0.001, (t.finishedAt ?? now).timeIntervalSince(t.transferStartedAt ?? t.startedAt))
            let moved = p.totalBytes - p.resumedBytes
            status = "\(Format.files(p.totalFiles)), \(Format.bytes(p.totalBytes)) in \(Format.duration(seconds)) · \(Format.bitRate(Double(moved) / seconds))"
            if p.resumedBytes > 0 { status += " · continued from \(Format.bytes(p.resumedBytes))" }
            let trouble = t.stats
            if trouble.connectionFailures > 0 || trouble.damagedChunks > 0 || trouble.reconnects > 0 { status += "\n" + Self.troubleText(trouble) }
        case .declined(let why): status = why; failed = true
        case .failed(let why): status = why; failed = true
        case .cancelled: status = "Cancelled"; failed = true
        }
        return TransferRow(id: t.id, direction: t.direction, peerName: t.peerName, peerAddress: t.peerAddress, title: t.title,
                           status: status, fraction: state == .completed ? 1 : p.fraction, isActive: !state.isFinal,
                           isIndeterminate: indeterminate, failed: failed,
                           canReveal: state == .completed && !t.savedURLs.isEmpty,
                           canRetry: failed && sends[t.id] != nil)
    }

    /// What the drop got past, said so that it cannot be taken for starting over: after trouble
    /// only the missing parts go again, never the whole drop.
    static func troubleText(_ s: TransferStats) -> String {
        var parts: [String] = []
        let lost = s.connectionFailures - s.damagedChunks
        if s.reconnects > 0 { parts.append("reconnected \(s.reconnects == 1 ? "once" : "\(s.reconnects) times")") }
        if lost > 0 { parts.append("\(lost) \(lost == 1 ? "connection" : "connections") dropped") }
        if s.damagedChunks > 0 { parts.append("\(s.damagedChunks) damaged \(s.damagedChunks == 1 ? "chunk" : "chunks") caught") }
        return "Recovered: " + parts.joined(separator: ", ") + (lost > 0 || s.damagedChunks > 0 ? ". Only the missing parts were sent again." : ".")
    }

    // MARK: Notifications

    /// A received drop, or a send that ended, is worth a notification: the window is often
    /// closed and a long drop is something you walk away from.
    private func announce(_ t: Transfer) {
        guard Bundle.main.bundleIdentifier != nil else { return }
        let content = UNMutableNotificationContent()
        switch (t.direction, t.state) {
        case (.receive, .completed):
            content.title = "Received “\(t.title)” from \(t.peerName)"
            content.body = "\(Format.files(t.progress.totalFiles)), \(Format.bytes(t.progress.totalBytes)). Saved to \(t.savedURLs.first?.deletingLastPathComponent().lastPathComponent ?? "disk")."
        case (.send, .completed):
            content.title = "Sent “\(t.title)” to \(t.peerName)"
            content.body = "\(Format.files(t.progress.totalFiles)), \(Format.bytes(t.progress.totalBytes))."
        case (.send, .declined(let why)):
            content.title = "“\(t.title)” was not sent"
            content.body = why
        case (_, .failed(let why)):
            // A drop this Mac never accepted is the sender's business, not news here.
            if t.direction == .receive, t.transferStartedAt == nil { return }
            content.title = t.direction == .send ? "Sending “\(t.title)” to \(t.peerName) stopped" : "Receiving “\(t.title)” from \(t.peerName) stopped"
            content.body = why + " Send it again to continue."
        default:
            return
        }
        let center = UNUserNotificationCenter.current()
        center.requestAuthorization(options: [.alert, .sound]) { ok, _ in
            guard ok else { return }
            center.add(UNNotificationRequest(identifier: t.id.uuidString, content: content, trigger: nil))
        }
    }
}

/// An answer carried from the main thread back to an engine thread.
private final class Located: @unchecked Sendable {
    private let lock = NSLock()
    private var _value: (host: String, port: UInt16)?
    var value: (host: String, port: UInt16)? {
        get { lock.withLock { _value } }
        set { lock.withLock { _value = newValue } }
    }
}

/// Bytes per second over the last few seconds, so the figure neither jitters nor lags.
private final class RateMeter {
    private var samples: [(time: Date, bytes: Int64)] = []

    func rate(bytes: Int64, now: Date) -> Double {
        samples.append((now, bytes))
        samples.removeAll { now.timeIntervalSince($0.time) > 4 }
        guard let first = samples.first, now.timeIntervalSince(first.time) >= 0.5 else { return 0 }
        return Double(bytes - first.bytes) / now.timeIntervalSince(first.time)
    }
}
