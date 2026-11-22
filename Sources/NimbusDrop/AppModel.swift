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

    /// "Christmas 2026 → macbookair" / "Christmas 2026 ← macstudio".
    var headline: String { "\(title) \(direction == .send ? "→" : "←") \(peerName)" }
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
    @Published var openAtLogin = LoginItem.isEnabled
    /// "0.2.0", when the updater has that version downloaded and ready to install.
    @Published var updateReady: String?
    var installUpdate: (() -> Void)?
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
    private var meters: [UUID: RateMeter] = [:]
    private var announced = Set<UUID>()
    private var timer: Timer?
    private var activity: NSObjectProtocol?
    private var prompts: [ReceiveSession] = []
    private var panel: NSOpenPanel?
    private var question: OfferPanel?
    private var panelSession: ReceiveSession?
    private let live: Bool

    init() {
        identity = Settings.identity
        receiving = Settings.receiving
        addresses = LocalHost.addresses
        live = true
    }

    /// Made-up contents for `--dump-window`; touches no network.
    init(demoPeers: [Peer], manual: [Peer], rows: [TransferRow], receiving: Bool = true, askingForAddress: Bool = false) {
        identity = Identity(name: "macbookpro", id: "demo")
        self.receiving = receiving
        addresses = [LocalHost.Address(interface: "en0", address: "192.168.1.129")]
        peers = demoPeers
        self.manual = manual
        self.rows = rows
        self.askingForAddress = askingForAddress
        live = false
    }

    // MARK: Lifecycle

    func start() {
        guard live else { return }
        let b = PeerBrowser(selfID: identity.id)
        b.onChange = { [weak self] peers in
            MainActor.assumeIsolated {
                guard let self else { return }
                self.peers = peers
                self.updateProblem()
                self.onChange?()
            }
        }
        b.start()
        browser = b
        manual = Settings.manualDestinations.map(Self.placeholder)
        probeManual()
        applyReceiving()
        // Addresses change (Wi-Fi joins, a cable goes in) without anything telling us.
        let t = Timer(timeInterval: 5, repeats: true) { [weak self] _ in
            MainActor.assumeIsolated {
                guard let self else { return }
                let now = LocalHost.addresses
                if now != self.addresses { self.addresses = now; self.onChange?() }
                self.probeManual()
            }
        }
        RunLoop.main.add(t, forMode: .common)
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
        if receiving {
            do {
                let l = try DropListener(identity: identity)
                l.onOffer = { [weak self] session in
                    DispatchQueue.main.async { MainActor.assumeIsolated { self?.offered(session) } }
                }
                l.start()
                listener = l
                advertiser = try Advertiser(identity: identity, port: l.port)
            } catch {
                listenProblem = (error as? DropError)?.message ?? error.localizedDescription
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

    func send(_ urls: [URL], to peer: Peer) {
        guard live, !urls.isEmpty, let browser else { return }
        pendingURLs = []
        if peer.isManual, let address = peer.address {
            let session = SendSession(urls: urls, host: address, port: peer.port ?? defaultPort, peerName: peer.name,
                                      identity: identity, streams: Settings.streams)
            add(session)
            session.start()
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
                let session = SendSession(urls: urls, host: address, port: port, peerName: peer.name,
                                          identity: self.identity, streams: Settings.streams)
                self.add(session)
                session.start()
            }
        }
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

    private func offered(_ session: ReceiveSession) {
        add(session)
        session.onWithdrawn = { [weak self, weak session] in
            DispatchQueue.main.async {
                MainActor.assumeIsolated {
                    guard let self, let session else { return }
                    self.prompts.removeAll { $0 === session }
                    if self.panelSession === session {
                        self.question?.dismiss()
                        self.panel?.cancel(nil)
                    }
                }
            }
        }
        prompts.append(session)
        askNext()
    }

    /// Two questions, one at a time: "do you want this?" in a small panel that says who is
    /// sending, what, how many files and how big; then, only after Accept, "where do you want
    /// to save it?" in a folder chooser. Declining either declines the drop. Further offers
    /// wait their turn.
    private func askNext() {
        guard question == nil, panel == nil else { return }
        prompts.removeAll { $0.state != .waitingForAccept }
        guard let session = prompts.first else { return }
        prompts.removeFirst()
        panelSession = session

        let q = OfferPanel(session: session) { [weak self] accepted in
            MainActor.assumeIsolated {
                guard let self else { return }
                self.question = nil
                if accepted, session.state == .waitingForAccept {
                    self.askWhere(session)
                } else {
                    session.decline("\(self.identity.name) declined")
                    self.panelSession = nil
                    self.askNext()
                }
            }
        }
        question = q
        NSApp.activate(ignoringOtherApps: true)
        NSSound(named: "Glass")?.play()
        q.show()
    }

    private func askWhere(_ session: ReceiveSession) {
        let p = NSOpenPanel()
        p.title = "Save Incoming Drop"
        p.canChooseFiles = false
        p.canChooseDirectories = true
        p.canCreateDirectories = true
        p.allowsMultipleSelection = false
        p.directoryURL = FileManager.default.urls(for: .downloadsDirectory, in: .userDomainMask).first
        p.message = "Where do you want to save “\(session.title)” from \(session.peerName)?"
        p.prompt = "Save Here"
        p.level = .modalPanel
        panel = p
        NSApp.activate(ignoringOtherApps: true)
        p.begin { [weak self] response in
            MainActor.assumeIsolated {
                guard let self else { return }
                if response == .OK, let url = p.url {
                    session.accept(destination: url)
                } else {
                    session.decline("\(self.identity.name) declined")
                }
                self.panel = nil
                self.panelSession = nil
                self.askNext()
            }
        }
        p.makeKeyAndOrderFront(nil)
    }

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
        refresh()
    }

    func clearFinished() {
        transfers.removeAll { $0.state.isFinal }
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
        rows = transfers.map { row(for: $0, now: now) }
        let active = transfers.contains { !$0.state.isFinal }

        // Poll while anything is moving; hold the Mac awake for as long.
        if active, timer == nil {
            let t = Timer(timeInterval: 0.25, repeats: true) { [weak self] _ in MainActor.assumeIsolated { self?.refresh() } }
            RunLoop.main.add(t, forMode: .common)
            timer = t
            activity = ProcessInfo.processInfo.beginActivity(options: [.userInitiated, .idleSystemSleepDisabled],
                                                             reason: "A drop is under way")
        } else if !active, let t = timer {
            t.invalidate()
            timer = nil
            if let a = activity { ProcessInfo.processInfo.endActivity(a) }
            activity = nil
        }
        for t in transfers where t.state.isFinal && announced.insert(t.id).inserted { announce(t) }
        onChange?()
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
            if trouble.connectionFailures > 0 || trouble.damagedChunks > 0 { status += "\n" + Self.troubleText(trouble) }
        case .finishing: status = "Finishing…"; indeterminate = true
        case .completed:
            let seconds = max(0.001, (t.finishedAt ?? now).timeIntervalSince(t.transferStartedAt ?? t.startedAt))
            let moved = p.totalBytes - p.resumedBytes
            status = "\(Format.files(p.totalFiles)), \(Format.bytes(p.totalBytes)) in \(Format.duration(seconds)) · \(Format.bitRate(Double(moved) / seconds))"
            if p.resumedBytes > 0 { status += " · continued from \(Format.bytes(p.resumedBytes))" }
            let trouble = t.stats
            if trouble.connectionFailures > 0 || trouble.damagedChunks > 0 { status += "\n" + Self.troubleText(trouble) }
        case .declined(let why): status = why; failed = true
        case .failed(let why): status = why; failed = true
        case .cancelled: status = "Cancelled"; failed = true
        }
        return TransferRow(id: t.id, direction: t.direction, peerName: t.peerName, peerAddress: t.peerAddress, title: t.title,
                           status: status, fraction: state == .completed ? 1 : p.fraction, isActive: !state.isFinal,
                           isIndeterminate: indeterminate, failed: failed,
                           canReveal: state == .completed && !t.savedURLs.isEmpty)
    }

    /// "2 connections lost and 1 damaged chunk re-sent": what the drop got past.
    static func troubleText(_ s: TransferStats) -> String {
        var parts: [String] = []
        let lost = s.connectionFailures - s.damagedChunks
        if lost > 0 { parts.append("\(lost) \(lost == 1 ? "connection" : "connections") lost") }
        if s.damagedChunks > 0 { parts.append("\(s.damagedChunks) damaged \(s.damagedChunks == 1 ? "chunk" : "chunks") caught") }
        return parts.joined(separator: ", ") + "; re-sent"
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
