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
    /// This Mac's key and what it knows of others'. Always there; when the stored identity could
    /// not be opened it is a stand-in held in memory, and `trustProblem` says so.
    private(set) var trust: Trust
    /// Bumped whenever the trust store changes, so that what is drawn from it is drawn again.
    @Published var trustChanges = 0
    /// The pairing windows open right now.
    private var pairings: [UUID: PairingPanel] = [:]
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
    /// Take drops only from addresses on this Mac's own subnets.
    @Published var localOnly = Settings.localOnly
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
        let mine = trust.publicKey
        // This Mac's own record never appears in its own list, whatever it is announced as.
        return (peers + manual.filter { !found.contains($0.id) }).filter { $0.key != mine || $0.isManual }
    }

    /// What a destination is to this Mac: from the key its address proved, and nothing else.
    func standing(_ peer: Peer) -> PeerStanding {
        if let demo = demoStandings[peer.id] { return demo }
        if !peer.isCompatible { return .needsUpdate }
        guard let key = peer.key else { return peer.unproved || (peer.isManual && peer.unreachable) ? .unproved : .checking }
        switch trust.standing(of: key) {
        case .mine: return .unproved
        case .paired(let mac): return .paired(mac)
        case .expired(let mac): return .refused("\(mac.name)'s key has run out; it will have a new one after Nimbus Drop is opened there")
        case .retired(let t): return .refused("An identity that \(t.name) gave up")
        case .renew(let r): return .renew(r.name)
        case .unknown:
            guard let clash = trust.nameClash(peer.name, key: key) else { return .new }
            return clash.expected ? .renew(clash.name) : .nameInUse(clash)
        }
    }
    /// Made-up standings for the pictures.
    var demoStandings: [String: PeerStanding] = [:]

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
        (trust, trustProblem) = AppModel.openTrust()
        receiving = Settings.receiving
        addresses = LocalHost.addresses
        live = true
    }

    /// Made-up contents for `--dump-window`; touches no network.
    init(demoPeers: [Peer], manual: [Peer], rows: [TransferRow], receiving: Bool = true, askingForAddress: Bool = false, listLayout: Bool = false) {
        identity = Identity(name: "macbookpro", id: "demo")
        trust = Trust.inMemory()
        self.receiving = receiving
        addresses = [LocalHost.Address(interface: "en0", address: "192.168.1.129")]
        peers = demoPeers
        self.manual = manual
        self.rows = rows
        self.askingForAddress = askingForAddress
        live = false
        self.listLayout = listLayout
    }

    /// Why this Mac's stored identity could not be used, when it could not.
    @Published var trustProblem: String?
    /// Reset Identity is telling the other Macs.
    @Published var resetting = false

    /// Opens the stored identity. If it cannot be opened the app still runs, on an identity held
    /// in memory that nothing is paired with, and says why; nothing stored is replaced.
    private static func openTrust() -> (Trust, String?) {
        let storage = EnclaveStorage.standard(bundleID: Settings.bundleID)
        do { return (try Trust(storage: storage), nil) } catch TrustFault.damaged {
            return (Trust.inMemory(), "damaged")
        } catch TrustFault.unavailable(let why) {
            return (Trust.inMemory(), "This Mac's identity cannot be opened right now (\(why)). Nothing can be sent or received until it can; quit and open Nimbus Drop again.")
        } catch {
            return (Trust.inMemory(), "This Mac's identity cannot be opened: \(error)")
        }
    }

    /// What a Mac is called here: the name the person gave it once paired, what it announces otherwise.
    func displayName(_ peer: Peer) -> String {
        if let key = peer.key, case .paired(let mac) = trust.standing(of: key) { return mac.name }
        return peer.name
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
        trust.onChange = { [weak self] in
            DispatchQueue.main.async { MainActor.assumeIsolated { self?.trustChanged() } }
        }
        if trustProblem == "damaged" { DispatchQueue.main.async { MainActor.assumeIsolated { self.askAboutDamagedIdentity() } } }
        // Said once, to someone who had an earlier version: what changed and what they will be asked.
        if !UserDefaults.standard.bool(forKey: "toldEncrypted") {
            UserDefaults.standard.set(true, forKey: "toldEncrypted")
            if UserDefaults.standard.object(forKey: "receiving") != nil || !history.isEmpty {
                DispatchQueue.main.asyncAfter(deadline: .now() + 1) {
                    let alert = NSAlert()
                    alert.messageText = "Drops are now encrypted"
                    alert.informativeText = "This Mac has its own identity. The first time you exchange a drop with another Mac, each of you will read out a 6-digit code and type the other's. Keys are replaced every 90 days, and you pair again then.\n\nEvery Mac needs Nimbus Drop 0.3 or later: this version does not talk to earlier ones."
                    NSApp.activate(ignoringOtherApps: true)
                    alert.runModal()
                }
            }
        }
        if trust.startNote == "foreign" {
            DropLog.write("identity: this copy's files came from another Mac; this Mac has a new identity and is paired with nobody", .warn)
        }
        DropLog.write("identity: this Mac's key is \(trust.publicKey.tag), good until \(trust.ends.formatted(date: .abbreviated, time: .shortened)); paired with \(trust.known.count) Macs")
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
                // Keys end on their dates whether or not anything is happening.
                let trust = self.trust
                DispatchQueue.global(qos: .utility).async { trust.tick() }
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
                DropLog.write("discovery: \(p.name) is at \(place)", .debug)
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
        if receiving, trustProblem == nil {
            do {
                let l = try DropListener(identity: identity, trust: trust)
                l.localOnly = localOnly
                l.onOffer = { [weak self] session in
                    DispatchQueue.main.async { MainActor.assumeIsolated { self?.offered(session) } }
                }
                l.onPairRequest = { [weak self] pairing in
                    DispatchQueue.main.async { MainActor.assumeIsolated { self?.pairRequested(pairing) } }
                }
                l.onRefusedIdentity = { [weak self] name, address in
                    DispatchQueue.main.async { MainActor.assumeIsolated { self?.refusedIdentity(name: name, address: address) } }
                }
                l.start()
                listener = l
                advertiser = try Advertiser(identity: identity, port: l.port)
                DropLog.write("receiving as \(identity.name) on port \(l.port), \(localOnly ? "from the local network only" : "from any address"); addresses \(LocalHost.addresses.map { "\($0.address) (\($0.interface))" }.joined(separator: ", "))")
            } catch {
                listenProblem = (error as? DropError)?.message ?? error.localizedDescription
                DropLog.write("cannot receive: \(listenProblem ?? "")", .error)
            }
        }
        updateProblem()
    }

    private func updateProblem() {
        problem = (trustProblem == "damaged" ? "This Mac's identity cannot be read." : trustProblem) ?? listenProblem ?? browser?.problem.map { "Cannot look for other Macs: \($0). Check System Settings › Privacy & Security › Local Network." }
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
        // Nothing goes to a Mac that is not paired: pair first, then send.
        let standing = standing(peer)
        guard standing.canSend else {
            if standing.canPair { pair(with: peer, then: urls) } else { browser?.probe(peer.id, fresh: true); explain(peer, standing) }
            return
        }
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
        let session = SendSession(urls: urls, host: host, port: port, peerName: displayName(peer),
                                  identity: identity, trust: trust, expect: peer.key, streams: Settings.streams, prescanned: scanned)
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

    // MARK: Pairing

    private func explain(_ peer: Peer, _ standing: PeerStanding) {
        let alert = NSAlert()
        alert.messageText = "Cannot send to \(peer.name)"
        switch standing {
        case .needsUpdate: alert.informativeText = "It runs a version of Nimbus Drop from before drops were encrypted. Update Nimbus Drop there."
        case .checking: alert.informativeText = "This Mac is still finding out who that is. Try again in a moment."
        case .unproved: alert.informativeText = "The Mac at \(peer.address ?? "that address") did not answer when asked to prove who it is. Check that Nimbus Drop 0.3 or later is running there with receiving on."
        case .refused(let why): alert.informativeText = "\(why). It cannot be used. If that Mac has a new identity by now, its tile will change in a moment and you can pair with it again."
        default: alert.informativeText = "It is not paired with this Mac."
        }
        NSApp.activate(ignoringOtherApps: true)
        alert.runModal()
    }

    /// Starts a pairing with a destination, as the person asked by dropping files on it or from
    /// its menu. `then`: what to send once it is made. When the Mac's name is that of one this
    /// Mac already knows under another key, the person is stopped and asked what it is first.
    func pair(with peer: Peer, then urls: [URL] = [], byNumber: Bool = false) {
        guard live, let address = peer.address, let key = peer.key else { return }
        var replacing: PublicKey?
        if case .nameInUse(let clash) = standing(peer) {
            let alert = NSAlert()
            alert.alertStyle = .critical
            alert.messageText = "This is not the \(clash.name) you paired with"
            alert.informativeText = "The Mac at \(address) calls itself \(peer.name) but has a different identity from the one you paired with\(clash.pairedAt.map { " on \($0.formatted(date: .abbreviated, time: .omitted))" } ?? ""). Nothing was sent.\n\nIt may be a Mac that was erased or replaced, another Mac with the same name, or someone pretending. Ask the person there before going on."
            alert.addButton(withTitle: "Cancel")
            alert.addButton(withTitle: "It Replaces \(clash.name)…")
            alert.addButton(withTitle: "It Is Another Mac…")
            NSApp.activate(ignoringOtherApps: true)
            switch alert.runModal() {
            case .alertSecondButtonReturn: replacing = clash.key
            case .alertThirdButtonReturn: break
            default: return
            }
            trust.noteImpostor(of: clash.key, at: address)
        } else if case .renew = standing(peer), let clash = trust.nameClash(peer.name, key: key), clash.expected {
            // The key it had ran out, as scheduled: the new one takes its place.
            replacing = clash.key
        }
        let title = urls.isEmpty ? nil : (urls.count == 1 ? urls[0].lastPathComponent : "\(urls.count) items")
        let session = PairingSession(host: address, port: peer.port ?? defaultPort, peerName: peer.name, identity: identity, trust: trust,
                                     expect: key, replacing: replacing, byNumber: byNumber)
        present(session, pending: title) { [weak self] send in
            guard let self, send, !urls.isEmpty else { return }
            self.send(urls, to: peer)
        }
    }

    /// A drop stopped at the handshake because the other Mac no longer has this one paired
    /// (it chose Forget, or its half of a pairing never arrived). Rather than leave a failed
    /// row whose Retry leads to the same place, ask now: pair again, then send what was being
    /// sent. Asked only when the Mac can be paired with; a key that was given up or has run
    /// out cannot, and its row says why.
    private func offerToPairAgain(_ id: UUID) {
        guard live, let again = sends[id] else { return }
        let peer = destinations.first { $0.id == again.peer.id } ?? again.peer
        guard standing(peer).canPair else { return }
        let alert = NSAlert()
        alert.messageText = "\(displayName(peer)) no longer has this Mac paired"
        alert.informativeText = "Nothing was sent. Someone there chose to forget this Mac, or the last pairing did not finish. Pair again now, with the person there, and the drop is sent as soon as you have."
        alert.addButton(withTitle: "Pair Again and Send…")
        alert.addButton(withTitle: "Not Now")
        NSApp.activate(ignoringOtherApps: true)
        guard alert.runModal() == .alertFirstButtonReturn else { return }
        transfers.removeAll { $0.id == id }
        meters[id] = nil
        sends[id] = nil
        refresh()
        pair(with: peer, then: again.urls)
    }

    /// Another Mac asks to pair, and its request has reached the front of the queue.
    private func pairRequested(_ session: PairingSession) {
        NSSound(named: "Glass")?.play()
        present(session, pending: nil) { _ in }
    }

    private func present(_ session: PairingSession, pending: String?, done: @escaping (Bool) -> Void) {
        let id = session.id
        let panel = PairingPanel(session: session, pending: pending, myNumber: trust.publicKey.identityNumber) { [weak self] _, send in
            self?.pairings[id] = nil
            done(send)
        }
        pairings[id] = panel
        panel.show()
    }

    /// A retired identity was used. Said in a notification, not a window that takes the keyboard;
    /// the engine has already rationed how often.
    private func refusedIdentity(name: String, address: String) {
        let content = UNMutableNotificationContent()
        content.title = "A retired identity of \(name) was used"
        content.body = "The Mac at \(address) proved an identity that was given up or replaced. Someone may hold a copy of it. Nothing was sent or received. (The name is what this Mac called it; the address is all that is known of the caller.)"
        UNUserNotificationCenter.current().add(UNNotificationRequest(identifier: UUID().uuidString, content: content, trigger: nil))
    }

    private func trustChanged() {
        trustChanges += 1
        onChange?()
        warnIfUnsaved()
        // A key was paired, forgotten, retired or ran out: what each tile shows may be a key
        // its Mac no longer has. A Mac that retires a key says so just before it has the new
        // one, hence the second look.
        browser?.probeAll()
        DispatchQueue.main.asyncAfter(deadline: .now() + 2) { [weak self] in self?.browser?.probeAll() }
    }

    private var warnedUnsaved = false

    /// A change to who is trusted is in force but could not be written (a full disk): said
    /// once, because quitting now would undo it, and a Forget undone is a Mac trusted again.
    private func warnIfUnsaved() {
        guard trust.unsaved else { warnedUnsaved = false; return }
        guard !warnedUnsaved else { return }
        warnedUnsaved = true
        let alert = NSAlert()
        alert.alertStyle = .critical
        alert.messageText = "A change to this Mac's trusted Macs could not be saved"
        alert.informativeText = "The change is in force now, but it is not on the disk (the disk may be full). If Nimbus Drop quits before it is saved, the change is undone: a Mac you forgot, or an identity that was retired or replaced, would be trusted again.\n\nNimbus Drop keeps trying. Free some space and leave it running; Internals shows when it has been written."
        alert.addButton(withTitle: "OK")
        NSApp.activate(ignoringOtherApps: true)
        alert.runModal()
    }

    // MARK: Known Macs and this Mac's identity

    func forget(_ mac: KnownMac) {
        let alert = NSAlert()
        alert.messageText = "Forget \(mac.name)?"
        alert.informativeText = "Drops to and from it stop until the two of you pair again. Anything it is sending or receiving now is ended."
        alert.addButton(withTitle: "Forget")
        alert.addButton(withTitle: "Cancel")
        guard alert.runModal() == .alertFirstButtonReturn else { return }
        let trust = trust
        DispatchQueue.global().async { trust.forget(mac.key) }
    }

    func rename(_ mac: KnownMac) {
        let alert = NSAlert()
        alert.messageText = "What do you call \(mac.name)?"
        alert.informativeText = "This is the name shown on this Mac, whatever that Mac calls itself."
        let field = NSTextField(frame: NSRect(x: 0, y: 0, width: 260, height: 24))
        field.stringValue = mac.name
        alert.accessoryView = field
        alert.addButton(withTitle: "Rename")
        alert.addButton(withTitle: "Cancel")
        alert.window.initialFirstResponder = field
        guard alert.runModal() == .alertFirstButtonReturn, !field.stringValue.trimmingCharacters(in: .whitespaces).isEmpty else { return }
        trust.rename(mac.key, to: field.stringValue)
    }

    func setKeyLifetime(_ seconds: Double) {
        let trust = trust
        DispatchQueue.global().async { trust.setLifetime(seconds) }
    }

    func setRequestsOff(_ off: Bool) { trust.requestsOff = off }

    func showIdentityNumber() {
        let number = PublicKey.grouped(trust.publicKey.identityNumber)
        let alert = NSAlert()
        alert.messageText = "This Mac's identity number"
        alert.informativeText = "\(number)\n\nGive it to someone who wants to check this Mac; it is safe to send in a message. They enter it on their Mac, which does the comparing. It is good until \(trust.ends.formatted(date: .abbreviated, time: .omitted)), when this Mac's key is replaced."
        alert.addButton(withTitle: "Copy")
        alert.addButton(withTitle: "Done")
        if alert.runModal() == .alertFirstButtonReturn {
            NSPasteboard.general.clearContents()
            NSPasteboard.general.setString(number, forType: .string)
        }
    }

    /// Reset Identity: for when this Mac's key may have been copied. Tells every paired Mac that
    /// can be reached to stop trusting the old key, then makes a new one.
    func resetIdentity() {
        let count = trust.known.count
        let alert = NSAlert()
        alert.alertStyle = .critical
        alert.messageText = "Reset This Mac's Identity?"
        alert.informativeText = "Do this if you think this Mac's identity was copied. "
            + (count == 0 ? "This Mac is paired with no other." : "The \(count) \(count == 1 ? "Mac" : "Macs") you are paired with will be told to stop trusting the old identity, and you will need to pair with \(count == 1 ? "it" : "each of them") again.")
            + " This cannot be undone."
        alert.addButton(withTitle: "Cancel")
        alert.addButton(withTitle: "Reset and Unpair Everything")
        guard alert.runModal() == .alertSecondButtonReturn else { return }
        var places: [PublicKey: (String, UInt16)] = [:]
        for p in destinations { if let key = p.key, let a = p.address, let port = p.port { places[key] = (a, port) } }
        let reach = places
        let trust = trust, identity = identity
        resetting = true
        DispatchQueue.global().async {
            trust.reset(identity: identity, reach: { reach[$0].map { (host: $0.0, port: $0.1) } })
            DispatchQueue.main.async { MainActor.assumeIsolated { self.resetting = false; self.browser?.probeAll() } }
        }
    }

    /// The stored identity is there and will not open. It is never replaced without asking,
    /// because the record of retired identities would go with it.
    private func askAboutDamagedIdentity() {
        let alert = NSAlert()
        alert.alertStyle = .critical
        alert.messageText = "This Mac's identity cannot be read"
        alert.informativeText = "The file that holds this Mac's identity and the Macs it is paired with is damaged. It has not been changed.\n\nYou can start afresh with a new identity. Every Mac will need pairing again, and the record of identities that were retired or have run out is lost with the old file, which is kept beside the new one."
        alert.addButton(withTitle: "Quit")
        alert.addButton(withTitle: "Start Afresh")
        NSApp.activate(ignoringOtherApps: true)
        guard alert.runModal() == .alertSecondButtonReturn else { NSApp.terminate(nil); return }
        guard let fresh = try? Trust.startFresh(storage: EnclaveStorage.standard(bundleID: Settings.bundleID)) else { return }
        trust = fresh
        trustProblem = nil
        fresh.onChange = { [weak self] in DispatchQueue.main.async { MainActor.assumeIsolated { self?.trustChanged() } } }
        applyReceiving()
        trustChanged()
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
        let identity = identity, trust = trust
        DispatchQueue.global(qos: .utility).async {
            let answers = entries.map { entry -> Peer in
                let (host, port) = Self.parse(entry)
                guard var peer = try? Probe.hello(host: host, port: port, identity: identity, trust: trust, timeout: 2) else { return Self.placeholder(entry) }
                peer.id = "manual:" + entry
                peer.isManual = true
                if peer.key == trust.publicKey { peer.name += " (this Mac)" }
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

    func setLocalOnly(_ on: Bool) {
        Settings.localOnly = on
        localOnly = on
        listener?.localOnly = on
        DropLog.write(on ? "now receiving from the local network only" : "now receiving from any address")
    }

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
            if t.needsPairing, sends[t.id] != nil {
                let id = t.id
                DispatchQueue.main.async { [weak self] in self?.offerToPairAgain(id) }
            }
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
        entry.retransmittedChunks = stats.retransmittedChunks
        entry.skippedLinks = stats.skippedLinks
        historyStore?.add(entry)
        history = historyStore?.entries ?? []
    }

    // MARK: Internals

    /// Staged text for `--dump-internals`.
    var demoInternals: String?

    /// The live status at the top of the Internals panel: this Mac, who it can see, and every
    /// drop with each of its connections. Plain text, so it copies into a bug report as it is.
    func internalsStatus() -> String {
        if let demoInternals { return demoInternals }
        let now = Date()
        var out: [String] = []
        func line(_ label: String, _ text: String) { out.append(label.padding(toLength: 13, withPad: " ", startingAt: 0) + text) }
        line("This Mac", "\(identity.name) · \(addresses.isEmpty ? "no network" : addresses.map { "\($0.address) (\($0.interface))" }.joined(separator: ", ")) · Nimbus Drop \(identity.appVersion) · protocol \(protocolVersionText)")
        line("Identity", "key \(trust.publicKey.tag) · made \(trust.made.formatted(date: .abbreviated, time: .shortened)) · good until \(trust.ends.formatted(date: .abbreviated, time: .shortened)) (keys last \(Format.lifetime(trust.lifetime)))"
             + (trustProblem.map { " · PROBLEM: \($0)" } ?? ""))
        line("Known Macs", trust.known.isEmpty ? "none" : trust.known.map { "\($0.name) [\($0.key.tag)] until \($0.endsWall.formatted(date: .abbreviated, time: .omitted))\($0.impostors > 0 ? ", name used by another key \($0.impostors)×" : "")" }.joined(separator: "; "))
        if !trust.again.isEmpty { line("Pair again", trust.again.filter { !$0.pairedAgain }.map { "\($0.name) [\($0.key.tag)]\($0.told.map { $0 ? " told" : " NOT REACHED" } ?? "")" }.joined(separator: "; ")) }
        line("Receiving", (receiving ? "on" + (listener.map { ", port \($0.port), \(localOnly ? "local network only" : "from any address")" } ?? ", NOT LISTENING") : "off")
             + " · open at login: \(LoginItem.statusDescription)" + (problem.map { " · PROBLEM: \($0)" } ?? ""))
        line("Discovery", "\(browser?.problem.map { "PROBLEM: \($0)" } ?? "browsing") · \(destinations.count) \(destinations.count == 1 ? "destination" : "destinations")")
        for p in destinations {
            line("", p.name.padding(toLength: 22, withPad: " ", startingAt: 0) + " "
                 + ("\(p.address ?? "address not known")\(p.port.map { ":\($0)" } ?? "")").padding(toLength: 22, withPad: " ", startingAt: 0)
                 + " protocol \(p.protocolText) · \(p.key?.tag ?? "no key proved") · \(standing(p).badge?.text ?? "checking")"
                 + (p.isManual ? " · added by address\(p.unreachable ? ", not answering" : "")" : "") + (p.isCompatible ? "" : " · INCOMPATIBLE"))
        }
        out.append("")
        let moving = transfers.filter { !$0.state.isFinal }.count
        line("Drops", transfers.isEmpty ? "none (finished drops are in History)" : "\(moving) moving, \(transfers.count - moving) ended in the last minute")
        for t in transfers {
            let p = t.progress, s = t.stats
            let since = Format.duration(now.timeIntervalSince(t.transferStartedAt ?? t.startedAt))
            line(String(t.id.uuidString.prefix(6)) + (t.direction == .send ? " send" : " recv"),
                 "“\(t.title)” \(t.direction == .send ? "→" : "←") \(t.peerName) (\(t.peerAddress))   \(t.state) for \(since)")
            let rate = meters[t.id]?.current ?? 0
            line("", "\(Format.bytes(p.doneBytes)) of \(Format.bytes(p.totalBytes)) (\(Int(p.fraction * 100)) %) · \(Format.bitRate(rate)) · \(Format.files(p.totalFiles)), \(p.doneFiles) done"
                 + (p.resumedBytes > 0 ? " · \(Format.bytes(p.resumedBytes)) were already there" : ""))
            line("", "round \(max(1, s.rounds)) · \(s.chunks) chunks \(t.direction == .send ? "sent" : "received"), \(s.retransmittedChunks) retransmitted"
                 + " · \(s.connectionFailures) connections dropped · \(s.damagedChunks) damaged chunks · \(s.reconnects) reconnects in \(s.reconnectAttempts) attempts")
            let connections = t.dataConnections
            for (i, c) in connections.enumerated() {
                let idle = now.timeIntervalSince(c.lastActivity)
                line(i == 0 ? "" : "", (i == 0 ? "connections  " : "             ") + "#\(c.id)".padding(toLength: 5, withPad: " ", startingAt: 0)
                     + c.remote.padding(toLength: 18, withPad: " ", startingAt: 0)
                     + "\(c.chunks) chunks".padding(toLength: 14, withPad: " ", startingAt: 0)
                     + Format.bytes(c.bytes).padding(toLength: 10, withPad: " ", startingAt: 0)
                     + (idle < 1 ? "active now" : "idle \(String(format: "%.0f", idle)) s"))
            }
            if connections.isEmpty, !t.state.isFinal { line("", "connections  none open") }
        }
        return out.joined(separator: "\n")
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
            if let trouble = Self.troubleText(t.stats) { status += "\n" + trouble }
        case .reconnecting:
            status = t.direction == .send ? "Lost the connection to \(t.peerName); trying to get it back…"
                                          : "Lost the connection to \(t.peerName); waiting for it to come back…"
            status += "\n\(Format.bytes(p.doneBytes)) of \(Format.bytes(p.totalBytes)) so far"
            indeterminate = true
        case .finishing: status = "Finishing…"; indeterminate = true
        case .completed:
            let seconds = max(0.001, (t.finishedAt ?? now).timeIntervalSince(t.transferStartedAt ?? t.startedAt))
            let moved = p.totalBytes - p.resumedBytes
            status = "\(Format.files(p.totalFiles)), \(Format.bytes(p.totalBytes)) in \(Format.lifetime(seconds)) · \(Format.bitRate(Double(moved) / seconds))"
            if p.resumedBytes > 0 { status += " · continued from \(Format.bytes(p.resumedBytes))" }
            if let trouble = Self.troubleText(t.stats) { status += "\n" + trouble }
            if let links = Self.linksText(t.stats) { status += "\n" + links }
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

    /// What the drop got past, as what it cost: the chunks that went a second time. How many
    /// connections were dropped along the way is in Internals and the log, not here (the owner:
    /// "I don't think there's much value in showing the number of connections that were
    /// dropped"). Nil when there is nothing to say.
    static func troubleText(_ s: TransferStats) -> String? {
        var parts: [String] = []
        if s.reconnects > 0 { parts.append("reconnected \(s.reconnects == 1 ? "once" : "\(s.reconnects) times")") }
        if s.damagedChunks > 0 { parts.append("\(s.damagedChunks) damaged \(s.damagedChunks == 1 ? "chunk" : "chunks") caught") }
        if s.retransmittedChunks > 0 { parts.append("\(s.retransmittedChunks) \(s.retransmittedChunks == 1 ? "chunk" : "chunks") retransmitted") }
        return parts.isEmpty ? nil : "Recovered: " + parts.joined(separator: ", ")
    }

    /// "2 links that pointed outside the drop were left out", when any were.
    static func linksText(_ s: TransferStats) -> String? {
        guard s.skippedLinks > 0 else { return nil }
        return s.skippedLinks == 1 ? "1 link that pointed outside the drop was left out"
                                   : "\(s.skippedLinks) links that pointed outside the drop were left out"
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

    /// The last figure worked out, for anything else that wants to show it.
    private(set) var current: Double = 0

    func rate(bytes: Int64, now: Date) -> Double {
        samples.append((now, bytes))
        samples.removeAll { now.timeIntervalSince($0.time) > 4 }
        guard let first = samples.first, now.timeIntervalSince(first.time) >= 0.5 else { return 0 }
        current = Double(bytes - first.bytes) / now.timeIntervalSince(first.time)
        return current
    }
}
