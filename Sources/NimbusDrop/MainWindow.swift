// Copyright (C) 2026 Niels Joubert
// SPDX-License-Identifier: GPL-3.0-or-later
import AppKit
import NimbusDropCore
import SwiftUI

/// The window, which is the whole app: this Mac and its receiving switch at the top, a tile for
/// every destination (drag files onto one to send them), the drops under way or finished, and
/// the few settings at the bottom. The menu bar item only opens it.
struct MainView: View {
    @ObservedObject var model: AppModel
    @State private var address = ""
    @State private var addressError: String?
    @State private var backgroundTargeted = false
    @State private var dropsHeight: CGFloat = 120
    @FocusState private var addressFocused: Bool

    var body: some View {
        VStack(spacing: 0) {
            header
            Divider()
            ScrollView {
                VStack(alignment: .leading, spacing: 20) {
                    // Redrawn when the trust store changes: a tile's badge comes from it.
                    let _ = model.trustChanges
                    if let problem = model.problem {
                        Label(problem, systemImage: "exclamationmark.triangle.fill")
                            .font(.callout).foregroundStyle(Palette.warning)
                    }
                    destinations
                }
                .padding(20)
                .frame(maxWidth: .infinity, alignment: .leading)
            }
            // Files dropped beside the tiles: sent at once when there is only one place they
            // could go, otherwise held until a destination is clicked.
            .dropDestination(for: URL.self) { urls, _ in
                let files = urls.filter(\.isFileURL)
                guard !files.isEmpty else { return false }
                let usable = model.destinations.filter { model.standing($0).canSend || model.standing($0).canPair }
                if usable.count == 1 { model.send(files, to: usable[0]) } else { model.pendingURLs = files }
                return true
            } isTargeted: { backgroundTargeted = $0 }
            // The drops stay put under the destinations, however many of those there are: a
            // transfer's progress must not scroll away. Past a few drops, they scroll on their own.
            if !model.rows.isEmpty {
                Divider()
                ScrollView {
                    drops.padding(.horizontal, 20).padding(.vertical, 12)
                        .background(GeometryReader { g in Color.clear.preference(key: HeightKey.self, value: g.size.height) })
                }
                .onPreferenceChange(HeightKey.self) { dropsHeight = $0 }
                // As tall as its drops, and no taller than about three of them.
                .frame(height: min(max(dropsHeight, 40), 250))
            }
            // The few settings live in the Settings window. All that shows here is an update
            // that is downloaded and waiting.
            if let version = model.updateReady {
                Divider()
                HStack {
                    Text("Nimbus Drop \(version) is ready to install.").font(.callout)
                    Spacer()
                    Button("Install and Relaunch") { model.installUpdate?() }.controlSize(.small)
                }
                .padding(.horizontal, 20).padding(.vertical, 8)
            }
        }
        .frame(minWidth: 500, idealWidth: 560, minHeight: 360, idealHeight: 480)
        .tint(Palette.send)
        .sheet(item: $model.kindQuestion) { KindSheet(question: $0, model: model).tint(Palette.send) }
    }

    private var header: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack {
                Text("This computer").font(.title3.weight(.semibold))
                Spacer()
                Toggle("Receive drops", isOn: Binding(get: { model.receiving }, set: { model.setReceiving($0) }))
                    .toggleStyle(.switch).tint(Palette.receive)
            }
            HStack(spacing: 12) {
                Image(systemName: "laptopcomputer")
                    .font(.system(size: 24)).foregroundStyle(.secondary).frame(width: 36)
                VStack(alignment: .leading, spacing: 2) {
                    Text(model.identity.name).font(.headline)
                    Text(model.addresses.isEmpty ? "No network" : model.addresses.map(\.address).joined(separator: "  ·  "))
                        .font(.system(.subheadline, design: .monospaced)).foregroundStyle(.secondary)
                        .textSelection(.enabled)
                }
                Spacer()
                // Said only when it is off, which is the state that explains a surprise.
                if !model.receiving {
                    Text("Hidden: nobody can send to this Mac").font(.caption).foregroundStyle(.secondary)
                }
            }
        }
        .padding(.horizontal, 20).padding(.vertical, 14)
    }

    private var destinations: some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack {
                Text("Destinations").font(.title3.weight(.semibold))
                Spacer()
                Picker("View", selection: $model.listLayout) {
                    Image(systemName: "square.grid.2x2").tag(false).help("Tiles")
                    Image(systemName: "list.bullet").tag(true).help("List")
                }
                .pickerStyle(.segmented).labelsHidden().fixedSize().controlSize(.small)
                .help("Show destinations as tiles or as a compact list.")
                Button { model.askingForAddress.toggle() } label: { Label("Add by Address…", systemImage: "plus") }
                    .controlSize(.small)
                    .help("Add a Mac by its IP address or host name, for when it is not found on its own.")
            }
            if model.askingForAddress { addressField }
            if let reading = model.scanning {
                HStack(spacing: 8) { ProgressView().controlSize(.small); Text(reading).font(.callout).foregroundStyle(.secondary) }
            }
            if !model.pendingURLs.isEmpty {
                HStack {
                    Text("Click a destination to send \(model.pendingURLs.count == 1 ? "“\(model.pendingURLs[0].lastPathComponent)”" : "\(model.pendingURLs.count) items").")
                        .font(.callout).foregroundStyle(.tint)
                    Button("Never Mind") { model.pendingURLs = [] }.controlSize(.small)
                }
            }
            if model.destinations.isEmpty {
                VStack(spacing: 8) {
                    ProgressView().controlSize(.small)
                    Text("Looking for other Macs…").font(.callout)
                    Text("Open Nimbus Drop on the other Mac, on the same network, with Receive drops on.\nIf it does not appear, add it by its IP address. No internet is needed.")
                        .font(.caption).foregroundStyle(.secondary).multilineTextAlignment(.center)
                }
                .frame(maxWidth: .infinity).padding(.vertical, 34)
                .background(RoundedRectangle(cornerRadius: 12).strokeBorder(.quaternary, style: StrokeStyle(lineWidth: 1.5, dash: [6, 5])))
            } else if model.listLayout {
                VStack(spacing: 0) {
                    ForEach(Array(model.destinations.enumerated()), id: \.element.id) { index, peer in
                        if index > 0 { Divider().padding(.leading, 40) }
                        PeerRow(peer: peer, model: model, hint: backgroundTargeted && onlyOne)
                    }
                }
                .background(RoundedRectangle(cornerRadius: 10).fill(.quaternary.opacity(0.4)))
            } else {
                LazyVGrid(columns: [GridItem(.adaptive(minimum: 150, maximum: 220), spacing: 12)], alignment: .leading, spacing: 12) {
                    ForEach(model.destinations) { PeerTile(peer: $0, model: model, hint: backgroundTargeted && onlyOne) }
                }
            }
        }
    }

    /// Files dragged over the window have exactly one place they could go.
    private var onlyOne: Bool { model.destinations.filter { model.standing($0).canSend || model.standing($0).canPair }.count == 1 }

    private var addressField: some View {
        VStack(alignment: .leading, spacing: 4) {
            HStack {
                TextField("IP address or host name, e.g. 192.168.1.20", text: $address)
                    .textFieldStyle(.roundedBorder)
                    .font(.system(.body, design: .monospaced))
                    .focused($addressFocused)
                    .onSubmit(add)
                Button("Add", action: add).keyboardShortcut(.defaultAction).disabled(address.trimmingCharacters(in: .whitespaces).isEmpty)
                Button("Cancel") { model.askingForAddress = false; address = ""; addressError = nil }
            }
            Text(addressError ?? "The other Mac needs Nimbus Drop running with Receive drops on. Port \(String(defaultPort)) unless you add “:port”.")
                .font(.caption).foregroundStyle(addressError == nil ? AnyShapeStyle(.secondary) : AnyShapeStyle(Palette.failure))
        }
        .onAppear { addressFocused = true }
    }

    private func add() {
        addressError = model.addManual(address)
        if addressError == nil { address = ""; model.askingForAddress = false }
    }

    private var drops: some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack {
                Text("Drops").font(.title3.weight(.semibold))
                Spacer()
                if model.rows.contains(where: { !$0.isActive }) {
                    Button("Clear Finished") { model.clearFinished() }.controlSize(.small)
                }
            }
            VStack(spacing: 0) {
                ForEach(Array(model.rows.enumerated()), id: \.element.id) { index, row in
                    if index > 0 { Divider() }
                    DropRow(row: row, model: model)
                }
            }
            .background(RoundedRectangle(cornerRadius: 10).fill(.quaternary.opacity(0.4)))
        }
    }
}

private struct HeightKey: PreferenceKey {
    static let defaultValue: CGFloat = 0
    static func reduce(value: inout CGFloat, nextValue: () -> CGFloat) { value = max(value, nextValue()) }
}

/// One destination. A drop target, and a button for people who would rather pick files from a panel.
private struct PeerTile: View {
    let peer: Peer
    /// Observed, not just held: the badge comes from the trust store, and a view whose inputs
    /// have not changed is not redrawn because its parent was. A tile stayed "needs pairing"
    /// after a pairing until the pointer crossed it (found by the owner, 2026-11-23).
    @ObservedObject var model: AppModel
    /// Files are being dragged over the window and this is the only place they could go.
    var hint = false
    @State private var targeted = false
    @State private var hovered = false

    private var standing: PeerStanding { model.standing(peer) }
    /// Files can be dropped on it: it is paired, or can be paired first.
    private var usable: Bool { standing.canSend || standing.canPair }
    private var lit: Bool { (targeted || hint) && usable }

    private var caption: String {
        switch standing {
        case .needsUpdate: return "Runs a version from before drops were encrypted"
        case .checking: return "Finding out who this is…"
        case .unproved: return "Could not prove who it is"
        case .refused(let why): return why
        case .new, .renew, .nameInUse: return lit ? "Release to pair, then send" : "Drop files here to pair"
        case .paused: return "Not taking requests just now · click this Mac's tile there"
        case .paired: return lit ? "Release to send" : (peer.isManual ? "Added by address · drop files here" : "Drop files here")
        }
    }

    var body: some View {
        Button {
            if model.pendingURLs.isEmpty { model.chooseAndSend(to: peer) } else { model.send(model.pendingURLs, to: peer) }
        } label: {
            VStack(spacing: 6) {
                Image(systemName: lit ? "arrow.down.circle.fill" : (standing == .unproved ? "questionmark.circle" : "laptopcomputer"))
                    .font(.system(size: 34)).foregroundStyle(lit ? AnyShapeStyle(.tint) : AnyShapeStyle(.primary))
                    .frame(height: 40)
                Text(model.displayName(peer)).font(.headline).lineLimit(1).truncationMode(.middle)
                Text((peer.address ?? "finding address…") + (peer.isManual && peer.port != defaultPort ? ":\(peer.port ?? 0)" : ""))
                    .font(.system(.caption, design: .monospaced)).foregroundStyle(.secondary)
                if model.wasJustPaired(peer) {
                    PairedPulse()
                } else if let badge = standing.badge {
                    Text(badge.text).font(.caption2.weight(.semibold)).foregroundStyle(badge.colour)
                        .padding(.horizontal, 7).padding(.vertical, 2).background(Capsule().fill(badge.colour.opacity(0.16)))
                }
                Text(caption)
                    .font(.caption2).multilineTextAlignment(.center).lineLimit(2)
                    .foregroundStyle(lit ? AnyShapeStyle(.tint) : AnyShapeStyle(.tertiary))
            }
            .frame(maxWidth: .infinity).padding(.vertical, 14).padding(.horizontal, 8)
            .background(RoundedRectangle(cornerRadius: 12).fill(lit ? AnyShapeStyle(.tint.opacity(0.14)) : AnyShapeStyle(.quaternary.opacity(hovered ? 0.9 : 0.5))))
            .overlay(RoundedRectangle(cornerRadius: 12).strokeBorder(lit ? AnyShapeStyle(.tint) : AnyShapeStyle(.clear), lineWidth: 2))
            .contentShape(RoundedRectangle(cornerRadius: 12))
            .opacity(usable ? 1 : 0.6)
        }
        .buttonStyle(.plain)
        .disabled(!usable)
        .contextMenu { PeerMenu(peer: peer, model: model) }
        .overlay(alignment: .topTrailing) {
            if peer.isManual, hovered {
                Button { model.removeManual(peer) } label: { Image(systemName: "xmark.circle.fill") }
                    .buttonStyle(.plain).foregroundStyle(.secondary).padding(6).help("Remove this address")
            }
        }
        .onHover { hovered = $0 }
        .dropDestination(for: URL.self) { urls, _ in
            let files = urls.filter(\.isFileURL)
            guard !files.isEmpty, usable else { return false }
            model.send(files, to: peer)
            return true
        } isTargeted: { targeted = $0 }
        .help(PeerMenu.help(peer, standing, model))
    }
}

/// What a right-click on a destination offers, and the words for hovering over one.
private struct PeerMenu: View {
    let peer: Peer
    let model: AppModel

    var body: some View {
        let standing = model.standing(peer)
        if standing.canPair {
            Button("Pair with Codes…") { model.pair(with: peer) }
            Button("Pair by Identity Number…") { model.pair(with: peer, byNumber: true) }
        }
        if case .paired(let mac) = standing {
            Button("Rename…") { model.rename(mac) }
            Button("Forget \(mac.name)…") { model.forget(mac) }
        }
        if let key = peer.key { Text("Key \(key.tag)") }
    }

    static func help(_ peer: Peer, _ standing: PeerStanding, _ model: AppModel) -> String {
        switch standing {
        case .paired(let mac): return "Drag files or folders here to send them to \(mac.name), or click to choose them. Paired on \(mac.pairedAt.formatted(date: .abbreviated, time: .omitted)); good until \(mac.endsWall.formatted(date: .abbreviated, time: .omitted))."
        case .new: return "\(peer.name) has not been paired with this Mac. Drop files here and the two of you will each read out a code and type the other's."
        case .renew(let name): return "\(name) needs pairing again: a key was replaced (they are, on a schedule), or one of the two Macs chose to forget the other. Drop files here to renew it with two codes."
        case .nameInUse(let clash): return "This Mac calls itself \(peer.name) but is not the \(clash.name) you paired with. It may have been erased or replaced, or be another Mac using the name."
        case .needsUpdate: return "\(peer.name) runs a version of Nimbus Drop from before drops were encrypted (protocol \(peer.protocolText)). Update Nimbus Drop there."
        case .checking: return "Asking the Mac at \(peer.address ?? "this address") to prove who it is."
        case .unproved: return "The Mac at \(peer.address ?? "this address") did not prove who it is."
        case .refused(let why): return why
        case .paused(let until):
            return "\(peer.name) is not showing requests to pair for another \(max(1, Int(until.timeIntervalSinceNow.rounded(.up)))) s: a request to it was refused or abandoned a moment ago, perhaps not yours. Start the pairing from \(peer.name) instead (click this Mac's tile there); its request will be shown here."
        }
    }
}

/// "Pairing successful", pulsing, where a tile's badge is: what a pairing that worked shows
/// in place of a window. It gives way to "✓ Paired" after a few seconds.
struct PairedPulse: View {
    @State private var bright = false
    var body: some View {
        Text("✓ Pairing successful").font(.caption2.weight(.bold)).foregroundStyle(.white).lineLimit(1)
            .padding(.horizontal, 8).padding(.vertical, 3)
            .background(Capsule().fill(Palette.receive.opacity(bright ? 1 : 0.55)))
            .scaleEffect(bright ? 1.08 : 1)
            .shadow(color: Palette.receive.opacity(bright ? 0.7 : 0), radius: 6)
            .onAppear { withAnimation(.easeInOut(duration: 0.6).repeatForever(autoreverses: true)) { bright = true } }
    }
}

/// "Which kinds of file do you want to send?" Everything is ticked to begin with, so Return
/// sends it all; untick to narrow it. Shown only for a drop that holds more than one kind.
private struct KindSheet: View {
    let question: KindQuestion
    let model: AppModel
    @State private var chosen: Set<String>

    init(question: KindQuestion, model: AppModel) {
        self.question = question
        self.model = model
        _chosen = State(initialValue: Set(question.kinds.map(\.id)))
    }

    private var all: Bool { chosen.count == question.kinds.count }
    private var files: Int { question.kinds.filter { chosen.contains($0.id) }.reduce(0) { $0 + $1.files } }
    private var bytes: Int64 { question.kinds.filter { chosen.contains($0.id) }.reduce(0) { $0 + $1.bytes } }

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("Send “\(question.title)” to \(question.peer.name)").font(.headline)
            Text("It holds \(question.kinds.count) kinds of file. Send everything, or untick what should stay behind.")
                .font(.callout).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
            ScrollView {
                VStack(spacing: 0) {
                    ForEach(Array(question.kinds.enumerated()), id: \.element.id) { index, kind in
                        if index > 0 { Divider() }
                        Toggle(isOn: Binding(get: { chosen.contains(kind.id) },
                                             set: { if $0 { chosen.insert(kind.id) } else { chosen.remove(kind.id) } })) {
                            HStack {
                                VStack(alignment: .leading, spacing: 1) {
                                    Text(kind.label)
                                    if !kind.extensions.isEmpty {
                                        Text(kind.extensions.map { "." + $0 }.joined(separator: "  "))
                                            .font(.system(.caption, design: .monospaced)).foregroundStyle(.secondary)
                                    }
                                }
                                Spacer()
                                Text("\(Format.files(kind.files)) · \(Format.bytes(kind.bytes))")
                                    .font(.callout.monospacedDigit()).foregroundStyle(.secondary)
                            }
                            .padding(.leading, 4)
                        }
                        .toggleStyle(.checkbox)
                        .padding(.horizontal, 10).padding(.vertical, 6)
                    }
                }
            }
            .frame(maxHeight: 260)
            .background(RoundedRectangle(cornerRadius: 8).fill(.quaternary.opacity(0.4)))
            HStack {
                Button(all ? "Untick All" : "Tick All") { chosen = all ? [] : Set(question.kinds.map(\.id)) }
                    .controlSize(.small)
                Spacer()
                Button("Cancel") { model.answer(question, kinds: nil, send: false) }.keyboardShortcut(.cancelAction)
                // Always with what is about to go: the size is the thing being decided.
                Button(all ? "Send All (\(Format.bytes(bytes)))" : "Send \(Format.files(files)) (\(Format.bytes(bytes)))") {
                    model.answer(question, kinds: all ? nil : chosen, send: true)
                }
                .keyboardShortcut(.defaultAction).disabled(chosen.isEmpty)
            }
        }
        .padding(20)
        .frame(width: 460)
    }
}

/// One destination as a line in the compact list: the same drop target and button as a tile.
private struct PeerRow: View {
    let peer: Peer
    /// Observed, not just held: the badge comes from the trust store, and a view whose inputs
    /// have not changed is not redrawn because its parent was. A tile stayed "needs pairing"
    /// after a pairing until the pointer crossed it (found by the owner, 2026-11-23).
    @ObservedObject var model: AppModel
    var hint = false
    @State private var targeted = false
    @State private var hovered = false

    private var standing: PeerStanding { model.standing(peer) }
    private var usable: Bool { standing.canSend || standing.canPair }
    private var lit: Bool { (targeted || hint) && usable }
    private var silent: Bool { standing == .unproved }

    var body: some View {
        Button {
            if model.pendingURLs.isEmpty { model.chooseAndSend(to: peer) } else { model.send(model.pendingURLs, to: peer) }
        } label: {
            HStack(spacing: 10) {
                Image(systemName: lit ? "arrow.down.circle.fill" : (silent ? "questionmark.circle" : "laptopcomputer"))
                    .foregroundStyle(lit ? AnyShapeStyle(.tint) : AnyShapeStyle(.secondary)).frame(width: 20)
                Text(model.displayName(peer)).font(.body.weight(.medium)).lineLimit(1).truncationMode(.middle)
                Text((peer.address ?? "finding address…") + (peer.isManual && peer.port != defaultPort ? ":\(peer.port ?? 0)" : ""))
                    .font(.system(.callout, design: .monospaced)).foregroundStyle(.secondary).lineLimit(1)
                Spacer(minLength: 8)
                if lit {
                    Text(standing.canSend ? "Release to send" : "Release to pair").font(.caption).foregroundStyle(.tint)
                } else if model.wasJustPaired(peer) {
                    PairedPulse()
                } else if let badge = standing.badge {
                    Text(badge.text).font(.caption2.weight(.semibold)).foregroundStyle(badge.colour).lineLimit(1)
                        .padding(.horizontal, 7).padding(.vertical, 2).background(Capsule().fill(badge.colour.opacity(0.16)))
                }
                if peer.isManual, hovered {
                    Button { model.removeManual(peer) } label: { Image(systemName: "xmark.circle.fill") }
                        .buttonStyle(.plain).foregroundStyle(.secondary).help("Remove this address")
                }
            }
            .padding(.horizontal, 12).padding(.vertical, 7)
            .background(lit ? AnyShapeStyle(.tint.opacity(0.16)) : AnyShapeStyle(.quaternary.opacity(hovered ? 0.6 : 0)))
            .contentShape(Rectangle())
            .opacity(usable ? 1 : 0.6)
        }
        .buttonStyle(.plain)
        .disabled(!usable)
        .contextMenu { PeerMenu(peer: peer, model: model) }
        .onHover { hovered = $0 }
        .dropDestination(for: URL.self) { urls, _ in
            let files = urls.filter(\.isFileURL)
            guard !files.isEmpty, usable else { return false }
            model.send(files, to: peer)
            return true
        } isTargeted: { targeted = $0 }
        .help(PeerMenu.help(peer, standing, model))
    }
}

private struct DropRow: View {
    let row: TransferRow
    let model: AppModel
    @State private var hovered = false
    /// Blue going out, green coming in, as in the icon.
    private var colour: Color { row.direction == .send ? Palette.send : Palette.receive }

    var body: some View {
        HStack(spacing: 10) {
            Image(systemName: row.failed ? "exclamationmark.circle.fill" : (row.direction == .send ? "arrow.up.circle.fill" : "arrow.down.circle.fill"))
                .font(.system(size: 22))
                .foregroundStyle(row.failed ? Palette.failure : colour)
                // The glow the icons give their arrows, while the drop is moving.
                .shadow(color: row.isActive && !row.failed ? colour.opacity(0.55) : .clear, radius: 5)
            VStack(alignment: .leading, spacing: 4) {
                HStack(spacing: 4) {
                    Text(row.title).font(.body.weight(.medium)).lineLimit(1).truncationMode(.middle)
                    Text(row.direction == .send ? "to" : "from").foregroundStyle(.secondary)
                    Text(row.peerName).lineLimit(1)
                    Text(row.peerAddress).font(.system(.caption, design: .monospaced)).foregroundStyle(.tertiary).lineLimit(1)
                }
                if row.isActive {
                    Group {
                        if row.isIndeterminate { ProgressView().progressViewStyle(.linear) } else { ProgressView(value: row.fraction) }
                    }
                    .tint(colour)
                }
                Text(row.status).font(.caption.monospacedDigit())
                    .foregroundStyle(row.failed ? AnyShapeStyle(Palette.failure) : AnyShapeStyle(.secondary))
                    .lineLimit(3).fixedSize(horizontal: false, vertical: true)
            }
            Spacer(minLength: 0)
            if row.canRetry {
                Button { model.retry(row.id) } label: { Label("Retry", systemImage: "arrow.clockwise") }
                    .controlSize(.small).help("Send it again to \(row.peerName). It carries on from what already arrived.")
            }
            if row.canReveal {
                Button { model.reveal(row.id) } label: { Image(systemName: "magnifyingglass.circle.fill") }
                    .buttonStyle(.plain).foregroundStyle(.secondary).help("Show in Finder")
            }
            Button { row.isActive ? model.cancel(row.id) : model.remove(row.id) } label: { Image(systemName: "xmark.circle.fill") }
                .buttonStyle(.plain).foregroundStyle(.secondary).help(row.isActive ? "Stop this drop" : "Remove from the list")
        }
        .font(.system(size: 13))
        .padding(.horizontal, 12).padding(.vertical, 10)
        // A received drop: the whole card opens where it was saved, not only the magnifier.
        .background(row.canReveal && hovered ? AnyShapeStyle(.quaternary.opacity(0.6)) : AnyShapeStyle(.clear))
        .contentShape(Rectangle())
        .onHover { hovered = $0 }
        .onTapGesture { if row.canReveal { model.reveal(row.id) } }
        .help(row.canReveal ? "Click to show it in Finder" : "")
    }
}

/// The window itself. While it is open the app has a Dock icon, a menu bar of its own and a
/// place in ⌘-Tab; closing it puts the app back in the menu bar only.
@MainActor
final class MainWindowController: NSObject, NSWindowDelegate {
    private let window: NSWindow

    init(model: AppModel) {
        window = NSWindow(contentViewController: NSHostingController(rootView: MainView(model: model)))
        super.init()
        window.title = "Nimbus Drop"
        window.styleMask = [.titled, .closable, .miniaturizable, .resizable]
        // Room for two rows of destinations with no drops showing; the person's own size and
        // place are remembered from then on.
        window.setContentSize(NSSize(width: 560, height: 480))
        window.isReleasedWhenClosed = false
        window.setFrameAutosaveName("NimbusDropMain4")
        if window.frame.origin == .zero { window.center() }
        window.delegate = self
    }

    /// On screen and the window being worked in.
    var isFront: Bool { window.isVisible && window.isKeyWindow && NSApp.isActive }

    /// Opens the window. `anchor` is the menu bar icon's frame on screen: a window that is not
    /// showing yet opens right beneath it, as something belonging to that icon should, at the
    /// size it was last given. One that is already open is brought forward where it is.
    func show(under anchor: NSRect? = nil) {
        NSApp.setActivationPolicy(.regular)
        if !window.isVisible { place(under: anchor) }
        window.makeKeyAndOrderFront(nil)
        NSApp.activate(ignoringOtherApps: true)
    }

    /// Puts the window beneath the menu bar icon. Right after launch the icon has no place yet
    /// (its frame is still at the origin); then, and whenever the icon cannot be found in a
    /// menu bar, the window goes under the right end of the main screen's menu bar, which is
    /// where the icon is about to be.
    private func place(under anchor: NSRect?) {
        let size = window.frame.size
        if let anchor, anchor.width > 0,
           let screen = NSScreen.screens.first(where: { $0.frame.intersects(anchor) }), anchor.minY > screen.frame.midY {
            let area = screen.visibleFrame
            let x = min(max(anchor.midX - size.width / 2, area.minX + 8), area.maxX - size.width - 8)
            window.setFrameOrigin(NSPoint(x: x, y: max(min(anchor.minY, area.maxY) - 6 - size.height, area.minY)))
        } else if let area = NSScreen.main?.visibleFrame {
            window.setFrameOrigin(NSPoint(x: area.maxX - size.width - 8, y: max(area.maxY - 6 - size.height, area.minY)))
        }
    }

    /// Once the icon has its place, a window that was opened before then moves to it.
    func settle(under anchor: NSRect?) {
        guard window.isVisible else { return }
        place(under: anchor)
    }

    func close() { window.performClose(nil) }

    func windowWillClose(_ notification: Notification) { NSApp.setActivationPolicy(.accessory) }

    // MARK: Layout check

    /// The "which kinds of file?" sheet with a made-up shoot, as a PNG.
    static func dumpKinds(to path: String) -> Bool {
        _ = NSApplication.shared
        let kinds = [FileKind(id: "raw", label: "Canon raw image", extensions: ["cr3"], files: 612, bytes: 21_400_000_000),
                     FileKind(id: "public.jpeg", label: "JPEG image", extensions: ["jpeg", "jpg"], files: 1180, bytes: 9_200_000_000),
                     FileKind(id: "public.mpeg-4", label: "MPEG-4 movie", extensions: ["mp4"], files: 4, bytes: 610_000_000),
                     FileKind(id: "ext:xmp", label: "XMP file", extensions: ["xmp"], files: 612, bytes: 4_100_000),
                     FileKind(id: "none", label: "Files with no extension", extensions: [], files: 3, bytes: 18_000)]
        let q = KindQuestion(urls: [], peer: Peer(id: "1", name: "macbookairm4"), scanned: ScannedDrop(manifest: Manifest(chunkSize: 4096, entries: []), sources: []),
                             kinds: kinds, title: "Christmas 2026")
        let model = AppModel(demoPeers: [], manual: [], rows: [])
        let host = NSHostingView(rootView: KindSheet(question: q, model: model).tint(Palette.send).background(Color(nsColor: .windowBackgroundColor)))
        let window = NSWindow(contentRect: NSRect(origin: .zero, size: host.fittingSize), styleMask: [.titled], backing: .buffered, defer: false)
        window.appearance = NSAppearance(named: .darkAqua)
        window.contentView = host
        host.layoutSubtreeIfNeeded()
        RunLoop.main.run(until: Date().addingTimeInterval(0.3))
        guard let rep = host.bitmapImageRepForCachingDisplay(in: host.bounds) else { return false }
        host.cacheDisplay(in: host.bounds, to: rep)
        do { try rep.representation(using: .png, properties: [:])?.write(to: URL(fileURLWithPath: path)) } catch { return false }
        print("wrote \(path)")
        return true
    }

    /// The window with `count` made-up destinations and one drop, at its default size and at a
    /// wide one: how the grid copes with a busy network.
    private static func dumpCrowd(to path: String, count: Int) -> Bool {
        let kinds = ["macbookpro", "macbookair", "macstudio", "macmini", "imac", "render-node", "edit-bay", "front-desk"]
        let peers = (0..<count).map { i -> Peer in
            Peer(id: "\(i)", name: i % 5 == 4 ? "\(kinds[i % kinds.count])-with-a-long-name-\(i)" : "\(kinds[i % kinds.count])\(i / kinds.count + 1)",
                 address: "192.168.1.\(20 + i * 3)", port: 47823)
        }
        let rows = [TransferRow(id: UUID(), direction: .send, peerName: "macstudio1", peerAddress: "192.168.1.26", title: "Christmas 2026",
                                status: "13.1 GB of 31.2 GB · 921 Mbps · 8 connections · 2:37 left", fraction: 0.42, isActive: true,
                                isIndeterminate: false, failed: false, canReveal: false),
                    TransferRow(id: UUID(), direction: .receive, peerName: "edit-bay1", peerAddress: "192.168.1.38", title: "Scans",
                                status: "1,204 files, 8.40 GB in 1:13 · 918 Mbps", fraction: 1, isActive: false,
                                isIndeterminate: false, failed: false, canReveal: true)]
        let base = path.hasSuffix(".png") ? String(path.dropLast(4)) : path
        var ok = true
        for (suffix, size, list) in [("", NSSize(width: 560, height: 620), false), ("-list", NSSize(width: 560, height: 620), true),
                                     ("-wide", NSSize(width: 1000, height: 700), false)] {
            let model = AppModel(demoPeers: peers, manual: [], rows: rows, listLayout: list)
            for (i, p) in peers.enumerated() {
                // Mostly paired, with a few of the other states among them.
                // swiftlint:disable:next force_try
                model.demoStandings[p.id] = i % 7 == 3 ? .new : (i % 11 == 6 ? .renew(p.name) : .paired(try! model.trust.store(pairing: KeyPair().publicKey, announced: p.name, method: "codes", remaining: 80 * 86400)))
            }
            let host = NSHostingView(rootView: MainView(model: model).background(Color(nsColor: .windowBackgroundColor)))
            let window = NSWindow(contentRect: NSRect(origin: .zero, size: size), styleMask: [.titled], backing: .buffered, defer: false)
            window.appearance = NSAppearance(named: .darkAqua)
            window.contentView = host
            window.setContentSize(size)
            host.layoutSubtreeIfNeeded()
            RunLoop.main.run(until: Date().addingTimeInterval(0.3))
            host.layoutSubtreeIfNeeded()
            guard let rep = host.bitmapImageRepForCachingDisplay(in: host.bounds) else { ok = false; continue }
            host.cacheDisplay(in: host.bounds, to: rep)
            let out = base + suffix + ".png"
            do { try rep.representation(using: .png, properties: [:])?.write(to: URL(fileURLWithPath: out)); print("wrote \(out)") }
            catch { ok = false }
        }
        return ok
    }

    /// The window with made-up Macs and drops, off screen, as PNGs: dark, light, and empty.
    static func dump(to path: String, crowd: Int = 0) -> Bool {
        _ = NSApplication.shared
        if crowd > 0 { return dumpCrowd(to: path, count: crowd) }
        var added = Peer(id: "3", name: "dads-imac", address: "192.168.1.77", port: 47823)
        added.isManual = true
        let old = Peer(id: "4", name: "PHJ-MacBook", address: "192.168.1.148", port: 47823, version: 2)
        let peers = [Peer(id: "1", name: "macbookairm4", address: "192.168.1.52", port: 47823),
                     Peer(id: "2", name: "macstudio", address: "192.168.1.20", port: 47823),
                     Peer(id: "5", name: "macstudio", address: "192.168.1.166", port: 47823),
                     Peer(id: "6", name: "macmini", address: "192.168.1.31", port: 47823), old]
        // The states a destination can be in, with made-up keys.
        func demo(_ model: AppModel) -> AppModel {
            func mac(_ name: String) -> KnownMac {
                // swiftlint:disable:next force_try
                try! model.trust.store(pairing: KeyPair().publicKey, announced: name, method: "codes", remaining: 80 * 86400)
            }
            let studio = mac("macstudio")
            model.demoStandings = ["1": .paired(mac("My MacBook Air")), "2": .paired(studio), "3": .new, "6": .renew("macmini"),
                                   "5": .nameInUse(NameClash(name: "macstudio", key: studio.key, pairedAt: studio.pairedAt, expected: false, paired: true))]
            return model
        }
        let rows = [
            TransferRow(id: UUID(), direction: .send, peerName: "dads-imac", peerAddress: "192.168.1.77", title: "Christmas 2026",
                        status: "13.1 GB of 31.2 GB · 921 Mbps · 8 connections · 2:37 left", fraction: 0.42, isActive: true, isIndeterminate: false, failed: false, canReveal: false),
            TransferRow(id: UUID(), direction: .send, peerName: "macstudio", peerAddress: "192.168.1.20", title: "render.mov and 2 more",
                        status: "Waiting for macstudio to accept…", fraction: 0, isActive: true, isIndeterminate: true, failed: false, canReveal: false),
            TransferRow(id: UUID(), direction: .receive, peerName: "macbookairm4", peerAddress: "192.168.1.52", title: "Scans",
                        status: "1,204 files, 8.40 GB in 1:13 · 918 Mbps\nRecovered: reconnected once, 9 chunks retransmitted", fraction: 1, isActive: false, isIndeterminate: false, failed: false, canReveal: true),
            TransferRow(id: UUID(), direction: .send, peerName: "macbookairm4", peerAddress: "192.168.1.52", title: "Backups",
                        status: "Lost the connection to macbookairm4 and could not get it back; send the drop again to continue it", fraction: 0.2, isActive: false, isIndeterminate: false, failed: true, canReveal: false, canRetry: true),
        ]
        let base = path.hasSuffix(".png") ? String(path.dropLast(4)) : path
        var ok = true
        for (suffix, appearance, model) in [
            ("", NSAppearance.Name.darkAqua, demo(AppModel(demoPeers: peers, manual: [added], rows: rows))),
            ("-light", .aqua, demo(AppModel(demoPeers: peers, manual: [added], rows: rows))),
            ("-empty", .darkAqua, AppModel(demoPeers: [], manual: [], rows: [], receiving: false, askingForAddress: true)),
        ] {
            let host = NSHostingView(rootView: MainView(model: model).background(Color(nsColor: .windowBackgroundColor)))
            let window = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 560, height: 700), styleMask: [.titled], backing: .buffered, defer: false)
            window.appearance = NSAppearance(named: appearance)
            window.contentView = host
            window.setContentSize(NSSize(width: 560, height: 700))
            host.layoutSubtreeIfNeeded()
            RunLoop.main.run(until: Date().addingTimeInterval(0.3))
            host.layoutSubtreeIfNeeded()
            guard let rep = host.bitmapImageRepForCachingDisplay(in: host.bounds) else { ok = false; continue }
            host.cacheDisplay(in: host.bounds, to: rep)
            let out = base + suffix + ".png"
            do { try rep.representation(using: .png, properties: [:])?.write(to: URL(fileURLWithPath: out)); print("wrote \(out)") }
            catch { ok = false }
        }
        return ok
    }
}
