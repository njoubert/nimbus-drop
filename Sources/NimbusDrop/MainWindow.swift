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
                let usable = model.destinations.filter(\.isCompatible)
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
            Divider()
            footer
        }
        .frame(minWidth: 500, idealWidth: 560, minHeight: 360, idealHeight: 470)
        .tint(Palette.send)
    }

    private var header: some View {
        HStack(spacing: 12) {
            Image(systemName: "laptopcomputer")
                .font(.system(size: 26)).foregroundStyle(.secondary).frame(width: 40)
            VStack(alignment: .leading, spacing: 2) {
                Text(model.identity.name).font(.headline)
                Text(model.addresses.isEmpty ? "No network" : model.addresses.map(\.address).joined(separator: "  ·  "))
                    .font(.system(.subheadline, design: .monospaced)).foregroundStyle(.secondary)
                    .textSelection(.enabled)
            }
            Spacer()
            VStack(alignment: .trailing, spacing: 2) {
                Toggle("Receive drops", isOn: Binding(get: { model.receiving }, set: { model.setReceiving($0) }))
                    .toggleStyle(.switch).tint(Palette.receive)
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
                Text("Destinations on this LAN").font(.title3.weight(.semibold))
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
                    Text("Open Nimbus Drop on the other Mac, on the same network, with Receive drops on.\nIf it does not appear, add it by its IP address.")
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
    private var onlyOne: Bool { model.destinations.filter(\.isCompatible).count == 1 }

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

    private var footer: some View {
        HStack(spacing: 14) {
            Picker("Connections", selection: Binding(get: { model.streams }, set: { model.setStreams($0) })) {
                ForEach(Settings.streamChoices, id: \.self) { Text("\($0)").tag($0) }
            }
            .fixedSize()
            .help("How many parallel connections a drop you send is spread over. More helps on fast wired networks and with many small files.")
            Toggle("Open at login", isOn: Binding(get: { model.openAtLogin }, set: { model.setOpenAtLogin($0) }))
                .disabled(Bundle.main.bundleIdentifier == nil)
            Spacer()
            if let version = model.updateReady {
                Button("Install Update \(version)") { model.installUpdate?() }.controlSize(.small)
            }
            Text(StatusBarController.versionString())
                .font(.caption).foregroundStyle(.tertiary).textSelection(.enabled)
        }
        .controlSize(.small)
        .padding(.horizontal, 20).padding(.vertical, 9)
    }
}

private struct HeightKey: PreferenceKey {
    static let defaultValue: CGFloat = 0
    static func reduce(value: inout CGFloat, nextValue: () -> CGFloat) { value = max(value, nextValue()) }
}

/// One destination. A drop target, and a button for people who would rather pick files from a panel.
private struct PeerTile: View {
    let peer: Peer
    let model: AppModel
    /// Files are being dragged over the window and this is the only place they could go.
    var hint = false
    @State private var targeted = false
    @State private var hovered = false

    private var lit: Bool { (targeted || hint) && peer.isCompatible }

    private var caption: String {
        if !peer.isCompatible { return "Needs an update: speaks protocol \(peer.protocolText), this Mac \(protocolVersionText)" }
        if peer.isManual && peer.unreachable { return "Not answering" }
        if lit { return "Release to send" }
        return peer.isManual ? "Added by address · drop files here" : "Drop files here"
    }

    var body: some View {
        Button {
            if model.pendingURLs.isEmpty { model.chooseAndSend(to: peer) } else { model.send(model.pendingURLs, to: peer) }
        } label: {
            VStack(spacing: 6) {
                Image(systemName: lit ? "arrow.down.circle.fill" : (peer.isManual && peer.unreachable ? "questionmark.circle" : "laptopcomputer"))
                    .font(.system(size: 34)).foregroundStyle(lit ? AnyShapeStyle(.tint) : AnyShapeStyle(.primary))
                    .frame(height: 40)
                Text(peer.name).font(.headline).lineLimit(1).truncationMode(.middle)
                Text((peer.address ?? "finding address…") + (peer.isManual && peer.port != defaultPort ? ":\(peer.port ?? 0)" : ""))
                    .font(.system(.caption, design: .monospaced)).foregroundStyle(.secondary)
                Text(caption)
                    .font(.caption2).multilineTextAlignment(.center)
                    .foregroundStyle(lit ? AnyShapeStyle(.tint) : (peer.isCompatible ? AnyShapeStyle(.tertiary) : AnyShapeStyle(Palette.warning)))
            }
            .frame(maxWidth: .infinity).padding(.vertical, 16).padding(.horizontal, 8)
            .background(RoundedRectangle(cornerRadius: 12).fill(lit ? AnyShapeStyle(.tint.opacity(0.14)) : AnyShapeStyle(.quaternary.opacity(hovered ? 0.9 : 0.5))))
            .overlay(RoundedRectangle(cornerRadius: 12).strokeBorder(lit ? AnyShapeStyle(.tint) : AnyShapeStyle(.clear), lineWidth: 2))
            .contentShape(RoundedRectangle(cornerRadius: 12))
            .opacity(peer.isCompatible && !(peer.isManual && peer.unreachable) ? 1 : 0.6)
        }
        .buttonStyle(.plain)
        .disabled(!peer.isCompatible)
        .overlay(alignment: .topTrailing) {
            if peer.isManual, hovered {
                Button { model.removeManual(peer) } label: { Image(systemName: "xmark.circle.fill") }
                    .buttonStyle(.plain).foregroundStyle(.secondary).padding(6).help("Remove this address")
            }
        }
        .onHover { hovered = $0 }
        .dropDestination(for: URL.self) { urls, _ in
            let files = urls.filter(\.isFileURL)
            guard !files.isEmpty, peer.isCompatible else { return false }
            model.send(files, to: peer)
            return true
        } isTargeted: { targeted = $0 }
        .help(peer.isCompatible
              ? "Drag files or folders here to send them to \(peer.name)\(peer.appVersion.map { " (Nimbus Drop \($0))" } ?? ""), or click to choose them."
              : "\(peer.name) runs Nimbus Drop \(peer.appVersion ?? "of another version"), which speaks protocol \(peer.protocolText). This Mac speaks \(protocolVersionText). Update Nimbus Drop on both.")
    }
}

/// One destination as a line in the compact list: the same drop target and button as a tile.
private struct PeerRow: View {
    let peer: Peer
    let model: AppModel
    var hint = false
    @State private var targeted = false
    @State private var hovered = false

    private var lit: Bool { (targeted || hint) && peer.isCompatible }
    private var silent: Bool { peer.isManual && peer.unreachable }

    private var note: String {
        if !peer.isCompatible { return "Needs an update (protocol \(peer.protocolText))" }
        if silent { return "Not answering" }
        if lit { return "Release to send" }
        return peer.isManual ? "Added by address" : ""
    }

    var body: some View {
        Button {
            if model.pendingURLs.isEmpty { model.chooseAndSend(to: peer) } else { model.send(model.pendingURLs, to: peer) }
        } label: {
            HStack(spacing: 10) {
                Image(systemName: lit ? "arrow.down.circle.fill" : (silent ? "questionmark.circle" : "laptopcomputer"))
                    .foregroundStyle(lit ? AnyShapeStyle(.tint) : AnyShapeStyle(.secondary)).frame(width: 20)
                Text(peer.name).font(.body.weight(.medium)).lineLimit(1).truncationMode(.middle)
                Text((peer.address ?? "finding address…") + (peer.isManual && peer.port != defaultPort ? ":\(peer.port ?? 0)" : ""))
                    .font(.system(.callout, design: .monospaced)).foregroundStyle(.secondary).lineLimit(1)
                Spacer(minLength: 8)
                Text(note).font(.caption).lineLimit(1)
                    .foregroundStyle(lit ? AnyShapeStyle(.tint) : (peer.isCompatible ? AnyShapeStyle(.tertiary) : AnyShapeStyle(Palette.warning)))
                if peer.isManual, hovered {
                    Button { model.removeManual(peer) } label: { Image(systemName: "xmark.circle.fill") }
                        .buttonStyle(.plain).foregroundStyle(.secondary).help("Remove this address")
                }
            }
            .padding(.horizontal, 12).padding(.vertical, 7)
            .background(lit ? AnyShapeStyle(.tint.opacity(0.16)) : AnyShapeStyle(.quaternary.opacity(hovered ? 0.6 : 0)))
            .contentShape(Rectangle())
            .opacity(peer.isCompatible && !silent ? 1 : 0.6)
        }
        .buttonStyle(.plain)
        .disabled(!peer.isCompatible)
        .onHover { hovered = $0 }
        .dropDestination(for: URL.self) { urls, _ in
            let files = urls.filter(\.isFileURL)
            guard !files.isEmpty, peer.isCompatible else { return false }
            model.send(files, to: peer)
            return true
        } isTargeted: { targeted = $0 }
        .help(peer.isCompatible
              ? "Drag files or folders here to send them to \(peer.name), or click to choose them."
              : "\(peer.name) speaks protocol \(peer.protocolText); this Mac speaks \(protocolVersionText). Update Nimbus Drop on both.")
    }
}

private struct DropRow: View {
    let row: TransferRow
    let model: AppModel
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
            if row.canReveal {
                Button { model.reveal(row.id) } label: { Image(systemName: "magnifyingglass.circle.fill") }
                    .buttonStyle(.plain).foregroundStyle(.secondary).help("Show in Finder")
            }
            Button { row.isActive ? model.cancel(row.id) : model.remove(row.id) } label: { Image(systemName: "xmark.circle.fill") }
                .buttonStyle(.plain).foregroundStyle(.secondary).help(row.isActive ? "Stop this drop" : "Remove from the list")
        }
        .font(.system(size: 13))
        .padding(.horizontal, 12).padding(.vertical, 10)
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
        window.setContentSize(NSSize(width: 560, height: 470))
        window.isReleasedWhenClosed = false
        window.setFrameAutosaveName("NimbusDropMain2")
        if window.frame.origin == .zero { window.center() }
        window.delegate = self
    }

    /// On screen and the window being worked in.
    var isFront: Bool { window.isVisible && window.isKeyWindow && NSApp.isActive }

    func show() {
        NSApp.setActivationPolicy(.regular)
        window.makeKeyAndOrderFront(nil)
        NSApp.activate(ignoringOtherApps: true)
    }

    func close() { window.performClose(nil) }

    func windowWillClose(_ notification: Notification) { NSApp.setActivationPolicy(.accessory) }

    // MARK: Layout check

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
        var old = Peer(id: "4", name: "macmini", address: "192.168.1.31", port: 47823, version: 1)
        old.appVersion = "0.1.0"
        let peers = [Peer(id: "1", name: "macbookairm4", address: "192.168.1.52", port: 47823),
                     Peer(id: "2", name: "macstudio", address: "192.168.1.20", port: 47823), old]
        let rows = [
            TransferRow(id: UUID(), direction: .send, peerName: "dads-imac", peerAddress: "192.168.1.77", title: "Christmas 2026",
                        status: "13.1 GB of 31.2 GB · 921 Mbps · 8 connections · 2:37 left", fraction: 0.42, isActive: true, isIndeterminate: false, failed: false, canReveal: false),
            TransferRow(id: UUID(), direction: .send, peerName: "macstudio", peerAddress: "192.168.1.20", title: "render.mov and 2 more",
                        status: "Waiting for macstudio to accept…", fraction: 0, isActive: true, isIndeterminate: true, failed: false, canReveal: false),
            TransferRow(id: UUID(), direction: .receive, peerName: "macbookairm4", peerAddress: "192.168.1.52", title: "Scans",
                        status: "1,204 files, 8.40 GB in 1:13 · 918 Mbps\n1 connection lost, 1 damaged chunk caught; re-sent", fraction: 1, isActive: false, isIndeterminate: false, failed: false, canReveal: true),
            TransferRow(id: UUID(), direction: .send, peerName: "macbookairm4", peerAddress: "192.168.1.52", title: "Backups",
                        status: "macbookairm4 stopped responding; send the drop again to continue it", fraction: 0.2, isActive: false, isIndeterminate: false, failed: true, canReveal: false),
        ]
        let base = path.hasSuffix(".png") ? String(path.dropLast(4)) : path
        var ok = true
        for (suffix, appearance, model) in [
            ("", NSAppearance.Name.darkAqua, AppModel(demoPeers: peers, manual: [added], rows: rows)),
            ("-light", .aqua, AppModel(demoPeers: peers, manual: [added], rows: rows)),
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
