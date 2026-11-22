// Copyright (C) 2026 Niels Joubert
// SPDX-License-Identifier: GPL-3.0-or-later
import AppKit
import NimbusDropCore
import SwiftUI

/// The window: this Mac and its receiving switch at the top, a tile for every Mac found (drag
/// files onto one to send them), and the drops under way or finished.
struct MainView: View {
    @ObservedObject var model: AppModel

    var body: some View {
        VStack(spacing: 0) {
            header
            Divider()
            ScrollView {
                VStack(alignment: .leading, spacing: 20) {
                    if let problem = model.problem {
                        Label(problem, systemImage: "exclamationmark.triangle.fill")
                            .font(.callout).foregroundStyle(.orange)
                    }
                    peers
                    if !model.rows.isEmpty { drops }
                }
                .padding(20)
            }
        }
        .frame(minWidth: 480, idealWidth: 540, minHeight: 420, idealHeight: 560)
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
                    .toggleStyle(.switch)
                Text(model.receiving ? "Other Macs on this network can see this one" : "Hidden: nobody can send to this Mac")
                    .font(.caption).foregroundStyle(.secondary)
            }
        }
        .padding(.horizontal, 20).padding(.vertical, 14)
    }

    private var peers: some View {
        VStack(alignment: .leading, spacing: 10) {
            Text("Nearby Macs").font(.title3.weight(.semibold))
            if !model.pendingURLs.isEmpty {
                Text("Click a Mac to send \(model.pendingURLs.count == 1 ? "“\(model.pendingURLs[0].lastPathComponent)”" : "\(model.pendingURLs.count) items").")
                    .font(.callout).foregroundStyle(.tint)
            }
            if model.peers.isEmpty {
                VStack(spacing: 8) {
                    ProgressView().controlSize(.small)
                    Text("Looking for other Macs…").font(.callout)
                    Text("Open Nimbus Drop on the other Mac, on the same network, with Receive drops on.")
                        .font(.caption).foregroundStyle(.secondary).multilineTextAlignment(.center)
                }
                .frame(maxWidth: .infinity).padding(.vertical, 34)
                .background(RoundedRectangle(cornerRadius: 12).strokeBorder(.quaternary, style: StrokeStyle(lineWidth: 1.5, dash: [6, 5])))
            } else {
                LazyVGrid(columns: [GridItem(.adaptive(minimum: 150, maximum: 220), spacing: 12)], alignment: .leading, spacing: 12) {
                    ForEach(model.peers) { PeerTile(peer: $0, model: model) }
                }
            }
        }
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

/// One Mac. A drop target, and a button for people who would rather pick files from a panel.
private struct PeerTile: View {
    let peer: Peer
    let model: AppModel
    @State private var targeted = false
    @State private var hovered = false

    var body: some View {
        Button {
            if model.pendingURLs.isEmpty { model.chooseAndSend(to: peer) } else { model.send(model.pendingURLs, to: peer) }
        } label: {
            VStack(spacing: 6) {
                Image(systemName: targeted ? "arrow.down.circle.fill" : "laptopcomputer")
                    .font(.system(size: 34)).foregroundStyle(targeted ? AnyShapeStyle(.tint) : AnyShapeStyle(.primary))
                    .frame(height: 40)
                Text(peer.name).font(.headline).lineLimit(1).truncationMode(.middle)
                Text(peer.address ?? "finding address…")
                    .font(.system(.caption, design: .monospaced)).foregroundStyle(.secondary)
                Text(targeted ? "Release to send" : "Drop files here")
                    .font(.caption2).foregroundStyle(targeted ? AnyShapeStyle(.tint) : AnyShapeStyle(.tertiary))
            }
            .frame(maxWidth: .infinity).padding(.vertical, 16).padding(.horizontal, 8)
            .background(RoundedRectangle(cornerRadius: 12).fill(targeted ? AnyShapeStyle(.tint.opacity(0.14)) : AnyShapeStyle(.quaternary.opacity(hovered ? 0.9 : 0.5))))
            .overlay(RoundedRectangle(cornerRadius: 12).strokeBorder(targeted ? AnyShapeStyle(.tint) : AnyShapeStyle(.clear), lineWidth: 2))
            .contentShape(RoundedRectangle(cornerRadius: 12))
        }
        .buttonStyle(.plain)
        .onHover { hovered = $0 }
        .dropDestination(for: URL.self) { urls, _ in
            let files = urls.filter(\.isFileURL)
            guard !files.isEmpty else { return false }
            model.send(files, to: peer)
            return true
        } isTargeted: { targeted = $0 }
        .help("Drag files or folders here to send them to \(peer.name), or click to choose them.")
    }
}

private struct DropRow: View {
    let row: TransferRow
    let model: AppModel

    var body: some View {
        HStack(spacing: 10) {
            Image(systemName: row.failed ? "exclamationmark.circle.fill" : (row.direction == .send ? "arrow.up.circle.fill" : "arrow.down.circle.fill"))
                .font(.system(size: 22))
                .foregroundStyle(row.failed ? AnyShapeStyle(.red) : (row.isActive ? AnyShapeStyle(.tint) : AnyShapeStyle(.green)))
            VStack(alignment: .leading, spacing: 4) {
                HStack(spacing: 4) {
                    Text(row.title).font(.body.weight(.medium)).lineLimit(1).truncationMode(.middle)
                    Text(row.direction == .send ? "to" : "from").foregroundStyle(.secondary)
                    Text(row.peerName).lineLimit(1)
                    Text(row.peerAddress).font(.system(.caption, design: .monospaced)).foregroundStyle(.tertiary).lineLimit(1)
                }
                if row.isActive {
                    if row.isIndeterminate { ProgressView().progressViewStyle(.linear) } else { ProgressView(value: row.fraction) }
                }
                Text(row.status).font(.caption.monospacedDigit())
                    .foregroundStyle(row.failed ? AnyShapeStyle(.red) : AnyShapeStyle(.secondary))
                    .lineLimit(2).fixedSize(horizontal: false, vertical: true)
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

/// The window itself. While it is open the app has a Dock icon and a place in ⌘-Tab; closing
/// it puts the app back in the menu bar only.
@MainActor
final class MainWindowController: NSObject, NSWindowDelegate {
    private let window: NSWindow

    init(model: AppModel) {
        window = NSWindow(contentViewController: NSHostingController(rootView: MainView(model: model)))
        super.init()
        window.title = "Nimbus Drop"
        window.styleMask = [.titled, .closable, .miniaturizable, .resizable]
        window.setContentSize(NSSize(width: 540, height: 560))
        window.isReleasedWhenClosed = false
        window.setFrameAutosaveName("NimbusDropMain")
        if window.frame.origin == .zero { window.center() }
        window.delegate = self
    }

    func show() {
        NSApp.setActivationPolicy(.regular)
        window.makeKeyAndOrderFront(nil)
        NSApp.activate(ignoringOtherApps: true)
    }

    func windowWillClose(_ notification: Notification) { NSApp.setActivationPolicy(.accessory) }

    // MARK: Layout check

    /// The window with made-up Macs and drops, off screen, as PNGs: dark, light, and empty.
    static func dump(to path: String) -> Bool {
        _ = NSApplication.shared
        let peers = [Peer(id: "1", name: "macbookairm4", address: "192.168.1.52", port: 47823),
                     Peer(id: "2", name: "macstudio", address: "192.168.1.20", port: 47823),
                     Peer(id: "3", name: "dads-imac", address: "192.168.1.77", port: 47823)]
        let rows = [
            TransferRow(id: UUID(), direction: .send, peerName: "dads-imac", peerAddress: "192.168.1.77", title: "Christmas 2026",
                        status: "13.1 GB of 31.2 GB · 108 MB/s · 2:47 left", fraction: 0.42, isActive: true, isIndeterminate: false, failed: false, canReveal: false),
            TransferRow(id: UUID(), direction: .send, peerName: "macstudio", peerAddress: "192.168.1.20", title: "render.mov and 2 more",
                        status: "Waiting for macstudio to accept…", fraction: 0, isActive: true, isIndeterminate: true, failed: false, canReveal: false),
            TransferRow(id: UUID(), direction: .receive, peerName: "macbookairm4", peerAddress: "192.168.1.52", title: "Scans",
                        status: "1,204 files, 8.40 GB in 0:09 · 912 MB/s", fraction: 1, isActive: false, isIndeterminate: false, failed: false, canReveal: true),
            TransferRow(id: UUID(), direction: .send, peerName: "macbookairm4", peerAddress: "192.168.1.52", title: "Backups",
                        status: "The connection closed", fraction: 0.2, isActive: false, isIndeterminate: false, failed: true, canReveal: false),
        ]
        let base = path.hasSuffix(".png") ? String(path.dropLast(4)) : path
        var ok = true
        for (suffix, appearance, model) in [
            ("", NSAppearance.Name.darkAqua, AppModel(demoPeers: peers, rows: rows)),
            ("-light", .aqua, AppModel(demoPeers: peers, rows: rows)),
            ("-empty", .darkAqua, AppModel(demoPeers: [], rows: [], receiving: false)),
        ] {
            let host = NSHostingView(rootView: MainView(model: model).background(Color(nsColor: .windowBackgroundColor)))
            let window = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 540, height: 600), styleMask: [.titled], backing: .buffered, defer: false)
            window.appearance = NSAppearance(named: appearance)
            window.contentView = host
            window.setContentSize(NSSize(width: 540, height: 600))
            host.layoutSubtreeIfNeeded()
            RunLoop.main.run(until: Date().addingTimeInterval(0.3))
            guard let rep = host.bitmapImageRepForCachingDisplay(in: host.bounds) else { ok = false; continue }
            host.cacheDisplay(in: host.bounds, to: rep)
            let out = base + suffix + ".png"
            do { try rep.representation(using: .png, properties: [:])?.write(to: URL(fileURLWithPath: out)); print("wrote \(out)") }
            catch { ok = false }
        }
        return ok
    }
}

/// An LSUIElement app has no menu bar of its own until it builds one; without it ⌘W, ⌘Q and
/// ⌘C do nothing in the window.
@MainActor
enum MainMenu {
    static func install() {
        let main = NSMenu()
        let appItem = NSMenuItem()
        let app = NSMenu()
        app.addItem(withTitle: "Hide Nimbus Drop", action: #selector(NSApplication.hide(_:)), keyEquivalent: "h")
        app.addItem(.separator())
        app.addItem(withTitle: "Quit Nimbus Drop", action: #selector(NSApplication.terminate(_:)), keyEquivalent: "q")
        appItem.submenu = app
        main.addItem(appItem)

        let editItem = NSMenuItem()
        let edit = NSMenu(title: "Edit")
        edit.addItem(withTitle: "Copy", action: #selector(NSText.copy(_:)), keyEquivalent: "c")
        edit.addItem(withTitle: "Select All", action: #selector(NSText.selectAll(_:)), keyEquivalent: "a")
        editItem.submenu = edit
        main.addItem(editItem)

        let windowItem = NSMenuItem()
        let window = NSMenu(title: "Window")
        window.addItem(withTitle: "Close", action: #selector(NSWindow.performClose(_:)), keyEquivalent: "w")
        window.addItem(withTitle: "Minimize", action: #selector(NSWindow.performMiniaturize(_:)), keyEquivalent: "m")
        windowItem.submenu = window
        main.addItem(windowItem)
        NSApp.mainMenu = main
    }
}
