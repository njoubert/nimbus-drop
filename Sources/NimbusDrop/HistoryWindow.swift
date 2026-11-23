// Copyright (C) 2026 Niels Joubert
// SPDX-License-Identifier: GPL-3.0-or-later
import AppKit
import NimbusDropCore
import SwiftUI

/// Every drop that has ended, newest first. The main window forgets a finished drop after a
/// minute; this is where it can still be found.
struct HistoryView: View {
    @ObservedObject var model: AppModel

    private static let when: DateFormatter = {
        let f = DateFormatter()
        f.dateStyle = .medium
        f.timeStyle = .short
        f.doesRelativeDateFormatting = true
        return f
    }()

    var body: some View {
        VStack(spacing: 0) {
            if model.history.isEmpty {
                VStack(spacing: 6) {
                    Image(systemName: "clock").font(.system(size: 30)).foregroundStyle(.tertiary)
                    Text("No drops yet").font(.callout).foregroundStyle(.secondary)
                }
                .frame(maxWidth: .infinity, maxHeight: .infinity)
            } else {
                List(model.history) { entry in HistoryRow(entry: entry, when: Self.when.string(from: entry.date)) }
                    .listStyle(.inset)
            }
            Divider()
            HStack {
                Text(model.history.isEmpty ? "" : "\(model.history.count) \(model.history.count == 1 ? "drop" : "drops")")
                    .font(.caption).foregroundStyle(.secondary)
                Spacer()
                Button("Show Log") { AppDelegate.shared?.showLog() }
                    .help("The debug log: everything each drop did, with times. Useful when one fails.")
                Button("Clear History") { model.clearHistory() }.disabled(model.history.isEmpty)
            }
            .controlSize(.small)
            .padding(.horizontal, 14).padding(.vertical, 8)
        }
        .frame(minWidth: 520, idealWidth: 600, minHeight: 300, idealHeight: 440)
        .tint(Palette.send)
    }
}

private struct HistoryRow: View {
    let entry: HistoryEntry
    let when: String

    private var colour: Color { entry.outcome == .completed ? (entry.sent ? Palette.send : Palette.receive) : Palette.failure }

    private var summary: String {
        switch entry.outcome {
        case .completed:
            var text = "\(Format.files(entry.files)), \(Format.bytes(entry.bytes))"
            if let s = entry.seconds, s > 0.05 { text += " in \(Format.duration(s)) · \(Format.bitRate(Double(entry.bytes) / s))" }
            return text
        case .failed: return entry.detail ?? "Failed"
        case .declined: return entry.detail ?? "Declined"
        case .cancelled: return "Cancelled"
        }
    }

    /// "reconnected once, 3 connections lost; re-sent": what the drop went through, when it did.
    private var trouble: String? {
        var s = TransferStats()
        s.connectionFailures = entry.connectionsLost ?? 0
        s.damagedChunks = entry.damagedChunks ?? 0
        s.reconnects = entry.reconnects ?? 0
        s.retransmittedChunks = entry.retransmittedChunks ?? 0
        guard s.connectionFailures > 0 || s.damagedChunks > 0 || s.reconnects > 0 else { return nil }
        return AppModel.troubleText(s)
    }

    /// The saved items that are still where they were put.
    private var saved: [URL] {
        entry.savedPaths.map { URL(fileURLWithPath: $0) }.filter { FileManager.default.fileExists(atPath: $0.path) }
    }

    var body: some View {
        HStack(spacing: 10) {
            Image(systemName: entry.outcome == .completed ? (entry.sent ? "arrow.up.circle.fill" : "arrow.down.circle.fill") : "exclamationmark.circle.fill")
                .font(.system(size: 20)).foregroundStyle(colour)
            VStack(alignment: .leading, spacing: 2) {
                HStack(spacing: 4) {
                    Text(entry.title).fontWeight(.medium).lineLimit(1).truncationMode(.middle)
                    Text(entry.sent ? "to" : "from").foregroundStyle(.secondary)
                    Text(entry.peerName).lineLimit(1)
                    Text(entry.peerAddress).font(.system(.caption, design: .monospaced)).foregroundStyle(.tertiary).lineLimit(1)
                }
                Text(summary).font(.caption.monospacedDigit())
                    .foregroundStyle(entry.outcome == .completed ? AnyShapeStyle(.secondary) : AnyShapeStyle(Palette.failure))
                    .lineLimit(2)
                if let trouble { Text(trouble).font(.caption).foregroundStyle(.tertiary) }
            }
            Spacer(minLength: 8)
            Text(when).font(.caption).foregroundStyle(.secondary)
            if !saved.isEmpty {
                Button { NSWorkspace.shared.activateFileViewerSelecting(saved) } label: { Image(systemName: "magnifyingglass.circle.fill") }
                    .buttonStyle(.plain).foregroundStyle(.secondary).help("Show in Finder")
            }
        }
        .padding(.vertical, 3)
        // The whole row opens where a received drop was saved, while it is still there.
        .contentShape(Rectangle())
        .onTapGesture { if !saved.isEmpty { NSWorkspace.shared.activateFileViewerSelecting(saved) } }
        .help(saved.isEmpty ? "" : "Click to show it in Finder")
    }
}

@MainActor
final class HistoryWindowController {
    private let window: NSWindow

    init(model: AppModel) {
        window = NSWindow(contentViewController: NSHostingController(rootView: HistoryView(model: model)))
        window.title = "Drop History"
        window.styleMask = [.titled, .closable, .resizable, .miniaturizable]
        window.setContentSize(NSSize(width: 600, height: 440))
        window.isReleasedWhenClosed = false
        window.setFrameAutosaveName("NimbusDropHistory")
        if window.frame.origin == .zero { window.center() }
    }

    func show() {
        NSApp.activate(ignoringOtherApps: true)
        window.makeKeyAndOrderFront(nil)
    }

    /// The window with a made-up history, as a PNG, for `--dump-history`.
    static func dump(to path: String) -> Bool {
        _ = NSApplication.shared
        let model = AppModel(demoPeers: [], manual: [], rows: [])
        let now = Date()
        model.history = [
            HistoryEntry(date: now.addingTimeInterval(-240), sent: true, title: "Christmas 2026", peerName: "dads-imac", peerAddress: "192.168.1.77",
                         files: 1204, bytes: 31_200_000_000, seconds: 272, outcome: .completed, detail: nil, savedPaths: []),
            HistoryEntry(date: now.addingTimeInterval(-3600), sent: false, title: "Scans", peerName: "macbookairm4", peerAddress: "192.168.1.143",
                         files: 212, bytes: 8_400_000_000, seconds: 73, outcome: .completed, detail: nil, savedPaths: ["/"]),
            HistoryEntry(date: now.addingTimeInterval(-90000), sent: true, title: "jpeg", peerName: "Pierre-Henris-MacBook-Air", peerAddress: "192.168.1.171",
                         files: 19, bytes: 814_000_000, seconds: 40, outcome: .failed,
                         detail: "Lost the connection to Pierre-Henris-MacBook-Air and could not get it back; send the drop again to continue it", savedPaths: []),
            HistoryEntry(date: now.addingTimeInterval(-180000), sent: true, title: "render.mov and 2 more", peerName: "macstudio", peerAddress: "192.168.1.20",
                         files: 3, bytes: 4_100_000_000, seconds: nil, outcome: .declined, detail: "macstudio declined", savedPaths: []),
        ]
        let host = NSHostingView(rootView: HistoryView(model: model).background(Color(nsColor: .windowBackgroundColor)))
        let window = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 600, height: 330), styleMask: [.titled], backing: .buffered, defer: false)
        window.appearance = NSAppearance(named: .darkAqua)
        window.contentView = host
        window.setContentSize(NSSize(width: 600, height: 330))
        host.layoutSubtreeIfNeeded()
        RunLoop.main.run(until: Date().addingTimeInterval(0.4))
        host.layoutSubtreeIfNeeded()
        guard let rep = host.bitmapImageRepForCachingDisplay(in: host.bounds) else { return false }
        host.cacheDisplay(in: host.bounds, to: rep)
        do { try rep.representation(using: .png, properties: [:])?.write(to: URL(fileURLWithPath: path)) } catch { return false }
        print("wrote \(path)")
        return true
    }
}
