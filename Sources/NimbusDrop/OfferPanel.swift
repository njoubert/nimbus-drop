// Copyright (C) 2026 Niels Joubert
// SPDX-License-Identifier: GPL-3.0-or-later
import AppKit
import NimbusDropCore
import SwiftUI

/// The first of the two questions an incoming drop asks: do you want this? It says who is
/// sending (host name and address), what, how many files and how big. Not modal, so the app
/// keeps running behind it and the panel can be taken away if the sender gives up.
@MainActor
final class OfferPanel: NSObject, NSWindowDelegate {
    private let panel: NSPanel
    private var answer: ((Bool) -> Void)?

    init(session: ReceiveSession, answer: @escaping (Bool) -> Void) {
        self.answer = answer
        panel = NSPanel(contentRect: .zero, styleMask: [.titled, .closable], backing: .buffered, defer: false)
        super.init()
        let view = OfferView(sender: session.peerName, address: session.peerAddress, title: session.title,
                             detail: "\(Format.files(session.offeredFiles)), \(Format.bytes(session.offeredBytes))",
                             version: "Nimbus Drop \(session.senderAppVersion)",
                             decline: { [weak self] in self?.finish(false) },
                             accept: { [weak self] in self?.finish(true) })
        panel.contentViewController = NSHostingController(rootView: view)
        panel.title = "Incoming Drop"
        panel.level = .modalPanel
        panel.isReleasedWhenClosed = false
        panel.hidesOnDeactivate = false
        panel.delegate = self
    }

    func show() {
        panel.center()
        panel.makeKeyAndOrderFront(nil)
    }

    /// The sender gave up: take the question away without it counting as an answer here.
    func dismiss() {
        answer = nil
        panel.close()
    }

    private func finish(_ accepted: Bool) {
        let a = answer
        answer = nil
        panel.close()
        a?(accepted)
    }

    /// Closing the panel by its close button is a no.
    func windowWillClose(_ notification: Notification) {
        guard let a = answer else { return }
        answer = nil
        DispatchQueue.main.async { a(false) }
    }

    /// The panel's contents as a PNG, for `--dump-offer`.
    static func dump(to path: String) -> Bool {
        _ = NSApplication.shared
        let view = OfferView(sender: "macbookairm4", address: "192.168.1.143", title: "Christmas 2026",
                             detail: "1,204 files, 31.2 GB", version: "Nimbus Drop 0.1.0", decline: {}, accept: {})
        let host = NSHostingView(rootView: view.background(Color(nsColor: .windowBackgroundColor)))
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
}

private struct OfferView: View {
    let sender: String
    let address: String
    let title: String
    let detail: String
    let version: String
    let decline: () -> Void
    let accept: () -> Void

    var body: some View {
        VStack(spacing: 14) {
            Image(systemName: "arrow.down.circle.fill").font(.system(size: 44)).foregroundStyle(.tint)
            VStack(spacing: 4) {
                Text("\(sender) wants to send you").font(.headline)
                Text("“\(title)”").font(.title3.weight(.semibold)).multilineTextAlignment(.center).lineLimit(3)
                Text(detail).font(.body.monospacedDigit())
            }
            VStack(spacing: 2) {
                Text("From \(sender) at \(address)").font(.system(.callout, design: .monospaced)).textSelection(.enabled)
                Text(version).font(.caption).foregroundStyle(.tertiary)
            }
            .foregroundStyle(.secondary)
            HStack(spacing: 12) {
                Button("Decline", action: decline).keyboardShortcut(.cancelAction).frame(maxWidth: .infinity)
                Button("Accept…", action: accept).keyboardShortcut(.defaultAction).frame(maxWidth: .infinity)
            }
            .controlSize(.large)
            Text("Accepting asks where to save it. Nothing is written before that.").font(.caption).foregroundStyle(.secondary)
        }
        .padding(22)
        .frame(width: 380)
    }
}
