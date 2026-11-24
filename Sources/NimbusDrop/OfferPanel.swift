// Copyright (C) 2026 Niels Joubert
// SPDX-License-Identifier: GPL-3.0-or-later
import AppKit
import NimbusDropCore
import SwiftUI

/// What an incoming drop asks: do you want this, and where? It says who is sending (host name
/// and address), what, how many files and how big, and offers three answers: decline, save
/// straight to Downloads (one click, the usual case), or choose a folder first. Not modal, so
/// the app keeps running behind it and the panel can be taken away if the sender gives up.
@MainActor
final class OfferPanel: NSObject, NSWindowDelegate {
    private let panel: NSPanel
    enum Answer { case decline, downloads, choose, allow }
    private var answer: ((Answer) -> Void)?

    init(session: ReceiveSession, answer: @escaping (Answer) -> Void) {
        self.answer = answer
        panel = NSPanel(contentRect: .zero, styleMask: [.titled, .closable], backing: .buffered, defer: false)
        super.init()
        let view = OfferView(sender: session.peerName, address: session.peerAddress, paired: session.sender.pairedAt, title: session.title,
                             detail: "\(Format.files(session.offeredFiles)), \(Format.bytes(session.offeredBytes))",
                             answer: { [weak self] in self?.finish($0) })
        panel.contentViewController = NSHostingController(rootView: view)
        panel.title = "Incoming Drop"
        panel.level = .modalPanel
        panel.isReleasedWhenClosed = false
        panel.hidesOnDeactivate = false
        panel.delegate = self
    }

    /// The other question a paired Mac can put: may it measure the link to this one? Nothing
    /// one Mac has another do happens without a yes here, and this is where that yes is given.
    init(speed test: SpeedResponder, answer: @escaping (Answer) -> Void) {
        self.answer = answer
        panel = NSPanel(contentRect: .zero, styleMask: [.titled, .closable], backing: .buffered, defer: false)
        super.init()
        let view = SpeedAskView(asker: test.peerName, address: test.peerAddress, paired: test.pairedAt,
                                detail: "\(Int(test.secondsEachWay)) seconds each way · \(Format.connections(test.connections))",
                                answer: { [weak self] in self?.finish($0) })
        panel.contentViewController = NSHostingController(rootView: view)
        panel.title = "Speed Test"
        panel.level = .modalPanel
        panel.isReleasedWhenClosed = false
        panel.hidesOnDeactivate = false
        panel.delegate = self
    }

    /// Shows the panel; `cascade` steps it down and right so several offers do not hide each other.
    func show(cascade: Int = 0) {
        panel.center()
        let step = CGFloat(cascade % 8) * 28
        panel.setFrameOrigin(NSPoint(x: panel.frame.origin.x + step, y: panel.frame.origin.y - step))
        panel.makeKeyAndOrderFront(nil)
    }

    /// The sender gave up: take the question away without it counting as an answer here.
    func dismiss() {
        answer = nil
        panel.close()
    }

    private func finish(_ chosen: Answer) {
        let a = answer
        answer = nil
        panel.close()
        a?(chosen)
    }

    /// Closing the panel by its close button is a no.
    func windowWillClose(_ notification: Notification) {
        guard let a = answer else { return }
        answer = nil
        DispatchQueue.main.async { a(.decline) }
    }

    /// The panel's contents as a PNG, for `--dump-offer`.
    static func dump(to path: String) -> Bool {
        _ = NSApplication.shared
        let view = OfferView(sender: "My MacBook Air", address: "192.168.1.143", paired: Date().addingTimeInterval(-3 * 86400), title: "2026-05-03 - M10 - Canon 28mm LTE evening walk",
                             detail: "1,204 files, 31.2 GB", answer: { _ in })
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
    /// When the sender was paired with this Mac. Said plainly and without a tick: it means
    /// "this is that Mac", not "this drop is safe to take".
    let paired: Date
    let title: String
    let detail: String
    let answer: (OfferPanel.Answer) -> Void

    var body: some View {
        VStack(spacing: 14) {
            Image(systemName: "arrow.down.circle.fill").font(.system(size: 44)).foregroundStyle(Palette.receive)
                .shadow(color: Palette.receive.opacity(0.5), radius: 8)
            VStack(spacing: 4) {
                Text("\(sender) (\(address))").font(.headline).textSelection(.enabled)
                Text("paired with this Mac on \(paired.formatted(date: .abbreviated, time: .omitted)) · wants to send you").foregroundStyle(.secondary)
                    .multilineTextAlignment(.center).fixedSize(horizontal: false, vertical: true)
                // A long name wraps rather than being cut short: it is what is being agreed to.
                Text("“\(title)”").font(.title3.weight(.semibold)).multilineTextAlignment(.center)
                    .lineLimit(4).fixedSize(horizontal: false, vertical: true).padding(.top, 2)
                Text(detail).font(.body.monospacedDigit())
            }
            // One click for the usual case; the folder chooser for when it should go elsewhere.
            // Coloured by what they do: blue to take it, red to refuse.
            VStack(spacing: 8) {
                // No Return key for this button, on purpose. The panel takes the keyboard when it
                // appears, and someone typing in another app would accept a stranger's drop with
                // the Return they were about to press. It takes a click. (Escape still declines.)
                Button { answer(.downloads) } label: { Label("Save to Downloads", systemImage: "arrow.down.to.line") }
                    .buttonStyle(AnswerButton(fill: Palette.send, text: .white))
                HStack(spacing: 8) {
                    Button("Decline") { answer(.decline) }
                        .keyboardShortcut(.cancelAction)
                        .buttonStyle(AnswerButton(fill: Palette.failure, text: .white))
                    Button("Save to…") { answer(.choose) }
                        .buttonStyle(AnswerButton(fill: Color.primary.opacity(0.14), text: .primary))
                }
            }
        }
        .padding(22)
        .frame(width: 380)
    }
}

private struct SpeedAskView: View {
    let asker: String
    let address: String
    let paired: Date
    let detail: String
    let answer: (OfferPanel.Answer) -> Void

    var body: some View {
        VStack(spacing: 14) {
            Image(systemName: "speedometer").font(.system(size: 44)).foregroundStyle(Palette.send)
                .shadow(color: Palette.send.opacity(0.5), radius: 8)
            VStack(spacing: 4) {
                Text("\(asker) (\(address))").font(.headline).textSelection(.enabled)
                Text("paired with this Mac on \(paired.formatted(date: .abbreviated, time: .omitted)) · wants to test how fast the two Macs can send to each other")
                    .foregroundStyle(.secondary).multilineTextAlignment(.center).fixedSize(horizontal: false, vertical: true)
                Text(detail).font(.body.monospacedDigit()).padding(.top, 2)
                Text("It uses this Mac's network and processor for that long. Nothing is saved.")
                    .font(.caption).foregroundStyle(.secondary).multilineTextAlignment(.center).fixedSize(horizontal: false, vertical: true)
            }
            // No Return key for Allow, as for accepting a drop: it takes a click. Escape declines.
            HStack(spacing: 8) {
                Button("Decline") { answer(.decline) }
                    .keyboardShortcut(.cancelAction)
                    .buttonStyle(AnswerButton(fill: Palette.failure, text: .white))
                Button("Allow") { answer(.allow) }
                    .buttonStyle(AnswerButton(fill: Palette.send, text: .white))
            }
        }
        .padding(22)
        .frame(width: 380)
    }
}

/// The panel's buttons, drawn here rather than left to the system so that they are the app's
/// colours and look the same whether or not the panel is the key window.
private struct AnswerButton: ButtonStyle {
    let fill: Color
    let text: Color

    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .font(.body.weight(.medium))
            .foregroundStyle(text)
            .frame(maxWidth: .infinity)
            .padding(.vertical, 8)
            .background(RoundedRectangle(cornerRadius: 8).fill(fill).opacity(configuration.isPressed ? 0.7 : 1))
            .contentShape(RoundedRectangle(cornerRadius: 8))
    }
}
