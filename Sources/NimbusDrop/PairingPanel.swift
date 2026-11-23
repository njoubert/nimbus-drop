// Copyright (C) 2026 Niels Joubert
// SPDX-License-Identifier: GPL-3.0-or-later
import AppKit
import NimbusDropCore
import SwiftUI

/// What a destination is to this Mac, for a tile's badge and for what a click on it does.
/// Everything here comes from the key the Mac at that address proved, never from what it announces.
enum PeerStanding: Equatable {
    /// Speaks protocol 2: drawn from its Bonjour record alone; nothing is said to it.
    case needsUpdate
    /// Found; not yet asked who it is.
    case checking
    /// Asked, and it proved nothing (not answering, or not Nimbus Drop 0.3).
    case unproved
    case paired(KnownMac)
    case new
    /// An unknown key under the name of a Mac this one knows, whose own key is still good.
    case nameInUse(NameClash)
    /// Needs pairing again and nothing is odd about it: this Mac's key or its key ran out.
    case renew(String)
    /// It proved a key that was given up, replaced or has run out.
    case refused(String)

    var canSend: Bool { if case .paired = self { return true }; return false }
    var canPair: Bool {
        switch self {
        case .new, .nameInUse, .renew: return true
        default: return false
        }
    }

    var badge: (text: String, colour: Color)? {
        switch self {
        case .needsUpdate: return ("Needs an update", Palette.warning)
        case .checking: return nil
        case .unproved: return ("Not answering", Palette.warning)
        case .paired: return ("✓ Paired", Palette.receive)
        case .new: return ("New · pair to send", Palette.send)
        case .nameInUse: return ("New · name in use", Palette.failure)
        case .renew: return ("Renew pairing", Palette.send)
        case .refused: return ("Identity not accepted", Palette.failure)
        }
    }
}

/// A pairing as a window watches it.
@MainActor
final class PairingModel: ObservableObject {
    let session: PairingSession
    @Published var state: PairingSession.State
    @Published var entry = ""
    /// A responder's person has said yes to pairing at all (and, where asked, what the Mac is).
    @Published var agreed = false
    /// The question "does it replace the Mac you know, or is it another?" is showing.
    @Published var askingWhich = false
    /// What is sent once the pairing is made: "Send the Drop".
    let pending: String?
    var onDone: ((Bool) -> Void)?
    let myNumber: String
    let peerName: String

    init(session: PairingSession, pending: String?, myNumber: String) {
        self.session = session
        self.pending = pending
        self.myNumber = myNumber
        state = session.state
        peerName = session.peerName
        agreed = session.initiator
        session.onChange = { [weak self] in
            DispatchQueue.main.async { MainActor.assumeIsolated { self?.refresh() } }
        }
    }

    private func refresh() {
        let new = session.state
        if case .codes(_, let left) = new, case .codes(_, let before) = state, left != before { entry = "" }
        state = new
    }

    var clash: NameClash? { session.clash }
    /// The same Mac as before, renewing: nothing odd about it.
    var isRenewal: Bool {
        if case .renew = session.standing { return true }
        return clash?.expected == true
    }

    func agree() {
        if let clash, !clash.expected, clash.paired { askingWhich = true } else { proceed(replacing: clash?.expected == true ? clash?.key : nil) }
    }

    func proceed(replacing: PublicKey?) {
        askingWhich = false
        agreed = true
        session.proceed(replacing: replacing)
    }

    func submit() {
        let typed = entry
        DispatchQueue.global().async { [session] in session.submit(typed) }
    }

    func stop() { DispatchQueue.global().async { [session] in session.refuse() } }
}

/// The pairing window, at either Mac: asked first (a responder), then each reads their code out
/// and types the other's. Not modal, so that a request can be taken away if the other side gives up.
@MainActor
final class PairingPanel: NSObject, NSWindowDelegate {
    private let panel: NSPanel
    let model: PairingModel
    private var closed = false

    init(session: PairingSession, pending: String?, myNumber: String, done: @escaping (PairingSession, Bool) -> Void) {
        model = PairingModel(session: session, pending: pending, myNumber: myNumber)
        panel = NSPanel(contentRect: .zero, styleMask: [.titled, .closable], backing: .buffered, defer: false)
        super.init()
        model.onDone = { [weak self] send in
            self?.close()
            done(session, send)
        }
        panel.contentViewController = NSHostingController(rootView: PairingView(model: model))
        panel.title = session.initiator ? "Pair with \(session.peerName)" : "Pair with a New Mac?"
        panel.level = .modalPanel
        panel.isReleasedWhenClosed = false
        panel.hidesOnDeactivate = false
        panel.delegate = self
    }

    func show() {
        panel.center()
        NSApp.activate(ignoringOtherApps: true)
        panel.makeKeyAndOrderFront(nil)
    }

    func close() {
        closed = true
        panel.close()
    }

    /// Closing the window stops the pairing: nothing half-done is left behind.
    func windowWillClose(_ notification: Notification) {
        guard !closed else { return }
        closed = true
        if !model.state.isFinal { model.stop() }
        let finish = model.onDone
        DispatchQueue.main.async { finish?(false) }
    }

    /// The panel's stages as PNGs, for `--dump-pairing`: P-request, P-clash, P-codes, P-wrong,
    /// P-number, P-paired, P-failed.
    static func dump(to path: String) -> Bool {
        _ = NSApplication.shared
        let trust = Trust.inMemory()
        let known = KeyPair().publicKey
        _ = try? trust.store(pairing: known, announced: "macbookairm4", method: "codes", remaining: 80 * 86400)
        let clash = trust.nameClash("macbookairm4", key: KeyPair().publicKey)
        let stages: [(String, PairingStage)] = [
            ("request", .request(name: "macbookpro", address: "192.168.1.107", clash: nil, renewal: false)),
            ("clash", .request(name: "macbookairm4", address: "192.168.1.166", clash: clash, renewal: false)),
            ("renew", .request(name: "macbookpro", address: "192.168.1.107", clash: nil, renewal: true)),
            ("which", .which(name: "macbookairm4")),
            ("waiting", .waiting(name: "dads-imac")),
            ("codes", .codes(name: "dads-imac", mine: "482913", entry: "7053", left: 3, renewal: false)),
            ("wrong", .codes(name: "dads-imac", mine: "482913", entry: "", left: 2, renewal: false)),
            ("number", .number(name: "dads-imac", mine: "305178492611370652084991307754", entry: "9284136605711295843020", left: 3)),
            ("paired", .paired(name: "Dad's iMac", until: Date().addingTimeInterval(88 * 86400), pending: "Christmas 2026")),
            ("failed", .failed("The codes do not match. Something may be between the two Macs. Nothing was paired.")),
        ]
        var ok = true
        let base = (path as NSString).deletingPathExtension
        for (name, stage) in stages {
            let view = PairingStageView(stage: stage, entry: .constant(stage.entry), act: { _ in })
            let host = NSHostingView(rootView: view.background(Color(nsColor: .windowBackgroundColor)))
            let window = NSWindow(contentRect: NSRect(origin: .zero, size: host.fittingSize), styleMask: [.titled], backing: .buffered, defer: false)
            window.appearance = NSAppearance(named: .darkAqua)
            window.contentView = host
            host.layoutSubtreeIfNeeded()
            RunLoop.main.run(until: Date().addingTimeInterval(0.2))
            guard let rep = host.bitmapImageRepForCachingDisplay(in: host.bounds) else { ok = false; continue }
            host.cacheDisplay(in: host.bounds, to: rep)
            let out = "\(base)-\(name).png"
            do { try rep.representation(using: .png, properties: [:])?.write(to: URL(fileURLWithPath: out)); print("wrote \(out)") } catch { ok = false }
        }
        return ok
    }
}

/// What the pairing window is showing, with everything it needs to draw: so that the same view
/// draws the live window and the pictures of it.
enum PairingStage {
    case request(name: String, address: String, clash: NameClash?, renewal: Bool)
    case which(name: String)
    case waiting(name: String)
    case codes(name: String, mine: String, entry: String, left: Int, renewal: Bool)
    case number(name: String, mine: String, entry: String, left: Int)
    case confirming(name: String)
    case paired(name: String, until: Date, pending: String?)
    case failed(String)

    var entry: String {
        switch self {
        case .codes(_, _, let e, _, _), .number(_, _, let e, _): return e
        default: return ""
        }
    }
}

enum PairingAction { case agree, refuse, replaces, another, submit, done, send, copyNumber }

private struct PairingView: View {
    @ObservedObject var model: PairingModel

    private var stage: PairingStage {
        let s = model.session
        if model.askingWhich { return .which(name: model.clash?.name ?? s.peerName) }
        switch model.state {
        case .connecting: return .waiting(name: s.peerName)
        case .asking:
            return model.agreed ? .waiting(name: s.peerName) : .request(name: s.peerName, address: s.peerAddress, clash: model.clash, renewal: model.isRenewal)
        case .codes(let mine, let left):
            return s.byNumber ? .number(name: s.peerName, mine: model.myNumber, entry: model.entry, left: left)
                              : .codes(name: s.peerName, mine: mine, entry: model.entry, left: left, renewal: model.isRenewal)
        case .confirming: return .confirming(name: s.peerName)
        case .paired(let mac): return .paired(name: mac.name, until: mac.endsWall, pending: model.pending)
        case .failed(let why): return .failed(why)
        }
    }

    var body: some View {
        PairingStageView(stage: stage, entry: $model.entry) { action in
            switch action {
            case .agree: model.agree()
            case .refuse: model.stop(); model.onDone?(false)
            case .replaces: model.proceed(replacing: model.clash?.key)
            case .another: model.proceed(replacing: nil)
            case .submit: model.submit()
            case .done: model.onDone?(false)
            case .send: model.onDone?(true)
            case .copyNumber:
                NSPasteboard.general.clearContents()
                NSPasteboard.general.setString(PublicKey.grouped(model.myNumber), forType: .string)
            }
        }
    }
}

struct PairingStageView: View {
    let stage: PairingStage
    @Binding var entry: String
    let act: (PairingAction) -> Void
    @FocusState private var typing: Bool

    private func orb(_ symbol: String, _ colour: Color) -> some View {
        Image(systemName: symbol).font(.system(size: 44)).foregroundStyle(colour).shadow(color: colour.opacity(0.5), radius: 8)
    }

    private func spaced(_ code: String) -> String { code.count == 6 ? "\(code.prefix(3)) \(code.suffix(3))" : code }

    var body: some View {
        VStack(spacing: 14) {
            switch stage {
            case .request(let name, let address, let clash, let renewal):
                orb(clash != nil && !renewal ? "exclamationmark.circle.fill" : "arrow.left.arrow.right.circle.fill", clash != nil && !renewal ? Palette.failure : Palette.send)
                VStack(spacing: 4) {
                    Text(clash != nil && !renewal ? "A Mac calling itself \(name) (\(address))" : "\(name) (\(address))").font(.headline).multilineTextAlignment(.center)
                    if let clash, !renewal {
                        Text("wants to pair. It is **not** the \(clash.name) you paired with\(clash.pairedAt.map { " on \($0.formatted(date: .abbreviated, time: .omitted))" } ?? ""). Go on only if someone you can hear tells you why.")
                            .multilineTextAlignment(.center).fixedSize(horizontal: false, vertical: true)
                    } else if renewal {
                        Text("wants to pair again. Keys are replaced on a schedule, and one ran out, so this was expected. The codes will show whether it is the Mac you know. Go on only if someone you can hear is asking you to.")
                            .foregroundStyle(.secondary).multilineTextAlignment(.center).fixedSize(horizontal: false, vertical: true)
                    } else {
                        Text("wants to pair with this Mac. Go on only if someone you can hear is asking you to.")
                            .foregroundStyle(.secondary).multilineTextAlignment(.center).fixedSize(horizontal: false, vertical: true)
                    }
                }
                // Neither button answers to the Return key: the panel takes the keyboard when it
                // appears, and a person typing elsewhere must not agree to a pairing by accident.
                HStack(spacing: 8) {
                    Button("Not expecting this") { act(.refuse) }.keyboardShortcut(.cancelAction)
                        .buttonStyle(PanelButton(fill: Palette.failure, text: .white))
                    Button(renewal ? "Renew…" : "Pair…") { act(.agree) }
                        .buttonStyle(PanelButton(fill: Color.primary.opacity(0.14), text: .primary))
                }

            case .which(let name):
                orb("exclamationmark.circle.fill", Palette.failure)
                Text("This is not the \(name) you paired with").font(.headline).multilineTextAlignment(.center)
                Text("It may be a Mac that was erased or replaced, another Mac with the same name, or someone pretending. Ask the person there. Either way, the two codes come next.")
                    .foregroundStyle(.secondary).multilineTextAlignment(.center).fixedSize(horizontal: false, vertical: true)
                VStack(spacing: 8) {
                    Button("Stop") { act(.refuse) }.keyboardShortcut(.cancelAction).buttonStyle(PanelButton(fill: Palette.send, text: .white))
                    HStack(spacing: 8) {
                        Button("It Replaces \(name)…") { act(.replaces) }.buttonStyle(PanelButton(fill: Color.primary.opacity(0.14), text: .primary))
                        Button("It Is Another Mac…") { act(.another) }.buttonStyle(PanelButton(fill: Color.primary.opacity(0.14), text: .primary))
                    }
                }

            case .waiting(let name):
                ProgressView().controlSize(.large).frame(height: 44)
                Text("Waiting for the person at \(name)").font(.headline)
                Text("They are being asked whether to pair. Tell them it is you.").foregroundStyle(.secondary).multilineTextAlignment(.center)
                Button("Cancel") { act(.refuse) }.keyboardShortcut(.cancelAction).buttonStyle(PanelButton(fill: Color.primary.opacity(0.14), text: .primary))

            case .codes(let name, let mine, _, let left, let renewal):
                if left < 3 {
                    orb("exclamationmark.circle.fill", Palette.failure)
                    Text("That is not the code this Mac expected").font(.headline)
                    Text("Check it with the person at \(name) and type it once more (\(left) \(left == 1 ? "try" : "tries") left). If it is what they read out, stop: something may be between the two Macs.")
                        .foregroundStyle(.secondary).multilineTextAlignment(.center).fixedSize(horizontal: false, vertical: true)
                } else {
                    if renewal { Text("The same Mac you paired with before").font(.caption).foregroundStyle(Palette.receive) }
                    Text("Read this code out to the person at \(name):").foregroundStyle(.secondary).multilineTextAlignment(.center)
                }
                Text(spaced(mine)).font(.system(size: 40, weight: .semibold, design: .monospaced)).textSelection(.disabled)
                Text("Type the code they read to you:").foregroundStyle(.secondary)
                TextField("000 000", text: $entry)
                    // Not .roundedBorder: its height is fixed for body text and cut 22 pt digits off.
                    .textFieldStyle(.plain).font(.system(size: 24, weight: .medium, design: .monospaced)).multilineTextAlignment(.center)
                    .padding(.vertical, 7).padding(.horizontal, 10).frame(width: 180)
                    .background(RoundedRectangle(cornerRadius: 8).fill(Color.primary.opacity(0.08)))
                    .overlay(RoundedRectangle(cornerRadius: 8).strokeBorder(typing ? Palette.send : Color.primary.opacity(0.25), lineWidth: typing ? 2 : 1))
                    .focused($typing).onSubmit { if PublicKey.digits(entry).count == 6 { act(.submit) } }
                    .onAppear { typing = true }
                HStack(spacing: 8) {
                    Button("Stop Pairing") { act(.refuse) }.keyboardShortcut(.cancelAction).buttonStyle(PanelButton(fill: Color.primary.opacity(0.14), text: .primary))
                    Button("Pair") { act(.submit) }.disabled(PublicKey.digits(entry).count != 6)
                        .buttonStyle(PanelButton(fill: Palette.send, text: .white))
                }

            case .number(let name, let mine, _, let left):
                Text("Pair with \(name) by identity number").font(.headline)
                Text("Give this Mac's number to the person there. It is safe to send in a message.").foregroundStyle(.secondary).multilineTextAlignment(.center)
                    .fixedSize(horizontal: false, vertical: true)
                HStack {
                    Text(PublicKey.grouped(mine)).font(.system(.body, design: .monospaced)).textSelection(.enabled).fixedSize(horizontal: false, vertical: true)
                    Button("Copy") { act(.copyNumber) }.controlSize(.small)
                }
                Text(left < 3 ? "That is not the number of the Mac at the other end (\(left) \(left == 1 ? "try" : "tries") left)." : "Type or paste the identity number of \(name), as its owner gave it to you:")
                    .foregroundStyle(left < 3 ? AnyShapeStyle(Palette.failure) : AnyShapeStyle(.secondary)).multilineTextAlignment(.center).fixedSize(horizontal: false, vertical: true)
                TextField("30 digits", text: $entry)
                    .textFieldStyle(.roundedBorder).font(.system(.body, design: .monospaced)).focused($typing)
                    .onSubmit { if PublicKey.digits(entry).count == 30 { act(.submit) } }.onAppear { typing = true }
                HStack(spacing: 8) {
                    Button("Stop Pairing") { act(.refuse) }.keyboardShortcut(.cancelAction).buttonStyle(PanelButton(fill: Color.primary.opacity(0.14), text: .primary))
                    Button("Check") { act(.submit) }.disabled(PublicKey.digits(entry).count != 30)
                        .buttonStyle(PanelButton(fill: Palette.send, text: .white))
                }

            case .confirming(let name):
                ProgressView().controlSize(.large).frame(height: 44)
                Text("That is right").font(.headline)
                Text("Waiting for the person at \(name) to type theirs.").foregroundStyle(.secondary)
                Button("Stop Pairing") { act(.refuse) }.keyboardShortcut(.cancelAction).buttonStyle(PanelButton(fill: Color.primary.opacity(0.14), text: .primary))

            case .paired(let name, let until, let pending):
                orb("checkmark.circle.fill", Palette.receive)
                Text("Paired with \(name)").font(.headline)
                Text("Good until \(until.formatted(date: .abbreviated, time: .omitted)), when one of the two keys is replaced.")
                    .foregroundStyle(.secondary).multilineTextAlignment(.center).fixedSize(horizontal: false, vertical: true)
                if let pending {
                    HStack(spacing: 8) {
                        Button("Not Now") { act(.done) }.keyboardShortcut(.cancelAction).buttonStyle(PanelButton(fill: Color.primary.opacity(0.14), text: .primary))
                        Button("Send “\(pending)”") { act(.send) }.buttonStyle(PanelButton(fill: Palette.send, text: .white))
                    }
                } else {
                    Button("Done") { act(.done) }.keyboardShortcut(.defaultAction).buttonStyle(PanelButton(fill: Palette.send, text: .white))
                }

            case .failed(let why):
                orb("xmark.circle.fill", Palette.failure)
                Text("Not paired").font(.headline)
                Text(why).foregroundStyle(.secondary).multilineTextAlignment(.center).fixedSize(horizontal: false, vertical: true)
                Button("OK") { act(.done) }.keyboardShortcut(.defaultAction).buttonStyle(PanelButton(fill: Palette.send, text: .white))
            }
        }
        .padding(22)
        .frame(width: 400)
    }
}

/// The panels' buttons, drawn here so that they are the app's colours and look the same whether
/// or not the panel is the key window.
struct PanelButton: ButtonStyle {
    let fill: Color
    let text: Color
    @Environment(\.isEnabled) private var enabled

    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .font(.body.weight(.medium))
            .foregroundStyle(text)
            .frame(maxWidth: .infinity)
            .padding(.vertical, 8)
            .background(RoundedRectangle(cornerRadius: 8).fill(fill).opacity(configuration.isPressed ? 0.7 : (enabled ? 1 : 0.4)))
            .contentShape(RoundedRectangle(cornerRadius: 8))
    }
}
