// Copyright (C) 2026 Niels Joubert
// SPDX-License-Identifier: GPL-3.0-or-later
import AppKit
import NimbusDropCore
import NimbusUpdater
import SwiftUI

/// The Settings window (⌘,): what is set once and left alone, kept off the main window. How
/// many connections a send uses, Open at login, updates, and which version this is.
struct SettingsView: View {
    @ObservedObject var model: AppModel
    let updater: Updater?
    @State private var automatic: Bool
    @State private var serviceShown = ServiceMenu.isShown
    static var serviceName: String { "\(Bundle.main.infoDictionary?["CFBundleName"] as? String ?? "Nimbus Drop") To…" }
    /// For the picture of it: as tall as its contents. On screen it scrolls instead, since
    /// with a few Known Macs it is taller than a laptop's display.
    var whole = false

    init(model: AppModel, updater: Updater?, whole: Bool = false) {
        self.model = model
        self.updater = updater
        self.whole = whole
        _automatic = State(initialValue: updater?.automaticChecks ?? false)
    }

    var body: some View {
        Form {
            Section("Sending") {
                Picker("Parallel connections", selection: Binding(get: { model.streams }, set: { model.setStreams($0) })) {
                    ForEach(Settings.streamChoices, id: \.self) { n in
                        Text(n == Settings.defaultStreams ? "\(n) (default)" : "\(n)").tag(n)
                    }
                }
            }
            Section("Receiving") {
                Toggle("Only from the local network", isOn: Binding(get: { model.localOnly }, set: { model.setLocalOnly($0) }))
                    .help("On: drops are taken only from Macs on the same subnet as this one. Off: from any address that can reach this Mac, such as over a VPN or from another subnet. Every drop still has to be accepted.")
            }
            Section("This Mac's identity") {
                let _ = model.trustChanges
                LabeledContent("Key", value: model.trust.publicKey.tag)
                LabeledContent("Made", value: model.trust.made.formatted(date: .abbreviated, time: .shortened))
                LabeledContent("Good until", value: model.trust.ends.formatted(date: .abbreviated, time: .shortened))
                Picker("Keys last", selection: Binding(get: { model.trust.lifetime }, set: { model.setKeyLifetime($0) })) {
                    Text("90 days").tag(90 * 86400.0)
                    Text("30 days").tag(30 * 86400.0)
                    Text("1 week").tag(7 * 86400.0)
                    Text("1 day").tag(86400.0)
                    Text("1 hour").tag(3600.0)
                }
                Toggle("Let other Macs ask to pair", isOn: Binding(get: { !model.trust.requestsOff }, set: { model.setRequestsOff(!$0) }))
                    .help("Off: a pairing can only be started from this Mac.")
                HStack {
                    Button("Show Identity Number…") { model.showIdentityNumber() }
                    Spacer()
                    if model.resetting { ProgressView().controlSize(.small); Text("Telling the other Macs…").font(.caption) }
                    Button("Reset Identity…") { model.resetIdentity() }.disabled(model.resetting)
                }
            }
            Section("Known Macs") {
                let _ = model.trustChanges
                if model.trust.known.isEmpty {
                    Text("None yet. Drop a file on a Mac in the window: each of you reads out a code and types the other's.")
                        .font(.callout).foregroundStyle(.secondary)
                }
                ForEach(model.trust.known) { mac in
                    HStack(alignment: .firstTextBaseline) {
                        VStack(alignment: .leading, spacing: 2) {
                            HStack(spacing: 6) {
                                Text(mac.name).font(.body.weight(.medium))
                                if let said = mac.announced.last, said != mac.name { Text("announces itself as \(said)").font(.caption).foregroundStyle(.secondary) }
                            }
                            Text("paired \(mac.pairedAt.formatted(date: .abbreviated, time: .omitted)) by \(mac.method) · \(model.trust.standing(of: mac.key).isPaired ? "good until \(mac.endsWall.formatted(date: .abbreviated, time: .omitted))" : "its key has run out; pair again") · \(mac.key.tag)")
                                .font(.caption).foregroundStyle(.secondary).textSelection(.enabled)
                            if mac.impostors > 0 {
                                Text("Another Mac used this name \(mac.impostors) \(mac.impostors == 1 ? "time" : "times")\(mac.lastImpostor.map { ", last from \($0)" } ?? "")")
                                    .font(.caption).foregroundStyle(Palette.warning)
                            }
                        }
                        Spacer()
                        Button("Rename…") { model.rename(mac) }.controlSize(.small)
                        Button("Forget") { model.forget(mac) }.controlSize(.small)
                    }
                }
                let again = model.trust.again.filter { !$0.pairedAgain }
                if !again.isEmpty {
                    Text("Pair again").font(.callout.weight(.semibold)).padding(.top, 4)
                    ForEach(again) { r in
                        HStack(alignment: .firstTextBaseline) {
                            VStack(alignment: .leading, spacing: 2) {
                                Text(r.name).font(.body.weight(.medium))
                                switch r.told {
                                case true?: Text("told of the reset · it no longer trusts the old identity").font(.caption).foregroundStyle(.secondary)
                                case false?:
                                    Text("not reached · **it still trusts the old identity** until you pair again, or until \(r.endsWall.formatted(date: .abbreviated, time: .omitted))")
                                        .font(.caption).foregroundStyle(Palette.failure)
                                case nil: Text("this Mac's key was replaced; pair again the next time you send to it").font(.caption).foregroundStyle(.secondary)
                                }
                            }
                            Spacer()
                            Button("Remove") { model.trust.removeFromAgain(r.key) }.controlSize(.small)
                        }
                    }
                }
            }
            Section("General") {
                Toggle("Open at login", isOn: Binding(get: { model.openAtLogin }, set: { model.setOpenAtLogin($0) }))
                    .disabled(Bundle.main.bundleIdentifier == nil)
                Toggle("Show “\(Self.serviceName)” in Finder's Services menu", isOn: Binding(get: { serviceShown }, set: { serviceShown = $0; ServiceMenu.setShown($0) }))
                    .disabled(ServiceMenu.key == nil)
            }
            Section("History and log") {
                HStack {
                    Text("Drops that have ended.")
                    Spacer()
                    Button("Show History…") { AppDelegate.shared?.showHistory() }
                }
                HStack {
                    Text("What the app is doing, live, and its debug log.")
                    Spacer()
                    Button("Show Internals…") { AppDelegate.shared?.showInternals() }
                }
            }
            Section("Updates") {
                if let updater, updater.canInstall {
                    Toggle("Check for updates automatically", isOn: $automatic)
                        .onChange(of: automatic) { _, on in updater.automaticChecks = on }
                    Text("Once a day, asks github.com for the newest release and downloads it. Nothing else leaves your network.")
                        .font(.caption).foregroundStyle(.secondary)
                    Button("Check for Updates…") {
                        Task { @MainActor in updater.presentCheckResult(await updater.checkNow()) }
                    }
                } else {
                    Text(updater == nil ? "Updates are for the installed app; this is a development build."
                                        : "Updates install only into /Applications, and this copy runs from somewhere else.")
                        .font(.callout).foregroundStyle(.secondary)
                }
            }
            Section("Uninstall") {
                HStack {
                    Text("Removes the app and everything it has kept on this Mac, as if it had never been installed.")
                        .font(.callout).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
                    Spacer()
                    Button("Uninstall Nimbus Drop…", role: .destructive) { Uninstaller.ask(model: model) }.disabled(model.resetting)
                }
            }
            Section("About") {
                LabeledContent("Version", value: Self.appVersion)
                LabeledContent("Protocol", value: protocolVersionText)
                Text("Copies whose protocol begins with the same number can exchange drops. Protocol 3 is encrypted end to end and does not talk to earlier versions.")
                    .font(.caption).foregroundStyle(.secondary)
            }
        }
        .formStyle(.grouped)
        .frame(width: 440)
        .frame(height: whole ? nil : 640)
        .fixedSize(horizontal: false, vertical: whole)
        .tint(Palette.send)
    }

    /// "0.1.0 (12)", or "development build".
    static var appVersion: String {
        let info = Bundle.main.infoDictionary
        guard let short = info?["CFBundleShortVersionString"] as? String else { return "development build" }
        return "\(short) (\(info?["CFBundleVersion"] as? String ?? "?"))"
    }
}

@MainActor
final class SettingsWindowController {
    private let window: NSWindow

    init(model: AppModel, updater: Updater?) {
        window = NSWindow(contentViewController: NSHostingController(rootView: SettingsView(model: model, updater: updater)))
        window.title = "Nimbus Drop Settings"
        window.styleMask = [.titled, .closable]
        window.isReleasedWhenClosed = false
        window.center()
    }

    func show() {
        NSApp.activate(ignoringOtherApps: true)
        window.makeKeyAndOrderFront(nil)
    }

    /// The pane as a PNG, for `--dump-settings`.
    static func dump(to path: String) -> Bool {
        _ = NSApplication.shared
        let model = AppModel(demoPeers: [], manual: [], rows: [])
        _ = try? model.trust.store(pairing: PublicKey.madeUp(), announced: "macbookairm4", method: "codes", remaining: 88 * 86400, name: "My MacBook Air")
        _ = try? model.trust.store(pairing: PublicKey.madeUp(), announced: "dads-imac", method: "identity number", remaining: 60 * 86400, name: "Dad's iMac")
        if let studio = try? model.trust.store(pairing: PublicKey.madeUp(), announced: "macstudio", method: "codes", remaining: 40 * 86400) {
            model.trust.noteImpostor(of: studio.key, at: "192.168.1.166")
        }
        let host = NSHostingView(rootView: SettingsView(model: model, updater: nil, whole: true).background(Color(nsColor: .windowBackgroundColor)))
        let window = NSWindow(contentRect: NSRect(origin: .zero, size: host.fittingSize), styleMask: [.titled], backing: .buffered, defer: false)
        window.appearance = NSAppearance(named: .darkAqua)
        window.contentView = host
        host.layoutSubtreeIfNeeded()
        RunLoop.main.run(until: Date().addingTimeInterval(0.3))
        host.layoutSubtreeIfNeeded()
        guard let rep = host.bitmapImageRepForCachingDisplay(in: host.bounds) else { return false }
        host.cacheDisplay(in: host.bounds, to: rep)
        do { try rep.representation(using: .png, properties: [:])?.write(to: URL(fileURLWithPath: path)) } catch { return false }
        print("wrote \(path)")
        return true
    }
}
