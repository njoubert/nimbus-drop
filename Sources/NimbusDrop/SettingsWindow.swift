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

    init(model: AppModel, updater: Updater?) {
        self.model = model
        self.updater = updater
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
                Text("How many connections a drop you send is spread over. More helps on fast wired networks and with many small files. The receiving Mac takes however many the sender opens.")
                    .font(.caption).foregroundStyle(.secondary)
            }
            Section("General") {
                Toggle("Open at login", isOn: Binding(get: { model.openAtLogin }, set: { model.setOpenAtLogin($0) }))
                    .disabled(Bundle.main.bundleIdentifier == nil)
                Text("So this Mac is ready to receive after a restart. It starts in the menu bar, without opening the window.")
                    .font(.caption).foregroundStyle(.secondary)
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
            Section("About") {
                LabeledContent("Version", value: Self.appVersion)
                LabeledContent("Protocol", value: protocolVersionText)
                Text("Copies whose protocol begins with the same number can exchange drops.")
                    .font(.caption).foregroundStyle(.secondary)
            }
        }
        .formStyle(.grouped)
        .frame(width: 440)
        .fixedSize(horizontal: false, vertical: true)
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
        let host = NSHostingView(rootView: SettingsView(model: model, updater: nil).background(Color(nsColor: .windowBackgroundColor)))
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
