// Copyright (C) 2026 Niels Joubert
// SPDX-License-Identifier: GPL-3.0-or-later
import AppKit
import NimbusDropCore
import UserNotifications

/// "Nimbus Drop To…" in the Services menu (Finder's right-click menu and the app menus).
///
/// The item is declared in the Info.plist, which cannot be changed in a signed app. What can
/// be changed is whether macOS shows it: the same switch as System Settings › Keyboard ›
/// Keyboard Shortcuts › Services, kept by macOS in the `pbs` preferences.
enum ServiceMenu {
    private static let domain = "pbs" as CFString
    private static let statusKey = "NSServicesStatus" as CFString

    static var key: String? {
        guard let id = Bundle.main.bundleIdentifier, let name = Bundle.main.infoDictionary?["CFBundleName"] as? String else { return nil }
        return Leftovers.serviceKey(bundleID: id, bundleName: name)
    }

    private static var all: [String: Any] {
        CFPreferencesAppSynchronize(domain)
        return CFPreferencesCopyAppValue(statusKey, domain) as? [String: Any] ?? [:]
    }

    /// Shown unless someone has switched it off (here or in System Settings).
    static var isShown: Bool {
        guard let key, let entry = all[key] as? [String: Any] else { return true }
        if let on = entry["enabled_services_menu"] as? Bool { return on }
        if let modes = entry["presentation_modes"] as? [String: Any], let on = modes["ServicesMenu"] as? Bool { return on }
        return true
    }

    static func setShown(_ on: Bool) {
        guard let key else { return }
        var status = all
        // On is the default: the entry is removed, which is also what an uninstall leaves.
        status[key] = on ? nil : [
            "enabled_context_menu": false, "enabled_services_menu": false,
            "presentation_modes": ["ContextMenu": false, "ServicesMenu": false],
        ] as [String: Any]
        CFPreferencesSetAppValue(statusKey, status as CFDictionary, domain)
        CFPreferencesAppSynchronize(domain)
        refresh()
        DropLog.write("services: “\(key)” is now \(on ? "shown" : "hidden") in the Services menu")
    }

    /// Has macOS read the Services again, now.
    static func refresh() {
        let pbs = Process()
        pbs.executableURL = URL(fileURLWithPath: "/System/Library/CoreServices/pbs")
        pbs.arguments = ["-update"]
        try? pbs.run()
        NSUpdateDynamicServices()
    }
}

/// Removes this copy of the app and everything it has left on this Mac.
@MainActor
enum Uninstaller {
    /// What is on the disk now and would be removed, for the question and for the log.
    static func found(history: [HistoryEntry]) -> (library: [URL], partials: [URL], app: URL?) {
        let id = Settings.bundleID
        let name = Bundle.main.infoDictionary?["CFBundleName"] as? String ?? "Nimbus Drop"
        let home = FileManager.default.homeDirectoryForCurrentUser
        let library = Leftovers.library(bundleID: id, bundleName: name, home: home)
        let downloads = FileManager.default.urls(for: .downloadsDirectory, in: .userDomainMask)
        let partials = Leftovers.partials(near: history.flatMap(\.savedPaths), also: downloads)
        let bundle = Bundle.main.bundleURL
        return (library, partials, bundle.pathExtension == "app" ? bundle : nil)
    }

    static func ask(model: AppModel) {
        let what = found(history: model.history)
        let paired = model.trust.known.count
        let alert = NSAlert()
        alert.alertStyle = .critical
        alert.messageText = "Uninstall Nimbus Drop?"
        alert.informativeText = """
            This removes the app and everything it has kept on this Mac: this Mac's identity and its pairings, the history of drops, settings, logs, downloaded updates, Open at Login, the Finder service\(what.partials.isEmpty ? "" : ", and \(what.partials.count) unfinished \(what.partials.count == 1 ? "drop" : "drops")").
            \(paired == 0 ? "" : "\nThe \(paired) \(paired == 1 ? "Mac" : "Macs") you are paired with will be told to stop trusting this Mac's identity (those that can be reached now).\n")
            Files you have received stay where they were saved. macOS may go on listing Nimbus Drop under Privacy & Security › Local Network; only macOS can remove that.

            This cannot be undone.
            """
        alert.addButton(withTitle: "Cancel")
        alert.addButton(withTitle: "Uninstall")
        alert.buttons[1].hasDestructiveAction = true
        NSApp.activate(ignoringOtherApps: true)
        guard alert.runModal() == .alertSecondButtonReturn else { return }
        model.retireEverything {
            remove(what)
            NSApp.terminate(nil)
        }
    }

    /// From the command line (`--uninstall`, and `build.sh uninstall` through it): says what
    /// would go; with `--yes`, removes it. The paired Macs are not told from here: the command
    /// line cannot find them, and the app's Settings can.
    static func commandLine(confirmed: Bool) -> Int32 {
        guard Bundle.main.bundleIdentifier != nil else {
            fputs("--uninstall removes the copy it is run from: run the binary inside the app (…/Nimbus Drop.app/Contents/MacOS/NimbusDrop)\n", stderr)
            return 1
        }
        let support = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0].appendingPathComponent(Settings.bundleID)
        let what = found(history: HistoryStore(url: support.appendingPathComponent("history.json")).entries)
        let fm = FileManager.default
        let there = (what.library + what.partials + [what.app].compactMap { $0 }).filter { fm.fileExists(atPath: $0.path) }
        print(confirmed ? "removing:" : "would remove (say --uninstall --yes to do it):")
        for url in there { print("  \(url.path)") }
        print("  Open at Login, the Finder service's setting, notifications, privacy permissions (\(Settings.bundleID))")
        guard confirmed else { return 0 }
        print("Paired Macs are not told from the command line; they go on trusting this Mac's identity until it runs out. Use Settings › Uninstall in the app to have them told.")
        remove(what)
        return 0
    }

    /// The paired Macs have been told. Everything this process can remove while it runs is
    /// removed here; what it holds open or rewrites as it quits (its preferences, its log,
    /// the app itself) is removed by a small script that waits for it to be gone.
    private static func remove(_ what: (library: [URL], partials: [URL], app: URL?)) {
        DropLog.write("uninstall: removing \((what.library + what.partials).map(\.path).joined(separator: ", "))", .warn)
        try? LoginItem.setEnabled(false)
        if ServiceMenu.key != nil { ServiceMenu.setShown(true) }   // which removes its entry
        UNUserNotificationCenter.current().removeAllDeliveredNotifications()
        UNUserNotificationCenter.current().removeAllPendingNotificationRequests()
        let fm = FileManager.default
        for url in what.partials { try? fm.removeItem(at: url) }
        // Beside the app: what the updater leaves while it swaps a new copy in.
        var paths = what.library.map(\.path)
        if let app = what.app {
            let dir = app.deletingLastPathComponent(), stem = "NimbusDrop"
            paths += [dir.appendingPathComponent(".\(stem)-old.app").path, dir.appendingPathComponent(".\(stem)-update.app").path, app.path]
        }
        let script = """
            pid=$1; id=$2; shift 2
            while kill -0 "$pid" 2>/dev/null; do sleep 0.2; done
            defaults delete "$id" >/dev/null 2>&1
            for p in "$@"; do
              case "$p" in *.app) /System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister -u "$p" >/dev/null 2>&1;; esac
              rm -rf "$p"
            done
            tccutil reset All "$id" >/dev/null 2>&1
            /System/Library/CoreServices/pbs -update >/dev/null 2>&1
            """
        let after = Process()
        after.executableURL = URL(fileURLWithPath: "/bin/sh")
        after.arguments = ["-c", script, "sh", "\(ProcessInfo.processInfo.processIdentifier)", Settings.bundleID] + paths
        after.standardOutput = nil
        after.standardError = nil
        try? after.run()
    }
}
