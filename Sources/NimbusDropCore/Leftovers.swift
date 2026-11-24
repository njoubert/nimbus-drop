// Copyright (C) 2026 Niels Joubert
// SPDX-License-Identifier: GPL-3.0-or-later
import Foundation
import NimbusBase
import NimbusCrypto
import NimbusNet
import NimbusSafeStorageCore
import NimbusSecurityCore
import NimbusDiscovery
import NimbusTransferCore

/// Everything a copy of the app leaves on a Mac, for the uninstaller to remove: one list, so
/// that what is kept and what is cleaned up cannot drift apart. Something new that the app
/// writes outside a drop's destination belongs here.
public enum Leftovers {
    public static let releaseID = "com.njoubert.nimbusdrop"

    /// What the copy with this bundle identifier and name keeps under `home`/Library, whether
    /// or not each is there now.
    public static func library(bundleID: String, bundleName: String, home: URL) -> [URL] {
        let lib = home.appendingPathComponent("Library")
        var paths = [
            "Application Support/\(bundleID)",        // identity, Known Macs, history, the command line's identities
            "Caches/\(bundleID)",                     // the updater's downloads
            "HTTPStorages/\(bundleID)",
            "HTTPStorages/\(bundleID).binarycookies",
            "Cookies/\(bundleID).binarycookies",
            "Saved Application State/\(bundleID).savedState",
            "WebKit/\(bundleID)",
            "Logs/\(bundleName)",
            "Preferences/\(bundleID).plist",
        ]
        if bundleID == releaseID {
            // The binary run bare from a terminal has no bundle: its identities and settings
            // go under these names. They belong to the released app, not to a development copy.
            paths += ["Application Support/\(releaseID).cli", "Preferences/NimbusDrop.plist"]
        }
        return paths.map { lib.appendingPathComponent($0) }
    }

    /// Folders of drops that never finished, beside things that were saved (`saved`: paths of
    /// received items, from the history) and in `also`. Only a folder whose name is exactly
    /// what a receiver gives a partial folder is listed: "<label>.<32 hex digits>.nimbusdrop-partial".
    public static func partials(near saved: [String], also: [URL]) -> [URL] {
        var parents = Set(also.map(\.standardizedFileURL))
        for s in saved { parents.insert(URL(fileURLWithPath: s).deletingLastPathComponent().standardizedFileURL) }
        var found: [URL] = []
        for dir in parents.sorted(by: { $0.path < $1.path }) {
            let names = (try? FileManager.default.contentsOfDirectory(atPath: dir.path)) ?? []
            for name in names.sorted() where isPartial(name) {
                let url = dir.appendingPathComponent(name)
                var isDir: ObjCBool = false
                if FileManager.default.fileExists(atPath: url.path, isDirectory: &isDir), isDir.boolValue { found.append(url) }
            }
        }
        return found
    }

    static func isPartial(_ name: String) -> Bool {
        name.range(of: #"^.+\.[0-9a-f]{32}\.nimbusdrop-partial$"#, options: .regularExpression) != nil
    }

    /// The name macOS keeps a Service's on/off state under (in the `pbs` preferences):
    /// "<bundle id> - <menu item> - <message>".
    public static func serviceKey(bundleID: String, bundleName: String) -> String {
        "\(bundleID) - \(bundleName) To… - dropService"
    }
}
