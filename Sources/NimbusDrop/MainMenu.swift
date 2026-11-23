// Copyright (C) 2026 Niels Joubert
// SPDX-License-Identifier: GPL-3.0-or-later
import AppKit
import NimbusDropCore
import NimbusUpdater

/// The app's own menu bar, shown while the window is open. An LSUIElement app has none until it
/// builds one, and without it ⌘W, ⌘Q and ⌘C do nothing. Its first menu is `fill`, the one list
/// that is also the menu bar icon's right-click menu.
@MainActor
final class MainMenu: NSObject, NSMenuDelegate {
    private let model: AppModel
    private let updater: Updater?
    private let appMenu = NSMenu()

    init(model: AppModel, updater: Updater?) {
        self.model = model
        self.updater = updater
        super.init()
        let main = NSMenu()
        let appItem = NSMenuItem()
        appMenu.delegate = self
        appMenu.autoenablesItems = false
        appItem.submenu = appMenu
        main.addItem(appItem)

        let fileItem = NSMenuItem()
        let file = NSMenu(title: "File")
        file.addItem(withTitle: "Add Destination by Address…", action: #selector(AppDelegate.addByAddress), keyEquivalent: "n")
        file.addItem(.separator())
        file.addItem(withTitle: "Close", action: #selector(NSWindow.performClose(_:)), keyEquivalent: "w")
        fileItem.submenu = file
        main.addItem(fileItem)

        let editItem = NSMenuItem()
        let edit = NSMenu(title: "Edit")
        edit.addItem(withTitle: "Cut", action: #selector(NSText.cut(_:)), keyEquivalent: "x")
        edit.addItem(withTitle: "Copy", action: #selector(NSText.copy(_:)), keyEquivalent: "c")
        edit.addItem(withTitle: "Paste", action: #selector(NSText.paste(_:)), keyEquivalent: "v")
        edit.addItem(withTitle: "Select All", action: #selector(NSText.selectAll(_:)), keyEquivalent: "a")
        editItem.submenu = edit
        main.addItem(editItem)

        let windowItem = NSMenuItem()
        let window = NSMenu(title: "Window")
        window.addItem(withTitle: "Minimize", action: #selector(NSWindow.performMiniaturize(_:)), keyEquivalent: "m")
        windowItem.submenu = window
        main.addItem(windowItem)
        NSApp.mainMenu = main
        rebuild()
    }

    func menuNeedsUpdate(_ menu: NSMenu) {
        updater?.checkIfStale()
        rebuild()
    }

    private func rebuild() { fill(appMenu) }

    /// THE menu: everything the app offers outside its window. The app's own menu (under its
    /// name, while the window is open) and the right-click menu on the menu bar icon are both
    /// filled by this one function, so they are the same list by construction. Add an item
    /// here and it is in both.
    func fill(_ menu: NSMenu) {
        menu.removeAllItems()
        menu.autoenablesItems = false
        func add(_ title: String, _ action: Selector, key: String = "", target: AnyObject? = nil, on: Bool? = nil, enabled: Bool = true) {
            let item = NSMenuItem(title: title, action: action, keyEquivalent: key)
            item.target = target
            if let on { item.state = on ? .on : .off }
            item.isEnabled = enabled
            menu.addItem(item)
        }
        let version = NSMenuItem(title: StatusBarController.versionString(), action: #selector(copyVersion), keyEquivalent: "")
        version.target = self
        version.toolTip = "Click to copy"
        menu.addItem(version)
        menu.addItem(.separator())

        add("Open Nimbus Drop", #selector(AppDelegate.showWindow), key: "o", target: AppDelegate.shared)
        add("Receive Drops", #selector(toggleReceiving), key: "r", target: self, on: model.receiving)
        add("Open at Login", #selector(toggleLoginItem), target: self, on: LoginItem.isEnabled, enabled: Bundle.main.bundleIdentifier != nil)
        menu.addItem(.separator())

        add("History…", #selector(AppDelegate.showHistory), key: "y", target: AppDelegate.shared)
        add("Internals…", #selector(AppDelegate.showInternals), key: "i", target: AppDelegate.shared)
        add("Settings…", #selector(AppDelegate.showSettings), key: ",", target: AppDelegate.shared)
        menu.addItem(.separator())

        addUpdateItems(to: menu)
        menu.addItem(.separator())
        menu.addItem(withTitle: "Hide Nimbus Drop", action: #selector(NSApplication.hide(_:)), keyEquivalent: "h")
        menu.addItem(withTitle: "Quit Nimbus Drop", action: #selector(NSApplication.terminate(_:)), keyEquivalent: "q")
    }

    @objc private func toggleReceiving() { model.setReceiving(!model.receiving) }
    @objc private func toggleLoginItem() { model.setOpenAtLogin(!LoginItem.isEnabled) }
    @objc private func copyVersion() {
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(StatusBarController.versionString(), forType: .string)
    }

    // MARK: Updates (the same rows as the sibling apps; the behaviour lives in NimbusUpdater)

    private func addUpdateItems(to appMenu: NSMenu) {
        guard let updater else {
            let none = NSMenuItem(title: "Updates need the installed app", action: nil, keyEquivalent: "")
            none.isEnabled = false
            appMenu.addItem(none)
            return
        }
        switch updater.state {
        case .ready(let release) where updater.canInstall:
            let install = NSMenuItem(title: "Install Update \(release.version) and Relaunch", action: #selector(installUpdate), keyEquivalent: "")
            install.target = self
            appMenu.addItem(install)
        case .available(let release):
            let it = NSMenuItem(title: "Update \(release.version) Available…", action: #selector(openUpdatePage), keyEquivalent: "")
            it.target = self
            it.toolTip = updater.canInstall
                ? "That release has no installable download; this opens its page."
                : "Updates install only into /Applications, and this copy runs from \(Bundle.main.bundlePath). Opens the release page."
            appMenu.addItem(it)
        case .downloading(let release):
            let it = NSMenuItem(title: "Downloading \(release.version)…", action: nil, keyEquivalent: "")
            it.isEnabled = false
            appMenu.addItem(it)
        case .installing:
            let it = NSMenuItem(title: "Installing…", action: nil, keyEquivalent: "")
            it.isEnabled = false
            appMenu.addItem(it)
        default:
            break
        }
        let check = NSMenuItem(title: "Check for Updates…", action: #selector(checkForUpdates), keyEquivalent: "")
        check.target = self
        switch updater.state {
        case .checking, .downloading, .installing: check.isEnabled = false
        default: break
        }
        appMenu.addItem(check)
        if updater.canInstall {
            let auto = NSMenuItem(title: "Check for Updates Automatically", action: #selector(toggleAutomaticUpdates(_:)), keyEquivalent: "")
            auto.target = self
            auto.state = updater.automaticChecks ? .on : .off
            auto.toolTip = "Once a day, asks github.com for the newest release and downloads it."
            appMenu.addItem(auto)
        }
    }

    /// The updater moved: the window's footer says when a version is ready to install.
    func updaterChanged() {
        if let updater, case .ready(let release) = updater.state, updater.canInstall {
            model.updateReady = "\(release.version)"
        } else {
            model.updateReady = nil
        }
    }

    @objc func installUpdate() { updater?.installAndRelaunch() }
    @objc private func openUpdatePage() { updater?.openReleasePage() }
    @objc private func toggleAutomaticUpdates(_ sender: NSMenuItem) {
        guard let updater else { return }
        updater.automaticChecks.toggle()
        sender.state = updater.automaticChecks ? .on : .off
    }
    @objc private func checkForUpdates() {
        guard let updater else { return }
        Task { @MainActor in updater.presentCheckResult(await updater.checkNow()) }
    }
}
