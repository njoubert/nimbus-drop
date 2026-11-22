// Copyright (C) 2026 Niels Joubert
// SPDX-License-Identifier: GPL-3.0-or-later
import AppKit
import NimbusDropCore
import NimbusUpdater

/// The menu bar item: the cloud (hollow when receiving is off, a percentage beside it while a
/// drop moves) and the menu under it. The menu is rebuilt on every open; while it is open only
/// the transfer rows change, in place.
@MainActor
final class StatusBarController: NSObject, NSMenuDelegate {
    private let model: AppModel
    private let updater: Updater?
    private let item: NSStatusItem
    private let menu = NSMenu()
    private var menuOpen = false
    private var transferItems: [UUID: NSMenuItem] = [:]
    private var versionItem: NSMenuItem?
    private var lastBar = ""

    init(model: AppModel, updater: Updater?) {
        self.model = model
        self.updater = updater
        item = NSStatusBar.system.statusItem(withLength: NSStatusItem.variableLength)
        super.init()
        menu.delegate = self
        menu.autoenablesItems = false
        item.menu = menu
        model.onChange = { [weak self] in self?.modelChanged() }
        updateBar()
    }

    // MARK: The bar

    private func modelChanged() {
        updateBar()
        guard menuOpen else { return }
        // Rows under the cursor change in place; a different set of rows waits for the next open.
        for row in model.rows { if let it = transferItems[row.id] { configure(it, row) } }
    }

    private func updateBar() {
        let fraction = model.overallFraction
        let text = fraction.map { String(format: "%.0f%%", $0 * 100) } ?? ""
        let key = "\(model.receiving)|\(text)"
        guard key != lastBar, let button = item.button else { return }
        lastBar = key
        button.image = AppIcon.menuBarImage(dimmed: !model.receiving)
        button.imagePosition = text.isEmpty ? .imageOnly : .imageLeading
        button.attributedTitle = NSAttributedString(string: text.isEmpty ? "" : " " + text, attributes: [
            .font: NSFont.monospacedDigitSystemFont(ofSize: NSFont.systemFontSize(for: .small), weight: .medium)])
        button.toolTip = model.receiving ? "Nimbus Drop: receiving as \(model.identity.name)" : "Nimbus Drop: receiving is off"
    }

    // MARK: The menu

    func menuNeedsUpdate(_ menu: NSMenu) { rebuild() }
    func menuWillOpen(_ menu: NSMenu) { menuOpen = true; updater?.checkIfStale() }
    func menuDidClose(_ menu: NSMenu) { menuOpen = false }

    private func rebuild() {
        menu.removeAllItems()
        transferItems = [:]

        let who = model.identity.name + (model.addresses.first.map { "  ·  \($0.address)" } ?? "  ·  no network")
        menu.addItem(header(who))
        let receive = NSMenuItem(title: "Receive Drops", action: #selector(toggleReceiving), keyEquivalent: "")
        receive.target = self
        receive.state = model.receiving ? .on : .off
        receive.toolTip = "While on, other Macs running Nimbus Drop on this network can see this one and offer it files. Every drop still asks first."
        menu.addItem(receive)
        if let problem = model.problem {
            let it = NSMenuItem(title: "⚠︎ " + problem, action: nil, keyEquivalent: "")
            it.isEnabled = false
            menu.addItem(it)
        }

        if !model.rows.isEmpty {
            menu.addItem(.separator())
            menu.addItem(header("Drops"))
            for row in model.rows.prefix(6) {
                let it = NSMenuItem(title: "", action: #selector(openWindow), keyEquivalent: "")
                it.target = self
                configure(it, row)
                transferItems[row.id] = it
                menu.addItem(it)
            }
        }

        menu.addItem(.separator())
        menu.addItem(header("Send To"))
        if model.peers.isEmpty {
            let none = NSMenuItem(title: "No other Macs found", action: nil, keyEquivalent: "")
            none.isEnabled = false
            none.toolTip = "Nimbus Drop must be running on the other Mac, with Receive Drops on, on the same network."
            menu.addItem(none)
        }
        for peer in model.peers {
            let it = NSMenuItem(title: "\(peer.name)  ·  \(peer.address ?? "finding address…")…", action: #selector(sendTo(_:)), keyEquivalent: "")
            it.target = self
            it.representedObject = peer.id
            it.image = NSImage(systemSymbolName: "laptopcomputer", accessibilityDescription: nil)
            it.toolTip = "Choose files and folders to send to \(peer.name)."
            menu.addItem(it)
        }

        menu.addItem(.separator())
        let open = NSMenuItem(title: "Open Nimbus Drop", action: #selector(openWindow), keyEquivalent: "o")
        open.target = self
        menu.addItem(open)

        let streams = NSMenuItem(title: "Parallel Connections", action: nil, keyEquivalent: "")
        let sub = NSMenu()
        for n in Settings.streamChoices {
            let it = NSMenuItem(title: n == Settings.defaultStreams ? "\(n) (default)" : "\(n)", action: #selector(setStreams(_:)), keyEquivalent: "")
            it.target = self
            it.tag = n
            it.state = Settings.streams == n ? .on : .off
            sub.addItem(it)
        }
        streams.submenu = sub
        streams.toolTip = "How many connections a drop you send is spread over. More helps on fast wired networks and with many small files."
        menu.addItem(streams)

        let login = NSMenuItem(title: "Open at Login", action: #selector(toggleLoginItem(_:)), keyEquivalent: "")
        login.target = self
        login.state = LoginItem.isEnabled ? .on : .off
        login.isEnabled = Bundle.main.bundleIdentifier != nil
        menu.addItem(login)
        addUpdateItems()
        menu.addItem(.separator())

        let version = NSMenuItem(title: Self.versionString(), action: #selector(copyVersion), keyEquivalent: "")
        version.target = self
        version.toolTip = "Click to copy"
        menu.addItem(version)
        versionItem = version
        updateVersionRow()
        menu.addItem(NSMenuItem(title: "Quit Nimbus Drop", action: #selector(NSApplication.terminate(_:)), keyEquivalent: "q"))
    }

    private func header(_ text: String) -> NSMenuItem {
        let it = NSMenuItem(title: text, action: nil, keyEquivalent: "")
        it.isEnabled = false
        it.attributedTitle = NSAttributedString(string: text, attributes: [
            .font: NSFont.menuFont(ofSize: NSFont.smallSystemFontSize), .foregroundColor: NSColor.secondaryLabelColor])
        return it
    }

    /// Two lines: what and who, then how it is going.
    private func configure(_ it: NSMenuItem, _ row: TransferRow) {
        let text = NSMutableAttributedString(string: row.headline + "\n", attributes: [.font: NSFont.menuFont(ofSize: 0)])
        var status = row.status
        if row.isActive, !row.isIndeterminate { status = String(format: "%.0f%% · ", row.fraction * 100) + status }
        text.append(NSAttributedString(string: status, attributes: [
            .font: NSFont.monospacedDigitSystemFont(ofSize: NSFont.smallSystemFontSize, weight: .regular),
            .foregroundColor: row.failed ? NSColor.systemRed : NSColor.secondaryLabelColor]))
        it.attributedTitle = text
        let symbol = row.failed ? "exclamationmark.circle" : (row.direction == .send ? "arrow.up.circle" : "arrow.down.circle")
        it.image = NSImage(systemSymbolName: symbol, accessibilityDescription: nil)
    }

    // MARK: Actions

    @objc private func toggleReceiving() { model.setReceiving(!model.receiving) }

    @objc private func openWindow() { AppDelegate.shared?.showWindow() }

    @objc private func sendTo(_ sender: NSMenuItem) {
        guard let id = sender.representedObject as? String, let peer = model.peers.first(where: { $0.id == id }) else { return }
        model.chooseAndSend(to: peer)
    }

    @objc private func setStreams(_ sender: NSMenuItem) { Settings.streams = sender.tag }

    @objc private func toggleLoginItem(_ sender: NSMenuItem) {
        do {
            try LoginItem.setEnabled(!LoginItem.isEnabled)
            UserDefaults.standard.set(true, forKey: LoginItem.registeredDefaultsKey)
        } catch {
            let alert = NSAlert()
            alert.messageText = "Could not change Open at Login"
            alert.informativeText = error.localizedDescription
            alert.runModal()
        }
    }

    @objc private func copyVersion() {
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(Self.versionString(), forType: .string)
    }

    static func versionString() -> String {
        let info = Bundle.main.infoDictionary
        guard let short = info?["CFBundleShortVersionString"] as? String else { return "Nimbus Drop (dev build)" }
        return "Nimbus Drop v\(short) (\(info?["CFBundleVersion"] as? String ?? "?"))"
    }

    // MARK: Updates (the same rows as the sibling apps; the behaviour lives in NimbusUpdater)

    private func addUpdateItems() {
        guard let updater else { return }
        switch updater.state {
        case .ready(let release) where updater.canInstall:
            let install = NSMenuItem(title: "Install Update \(release.version) and Relaunch", action: #selector(installUpdate), keyEquivalent: "")
            install.target = self
            let firstLines = release.notes.split(separator: "\n").prefix(3).joined(separator: "\n")
            install.toolTip = firstLines.isEmpty ? "Downloaded and checked against this app's Developer ID. Installs in a few seconds." : firstLines
            menu.addItem(install)
        case .available(let release):
            let it = NSMenuItem(title: "Update \(release.version) Available…", action: #selector(openUpdatePage), keyEquivalent: "")
            it.target = self
            it.toolTip = updater.canInstall
                ? "That release has no installable download; this opens its page."
                : "Updates install only into /Applications, and this copy runs from \(Bundle.main.bundlePath). Opens the release page."
            menu.addItem(it)
        case .downloading(let release):
            let it = NSMenuItem(title: "Downloading \(release.version)…", action: nil, keyEquivalent: "")
            it.isEnabled = false
            menu.addItem(it)
        case .installing:
            let it = NSMenuItem(title: "Installing…", action: nil, keyEquivalent: "")
            it.isEnabled = false
            menu.addItem(it)
        default:
            break
        }
        let check = NSMenuItem(title: "Check for Updates…", action: #selector(checkForUpdates), keyEquivalent: "")
        check.target = self
        switch updater.state {
        case .checking, .downloading, .installing: check.isEnabled = false
        default: break
        }
        menu.addItem(check)
        if updater.canInstall {
            let auto = NSMenuItem(title: "Check for Updates Automatically", action: #selector(toggleAutomaticUpdates(_:)), keyEquivalent: "")
            auto.target = self
            auto.state = updater.automaticChecks ? .on : .off
            auto.toolTip = "Once a day, asks github.com for the newest release and downloads it."
            menu.addItem(auto)
        }
    }

    func updaterChanged() {
        guard menuOpen else { return }
        updateVersionRow()
    }

    private func updateVersionRow() {
        guard let item = versionItem else { return }
        var text = Self.versionString()
        if let updater, case .ready(let release) = updater.state { text += "  ·  \(release.version) ready" }
        item.attributedTitle = NSAttributedString(string: text, attributes: [
            .font: NSFont.menuFont(ofSize: NSFont.smallSystemFontSize), .foregroundColor: NSColor.secondaryLabelColor])
    }

    @objc private func installUpdate() { updater?.installAndRelaunch() }
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

    // MARK: Layout check

    /// The status item's three looks side by side on a menu-bar-coloured strip, light and dark.
    static func dumpBar(to path: String) -> Bool {
        let cells: [(Bool, String)] = [(true, ""), (false, ""), (true, " 42%")]
        let size = NSSize(width: 240, height: 56)
        guard let rep = NSBitmapImageRep(bitmapDataPlanes: nil, pixelsWide: Int(size.width) * 2, pixelsHigh: Int(size.height) * 2,
                                         bitsPerSample: 8, samplesPerPixel: 4, hasAlpha: true, isPlanar: false,
                                         colorSpaceName: .deviceRGB, bytesPerRow: 0, bitsPerPixel: 0) else { return false }
        rep.size = size
        NSGraphicsContext.saveGraphicsState()
        NSGraphicsContext.current = NSGraphicsContext(bitmapImageRep: rep)
        for (rowIndex, dark) in [false, true].enumerated() {
            let y = CGFloat(rowIndex) * 28
            (dark ? NSColor(white: 0.12, alpha: 1) : NSColor(white: 0.93, alpha: 1)).setFill()
            NSRect(x: 0, y: y, width: size.width, height: 28).fill()
            let ink = dark ? NSColor.white : NSColor.black
            var x: CGFloat = 16
            for (receiving, text) in cells {
                let glyph = AppIcon.menuBarImage(dimmed: !receiving)
                let tinted = NSImage(size: glyph.size, flipped: false) { r in
                    glyph.draw(in: r)
                    ink.set()
                    r.fill(using: .sourceAtop)
                    return true
                }
                tinted.draw(in: NSRect(x: x, y: y + 5, width: glyph.size.width, height: glyph.size.height))
                x += glyph.size.width
                NSAttributedString(string: text, attributes: [
                    .font: NSFont.monospacedDigitSystemFont(ofSize: NSFont.systemFontSize(for: .small), weight: .medium),
                    .foregroundColor: ink]).draw(at: NSPoint(x: x, y: y + 7))
                x += 56
            }
        }
        NSGraphicsContext.restoreGraphicsState()
        guard let data = rep.representation(using: .png, properties: [:]) else { return false }
        do { try data.write(to: URL(fileURLWithPath: path)) } catch { return false }
        print("wrote \(path)")
        return true
    }
}
