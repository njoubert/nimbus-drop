// Copyright (C) 2026 Niels Joubert
// SPDX-License-Identifier: GPL-3.0-or-later
import AppKit
import NimbusDropCore

/// The menu bar item: the cloud (hollow when receiving is off, a percentage beside it while a
/// drop moves). A click opens the window, which is where files are dropped and where everything
/// else lives; a click while the window is in front closes it again. A right-click brings the
/// app's menu: the same list `MainMenu.fill` puts under the app's name, from the same function.
@MainActor
final class StatusBarController: NSObject {
    private let model: AppModel
    private let item: NSStatusItem
    private var lastBar = ""

    init(model: AppModel) {
        self.model = model
        item = NSStatusBar.system.statusItem(withLength: NSStatusItem.variableLength)
        super.init()
        item.button?.target = self
        item.button?.action = #selector(clicked)
        item.button?.sendAction(on: [.leftMouseUp, .rightMouseUp])
        model.onChange = { [weak self] in self?.updateBar() }
        updateBar()
    }

    /// A click opens (or closes) the window. A right-click, or a control-click, brings a short
    /// menu: the things worth doing without opening it.
    @objc private func clicked() {
        let event = NSApp.currentEvent
        guard event?.type == .rightMouseUp || event?.modifierFlags.contains(.control) == true else {
            AppDelegate.shared?.toggleWindow()
            return
        }
        // The same list as the app's own menu, from the same function (MainMenu.fill).
        let menu = NSMenu()
        AppDelegate.shared?.menu.fill(menu)
        // A status item with a menu set shows it on every click; set it for this click only.
        item.menu = menu
        item.button?.performClick(nil)
        item.menu = nil
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
        button.toolTip = model.receiving ? "Nimbus Drop: receiving as \(model.identity.name). Click to open."
                                         : "Nimbus Drop: receiving is off. Click to open."
    }

    static func versionString() -> String {
        let info = Bundle.main.infoDictionary
        guard let short = info?["CFBundleShortVersionString"] as? String else { return "Nimbus Drop (dev build) · protocol \(protocolVersionText)" }
        return "Nimbus Drop v\(short) (\(info?["CFBundleVersion"] as? String ?? "?")) · protocol \(protocolVersionText)"
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
