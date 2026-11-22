// Copyright (C) 2026 Niels Joubert
// SPDX-License-Identifier: GPL-3.0-or-later
import AppKit
import SwiftUI

/// The Nimbus colours, as the app icons draw them: the blue of the upload arrow and the green of
/// the download arrow, and a red and an amber chosen to sit beside them. Light mode gets its own
/// values: nearly as bright (the first, deeper set looked drab on white), a touch more saturated
/// so they hold against a pale background.
enum Palette {
    /// Sending: the upload blue (#3AA8FF in the icons).
    static let send = dynamic(dark: 0x3AA8FF, light: 0x1C96FF)
    /// Receiving: the download green (#3DE89C in the icons).
    static let receive = dynamic(dark: 0x3DE89C, light: 0x12CC82)
    /// Something stopped: a coral rather than the system's signal red.
    static let failure = dynamic(dark: 0xFF6F61, light: 0xFF5546)
    /// Something needs attention: the amber of Nimbus UPS Bar's outage bands (#FAB219).
    static let warning = dynamic(dark: 0xFAB219, light: 0xF29D00)

    private static func dynamic(dark: Int, light: Int) -> Color {
        Color(nsColor: NSColor(name: nil) { appearance in
            let hex = appearance.bestMatch(from: [.aqua, .darkAqua]) == .darkAqua ? dark : light
            return NSColor(srgbRed: CGFloat(hex >> 16 & 0xFF) / 255, green: CGFloat(hex >> 8 & 0xFF) / 255,
                           blue: CGFloat(hex & 0xFF) / 255, alpha: 1)
        })
    }
}
