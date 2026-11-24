// Copyright (C) 2026 Niels Joubert
// SPDX-License-Identifier: GPL-3.0-or-later
import Foundation

/// Text from another machine, made fit to show and to log: a host name, a file name, a reason.
public enum Sanitize {
    /// One line of bounded length: control characters (newlines among them, which could forge
    /// a line of the log or push the real text out of a panel) become spaces.
    public static func label(_ text: String, limit: Int = 200) -> String {
        let cleaned = String(String.UnicodeScalarView(text.unicodeScalars.map {
            $0.properties.generalCategory == .control || $0.properties.generalCategory == .lineSeparator
                || $0.properties.generalCategory == .paragraphSeparator ? " " : $0
        }))
        let trimmed = cleaned.trimmingCharacters(in: .whitespaces)
        return trimmed.count > limit ? String(trimmed.prefix(limit)) + "…" : trimmed
    }
}
