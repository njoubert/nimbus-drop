// Copyright (C) 2026 Niels Joubert
// SPDX-License-Identifier: GPL-3.0-or-later
import Foundation

/// Text from another machine, made fit to show and to log: a host name, a file name, a reason.
public enum Sanitize {
    /// One line of bounded length: control characters (newlines among them, which could forge
    /// a line of the log or push the real text out of a panel) become spaces. And characters
    /// that are not seen but change what is (`invisible`) are left out: with a right-to-left
    /// override a file can show as "invoice-exe.pdf" and be "invoice-fdp.exe", and the name
    /// of a Mac can read as another's.
    public static func label(_ text: String, limit: Int = 200) -> String {
        let cleaned = String(String.UnicodeScalarView(text.unicodeScalars.compactMap { scalar -> Unicode.Scalar? in
            if invisible(scalar) { return nil }
            let category = scalar.properties.generalCategory
            return category == .control || category == .lineSeparator || category == .paragraphSeparator ? " " : scalar
        }))
        let trimmed = cleaned.trimmingCharacters(in: .whitespaces)
        return trimmed.count > limit ? String(trimmed.prefix(limit)) + "…" : trimmed
    }

    /// Format characters: the marks, embeddings, overrides and isolates that set the direction
    /// text runs in, the zero-width space and its kin, the soft hyphen, the tag characters.
    /// Kept: the zero-width joiner and non-joiner, which Persian, Indic scripts and emoji need
    /// to be written properly (comparing names ignores those too: `comparable`).
    public static func invisible(_ scalar: Unicode.Scalar) -> Bool {
        scalar.properties.generalCategory == .format && scalar != "\u{200C}" && scalar != "\u{200D}"
    }

    /// For comparing one name with another: nothing that cannot be seen, joiners included.
    public static func comparable(_ text: String) -> String {
        String(String.UnicodeScalarView(text.unicodeScalars.filter { $0.properties.generalCategory != .format && !$0.properties.isDefaultIgnorableCodePoint }))
    }
}
