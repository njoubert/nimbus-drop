// Copyright (C) 2026 Niels Joubert
// SPDX-License-Identifier: GPL-3.0-or-later
import Foundation
import NimbusBase

/// The receiver's answer to a manifest: what it already holds from an earlier attempt.
package struct Plan: Codable {
    package struct Partial: Codable { package var file: Int; package var chunks: [Int] }
    package var completeFiles: [Int]
    package var partialFiles: [Partial]
}
