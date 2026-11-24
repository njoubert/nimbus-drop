// Copyright (C) 2026 Niels Joubert
// SPDX-License-Identifier: GPL-3.0-or-later
import Darwin
import Foundation
import NimbusBase

/// The last system call's failure, as an error a person can read. It reads `errno`, which is
/// why it is here and not beside `DropError`: the pure module can name the error and cannot
/// ask the system what went wrong.
package func errnoError(_ what: String) -> DropError {
    DropError("\(what): \(String(cString: strerror(errno)))")
}
