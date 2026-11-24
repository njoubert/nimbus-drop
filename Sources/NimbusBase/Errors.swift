// Copyright (C) 2026 Niels Joubert
// SPDX-License-Identifier: GPL-3.0-or-later
import Darwin
import Foundation

/// The one error type the engine throws; its message is what the user reads.
public struct DropError: Error, CustomStringConvertible, LocalizedError, Equatable {
    public let message: String
    /// The link's fault rather than anybody's decision: the connection closed, timed out, could
    /// not be made, or carried a damaged message. These are what a drop tries to reconnect after.
    package var connection = false
    /// The two Macs are not paired (or no longer are): pair, then send again.
    public var needsPairing = false
    /// The Mac that answered is not the one that was meant.
    public var identity = false
    public init(_ message: String) { self.message = message }
    package init(_ message: String, connection: Bool) { self.message = message; self.connection = connection }
    public static func == (a: DropError, b: DropError) -> Bool { a.message == b.message }
    public var description: String { message }
    public var errorDescription: String? { message }
}

package func errnoError(_ what: String) -> DropError {
    DropError("\(what): \(String(cString: strerror(errno)))")
}
