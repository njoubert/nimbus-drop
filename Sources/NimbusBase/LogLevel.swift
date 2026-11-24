// Copyright (C) 2026 Niels Joubert
// SPDX-License-Identifier: GPL-3.0-or-later
import Foundation

/// How much a log line matters. Set where the line is written, by what it reports; nothing
/// downstream guesses it from the words ("0 damaged, connections lost 0" is a good drop).
///
/// - `debug`: detail for following the engine step by step (connections opened, what a round
///   sent, where a partial folder is).
/// - `info`: the story of a drop and of the network as a person would tell it (offered,
///   accepted, moving, done; a Mac found or gone).
/// - `warn`: trouble the drop is getting past (a connection lost, a damaged chunk, the control
///   connection gone and being won back, a reconnect attempt that did not get through).
/// - `error`: trouble that ended something (a drop failed, reconnecting given up, cannot listen).
public enum LogLevel: Int, Comparable, CaseIterable, Sendable {
    case debug, info, warn, error

    public static func < (a: LogLevel, b: LogLevel) -> Bool { a.rawValue < b.rawValue }

    /// As it is written in the log file: a fixed five columns.
    public var label: String {
        switch self {
        case .debug: return "DEBUG"
        case .info: return "INFO "
        case .warn: return "WARN "
        case .error: return "ERROR"
        }
    }

    public init?(label: String) {
        switch label.trimmingCharacters(in: .whitespaces) {
        case "DEBUG": self = .debug
        case "INFO": self = .info
        case "WARN": self = .warn
        case "ERROR": self = .error
        default: return nil
        }
    }
}
