// Copyright (C) 2026 Niels Joubert
// SPDX-License-Identifier: GPL-3.0-or-later
import Foundation
import NimbusBase
import NimbusCrypto
import NimbusNet

/// Who this Mac says it is: the name others see and an id that stays the same across launches
/// (it is what lets a re-sent drop be recognised, and how a Mac leaves itself out of its own list).
public struct Identity: Equatable, Sendable {
    public var name: String
    public var id: String
    /// The app's version, for the other side to show; "dev" for a bare binary.
    public var appVersion: String
    public init(name: String, id: String, appVersion: String = "dev") {
        self.name = name
        self.id = id
        self.appVersion = appVersion
    }
}
