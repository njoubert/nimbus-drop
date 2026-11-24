// Copyright (C) 2026 Niels Joubert
// SPDX-License-Identifier: GPL-3.0-or-later

// The whole engine under one name, for the app and the tests: `import NimbusDropCore` is every
// module below it. What is left in this module itself is what only an app needs of the engine
// (the history of drops, the kinds of file in one, what a copy leaves on a Mac).
//
// The modules, and what each may depend on, are in Package.swift; `scripts/check-layers.py`
// holds each to the system frameworks it is allowed.
@_exported import NimbusBase
@_exported import NimbusCrypto
@_exported import NimbusDiscovery
@_exported import NimbusNet
@_exported import NimbusRuntime
@_exported import NimbusSafeStorageCore
@_exported import NimbusSecurityCore
@_exported import NimbusTransferCore
