// Copyright (C) 2026 Niels Joubert
// SPDX-License-Identifier: GPL-3.0-or-later
import Foundation
import NimbusBase

/// Closes a socket unless told in time that it has earned its keep.
package final class Deadline: @unchecked Sendable {
    private let lock = NSLock()
    private var generation = 0
    private weak var socket: Socket?

    package init(_ socket: Socket, seconds: Double) {
        self.socket = socket
        arm(seconds)
    }

    /// Starts the clock again, from now.
    package func arm(_ seconds: Double) {
        let mine = lock.withLock { () -> Int in self.generation += 1; return self.generation }
        DispatchQueue.global().asyncAfter(deadline: .now() + seconds) { [weak self] in
            guard let self, self.lock.withLock({ self.generation == mine }) else { return }
            socket?.shutdown()
        }
    }

    package func cancel() { lock.withLock { self.generation += 1 } }
}
