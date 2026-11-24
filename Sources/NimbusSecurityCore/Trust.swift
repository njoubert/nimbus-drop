// Copyright (C) 2026 Niels Joubert
// SPDX-License-Identifier: GPL-3.0-or-later
import Darwin
import Foundation
import NimbusBase
import NimbusCrypto
import NimbusNet

/// Where the time comes from. The calendar can be set by anyone who controls a time server, so
/// lifetimes are counted on `continuous`, which runs through sleep and cannot be set.
public protocol TrustClock: Sendable {
    /// Changes at every boot.
    var bootSession: String { get }
    /// Seconds since boot, sleep included.
    var continuous: Double { get }
    var wall: Date { get }
}

public struct SystemClock: TrustClock {
    public init() {}
    public var bootSession: String {
        var size = 0
        sysctlbyname("kern.bootsessionuuid", nil, &size, nil, 0)
        var buffer = [CChar](repeating: 0, count: max(size, 1))
        sysctlbyname("kern.bootsessionuuid", &buffer, &size, nil, 0)
        return String(cString: buffer)
    }
    public var continuous: Double {
        var info = mach_timebase_info_data_t()
        mach_timebase_info(&info)
        return Double(mach_continuous_time()) * Double(info.numer) / Double(info.denom) / 1e9
    }
    public var wall: Date { Date() }
}

/// Where the trust file is kept. `EnclaveStorage` for the app; `MemoryStorage` for tests.
public protocol TrustStorage: Sendable {
    /// The stored bytes, or nil on a first run. Throws `TrustFault` otherwise.
    func load() throws -> Data?
    /// Replaces what is stored, durably: when this returns, it is on the disk.
    func save(_ data: Data) throws
    /// Moves what is stored out of the way, untouched, so that a fresh start can be made.
    func setAside(_ label: String)
}

/// Why the trust file could not be read. The reasons are kept apart because the right response
/// differs: only the first is a reason to start afresh without asking.
public enum TrustFault: Error, Equatable {
    /// The files were made on other hardware (migration, a restored backup).
    case foreign
    /// The Secure Enclave cannot be used right now. Nothing is regenerated.
    case unavailable(String)
    /// The file is there and will not open. Kept; the person decides.
    case damaged
}

public final class MemoryStorage: TrustStorage, @unchecked Sendable {
    private let lock = NSLock()
    private var data: Data?
    public private(set) var saves = 0
    /// Tests: what `load` throws.
    public var fault: TrustFault?
    public init(_ data: Data? = nil) { self.data = data }
    public func load() throws -> Data? { try lock.withLock { if let fault { throw fault }; return data } }
    /// Tests: every write fails, as on a full disk.
    public var failSaves = false
    public func save(_ data: Data) throws {
        try lock.withLock {
            if failSaves { throw DropError("No space left on device") }
            self.data = data; saves += 1
        }
    }
    public func setAside(_ label: String) { lock.withLock { data = nil; fault = nil } }
    public var stored: Data? { lock.withLock { data } }
}

/// Something a key authenticated and that must end when trust in that key does: a drop in
/// either direction, a speed test. The trust store knows no more of it than this; what a
/// session is and does is the transfer core's business.
package protocol TrustedSession: AnyObject {
    /// Over, however it ended.
    var isFinal: Bool { get }
    /// Asked about and not yet answered: nothing has begun.
    var isWaitingForAccept: Bool { get }
    func log(_ message: @autoclosure () -> String, _ level: LogLevel)
    /// The key that authenticated it is no longer trusted. Ends it now, and its keys with it.
    func withdrawn(_ error: DropError)
}

/// This Mac's identity and everything it knows about other Macs' identities: one object, one
/// file, one atomic write per change.
///
/// Thread-safe. Nothing here touches a socket; the sessions ask it who a key is and tell it
/// what happened.
///
/// Every decision is `TrustCore`'s (in `NimbusCrypto`: pure, and held equal to its formal
/// model). What is here is what a decision cannot be a function of: the lock, the clock, the
/// disk, the sessions themselves, and the order in which what was decided is carried out
/// (`perform`): the file is written with the lock held; sessions are ended and listeners told
/// once it is free.
public final class Trust: @unchecked Sendable {
    public static let lifetimes: [Double] = TrustCore.lifetimes
    public static let longestLifetime: Double = TrustCore.longestLifetime

    private let lock = NSRecursiveLock()
    private var depth = 0
    /// What a change under the lock leaves to be done once the lock is free: ending sessions
    /// and telling the listeners, both of which reach sockets. Run in the order they were set
    /// down, on the thread that made the change, before its call returns.
    private var afterwards: [() -> Void] = []
    /// Something a window shows changed; `onChange` is called once the lock is free.
    private var changed = false

    /// Everything here runs under the one lock, through this. The work a change leaves for
    /// afterwards is done when the outermost call lets go. Ending a session with the lock held
    /// stopped the whole store for good once: a sender blocked writing to a Mac that had
    /// stopped reading held its channel, the farewell waited on the channel, and every
    /// question about any key waited on the lock (the review of 2026-11-23, F7).
    private func locked<T>(_ body: () throws -> T) rethrows -> T {
        lock.lock()
        depth += 1
        defer {
            depth -= 1
            var run: [() -> Void] = []
            var notify = false
            if depth == 0 { run = afterwards; afterwards = []; notify = changed; changed = false }
            lock.unlock()
            for r in run { r() }
            if notify { onChange?() }
        }
        return try body()
    }
    private var core: TrustCore
    private let storage: TrustStorage
    private let clock: TrustClock
    /// Live sessions by the number the core knows each by.
    private var table: [Int: () -> TrustedSession?] = [:]
    private var nextSession = 0
    private var watchers: [(PublicKey) -> Void] = []
    /// One pairing at a time on this Mac, whoever started it.
    package let gate = PairingGate()

    /// Called (on whatever thread made the change, with the store unlocked) after anything a
    /// window would show changes.
    public var onChange: (@Sendable () -> Void)?
    /// What happened to the stored identity at launch, for the app to say once: nil, or
    /// "foreign" when files from other hardware were set aside.
    public private(set) var startNote: String?

    /// Opens the stored identity, or makes one on a first run. Throws `TrustFault.unavailable`
    /// or `.damaged`, on which nothing has been changed: see `startFresh`.
    public init(storage: TrustStorage, clock: TrustClock = SystemClock(), lifetime: Double = Trust.longestLifetime) throws {
        self.storage = storage
        self.clock = clock
        var loaded: Data?
        do { loaded = try storage.load() } catch TrustFault.foreign {
            storage.setAside("from-another-mac")
            startNote = "foreign"
            DropLog.write("identity: the stored identity was made on other hardware; it was set aside and a new one made", .warn)
        }
        if let loaded {
            guard let stored = TrustCore(decoding: loaded) else { throw TrustFault.damaged }
            core = stored
        } else {
            core = TrustCore(fresh: ClockReading(boot: clock.bootSession, continuous: clock.continuous, wall: clock.wall), lifetime: lifetime)
            try storage.save(try core.encoded())
            DropLog.write("identity: made this Mac's key \(core.pair.publicKey.tag), good for \(Format.lifetime(core.lifetime))")
        }
        tick()
    }

    /// After `TrustFault.damaged`, by the person's explicit choice: the damaged file is kept
    /// under another name and a new identity is made. The record of retired and expired keys is
    /// lost with it, which is why this is never done without asking.
    public static func startFresh(storage: TrustStorage, clock: TrustClock = SystemClock()) throws -> Trust {
        storage.setAside("damaged")
        DropLog.write("identity: starting afresh at the person's request; the record of retired identities is lost", .warn)
        return try Trust(storage: storage, clock: clock)
    }

    /// A trust store that lives only in memory: tests, and tools that have no business with a
    /// stored identity.
    public static func inMemory(clock: TrustClock = SystemClock(), lifetime: Double = Trust.longestLifetime) -> Trust {
        // Memory storage cannot fail.
        // swiftlint:disable:next force_try
        try! Trust(storage: MemoryStorage(), clock: clock, lifetime: lifetime)
    }

    // MARK: Carrying out what the core decided

    /// With the lock held. The file is written here and now; whatever reaches a socket is set
    /// down for when the lock is free, in the order the core gave.
    private func perform(_ effects: [TrustCore.Effect]) {
        for effect in effects {
            switch effect {
            case .save: save()
            case .end(let ending):
                let found = ending.sessions.compactMap { table[$0]?() }
                afterwards.append {
                    for t in found where !t.isFinal && (!ending.ifStillWaiting || t.isWaitingForAccept) {
                        t.log(ending.log, .warn)
                        t.withdrawn(DropError(ending.message))
                    }
                }
            case .tell(let key):
                let all = watchers
                afterwards.append { for w in all { w(key) } }
            case .log(let line, let level): DropLog.write(line, level)
            case .changed: changed = true
            }
        }
        // What the core no longer lists is no longer kept here.
        if table.count != core.sessions.count { table = table.filter { id, _ in core.sessions.contains { $0.id == id } } }
    }

    /// With the lock held: the clocks read once, the time counted, whatever has run out ended.
    @discardableResult
    private func ticked() -> ClockReading {
        let now = ClockReading(boot: clock.bootSession, continuous: clock.continuous, wall: clock.wall)
        var gone = Set<Int>(), waiting = Set<Int>()
        for (id, session) in table {
            guard let t = session(), !t.isFinal else { gone.insert(id); continue }
            if t.isWaitingForAccept { waiting.insert(id) }
        }
        core.prune(gone)
        perform(core.tick(now, waiting: waiting))
        return now
    }

    // MARK: This Mac

    /// This Mac's key as it is now: one that has reached its end is replaced before it is handed out.
    package var keyPair: KeyPair { locked { ticked(); return core.pair } }
    public var publicKey: PublicKey { locked { ticked(); return core.pair.publicKey } }
    public var made: Date { locked { core.made } }
    public var lifetime: Double { locked { core.lifetime } }
    /// Seconds this Mac's key has left.
    public var remaining: Double {
        locked {
            // The clocks first, then the question: `core.remaining(wall: ticked().wall)` would
            // read the core before the tick that the argument makes.
            let now = ticked()
            return core.remaining(wall: now.wall)
        }
    }
    /// When this Mac's key ends, as a date to show.
    public var ends: Date { clock.wall.addingTimeInterval(remaining) }
    public var requestsOff: Bool {
        get { locked { core.requestsOff } }
        set { locked { perform(core.setRequestsOff(newValue)) } }
    }

    /// How long keys made from now on last. A current key already older than that is replaced now.
    public func setLifetime(_ seconds: Double) {
        locked {
            ticked()
            perform(core.setLifetime(seconds))
            ticked()
        }
    }

    // MARK: Time

    /// Counts the time that has passed, ends whatever has run out, and now and then writes the
    /// count down. Cheap; called before every decision that depends on a date.
    public func tick() { locked { _ = ticked() } }

    // MARK: Other Macs

    public var known: [KnownMac] { locked { core.known } }
    public var again: [Renewal] { locked { core.again } }
    public var tombstones: [Tombstone] { locked { core.tombstones } }

    /// The one Known Mac a person means by `text`: the name this Mac has for it (which no other
    /// Known Mac shares), or its key tag. Never what a Mac on the network calls itself.
    public func knownMac(called text: String) -> KnownMac? { locked { ticked(); return core.knownMac(called: text) } }

    public func standing(of key: PublicKey) -> KeyStanding {
        locked {
            let now = ticked()
            return core.standing(of: key, wall: now.wall)
        }
    }

    /// Names as a person reads them: see `TrustCore.fold`.
    public static func fold(_ name: String) -> String { TrustCore.fold(name) }

    /// A Mac this one knows (paired now, run out, or waiting to be paired again) that `name`
    /// would be taken for, other than `key` itself. `expected`: that Mac's key has reached its
    /// end, so a new key under its name is what one would expect.
    public func nameClash(_ name: String, key: PublicKey) -> NameClash? {
        locked {
            let now = ticked()
            return core.nameClash(name, key: key, wall: now.wall)
        }
    }

    /// Counts a key that turned up under a Known Mac's name.
    public func noteImpostor(of mac: PublicKey, at address: String) { locked { perform(core.noteImpostor(of: mac, at: address)) } }

    public func seen(_ key: PublicKey, name: String, major: Int) { locked { core.seen(key, name: name, major: major, wall: clock.wall) } }

    /// Stores a pairing that two people have just made. `remaining`: how long the other Mac
    /// says its key has left; held to the longest lifetime there is, and an existing entry's end
    /// is never moved later. `replacing`: a Known Mac this one takes the place of, whose key is
    /// retired by this. `under`: the key of this Mac's that the pairing's handshake was made
    /// with. If this Mac's key has been replaced since (Reset Identity while the codes were on
    /// screen), what the two people confirmed is a key this Mac no longer has, and nothing is
    /// stored: asked and answered under the lock, as one decision.
    @discardableResult
    public func store(pairing key: PublicKey, announced: String, method: String, remaining: Double, major: Int = protocolVersion,
                      replacing: PublicKey? = nil, name: String? = nil, under: PublicKey? = nil) throws -> KnownMac {
        try locked {
            let now = ticked()
            if let under, under != core.pair.publicKey { throw DropError("This Mac's identity changed while pairing. Nothing was paired.") }
            let (mac, effects) = try core.store(pairing: key, announced: announced, method: method, remaining: remaining, major: major,
                                                replacing: replacing, name: name, wall: now.wall)
            perform(effects)
            return mac
        }
    }

    public func rename(_ key: PublicKey, to name: String) { locked { perform(core.rename(key, to: name)) } }

    /// Remove, on the pair-again list: the Mac is forgotten, and whatever it still had running ends.
    public func removeFromAgain(_ key: PublicKey) { locked { perform(core.removeFromAgain(key, wall: clock.wall)) } }

    // MARK: Withdrawing trust

    /// A session authenticated by `key`: ended at once if that key's trust is withdrawn, and
    /// here and now if it already was (`TrustCore.track`).
    package func track(_ transfer: TrustedSession, key: PublicKey) {
        locked {
            core.prune(Set(table.filter { $0.value() == nil }.keys))
            let id = nextSession
            nextSession += 1
            table[id] = { [weak transfer] in transfer }
            perform(core.track(id, key: key))
        }
    }

    /// Called with a key whose trust was withdrawn, after the store is written and its sessions
    /// are ended. The listener uses it to cancel what is waiting on a person.
    package func onWithdrawn(_ body: @escaping (PublicKey) -> Void) { locked { watchers.append(body) } }

    /// The other Mac said its identity is retired: refused from now on, for good. The steps
    /// every withdrawal of trust takes, in order: written to disk, then nothing new accepted
    /// (the store says so from here), then everything the key had authenticated ended and the
    /// listeners told, before this returns.
    public func retire(_ key: PublicKey, reason: String = "retired") { locked { perform(core.retire(key, reason: reason, wall: clock.wall)) } }

    /// Forget: the pairing goes and everything it had authenticated ends. The key itself is not
    /// refused for good (it may be paired again, by two people, like any other); a key already
    /// retired or run out stays refused.
    public func forget(_ key: PublicKey) { locked { perform(core.forget(key, wall: clock.wall)) } }

    /// A paired Mac has proved its key and said that it does not have this Mac paired
    /// (`TrustCore.notePairingGone`). Until this existed the tile went on saying Paired and
    /// every drop to it failed (found by the owner, 2026-11-23).
    public func notePairingGone(_ key: PublicKey) { locked { perform(core.notePairingGone(key, wall: clock.wall)) } }

    /// Whether `key` was paired no more than `seconds` ago.
    package func pairedWithin(_ seconds: Double, _ key: PublicKey) -> Bool { locked { core.pairedWithin(seconds, key, wall: clock.wall) } }

    /// A retired or expired key was presented. Counts it; true when the person should be told
    /// (once a day per key, three times a day in all).
    public func noteRefused(_ key: PublicKey) -> Bool { locked { core.noteRefused(key, wall: clock.wall) } }

    /// Reset Identity, first half: the key that is about to be destroyed and the Macs to tell,
    /// so that the caller can send the notices while the key still exists.
    package func beginReset() -> (old: KeyPair, peers: [KnownMac]) {
        locked {
            let now = ticked()
            return (core.pair, core.currentlyPaired(wall: now.wall))
        }
    }

    /// Reset Identity, second half: a new key, every Known Mac moved to the pair-again list
    /// marked with whether it was told, every session ended. The old key is gone when this returns.
    ///
    /// A pairing that is in progress ends too: it was being made with the old key. (It used to
    /// go on: both people typed their codes, the other Mac stored the identity that had just
    /// been given up, good for as long as that key had left, and this Mac stored the other
    /// under its new one. Found by an independent review, 2026-11-24.)
    public func completeReset(told: Set<PublicKey>) {
        locked {
            perform(core.reset(told: told, wall: clock.wall))
            let pairing = gate.active
            afterwards.append { pairing?.cancel("This Mac's identity was reset. Nothing was paired.") }
        }
    }

    // MARK: Storage

    /// A change is in force here and not on the disk: the last write failed (a full disk). If
    /// the app quit now, the change would be undone, which for a Forget, a retirement or a
    /// replacement means a Mac trusted again without anyone deciding so. The write is tried
    /// again until it holds (`tick`), and the app tells the person meanwhile. Until
    /// 2026-11-23 the failure was logged and nothing more (the review's divergence 13).
    public var unsaved: Bool { locked { core.unsaved } }

    /// With the lock held. A failure to write is logged, the change stays in force in memory
    /// and the write is tried again; nothing that is acknowledged to another Mac goes through
    /// here without `saveOrThrow`.
    private func save() {
        do { try saveOrThrow() } catch { DropLog.write("identity: could not write the trust file: \(error); it will be tried again", .error) }
    }

    private func saveOrThrow() throws {
        do { try storage.save(try core.encoded()) } catch {
            note(core.saved(false))
            throw error
        }
        note(core.saved(true))
    }

    /// What the core says after a write: a line for the log, and that a window should look again.
    /// Not `perform`: this runs in the middle of one, before the sessions it names are looked up.
    private func note(_ effects: [TrustCore.Effect]) {
        for effect in effects {
            if case .log(let line, let level) = effect { DropLog.write(line, level) }
            if case .changed = effect { changed = true }
        }
    }

    /// Writes the store now; throws if it did not reach the disk. For changes that are about to
    /// be acknowledged to another Mac.
    package func commit() throws { try locked { try saveOrThrow() } }
}
