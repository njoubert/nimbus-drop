// Copyright (C) 2026 Niels Joubert
// SPDX-License-Identifier: GPL-3.0-or-later
import Darwin
import Foundation

/// A Mac this one has paired with.
public struct KnownMac: Codable, Identifiable, Equatable, Sendable {
    public var key: PublicKey
    /// What the person here calls it; unique among the Known Macs. A Mac cannot rename itself
    /// into something misleading, because this is what is shown, not what it announces.
    public var name: String
    /// What it has called itself.
    public var announced: [String]
    public var pairedAt: Date
    /// "codes" or "identity number".
    public var method: String
    /// When its key ends: a reading of this Mac's elapsed-time counter, and a calendar date.
    /// Whichever comes first ends it. Never moved later.
    var endsElapsed: Double
    public var endsWall: Date
    public var lastSeen: Date?
    /// The highest protocol major it has proved; a lower one from it is refused afterwards.
    public var major: Int
    /// Times another key has used its name.
    public var impostors = 0
    public var lastImpostor: String?

    public var id: Data { key.raw }
}

/// A key that is never to be trusted again, and why.
public struct Tombstone: Codable, Equatable, Sendable {
    public var key: PublicKey
    public var name: String
    public var at: Date
    /// "retired" (it said so), "replaced" (the person paired its successor), "expired".
    public var reason: String
    /// Times it has been presented since.
    public var attempts = 0
}

/// A Mac that was paired with a key this Mac no longer has (it reset, or its key ran out). It
/// is not trusted; it is remembered so that pairing again can say it is the same Mac.
public struct Renewal: Codable, Equatable, Identifiable, Sendable {
    public var key: PublicKey
    public var name: String
    /// After a reset: whether it acknowledged being told. Nil after an ordinary expiry.
    public var told: Bool?
    /// When its own key ends, after which the entry is dropped.
    var endsElapsed: Double
    public var endsWall: Date
    public var pairedAgain = false
    public var id: Data { key.raw }
}

/// An unknown key is using the name of a Mac this one knows.
public struct NameClash: Equatable, Sendable {
    /// What that Mac is called here.
    public var name: String
    public var key: PublicKey
    public var pairedAt: Date?
    /// Its key has run out, so a new key under its name was to be expected.
    public var expected: Bool
    /// It is paired now (as opposed to waiting to be paired again).
    public var paired: Bool

    public init(name: String, key: PublicKey, pairedAt: Date?, expected: Bool, paired: Bool) {
        self.name = name; self.key = key; self.pairedAt = pairedAt; self.expected = expected; self.paired = paired
    }
}

/// What a key is to this Mac.
public enum KeyStanding: Equatable, Sendable {
    case mine
    /// Paired, and within its dates.
    case paired(KnownMac)
    /// Paired once; its key has reached its end. Refused, and cannot be paired again.
    case expired(KnownMac)
    /// Given up or replaced. Refused, and cannot be paired again.
    case retired(Tombstone)
    /// Known from before this Mac's own key changed; needs pairing again.
    case renew(Renewal)
    case unknown

    public var isPaired: Bool { if case .paired = self { return true }; return false }
    /// Whether a pairing with this key may be started at all.
    public var mayPair: Bool {
        switch self {
        case .unknown, .renew, .paired: return true
        case .mine, .expired, .retired: return false
        }
    }
}

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
    public func save(_ data: Data) throws { lock.withLock { self.data = data; saves += 1 } }
    public func setAside(_ label: String) { lock.withLock { data = nil; fault = nil } }
    public var stored: Data? { lock.withLock { data } }
}

/// This Mac's identity and everything it knows about other Macs' identities: one object, one
/// file, one atomic write per change.
///
/// Thread-safe. Nothing here touches a socket; the sessions ask it who a key is and tell it
/// what happened.
public final class Trust: @unchecked Sendable {
    public static let lifetimes: [Double] = [3600, 86400, 7 * 86400, 30 * 86400, 90 * 86400]
    public static let longestLifetime: Double = 90 * 86400

    struct File: Codable {
        var schema = 1
        var secret: Data
        var made: Date
        var endsElapsed: Double
        var endsWall: Date
        var lifetime: Double
        /// Seconds this Mac has counted, in all. Only ever rises.
        var elapsed: Double
        var lastBoot: String
        var lastContinuous: Double
        var lastWall: Date
        var known: [KnownMac] = []
        var tombstones: [Tombstone] = []
        var again: [Renewal] = []
        var requestsOff = false
    }

    private let lock = NSRecursiveLock()
    private var depth = 0
    /// What a change under the lock leaves to be done once the lock is free: ending sessions
    /// and telling the listeners, both of which reach sockets. Run in the order they were set
    /// down, on the thread that made the change, before its call returns.
    private var afterwards: [() -> Void] = []

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
            if depth == 0 { run = afterwards; afterwards = [] }
            lock.unlock()
            for r in run { r() }
        }
        return try body()
    }
    private var file: File
    private var pair: KeyPair
    private let storage: TrustStorage
    private let clock: TrustClock
    private var lastSave = 0.0
    /// Live sessions, who authenticated each, and the reading of the elapsed counter past which
    /// it may not run.
    private var sessions: [(transfer: () -> Transfer?, key: PublicKey, deadline: Double)] = []
    private var watchers: [(PublicKey) -> Void] = []
    /// One pairing at a time on this Mac, whoever started it.
    let gate = PairingGate()

    /// Called (on whatever thread made the change) after anything a window would show changes.
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
            guard let f = try? JSONDecoder().decode(File.self, from: loaded), let k = KeyPair(raw: f.secret), f.schema == 1 else { throw TrustFault.damaged }
            file = f
            pair = k
        } else {
            (file, pair) = Trust.fresh(clock: clock, lifetime: lifetime, elapsed: 0)
            try storage.save(try JSONEncoder().encode(file))
            DropLog.write("identity: made this Mac's key \(pair.publicKey.tag), good for \(Format.lifetime(file.lifetime))")
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

    private static func fresh(clock: TrustClock, lifetime: Double, elapsed: Double) -> (File, KeyPair) {
        let k = KeyPair()
        let now = clock.wall
        return (File(secret: k.raw, made: now, endsElapsed: elapsed + lifetime, endsWall: now.addingTimeInterval(lifetime), lifetime: lifetime,
                     elapsed: elapsed, lastBoot: clock.bootSession, lastContinuous: clock.continuous, lastWall: now), k)
    }

    // MARK: This Mac

    /// This Mac's key as it is now: one that has reached its end is replaced before it is handed out.
    public var keyPair: KeyPair { locked { tick(); return pair } }
    public var publicKey: PublicKey { locked { tick(); return pair.publicKey } }
    public var made: Date { locked { file.made } }
    public var lifetime: Double { locked { file.lifetime } }
    /// Seconds this Mac's key has left.
    public var remaining: Double { locked { tick(); return max(0, min(file.endsElapsed - file.elapsed, file.endsWall.timeIntervalSince(clock.wall))) } }
    /// When this Mac's key ends, as a date to show.
    public var ends: Date { clock.wall.addingTimeInterval(remaining) }
    public var requestsOff: Bool {
        get { locked { file.requestsOff } }
        set { locked { file.requestsOff = newValue; save() }; onChange?() }
    }

    /// How long keys made from now on last. A current key already older than that is replaced now.
    public func setLifetime(_ seconds: Double) {
        guard Trust.lifetimes.contains(seconds) else { return }
        locked {
            tick()
            let age = file.lifetime - (file.endsElapsed - file.elapsed)
            file.lifetime = seconds
            file.endsElapsed = min(file.endsElapsed, file.elapsed - age + seconds)
            file.endsWall = min(file.endsWall, file.made.addingTimeInterval(seconds))
            save()
            tick()
        }
        onChange?()
    }

    // MARK: Time

    /// Counts the time that has passed, ends whatever has run out, and now and then writes the
    /// count down. Cheap; called before every decision that depends on a date.
    public func tick() {
        var changed = false
        locked {
            let boot = clock.bootSession, c = clock.continuous, wall = clock.wall
            // Same boot: the continuous clock is exact, whether or not this process was running.
            // After a reboot: at least the time since boot, and the calendar's gap if that is more.
            let delta = boot == file.lastBoot ? c - file.lastContinuous : max(c, wall.timeIntervalSince(file.lastWall))
            file.elapsed += max(0, delta)
            file.lastBoot = boot
            file.lastContinuous = c
            file.lastWall = wall

            if file.elapsed >= file.endsElapsed || wall >= file.endsWall {
                rotate(reason: "its end date")
                changed = true
            }
            let elapsed = file.elapsed
            // A key's end is counted in elapsed time, and only that count refuses it for good.
            for k in file.known where elapsed >= k.endsElapsed && !file.tombstones.contains(where: { $0.key == k.key }) {
                file.tombstones.append(Tombstone(key: k.key, name: k.name, at: wall, reason: "expired"))
                changed = true
                DropLog.write("identity: \(k.name)'s key \(k.key.tag) reached its end date; it needs pairing again")
            }
            // The calendar reaching the date first ends the pairing and no more: the Mac is to
            // be paired again, and its key is not held to have run out. A calendar set forward
            // once (a forged time server, or a clock that was years behind being put right)
            // used to refuse every paired key for good, also after it was set back.
            for k in file.known where elapsed < k.endsElapsed && wall >= k.endsWall {
                file.again.removeAll { $0.key == k.key }
                file.again.append(Renewal(key: k.key, name: k.name, told: nil, endsElapsed: k.endsElapsed, endsWall: k.endsWall))
                changed = true
                DropLog.write("identity: the calendar passed the date recorded for \(k.name)'s key \(k.key.tag) before the time counted here did; it needs pairing again", .warn)
            }
            file.known.removeAll { elapsed < $0.endsElapsed && wall >= $0.endsWall }
            // A key that runs out while waiting to be paired again is refused like any other.
            for r in file.again where elapsed >= r.endsElapsed {
                if !file.tombstones.contains(where: { $0.key == r.key }) { file.tombstones.append(Tombstone(key: r.key, name: r.name, at: wall, reason: "expired")) }
                changed = true
            }
            file.again.removeAll { elapsed >= $0.endsElapsed }
            if file.tombstones.count > 2000 { file.tombstones.removeFirst(file.tombstones.count - 2000) }
            if changed || file.elapsed - lastSave > 3600 { save() }
            endSessionsPastGrace()
        }
        if changed { onChange?() }
    }

    private func current(_ endsElapsed: Double, _ endsWall: Date) -> Bool { file.elapsed < endsElapsed && clock.wall < endsWall }

    /// Replaces this Mac's key. Every Known Mac that is still current moves to the renew list.
    private func rotate(reason: String, told: [PublicKey: Bool]? = nil) {
        let old = pair.publicKey
        for k in file.known where file.elapsed < k.endsElapsed {
            file.again.removeAll { $0.key == k.key }
            file.again.append(Renewal(key: k.key, name: k.name, told: told.map { $0[k.key] ?? false }, endsElapsed: k.endsElapsed, endsWall: k.endsWall))
        }
        // Expired entries leave their tombstones behind; nothing else of them is needed.
        for k in file.known where !file.tombstones.contains(where: { $0.key == k.key }) && file.elapsed >= k.endsElapsed {
            file.tombstones.append(Tombstone(key: k.key, name: k.name, at: clock.wall, reason: "expired"))
        }
        file.known = []
        let (fresh, k) = Trust.fresh(clock: clock, lifetime: file.lifetime, elapsed: file.elapsed)
        file.secret = fresh.secret
        file.made = fresh.made
        file.endsElapsed = fresh.endsElapsed
        file.endsWall = fresh.endsWall
        pair = k
        DropLog.write("identity: this Mac's key \(old.tag) was replaced by \(k.publicKey.tag) (\(reason)); \(file.again.count) Macs need pairing again", .warn)
    }

    // MARK: Other Macs

    public var known: [KnownMac] { locked { file.known.sorted { $0.name.localizedStandardCompare($1.name) == .orderedAscending } } }
    public var again: [Renewal] { locked { file.again.sorted { $0.name.localizedStandardCompare($1.name) == .orderedAscending } } }
    public var tombstones: [Tombstone] { locked { file.tombstones } }

    /// The one Known Mac a person means by `text`: the name this Mac has for it (which no other
    /// Known Mac shares), or its key tag. Never what a Mac on the network calls itself.
    public func knownMac(called text: String) -> KnownMac? {
        locked {
            tick()
            let tag = text.uppercased().replacingOccurrences(of: "-", with: "")
            return file.known.first { $0.name.caseInsensitiveCompare(text) == .orderedSame }
                ?? file.known.first { $0.key.tag.replacingOccurrences(of: "-", with: "") == tag }
        }
    }

    public func standing(of key: PublicKey) -> KeyStanding {
        locked {
            tick()
            if key == pair.publicKey { return .mine }
            if let t = file.tombstones.first(where: { $0.key == key }), t.reason != "expired" { return .retired(t) }
            if let k = file.known.first(where: { $0.key == key }) { return current(k.endsElapsed, k.endsWall) ? .paired(k) : .expired(k) }
            if let t = file.tombstones.first(where: { $0.key == key }) { return .retired(t) }
            if let r = file.again.first(where: { $0.key == key && !$0.pairedAgain }) { return .renew(r) }
            return .unknown
        }
    }

    /// Names as a person reads them: case, accents, compatibility forms, and the "-2" or " (2)"
    /// macOS adds on a clash are folded away, so that "MacStudio", "macstudio-2" and
    /// "ｍａｃｓｔｕｄｉｏ" are one name.
    public static func fold(_ name: String) -> String {
        var s = name.precomposedStringWithCompatibilityMapping
        s = s.applyingTransform(.toLatin, reverse: false) ?? s
        s = s.folding(options: [.caseInsensitive, .diacriticInsensitive, .widthInsensitive], locale: nil)
        if s.hasSuffix(".local") { s.removeLast(6) }
        if let r = s.range(of: #"(-\d+| \(\d+\))$"#, options: .regularExpression) { s.removeSubrange(r) }
        return s.filter { !$0.isWhitespace && $0 != "-" && $0 != "_" }
    }

    /// A Mac this one knows (paired now, run out, or waiting to be paired again) that `name`
    /// would be taken for, other than `key` itself. `expected`: that Mac's key has reached its
    /// end, so a new key under its name is what one would expect.
    public func nameClash(_ name: String, key: PublicKey) -> NameClash? {
        locked {
            tick()
            let folded = Trust.fold(name)
            guard !folded.isEmpty else { return nil }
            if let k = file.known.first(where: { $0.key != key && (Trust.fold($0.name) == folded || $0.announced.contains { Trust.fold($0) == folded }) }) {
                return NameClash(name: k.name, key: k.key, pairedAt: k.pairedAt, expected: !current(k.endsElapsed, k.endsWall), paired: true)
            }
            if let r = file.again.first(where: { $0.key != key && !$0.pairedAgain && Trust.fold($0.name) == folded }) {
                return NameClash(name: r.name, key: r.key, pairedAt: nil, expected: !current(r.endsElapsed, r.endsWall), paired: false)
            }
            return nil
        }
    }

    /// Counts a key that turned up under a Known Mac's name.
    public func noteImpostor(of mac: PublicKey, at address: String) {
        locked {
            guard let i = file.known.firstIndex(where: { $0.key == mac }) else { return }
            file.known[i].impostors += 1
            file.known[i].lastImpostor = address
            save()
        }
        onChange?()
    }

    public func seen(_ key: PublicKey, name: String, major: Int) {
        locked {
            guard let i = file.known.firstIndex(where: { $0.key == key }) else { return }
            file.known[i].lastSeen = clock.wall
            file.known[i].major = max(file.known[i].major, major)
            let label = Sanitize.label(name, limit: 64)
            if !file.known[i].announced.contains(label) { file.known[i].announced = Array((file.known[i].announced + [label]).suffix(8)) }
        }
    }

    /// A name for a new Known Mac that no other has.
    private func uniqueName(_ wanted: String, except: PublicKey) -> String {
        let base = wanted.isEmpty ? "Mac" : wanted
        var name = base, n = 2
        while file.known.contains(where: { $0.key != except && $0.name.caseInsensitiveCompare(name) == .orderedSame }) {
            name = "\(base) \(n)"
            n += 1
        }
        return name
    }

    /// Stores a pairing that two people have just made. `remaining`: how long the other Mac
    /// says its key has left; held to the longest lifetime there is, and an existing entry's end
    /// is never moved later. `replacing`: a Known Mac this one takes the place of, whose key is
    /// retired by this.
    @discardableResult
    public func store(pairing key: PublicKey, announced: String, method: String, remaining: Double, major: Int = protocolVersion,
                      replacing: PublicKey? = nil, name: String? = nil) throws -> KnownMac {
        let made: KnownMac = try locked {
            tick()
            guard standing(of: key).mayPair else { throw DropError("That identity can no longer be paired") }
            let life = max(1, min(remaining, Trust.longestLifetime))
            var endsElapsed = file.elapsed + life, endsWall = clock.wall.addingTimeInterval(life)
            var inherited: String?
            if let old = file.known.first(where: { $0.key == key }) {
                endsElapsed = min(endsElapsed, old.endsElapsed)
                endsWall = min(endsWall, old.endsWall)
                inherited = old.name
            }
            if let r = file.again.firstIndex(where: { $0.key == key }) {
                endsElapsed = min(endsElapsed, file.again[r].endsElapsed)
                // Its calendar date too, unless the calendar is already past it: that ended the
                // pairing once, and the date now follows from what the elapsed count leaves.
                endsWall = clock.wall < file.again[r].endsWall ? min(endsWall, file.again[r].endsWall)
                                                               : min(endsWall, clock.wall.addingTimeInterval(endsElapsed - file.elapsed))
                inherited = inherited ?? file.again[r].name
                file.again[r].pairedAgain = true
            }
            if let replacing, replacing != key, let old = file.known.first(where: { $0.key == replacing }) {
                inherited = inherited ?? old.name
                withdrawLocked(replacing, name: old.name, reason: "replaced")
            }
            file.known.removeAll { $0.key == key }
            let label = Sanitize.label(announced, limit: 64)
            let mac = KnownMac(key: key, name: uniqueName(name ?? inherited ?? label, except: key), announced: [label], pairedAt: clock.wall, method: method,
                               endsElapsed: endsElapsed, endsWall: endsWall, lastSeen: clock.wall, major: major)
            file.known.append(mac)
            save()
            DropLog.write("identity: paired with \(mac.name) (\(key.tag)) by \(method); good until \(mac.endsWall)")
            return mac
        }
        onChange?()
        return made
    }

    public func rename(_ key: PublicKey, to name: String) {
        locked {
            guard let i = file.known.firstIndex(where: { $0.key == key }) else { return }
            file.known[i].name = uniqueName(Sanitize.label(name, limit: 64), except: key)
            save()
        }
        onChange?()
    }

    public func removeFromAgain(_ key: PublicKey) {
        locked { file.again.removeAll { $0.key == key }; save() }
        onChange?()
    }

    // MARK: Withdrawing trust

    /// A session authenticated by `key`: ended at once if that key's trust is withdrawn. When a
    /// key merely runs out (the other Mac's or this one's) a running session may finish, but not
    /// for ever: at most a day past the end, or one key lifetime if that is shorter.
    func track(_ transfer: Transfer, key: PublicKey) {
        locked {
            sessions.removeAll { $0.transfer() == nil }
            let theirs = file.known.first { $0.key == key }?.endsElapsed ?? file.elapsed
            let end = min(theirs, file.endsElapsed)
            sessions.append(({ [weak transfer] in transfer }, key, end + min(86400, file.lifetime)))
        }
    }

    /// Called with a key whose trust was withdrawn, after the store is written and its sessions
    /// are ended. The listener uses it to cancel what is waiting on a person.
    func onWithdrawn(_ body: @escaping (PublicKey) -> Void) { locked { watchers.append(body) } }

    /// The steps every withdrawal of trust takes, in order: written to disk, then nothing new
    /// accepted (the store says so from here), then everything the key had authenticated ended
    /// and the listeners told. With the lock held; the last two are done as it is let go
    /// (`locked`), before the call that withdrew the trust returns.
    private func withdrawLocked(_ key: PublicKey, name: String, reason: String, refuseForGood: Bool = true) {
        if let i = file.tombstones.firstIndex(where: { $0.key == key }) {
            if refuseForGood { file.tombstones[i].reason = reason }
        } else if refuseForGood {
            file.tombstones.append(Tombstone(key: key, name: name, at: clock.wall, reason: reason))
        }
        if file.tombstones.count > 2000 { file.tombstones.removeFirst(file.tombstones.count - 2000) }
        file.known.removeAll { $0.key == key }
        file.again.removeAll { $0.key == key }
        save()
        endSessions(of: key, because: "\(name) is no longer trusted (\(reason))")
        tellWatchers(key)
    }

    /// With the lock held. The sessions leave the list now; they are ended once it is let go.
    private func endSessions(of key: PublicKey, because: String) {
        let mine = sessions.filter { $0.key == key }.compactMap { $0.transfer() }
        sessions.removeAll { $0.key == key || $0.transfer() == nil }
        afterwards.append {
            for t in mine where !t.state.isFinal {
                t.log("ended: \(because)", .warn)
                t.withdrawn(DropError(because.prefix(1).uppercased() + because.dropFirst()))
            }
        }
    }

    /// With the lock held.
    private func tellWatchers(_ key: PublicKey) {
        let all = watchers
        afterwards.append { for w in all { w(key) } }
    }

    /// With the lock held. A drop that is running when its key runs out may finish, within the
    /// time allowed. One that has not begun (the question is still on screen, or still
    /// unanswered at the other Mac) does not begin: the pairing it was offered under is over.
    private func endSessionsPastGrace() {
        sessions.removeAll { $0.transfer().map(\.state.isFinal) ?? true }
        let late = sessions.filter { file.elapsed > $0.deadline }.compactMap { $0.transfer() }
        sessions.removeAll { file.elapsed > $0.deadline }
        let paired = Set(file.known.filter { current($0.endsElapsed, $0.endsWall) }.map(\.key))
        let unbegun = sessions.filter { !paired.contains($0.key) }.compactMap { $0.transfer() }.filter { $0.state == .waitingForAccept }
        guard !late.isEmpty || !unbegun.isEmpty else { return }
        afterwards.append {
            for t in late where !t.state.isFinal {
                t.log("ended: its key ran out and the time allowed to finish has passed", .warn)
                t.withdrawn(DropError("The pairing ran out before the drop finished; pair again and send it again to continue"))
            }
            for t in unbegun where t.state == .waitingForAccept {
                t.log("ended: the pairing ran out before the drop was accepted", .warn)
                t.withdrawn(DropError("The pairing ran out before the drop was accepted; pair again and send it again"))
            }
        }
    }

    /// The other Mac said its identity is retired: refused from now on, for good.
    public func retire(_ key: PublicKey, reason: String = "retired") {
        locked {
            let name = file.known.first { $0.key == key }?.name ?? file.again.first { $0.key == key }?.name ?? key.tag
            DropLog.write("identity: \(name)'s key \(key.tag) is \(reason); it will be refused from now on", .warn)
            withdrawLocked(key, name: name, reason: reason)
        }
        onChange?()
    }

    /// Forget: the pairing goes and everything it had authenticated ends. The key itself is not
    /// refused for good (it may be paired again, by two people, like any other); a key already
    /// retired or run out stays refused.
    public func forget(_ key: PublicKey) {
        locked {
            let name = file.known.first { $0.key == key }?.name ?? key.tag
            DropLog.write("identity: forgot \(name) (\(key.tag))")
            withdrawLocked(key, name: name, reason: "forgotten", refuseForGood: false)
        }
        onChange?()
    }

    /// A paired Mac has proved its key and said that it does not have this Mac paired: it
    /// forgot this Mac, or the last word of the pairing never reached it. This Mac's half is
    /// worth nothing, so it goes the way a Forget does (everything the key had authenticated
    /// ends) and the Mac is listed to be paired again, where its tile says so. Only the key
    /// itself can cause this, over a session it has proved, and only to its own entry.
    /// Until this existed the tile went on saying Paired and every drop to it failed
    /// (found by the owner, 2026-11-23).
    public func notePairingGone(_ key: PublicKey) {
        let changed: Bool = locked {
            guard let mac = file.known.first(where: { $0.key == key }), current(mac.endsElapsed, mac.endsWall) else { return false }
            DropLog.write("identity: \(mac.name) (\(key.tag)) no longer has this Mac paired; it needs pairing again", .warn)
            withdrawLocked(key, name: mac.name, reason: "the other Mac forgot this one", refuseForGood: false)
            file.again.append(Renewal(key: key, name: mac.name, told: nil, endsElapsed: mac.endsElapsed, endsWall: mac.endsWall))
            save()
            return true
        }
        if changed { onChange?() }
    }

    /// A retired or expired key was presented. Counts it; true when the person should be told
    /// (once a day per key, three times a day in all).
    public func noteRefused(_ key: PublicKey) -> Bool {
        locked {
            guard let i = file.tombstones.firstIndex(where: { $0.key == key }) else { return false }
            file.tombstones[i].attempts += 1
            let today = clock.wall.timeIntervalSince1970 / 86400
            let day = Int(today)
            if noticeDay != day { noticeDay = day; noticed = [] }
            guard noticed.count < 3, !noticed.contains(key) else { return false }
            noticed.insert(key)
            return true
        }
    }
    private var noticeDay = 0
    private var noticed = Set<PublicKey>()

    /// Reset Identity, first half: the key that is about to be destroyed and the Macs to tell,
    /// so that the caller can send the notices while the key still exists.
    public func beginReset() -> (old: KeyPair, peers: [KnownMac]) {
        locked { tick(); return (pair, file.known.filter { current($0.endsElapsed, $0.endsWall) }) }
    }

    /// Reset Identity, second half: a new key, every Known Mac moved to the pair-again list
    /// marked with whether it was told, every session ended. The old key is gone when this returns.
    public func completeReset(told: Set<PublicKey>) {
        locked {
            let everyone = file.known.map(\.key) + file.again.map(\.key)
            var map: [PublicKey: Bool] = [:]
            for k in file.known { map[k.key] = told.contains(k.key) }
            rotate(reason: "Reset Identity", told: map)
            save()
            for key in Set(everyone) { endSessions(of: key, because: "this Mac's identity was reset") }
            for key in Set(everyone) { tellWatchers(key) }
        }
        onChange?()
    }

    // MARK: Storage

    /// With the lock held. A failure to write is logged and the change stays in memory; nothing
    /// that is acknowledged to another Mac goes through here without `saveOrThrow`.
    private func save() {
        do { try saveOrThrow() } catch { DropLog.write("identity: could not write the trust file: \(error)", .error) }
    }

    private func saveOrThrow() throws {
        try storage.save(try JSONEncoder().encode(file))
        lastSave = file.elapsed
    }

    /// Writes the store now; throws if it did not reach the disk. For changes that are about to
    /// be acknowledged to another Mac.
    func commit() throws { try locked { try saveOrThrow() } }
}
