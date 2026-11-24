// Copyright (C) 2026 Niels Joubert
// SPDX-License-Identifier: GPL-3.0-or-later
import Foundation
import NimbusBase

/// Everything the trust store decides, as a function of what it is told: who a key is, what a
/// pairing stores, what a withdrawal of trust ends and in what order, what the passing of time
/// ends, and when the file must be written. No lock, no clock, no disk, no session: the time
/// is an argument (`ClockReading`), a session is a number, and what must happen outside is
/// returned as `Effect`s for whoever holds the lock to carry out (`Trust`, in the security
/// core).
///
/// It is this type the formal models are about. `formal/tla/TrustCore.tla` defines the same
/// decisions over one key and two sessions, `TrustCoreTests` writes this code's transitions
/// out as `formal/tla/TrustImpl.tla`, and TLC holds the two equal (`TrustRefinement.tla`).
/// `TrustWithdraw.tla` and `Expiry.tla` then prove their properties of that machine. A change
/// here is a change there first (CLAUDE.md, Verification).
package struct TrustCore {
    package static let lifetimes: [Double] = [3600, 86400, 7 * 86400, 30 * 86400, 90 * 86400]
    package static let longestLifetime: Double = 90 * 86400
    /// Tombstones kept, by default. See `tombstonesKept`.
    package static let tombstonesKeptByDefault = 2000

    /// The trust file. The names of its fields are the file's format.
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

    /// Something a key authenticated: all the core knows of it is its number, its key, and the
    /// reading of the elapsed counter past which it may not run.
    package struct Session: Equatable, Sendable {
        package let id: Int
        package let key: PublicKey
        package let deadline: Double
    }

    /// Sessions to end, and what to say.
    package struct Ending: Equatable, Sendable {
        package enum Why: String, Sendable {
            /// Trust in the key was withdrawn (retired, forgotten, replaced, this Mac reset).
            case withdrawn
            /// Trust in the key was withdrawn while the session was being set up.
            case duringSetUp
            /// The key ran out and the time allowed to finish has passed.
            case pastGrace
            /// The key ran out before the session had begun.
            case unbegun
        }
        package let why: Why
        package let sessions: [Int]
        /// For the session's own log.
        package let log: String
        /// What the person reads.
        package let message: String
        /// Ends only a session that is still waiting for its yes when the time comes.
        package var ifStillWaiting: Bool { why == .unbegun }
    }

    /// What a decision leaves to be done by whoever holds the lock, in this order.
    package enum Effect: Equatable, Sendable {
        /// Write the file now, with the lock held, and say how it went (`saved`).
        case save
        /// End these sessions once the lock is free: it closes sockets.
        case end(Ending)
        /// Tell the listeners that trust in this key was withdrawn, once the lock is free and
        /// after the sessions were ended.
        case tell(PublicKey)
        case log(String, LogLevel)
        /// Something a window shows has changed.
        case changed
    }

    var file: File
    /// How many tombstones are kept; the oldest goes when another is made. So "refused for
    /// good" is exactly: refused for as long as the key's tombstone is among the newest this
    /// many. After that the key is an unknown key again: nothing is trusted, and nothing
    /// stops two people from pairing it afresh. A tombstone is only ever made for a key that
    /// two people once paired, so it takes that many later pairings ended to push one out.
    package let tombstonesKept: Int
    /// This Mac's key as it is now.
    package private(set) var pair: KeyPair
    package private(set) var sessions: [Session] = []
    /// A change is in force here and not on the disk: the last write failed.
    package private(set) var unsaved = false
    private(set) var lastSave = 0.0
    private(set) var lastTry = 0.0
    private var noticeDay = 0
    private var noticed = Set<PublicKey>()

    // MARK: Beginning

    /// A first run: a new key, good for `lifetime` from now.
    package init(fresh now: ClockReading, lifetime: Double, tombstonesKept: Int = TrustCore.tombstonesKeptByDefault, newKey: () -> KeyPair = { KeyPair() }) {
        self.tombstonesKept = tombstonesKept
        let k = newKey()
        file = File(secret: k.raw, made: now.wall, endsElapsed: lifetime, endsWall: now.wall.addingTimeInterval(lifetime), lifetime: lifetime,
                    elapsed: 0, lastBoot: now.boot, lastContinuous: now.continuous, lastWall: now.wall)
        pair = k
    }

    /// From the trust file's plaintext. Nil when that is not what it is.
    package init?(decoding data: Data, tombstonesKept: Int = TrustCore.tombstonesKeptByDefault) {
        self.tombstonesKept = tombstonesKept
        guard let f = try? JSONDecoder().decode(File.self, from: data), let k = KeyPair(raw: f.secret), f.schema == 1 else { return nil }
        file = f
        pair = k
    }

    /// The trust file's plaintext. The one place this Mac's private key leaves this module as
    /// bytes: it goes to `TrustStorage.save`, which seals it, and nowhere else
    /// (`scripts/check-layers.py` holds the callers to that).
    package func encoded() throws -> Data { try JSONEncoder().encode(file) }

    // MARK: This Mac

    package var made: Date { file.made }
    package var lifetime: Double { file.lifetime }
    package var elapsed: Double { file.elapsed }
    package var requestsOff: Bool { file.requestsOff }

    /// Seconds this Mac's key has left.
    package func remaining(wall: Date) -> Double { max(0, min(file.endsElapsed - file.elapsed, file.endsWall.timeIntervalSince(wall))) }

    package mutating func setRequestsOff(_ off: Bool) -> [Effect] {
        file.requestsOff = off
        return [.save, .changed]
    }

    /// How long keys made from now on last. A current key already older than that is replaced
    /// at the next tick, which the caller makes.
    package mutating func setLifetime(_ seconds: Double) -> [Effect] {
        guard TrustCore.lifetimes.contains(seconds) else { return [] }
        let age = file.lifetime - (file.endsElapsed - file.elapsed)
        file.lifetime = seconds
        file.endsElapsed = min(file.endsElapsed, file.elapsed - age + seconds)
        file.endsWall = min(file.endsWall, file.made.addingTimeInterval(seconds))
        return [.save, .changed]
    }

    // MARK: Time

    /// The seconds counted so far, given the clocks as they were last read and as they are now.
    /// Same boot: the continuous clock is exact, whether or not this process was running. After
    /// a reboot: at least the time since boot, and the calendar's gap if that is more. Never
    /// less than before, whatever the calendar says.
    package static func count(elapsed: Double, lastBoot: String, lastContinuous: Double, lastWall: Date, now: ClockReading) -> Double {
        let delta = now.boot == lastBoot ? now.continuous - lastContinuous : max(now.continuous, now.wall.timeIntervalSince(lastWall))
        return elapsed + max(0, delta)
    }

    /// Whether the file is to be written at this tick. A change is written at once. Otherwise
    /// the count is written down hourly, and a write that failed is tried again, at most twice
    /// a minute. (Until 2026-11-24 a failed hourly write was tried again at EVERY tick, with a
    /// line in the log each time: on a full disk, several a second.)
    package static func saveDue(changed: Bool, unsaved: Bool, sinceSave: Double, sinceTry: Double) -> Bool {
        changed || (sinceTry >= 30 && (unsaved || sinceSave > 3600))
    }

    private func current(_ endsElapsed: Double, _ endsWall: Date, _ wall: Date) -> Bool { file.elapsed < endsElapsed && wall < endsWall }

    /// Counts the time that has passed and ends whatever has run out. `waiting`: the sessions
    /// that are still waiting for a person's yes.
    package mutating func tick(_ now: ClockReading, waiting: Set<Int> = [], newKey: () -> KeyPair = { KeyPair() }) -> [Effect] {
        var out: [Effect] = []
        var changed = false
        let wall = now.wall
        file.elapsed = TrustCore.count(elapsed: file.elapsed, lastBoot: file.lastBoot, lastContinuous: file.lastContinuous, lastWall: file.lastWall, now: now)
        file.lastBoot = now.boot
        file.lastContinuous = now.continuous
        file.lastWall = wall

        if file.elapsed >= file.endsElapsed || wall >= file.endsWall {
            out += rotate(reason: "its end date", wall: wall, newKey: newKey)
            changed = true
        }
        let elapsed = file.elapsed
        // A key's end is counted in elapsed time, and only that count refuses it for good.
        for k in file.known where elapsed >= k.endsElapsed && !file.tombstones.contains(where: { $0.key == k.key }) {
            file.tombstones.append(Tombstone(key: k.key, name: k.name, at: wall, reason: "expired"))
            changed = true
            out.append(.log("identity: \(k.name)'s key \(k.key.tag) reached its end date; it needs pairing again", .info))
        }
        // The calendar reaching the date first ends the pairing and no more: the Mac is to
        // be paired again, and its key is not held to have run out. A calendar set forward
        // once (a forged time server, or a clock that was years behind being put right)
        // used to refuse every paired key for good, also after it was set back.
        for k in file.known where elapsed < k.endsElapsed && wall >= k.endsWall {
            file.again.removeAll { $0.key == k.key }
            file.again.append(Renewal(key: k.key, name: k.name, told: nil, endsElapsed: k.endsElapsed, endsWall: k.endsWall))
            changed = true
            out.append(.log("identity: the calendar passed the date recorded for \(k.name)'s key \(k.key.tag) before the time counted here did; it needs pairing again", .warn))
        }
        file.known.removeAll { elapsed < $0.endsElapsed && wall >= $0.endsWall }
        // A key that runs out while waiting to be paired again is refused like any other.
        for r in file.again where elapsed >= r.endsElapsed {
            if !file.tombstones.contains(where: { $0.key == r.key }) { file.tombstones.append(Tombstone(key: r.key, name: r.name, at: wall, reason: "expired")) }
            changed = true
        }
        file.again.removeAll { elapsed >= $0.endsElapsed }
        trimTombstones()
        if TrustCore.saveDue(changed: changed, unsaved: unsaved, sinceSave: file.elapsed - lastSave, sinceTry: file.elapsed - lastTry) { out.append(.save) }
        out += endPastGrace(wall: wall, waiting: waiting)
        if changed { out.append(.changed) }
        return out
    }

    private mutating func trimTombstones() {
        if file.tombstones.count > tombstonesKept { file.tombstones.removeFirst(file.tombstones.count - tombstonesKept) }
    }

    /// Replaces this Mac's key. Every Known Mac that is still current moves to the renew list.
    private mutating func rotate(reason: String, told: [PublicKey: Bool]? = nil, wall: Date, newKey: () -> KeyPair) -> [Effect] {
        let old = pair.publicKey
        for k in file.known where file.elapsed < k.endsElapsed {
            file.again.removeAll { $0.key == k.key }
            file.again.append(Renewal(key: k.key, name: k.name, told: told.map { $0[k.key] ?? false }, endsElapsed: k.endsElapsed, endsWall: k.endsWall))
        }
        // Expired entries leave their tombstones behind; nothing else of them is needed.
        for k in file.known where !file.tombstones.contains(where: { $0.key == k.key }) && file.elapsed >= k.endsElapsed {
            file.tombstones.append(Tombstone(key: k.key, name: k.name, at: wall, reason: "expired"))
        }
        file.known = []
        let k = newKey()
        file.secret = k.raw
        file.made = wall
        file.endsElapsed = file.elapsed + file.lifetime
        file.endsWall = wall.addingTimeInterval(file.lifetime)
        pair = k
        return [.log("identity: this Mac's key \(old.tag) was replaced by \(k.publicKey.tag) (\(reason)); \(file.again.count) Macs need pairing again", .warn)]
    }

    // MARK: Other Macs

    package var known: [KnownMac] { file.known.sorted { $0.name.localizedStandardCompare($1.name) == .orderedAscending } }
    package var again: [Renewal] { file.again.sorted { $0.name.localizedStandardCompare($1.name) == .orderedAscending } }
    package var tombstones: [Tombstone] { file.tombstones }

    /// The Known Macs whose keys are within their dates.
    package func currentlyPaired(wall: Date) -> [KnownMac] { file.known.filter { current($0.endsElapsed, $0.endsWall, wall) } }

    /// The one Known Mac a person means by `text`: the name this Mac has for it (which no other
    /// Known Mac shares), or its key tag. Never what a Mac on the network calls itself.
    package func knownMac(called text: String) -> KnownMac? {
        let tag = text.uppercased().replacingOccurrences(of: "-", with: "")
        return file.known.first { $0.name.caseInsensitiveCompare(text) == .orderedSame }
            ?? file.known.first { $0.key.tag.replacingOccurrences(of: "-", with: "") == tag }
    }

    /// What `key` is to this Mac, as of the last tick.
    package func standing(of key: PublicKey, wall: Date) -> KeyStanding {
        if key == pair.publicKey { return .mine }
        if let t = file.tombstones.first(where: { $0.key == key }), t.reason != "expired" { return .retired(t) }
        if let k = file.known.first(where: { $0.key == key }) { return current(k.endsElapsed, k.endsWall, wall) ? .paired(k) : .expired(k) }
        if let t = file.tombstones.first(where: { $0.key == key }) { return .retired(t) }
        if let r = file.again.first(where: { $0.key == key && !$0.pairedAgain }) { return .renew(r) }
        return .unknown
    }

    /// Names as a person reads them: case, accents, compatibility forms, and the "-2" or " (2)"
    /// macOS adds on a clash are folded away, so that "MacStudio", "macstudio-2" and
    /// "ｍａｃｓｔｕｄｉｏ" are one name.
    package static func fold(_ name: String) -> String {
        // Nothing that cannot be seen: "mac\u{200B}studio" is "macstudio" to whoever reads it.
        var s = Sanitize.comparable(name).precomposedStringWithCompatibilityMapping
        s = s.applyingTransform(.toLatin, reverse: false) ?? s
        s = s.folding(options: [.caseInsensitive, .diacriticInsensitive, .widthInsensitive], locale: nil)
        if s.hasSuffix(".local") { s.removeLast(6) }
        if let r = s.range(of: #"(-\d+| \(\d+\))$"#, options: .regularExpression) { s.removeSubrange(r) }
        return s.filter { !$0.isWhitespace && $0 != "-" && $0 != "_" }
    }

    /// A Mac this one knows (paired now, run out, or waiting to be paired again) that `name`
    /// would be taken for, other than `key` itself. `expected`: that Mac's key has reached its
    /// end, so a new key under its name is what one would expect.
    package func nameClash(_ name: String, key: PublicKey, wall: Date) -> NameClash? {
        let folded = TrustCore.fold(name)
        guard !folded.isEmpty else { return nil }
        if let k = file.known.first(where: { $0.key != key && (TrustCore.fold($0.name) == folded || $0.announced.contains { TrustCore.fold($0) == folded }) }) {
            return NameClash(name: k.name, key: k.key, pairedAt: k.pairedAt, expected: !current(k.endsElapsed, k.endsWall, wall), paired: true)
        }
        if let r = file.again.first(where: { $0.key != key && !$0.pairedAgain && TrustCore.fold($0.name) == folded }) {
            return NameClash(name: r.name, key: r.key, pairedAt: nil, expected: !current(r.endsElapsed, r.endsWall, wall), paired: false)
        }
        return nil
    }

    /// Counts a key that turned up under a Known Mac's name.
    package mutating func noteImpostor(of mac: PublicKey, at address: String) -> [Effect] {
        guard let i = file.known.firstIndex(where: { $0.key == mac }) else { return [] }
        file.known[i].impostors += 1
        file.known[i].lastImpostor = address
        return [.save, .changed]
    }

    package mutating func seen(_ key: PublicKey, name: String, major: Int, wall: Date) {
        guard let i = file.known.firstIndex(where: { $0.key == key }) else { return }
        file.known[i].lastSeen = wall
        file.known[i].major = max(file.known[i].major, major)
        let label = Sanitize.label(name, limit: 64)
        if !file.known[i].announced.contains(label) { file.known[i].announced = Array((file.known[i].announced + [label]).suffix(8)) }
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
    /// retired by this. Throws, with nothing changed, for a key that may not be paired.
    package mutating func store(pairing key: PublicKey, announced: String, method: String, remaining: Double, major: Int,
                                replacing: PublicKey?, name: String?, wall: Date) throws -> (KnownMac, [Effect]) {
        guard standing(of: key, wall: wall).mayPair else { throw DropError("That identity can no longer be paired") }
        var out: [Effect] = [.save]
        let life = max(1, min(remaining, TrustCore.longestLifetime))
        var endsElapsed = file.elapsed + life, endsWall = wall.addingTimeInterval(life)
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
            endsWall = wall < file.again[r].endsWall ? min(endsWall, file.again[r].endsWall)
                                                     : min(endsWall, wall.addingTimeInterval(endsElapsed - file.elapsed))
            inherited = inherited ?? file.again[r].name
            file.again[r].pairedAgain = true
        }
        if let replacing, replacing != key, let old = file.known.first(where: { $0.key == replacing }) {
            inherited = inherited ?? old.name
            out += withdraw(replacing, name: old.name, reason: "replaced", refuseForGood: true, wall: wall)
        }
        file.known.removeAll { $0.key == key }
        let label = Sanitize.label(announced, limit: 64)
        let mac = KnownMac(key: key, name: uniqueName(name ?? inherited ?? label, except: key), announced: [label], pairedAt: wall, method: method,
                           endsElapsed: endsElapsed, endsWall: endsWall, lastSeen: wall, major: major)
        file.known.append(mac)
        out.append(.log("identity: paired with \(mac.name) (\(key.tag)) by \(method); good until \(mac.endsWall)", .info))
        out.append(.changed)
        return (mac, out)
    }

    package mutating func rename(_ key: PublicKey, to name: String) -> [Effect] {
        guard let i = file.known.firstIndex(where: { $0.key == key }) else { return [] }
        file.known[i].name = uniqueName(Sanitize.label(name, limit: 64), except: key)
        return [.save, .changed]
    }

    /// Remove, on the pair-again list: the Mac is not to be remembered at all. Whatever it
    /// still has running ends, as with Forget. (A Mac gets on that list with a drop still
    /// running when the calendar passes its date mid-drop; until 2026-11-24 Remove left that
    /// drop to run out its day of grace, under a Mac the person had just struck off. Found by
    /// `TrustCoreTests`' random walks: the session's deadline no longer belonged to anything.)
    package mutating func removeFromAgain(_ key: PublicKey, wall: Date) -> [Effect] {
        // Paired again since, and so on the Known list too: only the old entry goes.
        guard !file.known.contains(where: { $0.key == key }) else {
            file.again.removeAll { $0.key == key }
            return [.save, .changed]
        }
        let name = file.again.first { $0.key == key }?.name ?? key.tag
        return [.save] + withdraw(key, name: name, reason: "removed", refuseForGood: false, wall: wall) + [.changed]
    }

    /// Whether `key` was paired no more than `seconds` ago.
    package func pairedWithin(_ seconds: Double, _ key: PublicKey, wall: Date) -> Bool {
        file.known.first { $0.key == key }.map { abs(wall.timeIntervalSince($0.pairedAt)) < seconds } ?? false
    }

    /// A retired or expired key was presented. Counts it; true when the person should be told
    /// (once a day per key, three times a day in all).
    package mutating func noteRefused(_ key: PublicKey, wall: Date) -> Bool {
        guard let i = file.tombstones.firstIndex(where: { $0.key == key }) else { return false }
        file.tombstones[i].attempts += 1
        let day = Int(wall.timeIntervalSince1970 / 86400)
        if noticeDay != day { noticeDay = day; noticed = [] }
        guard noticed.count < 3, !noticed.contains(key) else { return false }
        noticed.insert(key)
        return true
    }

    // MARK: Sessions

    /// Sessions that are over, or whose owner is gone, leave the list.
    package mutating func prune(_ gone: Set<Int>) {
        guard !gone.isEmpty else { return }
        sessions.removeAll { gone.contains($0.id) }
    }

    /// A session authenticated by `key`: ended at once if that key's trust is withdrawn. When a
    /// key merely runs out (the other Mac's or this one's) a running session may finish, but not
    /// for ever: at most a day past the end, or one key lifetime if that is shorter.
    ///
    /// A session asks who a key is at the start of its handshake and comes here at the end of
    /// it, with the network (and the other Mac's leisure) in between. If trust in the key was
    /// withdrawn in that gap, the withdrawal found nothing of this session to end, so it is
    /// ended here: the question and the registration are one decision. Without this a drop
    /// begun in the moment its Mac was forgotten or retired ran to the end (found by
    /// `formal/tla/TrustWithdraw.tla`, 2026-11-24). A key that has run out on schedule is still
    /// on the Known list, and is not caught here: what it began may finish, within the time above.
    package mutating func track(_ id: Int, key: PublicKey) -> [Effect] {
        guard file.known.contains(where: { $0.key == key }) else {
            return [.end(Ending(why: .duringSetUp, sessions: [id], log: "ended: trust in \(key.tag) was withdrawn while this was being set up",
                                message: "That Mac is no longer paired with this one"))]
        }
        let theirs = file.known.first { $0.key == key }?.endsElapsed ?? file.elapsed
        let end = min(theirs, file.endsElapsed)
        sessions.append(Session(id: id, key: key, deadline: end + min(86400, file.lifetime)))
        return []
    }

    /// A drop that is running when its key runs out may finish, within the time allowed. One
    /// that has not begun (the question is still on screen, or still unanswered at the other
    /// Mac) does not begin: the pairing it was offered under is over.
    private mutating func endPastGrace(wall: Date, waiting: Set<Int>) -> [Effect] {
        let late = sessions.filter { file.elapsed > $0.deadline }.map(\.id)
        sessions.removeAll { file.elapsed > $0.deadline }
        let paired = Set(currentlyPaired(wall: wall).map(\.key))
        let unbegun = sessions.filter { !paired.contains($0.key) && waiting.contains($0.id) }.map(\.id)
        var out: [Effect] = []
        if !late.isEmpty {
            out.append(.end(Ending(why: .pastGrace, sessions: late, log: "ended: its key ran out and the time allowed to finish has passed",
                                   message: "The pairing ran out before the drop finished; pair again and send it again to continue")))
        }
        if !unbegun.isEmpty {
            out.append(.end(Ending(why: .unbegun, sessions: unbegun, log: "ended: the pairing ran out before the drop was accepted",
                                   message: "The pairing ran out before the drop was accepted; pair again and send it again")))
        }
        return out
    }

    // MARK: Withdrawing trust

    /// What every withdrawal of trust does to the store, and what it leaves to be done: the key
    /// is refused from here on, everything it had authenticated is to be ended, and the
    /// listeners are to be told. The caller puts `.save` before these, so that the order is:
    /// written to disk, sessions ended, listeners told.
    private mutating func withdraw(_ key: PublicKey, name: String, reason: String, refuseForGood: Bool, wall: Date) -> [Effect] {
        if let i = file.tombstones.firstIndex(where: { $0.key == key }) {
            if refuseForGood { file.tombstones[i].reason = reason }
        } else if refuseForGood {
            file.tombstones.append(Tombstone(key: key, name: name, at: wall, reason: reason))
        }
        trimTombstones()
        file.known.removeAll { $0.key == key }
        file.again.removeAll { $0.key == key }
        return endSessions(of: key, because: "\(name) is no longer trusted (\(reason))") + [.tell(key)]
    }

    /// The sessions leave the list now; they are ended once the lock is let go.
    private mutating func endSessions(of key: PublicKey, because: String) -> [Effect] {
        let mine = sessions.filter { $0.key == key }.map(\.id)
        sessions.removeAll { $0.key == key }
        return [.end(Ending(why: .withdrawn, sessions: mine, log: "ended: \(because)", message: because.prefix(1).uppercased() + because.dropFirst()))]
    }

    /// The other Mac said its identity is retired: refused from now on, for good.
    package mutating func retire(_ key: PublicKey, reason: String = "retired", wall: Date) -> [Effect] {
        let name = file.known.first { $0.key == key }?.name ?? file.again.first { $0.key == key }?.name ?? key.tag
        return [.log("identity: \(name)'s key \(key.tag) is \(reason); it will be refused from now on", .warn), .save]
            + withdraw(key, name: name, reason: reason, refuseForGood: true, wall: wall) + [.changed]
    }

    /// Forget: the pairing goes and everything it had authenticated ends. The key itself is not
    /// refused for good (it may be paired again, by two people, like any other); a key already
    /// retired or run out stays refused.
    package mutating func forget(_ key: PublicKey, wall: Date) -> [Effect] {
        let name = file.known.first { $0.key == key }?.name ?? key.tag
        return [.log("identity: forgot \(name) (\(key.tag))", .info), .save]
            + withdraw(key, name: name, reason: "forgotten", refuseForGood: false, wall: wall) + [.changed]
    }

    /// A paired Mac has proved its key and said that it does not have this Mac paired: it
    /// forgot this Mac, or the last word of the pairing never reached it. This Mac's half is
    /// worth nothing, so it goes the way a Forget does (everything the key had authenticated
    /// ends) and the Mac is listed to be paired again, where its tile says so. Only the key
    /// itself can cause this, over a session it has proved, and only to its own entry.
    package mutating func notePairingGone(_ key: PublicKey, wall: Date) -> [Effect] {
        guard let mac = file.known.first(where: { $0.key == key }), current(mac.endsElapsed, mac.endsWall, wall) else { return [] }
        var out: [Effect] = [.log("identity: \(mac.name) (\(key.tag)) no longer has this Mac paired; it needs pairing again", .warn), .save]
        out += withdraw(key, name: mac.name, reason: "the other Mac forgot this one", refuseForGood: false, wall: wall)
        file.again.append(Renewal(key: key, name: mac.name, told: nil, endsElapsed: mac.endsElapsed, endsWall: mac.endsWall))
        return out + [.changed]
    }

    /// Reset Identity: a new key, every Known Mac moved to the pair-again list marked with
    /// whether it was told, every session ended.
    ///
    /// Every session: also one whose key is on neither list any more. A key whose calendar
    /// date passed (so it moved to the pair-again list) and whose elapsed end then passed (so
    /// it left that too) can still have a drop running out its day of grace, and until
    /// 2026-11-24 a reset ended only the sessions of keys it found on a list: that drop ran
    /// on under the identity that was being destroyed (found writing `formal/tla/TrustCore.tla`).
    package mutating func reset(told: Set<PublicKey>, wall: Date, newKey: () -> KeyPair = { KeyPair() }) -> [Effect] {
        var everyone: [PublicKey] = []
        for key in file.known.map(\.key) + file.again.map(\.key) + sessions.map(\.key) where !everyone.contains(key) { everyone.append(key) }
        var map: [PublicKey: Bool] = [:]
        for k in file.known { map[k.key] = told.contains(k.key) }
        var out = rotate(reason: "Reset Identity", told: map, wall: wall, newKey: newKey) + [.save]
        for key in everyone { out += endSessions(of: key, because: "this Mac's identity was reset") }
        for key in everyone { out.append(.tell(key)) }
        return out + [.changed]
    }

    // MARK: Storage

    /// How the write a `.save` asked for went. A failure leaves the change in force here and
    /// not on the disk; the write is tried again (`tick`), and the app tells the person meanwhile.
    package mutating func saved(_ ok: Bool) -> [Effect] {
        lastTry = file.elapsed
        guard ok else {
            if unsaved { return [] }
            unsaved = true
            return [.changed]
        }
        lastSave = file.elapsed
        guard unsaved else { return [] }
        unsaved = false
        return [.log("identity: the trust file was written; nothing is unsaved any more", .info), .changed]
    }
}
