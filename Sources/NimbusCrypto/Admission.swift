// Copyright (C) 2026 Niels Joubert
// SPDX-License-Identifier: GPL-3.0-or-later
import Foundation

/// Which connection has a place at the listener and which gives way, and nothing else: no
/// connection is touched here, no clock is read and no lock is taken.
///
/// `DropListener` (in the transfer core) owns the connections, the lock and the clock. For
/// every thing that happens to a connection before it has said what it came for, it tells this
/// machine (`step`) and does what the answer says: keeps the connection, closes it, closes the
/// one that gives way for it. Everything about who waits is decided here:
///
/// - a connection from outside the local network gets nothing and counts for nothing;
/// - no more arrivals in one `window` than the rate allows, in all and from one address. Over
///   it the newcomer is closed: a rate is not a place, and nobody can give one up;
/// - a newcomer within the rate ALWAYS gets a place among the connections that have proved
///   nothing. When its address already holds as many as one address may, the oldest from that
///   address gives way; otherwise, when the pool is full, the oldest of all (`place`). It was
///   the newcomer that was refused at first, and 64 silent connections from one host kept
///   every paired Mac out (the review of the code, F1);
/// - the same for a data connection that has not yet proved which drop it belongs to, in a
///   pool of its own whose size is so many for each drop in progress, and none when none is.
///   When a drop ends the places it gave end with it: the ones that have waited longest give
///   way, as they would to a newcomer;
/// - a connection that has proved a key nobody here has paired has proved nothing either:
///   anyone can make a key. It moves to a third pool of the same kind (so many at once, so
///   many from one address, and the newcomer always gets a place while anyone can give way),
///   with one difference. A connection there that has said what it came for (its request to
///   pair has been read, and may be on screen for minutes) gives way to nobody; only those
///   that have asked for nothing can be told to. Where everyone who could give way has asked,
///   the newcomer is the one turned away. Until 2026-11-24 it always was, and one host
///   holding every place with fresh keys kept every Mac that was not paired at that moment
///   from asking to pair: F1 again, in the one pool its fix had not reached;
/// - a connection that has proved a PAIRED key is never the one that gives way. It is counted
///   among so many of its own key that have not yet said what they came for, and there the
///   newcomer is the one refused: only that key's own connections can cost it a place;
/// - an address decides who waits and nothing else. Nothing a paired key gets depends on where
///   it came from, on what any other key has waiting, or on what strangers do.
///
/// A connection is known here by the number it was given on arrival, counted from one and
/// never used twice. A fact about a number that holds no place of the kind the fact is about
/// (it gave way a moment ago, or it is gone) changes nothing, and where the listener is waiting
/// for an answer the answer is to close it.
///
/// `formal/tla/Admission.tla` is this machine written as a specification. `AdmissionTests`
/// walks every state THIS code can reach at two small sets of limits and has TLC confirm the
/// two transition relations are equal (`formal/tla/AdmissionRefinement.tla`); what is checked
/// of the specification in `AdmissionSystem.tla` is then checked of this code, at those sizes.
/// A change here that is not a change there fails `./build.sh verify`.
package struct Admission: Sendable {
    /// How many, and how fast. `Tuning` has the numbers the listener runs with; a test runs the
    /// machine at small ones.
    package struct Limits: Equatable, Sendable {
        /// Connections that have proved nothing yet, at once; and of those, from one address.
        package var strangers: Int
        package var strangersPerAddress: Int
        /// Arrivals taken within one `window`, from all and from one address.
        package var arrivals: Int
        package var arrivalsPerAddress: Int
        /// In the unit the time is given in (seconds, from the listener).
        package var window: Double
        /// Data connections that have not yet proved their drop: for each drop in progress, and
        /// of them all from one address.
        package var unattachedPerDrop: Int
        package var unattachedPerAddress: Int
        /// Connections that proved a key nobody here has paired, at once; and of those, from one
        /// address.
        package var unpaired: Int
        package var unpairedPerAddress: Int
        /// Connections from one paired key that have not yet said what they came for.
        package var pairedWaiting: Int

        package init(strangers: Int, strangersPerAddress: Int, arrivals: Int, arrivalsPerAddress: Int, window: Double,
                     unattachedPerDrop: Int, unattachedPerAddress: Int, unpaired: Int, unpairedPerAddress: Int, pairedWaiting: Int) {
            self.strangers = strangers
            self.strangersPerAddress = strangersPerAddress
            self.arrivals = arrivals
            self.arrivalsPerAddress = arrivalsPerAddress
            self.window = window
            self.unattachedPerDrop = unattachedPerDrop
            self.unattachedPerAddress = unattachedPerAddress
            self.unpaired = unpaired
            self.unpairedPerAddress = unpairedPerAddress
            self.pairedWaiting = pairedWaiting
        }
    }

    /// What the key a connection proved is to this Mac. Given by whoever keeps the trust store;
    /// never worked out here, and never from an address.
    package enum Proved: Equatable, Sendable {
        /// This Mac's own key.
        case mine
        /// A key that was given up or replaced: refused for good.
        case retired
        /// Any other key nobody here has paired (unknown, run out, or to be paired again).
        case unpaired
        case paired(PublicKey)
    }

    package enum Event: Sendable {
        /// A connection has been accepted. `local`: its address is on the local network (or
        /// Settings say any network will do). `now`: the time, in the unit of `Limits.window`,
        /// on a clock that does not go back: the rate is so many in a window of THAT clock, and
        /// one that is held still or set back a little at a time forgets nothing.
        case arrive(from: String, local: Bool, now: Double)
        /// It opened as a data connection. `drops`: how many drops (and speed tests) are in
        /// progress that one could belong to.
        case data(UInt64, drops: Int)
        /// It completed a handshake, and so proved a key.
        case proved(UInt64, Proved)
        /// A data connection proved which drop it belongs to.
        case attached(UInt64)
        /// A connection that proved a key said what it came for.
        case purpose(UInt64)
        /// It is gone, whatever it was.
        case closed(UInt64)
        /// A drop (or a speed test) has begun or ended: this many are in progress now.
        case drops(Int)
    }

    /// Why a connection is to be closed.
    package enum Refusal: String, Sendable {
        /// Not from the local network.
        case elsewhere
        /// Too many arrivals in the window.
        case rate
        /// A data connection, and no drop is in progress.
        case noDrop
        case mine
        case retired
        /// As many connections from keys nobody paired as there may be (in all, or from its
        /// address), and every one that could give way has said what it came for.
        case tooManyUnpaired
        /// As many from this paired key that have asked for nothing as there may be.
        case tooManyWaiting
        /// It holds no place among those that have proved nothing: it gave way, or is gone.
        case gone
    }

    package enum Answer: Equatable, Sendable {
        /// The arrival has a place, and this is its number. `displacing`: the connection that
        /// gives way for it, to be closed.
        case admitted(UInt64, displacing: UInt64?)
        /// It has the place its new standing gives it.
        case moved(displacing: UInt64?)
        /// Close it.
        case close(Refusal)
        /// Close these: they give way, and no newcomer takes their places.
        case giveWay([UInt64])
        /// Noted; nothing to do.
        case nothing
    }

    /// A connection that has proved nothing yet, and where it came from.
    package struct Unproved: Equatable, Sendable {
        package let id: UInt64
        package let address: String
    }

    /// A connection that proved a key nobody here has paired: where it came from, and whether
    /// it has said what it came for.
    package struct Unpaired: Equatable, Sendable {
        package let id: UInt64
        package let address: String
        package var asked: Bool
    }

    /// An arrival that still counts against the rate.
    package struct Arrival: Equatable, Sendable {
        package let at: Double
        package let address: String
    }

    package var limits: Limits
    /// Connections that have not said what they are, in order of arrival.
    package private(set) var strangers: [Unproved] = []
    /// Data connections that have not proved their drop, in the order they said they were one.
    package private(set) var unattached: [Unproved] = []
    /// Connections that proved a key nobody here has paired, in the order they proved it.
    package private(set) var unpaired: [Unpaired] = []
    /// Connections that proved a paired key and have not yet said what they came for.
    package private(set) var waiting: [UInt64: PublicKey] = [:]
    /// Arrivals within the last window, as of the last one.
    package private(set) var arrivals: [Arrival] = []
    /// The time of the last arrival from the local network: what `arrivals` is as of. Nothing
    /// is decided by it. It is here so that everything the specification's state says (how
    /// long ago each counted arrival was) is a function of this value alone.
    package private(set) var asOf: Double?
    /// The number the next arrival is given. Numbers are names: never compared but for equality.
    private var next: UInt64 = 1

    package init(limits: Limits) {
        self.limits = limits
    }

    /// Puts `new` in a pool of connections that have proved nothing; returns the one that gives
    /// way for it. At its address's own limit that is the oldest from the same address, so one
    /// address can only ever push out its own; with the whole pool full it is the oldest of all.
    /// An honest Mac proves itself within milliseconds of arriving and what an attacker's
    /// connection does is wait, so the longest wait is what loses the place.
    private static func place(_ new: Unproved, in pool: inout [Unproved], limit: Int, perAddress: Int) -> UInt64? {
        var out: Unproved?
        if let own = pool.firstIndex(where: { $0.address == new.address }), pool.filter({ $0.address == new.address }).count >= perAddress {
            out = pool.remove(at: own)
        } else if pool.count >= limit, !pool.isEmpty {
            out = pool.removeFirst()
        }
        pool.append(new)
        return out?.id
    }

    /// What `event` means now: the answer is what the listener is to do.
    package mutating func step(_ event: Event) -> Answer {
        switch event {
        case .arrive(let from, let local, let now):
            guard local else { return .close(.elsewhere) }
            asOf = now
            // An arrival counts for one window after it. And one from later than now is
            // forgotten: the time is the listener's to give, and if its clock was ever set back,
            // an arrival of before would otherwise go on counting until the clock came round to
            // it again, with everyone turned away for as long if the rate was full.
            arrivals.removeAll { now - $0.at > limits.window || $0.at > now }
            // The rate cannot be met by anyone giving way: over it, the newcomer is closed.
            guard arrivals.count < limits.arrivals,
                  arrivals.filter({ $0.address == from }).count < limits.arrivalsPerAddress else { return .close(.rate) }
            arrivals.append(Arrival(at: now, address: from))
            let id = next
            next += 1
            let out = Self.place(Unproved(id: id, address: from), in: &strangers, limit: limits.strangers, perAddress: limits.strangersPerAddress)
            return .admitted(id, displacing: out)

        case .data(let id, let drops):
            // One that gave way a moment ago gets nothing more.
            guard let it = strangers.first(where: { $0.id == id }) else { return .close(.gone) }
            strangers.removeAll { $0.id == it.id }
            // Nothing it could belong to.
            guard drops > 0 else { return .close(.noDrop) }
            let out = Self.place(it, in: &unattached, limit: limits.unattachedPerDrop * drops, perAddress: limits.unattachedPerAddress)
            return .moved(displacing: out)

        case .proved(let id, let who):
            guard let was = strangers.first(where: { $0.id == id }) else { return .close(.gone) }
            // No longer one of the connections that have not said what they are.
            strangers.removeAll { $0.id == was.id }
            switch who {
            case .mine: return .close(.mine)
            case .retired: return .close(.retired)
            case .unpaired:
                // A key nobody paired is a key anyone could have made a moment ago: the place
                // it gets is given as a stranger's is. At its address's share, that address's
                // oldest gives way; with the pool full, the oldest of all. But only one that has
                // asked for nothing can give way: a request to pair that has been read is not
                // closed to make room, and where there is nobody else the newcomer is.
                let own = unpaired.filter { $0.address == was.address }
                var out: Unpaired?
                if !own.isEmpty, own.count >= limits.unpairedPerAddress {
                    guard let silent = own.first(where: { !$0.asked }) else { return .close(.tooManyUnpaired) }
                    out = silent
                } else if !unpaired.isEmpty, unpaired.count >= limits.unpaired {
                    guard let silent = unpaired.first(where: { !$0.asked }) else { return .close(.tooManyUnpaired) }
                    out = silent
                }
                if let out { unpaired.removeAll { $0.id == out.id } }
                unpaired.append(Unpaired(id: id, address: was.address, asked: false))
                return .moved(displacing: out?.id)
            case .paired(let key):
                // Where it came from is forgotten here: it plays no part in what a paired key gets.
                guard waiting.values.filter({ $0 == key }).count < limits.pairedWaiting else { return .close(.tooManyWaiting) }
                waiting[id] = key
                return .moved(displacing: nil)
            }

        case .attached(let id):
            // It is one of its drop's connections now, and the drop counts those.
            unattached.removeAll { $0.id == id }
            return .nothing

        case .purpose(let id):
            // A paired key is counted until it has said what it came for. A key nobody paired
            // stays counted for as long as its connection lasts, and from here it keeps its
            // place: what it asked for may take a person minutes to answer.
            waiting[id] = nil
            if let at = unpaired.firstIndex(where: { $0.id == id }) { unpaired[at].asked = true }
            return .nothing

        case .closed(let id):
            // Whatever it held is given back.
            strangers.removeAll { $0.id == id }
            unattached.removeAll { $0.id == id }
            unpaired.removeAll { $0.id == id }
            waiting[id] = nil
            return .nothing

        case .drops(let drops):
            // So many places for each drop in progress. A drop that ends takes its places with
            // it, and with none left there is nothing a data connection could attach to. Until
            // 2026-11-24 nobody gave way then: the pool stayed over its limit for as long as
            // those in it cared to wait (formal/tla/AdmissionSystem.tla found it).
            let over = unattached.count - limits.unattachedPerDrop * max(0, drops)
            guard over > 0 else { return .nothing }
            let out = unattached.prefix(over).map(\.id)
            unattached.removeFirst(over)
            return .giveWay(out)
        }
    }
}
