----------------------------- MODULE Admission -----------------------------
(***************************************************************************)
(* Admission at one Mac's listener, as a state machine: which connection   *)
(* has a place, and which gives way.                                       *)
(*                                                                         *)
(* This is Sources/NimbusCrypto/Admission.swift written as a               *)
(* specification: Step(s, e) is Admission.step. The two are held equal.    *)
(* AdmissionTests walks every state the Swift machine can reach, at two    *)
(* small sets of limits, under every event, and writes the transition      *)
(* relation to AdmissionImpl.tla; AdmissionRefinement.tla has TLC check    *)
(* that relation against Step, both ways.                                  *)
(*                                                                         *)
(* THE ABSTRACTION CONTRACT. Three functions, each of the Swift value (and *)
(* of a naming: which strings are the addresses a, b, which keys are k1,   *)
(* k2, and how long one tick is) and of nothing else. They are code:       *)
(* AdmissionTests.abstract, .label and .answer.                            *)
(*                                                                         *)
(* The state. For a value m of the Swift type:                             *)
(*                                                                         *)
(*   strangers    the address of each element of m.strangers, in order     *)
(*   unattached   the address of each element of m.unattached, in order    *)
(*   unpaired     how many numbers are in m.unpaired                       *)
(*   waiting[k]   how many numbers m.waiting gives the key k               *)
(*   arrivals     for each element of m.arrivals, in order: its address,   *)
(*                and its age, (m.asOf - at) in ticks                      *)
(*                                                                         *)
(* Every stored property of the Swift type, and where it went:             *)
(*                                                                         *)
(*   strangers, unattached   IN THE STATE, but for the number of each      *)
(*       connection. A number is a name: the code never compares one but   *)
(*       for equality, so a connection that has proved nothing is its      *)
(*       place in its pool (1 is the oldest).                              *)
(*   unpaired, waiting       IN THE STATE as counts. Which numbers they    *)
(*       are is left out: a connection that has proved a key is told       *)
(*       apart from another of its kind by nothing the code looks at.      *)
(*   arrivals                IN THE STATE as ages. The times are left      *)
(*       out: the code only ever subtracts one from another.               *)
(*   asOf                    LEFT OUT: the origin the ages are counted     *)
(*       from. Nothing is decided by it.                                   *)
(*   next                    LEFT OUT: the number the next arrival gets.   *)
(*   limits                  THE CONSTANTS of this module. The listener    *)
(*       writes them before every step (from Tuning); in a walk they do    *)
(*       not change. Nothing in the state is worked out from them.         *)
(*                                                                         *)
(* An event. For an event of the code's, in the value m it is given in:    *)
(*                                                                         *)
(*   arrive(from, local, now)  << "arrive", address, "local", gap >> with  *)
(*       gap = (now - m.asOf) in ticks (anything, before the first); or    *)
(*       << "arrive", address, "elsewhere", 0 >>: the time of an arrival   *)
(*       from elsewhere is never looked at.                                *)
(*   data(n, drops), proved(n, as), attached(n), purpose(n), closed(n)     *)
(*       the same with `who` for the number n: << "stranger", i >> or      *)
(*       << "unattached", i >> if n is the i-th of that pool,              *)
(*       << "unpaired", 1 >> if n is in m.unpaired, << "waiting", k >> if  *)
(*       m.waiting gives n the key k, and << "nobody", 1 >> for every      *)
(*       other number (never given out, or holding nothing any more).      *)
(*                                                                         *)
(* An answer. admitted(n, displacing: d) is << "admitted", i >> where d is *)
(* the i-th of m.strangers BEFORE the event (0: nobody gave way). Which    *)
(* number n the arrival got is left out, except that the tests fail if it  *)
(* was given before. moved(displacing: d) likewise with m.unattached.      *)
(* close(why) and nothing are themselves. So an answer says WHICH          *)
(* connection gives way, not only that one does.                           *)
(*                                                                         *)
(* Why leaving those out is safe is not something TLC can say: one Swift   *)
(* value was walked for each state here. It is tested instead.             *)
(* AdmissionTests.testRandomWalksStayInsideTheRelation makes the code's    *)
(* own events at random under other namings (addresses, keys, a tick of an *)
(* eighth of a second or an hour, a clock that starts anywhere), other     *)
(* numbers, numbers long gone and histories of hundreds of events, labels  *)
(* each by the functions above, and fails on a step that is not in the     *)
(* relation; scripts/mutate.py has machines that depend on a number, on    *)
(* the time of day and on what an address is, and that test is the one     *)
(* that must notice each. What a walk at these sizes cannot reach (other   *)
(* limits, limits that change, times that are not whole ticks) is held to  *)
(* the rule said a second time: testRandomWalksAtOtherLimitsKeepToTheRule. *)
(*                                                                         *)
(* Time, then, is whole ticks here, and a window of one tick has every     *)
(* case the code's comparisons have: an arrival younger than the window,   *)
(* exactly as old (it still counts), older, and from later than now (a gap *)
(* below nothing: forgotten). Gaps run from one tick more than the window  *)
(* to as far back; any longer either way does the same as those. Nothing   *)
(* else in the machine has a time in it: the deadlines (ten seconds to     *)
(* prove a key, five to attach) are the listener's, and reach the machine  *)
(* as "closed".                                                            *)
(*                                                                         *)
(* What stays outside: the sockets (the listener closes what an answer     *)
(* says to close), the threads and the lock (the listener calls Step with  *)
(* its lock held, so steps do not interleave), the clock itself, whether   *)
(* an address is on the local network (given with the arrival), whether a  *)
(* key is paired (given with the proof, as the trust store says), how many *)
(* drops are in progress (given with a data connection), and everything    *)
(* after a connection has said what it came for: the questions on screen,  *)
(* a drop's own limit on its data connections, the pairing queue.          *)
(*                                                                         *)
(* Run: see formal/README.md, or ./build.sh verify                         *)
(***************************************************************************)
EXTENDS Integers, Sequences, FiniteSets

CONSTANTS Addresses, Keys,
          Strangers, StrangersPerAddress,           \* connections that have proved nothing: at once, and from one address
          Arrivals, ArrivalsPerAddress, Window,     \* arrivals taken within one window: from all, from one address
          UnattachedPerDrop, UnattachedPerAddress,  \* data connections that have not proved their drop
          Unpaired,                                 \* connections that proved a key nobody paired
          PairedWaiting,                            \* connections of one paired key that have not said what they came for
          Gaps,                                     \* how far the clock may move between one arrival and the next
          Drops                                     \* how many drops may be in progress

\* What a proved key can be to this Mac, besides a paired key (which is named).
Standings == {"mine", "retired", "unpaired"}

Start == [strangers |-> << >>, unattached |-> << >>, unpaired |-> 0,
          waiting |-> [k \in Keys |-> 0], arrivals |-> << >>]

Count(pool, a) == Cardinality({i \in 1..Len(pool): pool[i] = a})
From(arrivals, a) == Cardinality({i \in 1..Len(arrivals): arrivals[i].from = a})
Remove(seq, i) == SubSeq(seq, 1, i - 1) \o SubSeq(seq, i + 1, Len(seq))

(***************************************************************************)
(* Who gives way in a pool of connections that have proved nothing, for a  *)
(* newcomer from address a: a place in the pool, or 0 for nobody. At its   *)
(* address's own limit, the oldest from that address; otherwise, with the  *)
(* pool full, the oldest of all.                                           *)
(***************************************************************************)
GivesWay(pool, a, limit, perAddress) ==
    IF Count(pool, a) > 0 /\ Count(pool, a) >= perAddress
       THEN CHOOSE i \in 1..Len(pool): pool[i] = a /\ \A j \in 1..(i - 1): pool[j] # a
    ELSE IF Len(pool) > 0 /\ Len(pool) >= limit THEN 1
    ELSE 0

\* The pool with the newcomer in it, and who gave way.
Place(pool, a, limit, perAddress) ==
    LET out == GivesWay(pool, a, limit, perAddress)
    IN << Append(IF out = 0 THEN pool ELSE Remove(pool, out), a), out >>

\* The arrivals that still count when the clock has moved by gap: for one window after each,
\* and not at all once the clock says a time before it (a gap may be less than nothing: the
\* clock is the listener's, and a clock can be set back).
StillCounts(x) == x.age >= 0 /\ x.age <= Window
Recent(arrivals, gap) ==
    SelectSeq([i \in 1..Len(arrivals) |-> [arrivals[i] EXCEPT !.age = @ + gap]], StillCounts)

(***************************************************************************)
(* Everything that can happen, in state s. A fact can be about any         *)
(* connection that holds a place, or about nobody (a number that holds     *)
(* none), and can come in turn or out of it.                               *)
(***************************************************************************)
Whos(s) == {<< "stranger", i >> : i \in 1..Len(s.strangers)}
           \cup {<< "unattached", i >> : i \in 1..Len(s.unattached)}
           \cup (IF s.unpaired > 0 THEN {<< "unpaired", 1 >>} ELSE {})
           \cup {<< "waiting", k >> : k \in {k \in Keys: s.waiting[k] > 0}}
           \cup {<< "nobody", 1 >>}

Events(s) ==
    {<< "arrive", a, "local", g >> : a \in Addresses, g \in Gaps}
    \cup {<< "arrive", a, "elsewhere", 0 >> : a \in Addresses}
    \cup {<< "data", w, d >> : w \in Whos(s), d \in Drops}
    \cup {<< "proved", w, p >> : w \in Whos(s), p \in Standings \cup Keys}
    \cup {<< kind, w >> : kind \in {"attached", "purpose", "closed"}, w \in Whos(s)}

Close(s, why) == << s, << "close", why >> >>
Noted(s) == << s, << "nothing" >> >>

(***************************************************************************)
(* Step(s, e): the state after event e, and the answer: what the listener  *)
(* is to do.                                                               *)
(***************************************************************************)
Step(s, e) ==
    IF e[1] = "arrive" THEN
        \* << "arrive", address, "local" or "elsewhere", gap >>
        IF e[3] # "local" THEN Close(s, "elsewhere")
        ELSE LET recent == Recent(s.arrivals, e[4])
                 t == [s EXCEPT !.arrivals = recent]
             IN IF Len(recent) >= Arrivals \/ From(recent, e[2]) >= ArrivalsPerAddress
                   THEN Close(t, "rate")
                   ELSE LET p == Place(s.strangers, e[2], Strangers, StrangersPerAddress)
                        IN << [t EXCEPT !.arrivals = Append(recent, [age |-> 0, from |-> e[2]]), !.strangers = p[1]],
                              << "admitted", p[2] >> >>
    ELSE LET who == e[2] IN
    IF e[1] = "data" THEN
        \* << "data", who, drops in progress >>
        IF who[1] # "stranger" THEN Close(s, "gone")
        ELSE LET t == [s EXCEPT !.strangers = Remove(@, who[2])]
             IN IF e[3] = 0 THEN Close(t, "noDrop")
                ELSE LET p == Place(s.unattached, s.strangers[who[2]], UnattachedPerDrop * e[3], UnattachedPerAddress)
                     IN << [t EXCEPT !.unattached = p[1]], << "moved", p[2] >> >>
    ELSE IF e[1] = "proved" THEN
        \* << "proved", who, "mine", "retired", "unpaired" or a paired key >>
        IF who[1] # "stranger" THEN Close(s, "gone")
        ELSE LET t == [s EXCEPT !.strangers = Remove(@, who[2])]
             IN IF e[3] \in {"mine", "retired"} THEN Close(t, e[3])
                ELSE IF e[3] = "unpaired" THEN
                    IF s.unpaired < Unpaired THEN << [t EXCEPT !.unpaired = @ + 1], << "moved", 0 >> >>
                    ELSE Close(t, "tooManyUnpaired")
                ELSE
                    IF s.waiting[e[3]] < PairedWaiting THEN << [t EXCEPT !.waiting[e[3]] = @ + 1], << "moved", 0 >> >>
                    ELSE Close(t, "tooManyWaiting")
    ELSE IF e[1] = "attached" THEN
        IF who[1] = "unattached" THEN Noted([s EXCEPT !.unattached = Remove(@, who[2])])
        ELSE Noted(s)
    ELSE IF e[1] = "purpose" THEN
        IF who[1] = "waiting" THEN Noted([s EXCEPT !.waiting[who[2]] = @ - 1])
        ELSE Noted(s)
    ELSE \* closed: whatever it held is given back
        IF who[1] = "stranger" THEN Noted([s EXCEPT !.strangers = Remove(@, who[2])])
        ELSE IF who[1] = "unattached" THEN Noted([s EXCEPT !.unattached = Remove(@, who[2])])
        ELSE IF who[1] = "unpaired" THEN Noted([s EXCEPT !.unpaired = @ - 1])
        ELSE IF who[1] = "waiting" THEN Noted([s EXCEPT !.waiting[who[2]] = @ - 1])
        ELSE Noted(s)

=============================================================================
