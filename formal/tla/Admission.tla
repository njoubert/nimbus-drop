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
(* What is abstracted.                                                     *)
(*                                                                         *)
(*   Who a connection is. The code numbers connections as they arrive and  *)
(*   is told facts about a number. Here a connection that has proved       *)
(*   nothing is its place in its pool (1 is the oldest) and the address it *)
(*   came from; one that has proved a key is one of a count. A fact about  *)
(*   a number that holds nothing is a fact about "nobody". The answer      *)
(*   names the connection that gives way by its place before the event.    *)
(*                                                                         *)
(*   Time. The code is given a time with every arrival and keeps the time  *)
(*   of each arrival it still counts. Here an arrival carries how far the  *)
(*   clock has moved since the last one from the local network (a gap, in  *)
(*   whole ticks), and the state keeps ages. Nothing else in the machine   *)
(*   has a time in it: the deadlines (ten seconds to prove a key, five to  *)
(*   attach) are the listener's, and reach the machine as "closed".        *)
(*                                                                         *)
(*   Keys and addresses are names. Whether a key is paired is given with   *)
(*   the event, as the code is given it by the trust store.                *)
(*                                                                         *)
(* What stays outside: the sockets (the listener closes what an answer     *)
(* says to close), the threads and the lock (the listener calls Step with  *)
(* its lock held, so steps do not interleave), the clock itself, whether   *)
(* an address is on the local network (given with the arrival), how many   *)
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

\* The arrivals that still count when the clock has moved by gap.
StillCounts(x) == x.age <= Window
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
