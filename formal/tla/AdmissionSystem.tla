--------------------------- MODULE AdmissionSystem ---------------------------
(***************************************************************************)
(* A listener, the admission machine it asks (Admission.tla, which is      *)
(* Admission.swift), and everyone who connects to it.                      *)
(*                                                                         *)
(* One connection is watched: it comes from the address Honest, and it is  *)
(* an honest Mac's. It arrives and then either proves its key and says     *)
(* what it came for (a control connection), or says it is a data           *)
(* connection and attaches to a drop. It never gives up. When Paired, its  *)
(* key is one this Mac has paired, and it is the only connection that can  *)
(* prove it (what the handshake gives: formal/tamarin/NimbusHandshake      *)
(* .spthy). When not, it is a Mac nobody here has paired (a new one, or    *)
(* one whose pairing ran out), and what it came for is to ask to pair.     *)
(*                                                                         *)
(* Everyone else is "x": any number of connections, from any address       *)
(* (also from outside the local network, and, unless Alone, from the       *)
(* watched Mac's own address), at any moment, as slow as they like. Each   *)
(* may say nothing, open as a data connection, prove a key nobody paired,  *)
(* a retired key, this Mac's own, or a paired key other than HonestKey (a  *)
(* paired Mac that means harm), say what it came for, attach, or close.    *)
(* They are not numbered: there is no bound on how many there are.         *)
(*                                                                         *)
(* The listener is modelled as what DropListener does with the machine:    *)
(* it tells it each fact as one step (its lock is held around each), and   *)
(* closes whom the answer names. S, U and P are its sockets, oldest first: *)
(* who stands at each place of the machine's three pools, and for P (the   *)
(* keys nobody paired) whether each has in truth said what it came for.    *)
(* nw is how many connections of each paired key are in truth waiting.     *)
(* Nothing here re-decides who gets a place: the properties compare what   *)
(* the machine answered with what is true of the world.                    *)
(*                                                                         *)
(* Time: the true time moves by a gap at each arrival from the local       *)
(* network. The machine is given the gap its clock shows, which is the     *)
(* true one unless the clock was set back in between (at most SetBack      *)
(* ticks in all). The listener's clock cannot be set (it counts from       *)
(* boot); until 2026-11-24 it read the calendar, which can. Making the     *)
(* time an argument of the machine is what showed that, and this model is  *)
(* what it costs: with SetBack above nothing a Mac within the rate is      *)
(* turned away, and no rule inside the machine can prevent it (a clock     *)
(* held still forgets nothing). What the machine does promise of any clock *)
(* is NothingIsCountedFromLaterThanNow.                                    *)
(*                                                                         *)
(* Outside this model: the sockets and the threads (each fact is one step  *)
(* here because the listener's lock makes it one), the ten seconds a       *)
(* connection has to prove a key and the five to attach (they reach the    *)
(* machine as "closed", which anyone but the watched connection may do at  *)
(* any time), and everything after a connection has said what it came for. *)
(*                                                                         *)
(* Every run is at small limits and is bounded checking, not proof: see    *)
(* formal/check.py for the limits of each run.                             *)
(***************************************************************************)
EXTENDS Admission

CONSTANTS Honest,       \* the address the watched connection comes from
          HonestKey,    \* the paired key it proves, and nobody else can
          Outside,      \* addresses that are not on the local network
          Alone,        \* nobody else arrives from the watched Mac's address
          Quick,        \* the watched connection moves on before enough others to push it out have been given places after it
          SetBack,      \* how far, in all, the clock the machine is given may be set back
          Paired,       \* the watched Mac's key is paired here (otherwise it is a Mac nobody has paired, come to ask)
          OthersAsk     \* the others that prove a key nobody paired may go on to say what they came for

ASSUME Honest \in Addresses \ Outside /\ HonestKey \in Keys /\ Keys \cap Standings = {}
ASSUME \A n \in {Strangers, StrangersPerAddress, Arrivals, ArrivalsPerAddress, UnattachedPerDrop, UnattachedPerAddress,
                 Unpaired, UnpairedPerAddress, PairedWaiting}: n \in Nat /\ n >= 1

VARIABLES m,        \* the machine
          S, U,     \* who stands at each place among the strangers, and among the unattached: "w" (watched) or "x"
          P,        \* who stands at each place among the keys nobody paired, and whether it has in truth asked
          nw,       \* for each paired key, its connections that have not yet said what they came for
          w,        \* the watched connection: where it has got to, and how many were given a place in its pool after it
          drops,    \* drops in progress
          log,      \* the arrivals taken within the last window, by the true time
          back,     \* how far the machine's clock has been set back so far
          broken    \* the names of the properties of a single step that some step has broken

vars == << m, S, U, P, nw, w, drops, log, back, broken >>

Local  == Addresses \ Outside
\* Where anyone but the watched connection may come from.
Others == Outside \cup (Local \ (IF Alone THEN {Honest} ELSE {}))

(* The listener's own bookkeeping and the world's, written without the machine's definitions. *)
Number(seq, a)  == Cardinality({i \in 1..Len(seq): seq[i] = a})
Taken(lg, a)    == Cardinality({i \in 1..Len(lg): lg[i].from = a})
Without(seq, k) == IF k \in 1..Len(seq) THEN SubSeq(seq, 1, k - 1) \o SubSeq(seq, k + 1, Len(seq)) ELSE seq
Where(seq)      == IF \E i \in 1..Len(seq): seq[i] = "w" THEN CHOOSE i \in 1..Len(seq): seq[i] = "w" ELSE 0
Least(a, b)     == IF a < b THEN a ELSE b
InTheWindow(x)  == x.age <= Window
Aged(lg, g)     == SelectSeq([i \in 1..Len(lg) |-> [lg[i] EXCEPT !.age = @ + g]], InTheWindow)
AddressAt(pool, i) == IF i \in 1..Len(pool) THEN pool[i] ELSE Honest
\* Where the watched connection stands among the keys nobody paired.
WhereP == IF \E j \in 1..Len(P): P[j].who = "w" THEN CHOOSE j \in 1..Len(P): P[j].who = "w" ELSE 0

\* No count of "given a place after it" needs to go higher than the largest pool.
Most == LET sizes == {Strangers, Unpaired} \cup {UnattachedPerDrop * d : d \in Drops}
        IN CHOOSE n \in sizes: \A k \in sizes: k <= n

Fresh == [st |-> "unborn", later |-> 0, own |-> 0]
Went(to) == [st |-> to, later |-> 0, own |-> 0]
\* Another connection, from address a, was given a place in the pool the watched one waits in.
OneMore(a) == [w EXCEPT !.later = Least(@ + 1, Most), !.own = IF a = Honest THEN Least(@ + 1, Most) ELSE @]
\* With one more from address a, as many have been given places after the watched connection as
\* a pool of this size holds, or as many from its own address as an address may hold.
Enough(limit, perAddress, a) == w.later + 1 >= limit \/ (a = Honest /\ w.own + 1 >= perAddress)

(***************************************************************************)
(* The rule for who gives way, said of the world and not computed: nobody  *)
(* (k = 0) only when there is room; otherwise the oldest from the          *)
(* newcomer's address when that address holds as many as it may, and the   *)
(* oldest of all when it does not and the pool is full.                    *)
(***************************************************************************)
RightOneGivesWay(pool, a, limit, perAddress, k) ==
    IF k = 0 THEN Number(pool, a) < perAddress /\ Len(pool) < limit
    ELSE /\ k \in 1..Len(pool)
         /\ IF Number(pool, a) >= perAddress
               THEN pool[k] = a /\ \A j \in 1..(k - 1): pool[j] # a
               ELSE Len(pool) >= limit /\ k = 1

(***************************************************************************)
(* The same for a key nobody paired, by what is TRUE of each connection    *)
(* there (asked: whether it has said what it came for): only one that has  *)
(* asked for nothing may give way, and -1 says the newcomer must be turned *)
(* away because nobody may.                                                *)
(***************************************************************************)
RightKeyGivesWay(pool, asked, a) ==
    LET own      == {j \in 1..Len(pool): pool[j].from = a}
        silent   == {j \in 1..Len(asked): ~asked[j]}
        first(T) == CHOOSE j \in T: \A k \in T: j <= k
    IN IF own # {} /\ Cardinality(own) >= UnpairedPerAddress
          THEN IF own \cap silent # {} THEN first(own \cap silent) ELSE -1
       ELSE IF Len(pool) >= Unpaired
          THEN IF silent # {} THEN first(silent) ELSE -1
       ELSE 0

\* The same count for the watched connection among the keys nobody paired, where a connection
\* that has asked holds its place whoever arrives: with one more from address a, those that
\* have asked and those given places after the watched one are as many as the pool holds, or,
\* from its own address, as many as an address may hold.
HasAsked(j)    == P[j].asked
FromHonest(j)  == j <= Len(m.unpaired) /\ m.unpaired[j].from = Honest
EnoughKeys(a)  == \/ Cardinality({j \in 1..Len(P): HasAsked(j)}) + w.later + 1 >= Unpaired
                  \/ a = Honest /\ Cardinality({j \in 1..Len(P): HasAsked(j) /\ FromHonest(j)}) + w.own + 1 >= UnpairedPerAddress

Init == /\ m = Start /\ S = << >> /\ U = << >> /\ P = << >> /\ nw = [k \in Keys |-> 0]
        /\ w = Fresh /\ drops \in Drops /\ log = << >> /\ back = 0 /\ broken = {}

(* ---- A connection arrives ---------------------------------------------- *)

Arrive(who, a, g, j) ==
    LET local  == a \notin Outside
        e      == << "arrive", a, IF local THEN "local" ELSE "elsewhere", IF local THEN g - j ELSE 0 >>
        r      == Step(m, e)
        ans    == r[2]
        lg     == IF local THEN Aged(log, g) ELSE log
        under  == Len(lg) < Arrivals /\ Taken(lg, a) < ArrivalsPerAddress
        in     == ans[1] = "admitted"
        k      == IF in THEN ans[2] ELSE 0
        pushed == in /\ w.st = "stranger" /\ k # 0 /\ k = Where(S)
        others == Cardinality(Local \ {Honest})
        bad    == (IF ~local /\ (ans # << "close", "elsewhere" >> \/ r[1] # m) THEN {"outside"} ELSE {})
                  \cup (IF local /\ under /\ ~in THEN {"newcomer"} ELSE {})
                  \cup (IF local /\ ~under /\ (ans # << "close", "rate" >> \/ r[1].strangers # m.strangers) THEN {"rate"} ELSE {})
                  \cup (IF in /\ ~RightOneGivesWay(m.strangers, a, Strangers, StrangersPerAddress, k) THEN {"oldest"} ELSE {})
                  \cup (IF pushed /\ ~Enough(Strangers, StrangersPerAddress, a) THEN {"enough"} ELSE {})
                  \cup (IF who = "w" /\ local /\ ~in /\ Taken(lg, Honest) < ArrivalsPerAddress
                           /\ Taken(lg, Honest) + others * ArrivalsPerAddress < Arrivals THEN {"account"} ELSE {})
                  \cup (IF who = "w" /\ local /\ ~in /\ Taken(lg, Honest) = 0 THEN {"keptOut"} ELSE {})
    IN /\ IF who = "w" THEN w.st = "unborn" /\ a = Honest ELSE a \in Others
       /\ (who = "x" /\ Quick /\ w.st = "stranger" => ~Enough(Strangers, StrangersPerAddress, a))
       /\ IF local THEN j \in 0..(SetBack - back) ELSE j = 0
       /\ m' = r[1]
       /\ S' = IF in THEN Append(Without(S, k), who) ELSE S
       /\ log' = IF in THEN Append(lg, [age |-> 0, from |-> a]) ELSE lg
       /\ back' = back + j
       /\ w' = IF who = "w" THEN (IF in THEN Went("stranger") ELSE Went("refused"))
               ELSE IF pushed THEN Went("displaced")
               ELSE IF in /\ w.st = "stranger" THEN OneMore(a)
               ELSE w
       /\ broken' = broken \cup bad
       /\ UNCHANGED << U, P, nw, drops >>

(* ---- A stranger says what it is ---------------------------------------- *)

\* The connection at place i among the strangers opens as a data connection.
SaysData(i) ==
    LET who    == S[i]
        a      == AddressAt(m.strangers, i)
        limit  == UnattachedPerDrop * drops
        r      == Step(m, << "data", << "stranger", i >>, drops >>)
        ans    == r[2]
        in     == ans[1] = "moved"
        k      == IF in THEN ans[2] ELSE 0
        pushed == in /\ w.st = "unattached" /\ k # 0 /\ k = Where(U)
        bad    == (IF in # (drops > 0) \/ (drops = 0 /\ ans # << "close", "noDrop" >>) THEN {"noDrop"} ELSE {})
                  \cup (IF in /\ ~RightOneGivesWay(m.unattached, a, limit, UnattachedPerAddress, k) THEN {"oldest"} ELSE {})
                  \cup (IF pushed /\ ~Enough(limit, UnattachedPerAddress, a) THEN {"enough"} ELSE {})
    IN /\ i \in 1..Len(S)
       /\ (who = "x" /\ Quick /\ w.st = "unattached" /\ drops > 0 => ~Enough(limit, UnattachedPerAddress, a))
       /\ m' = r[1]
       /\ S' = Without(S, i)
       /\ U' = IF in THEN Append(Without(U, k), who) ELSE U
       /\ w' = IF who = "w" THEN (IF in THEN Went("unattached") ELSE Went("noDrop"))
               ELSE IF pushed THEN Went("displaced")
               ELSE IF in /\ w.st = "unattached" THEN OneMore(a)
               ELSE w
       /\ broken' = broken \cup bad
       /\ UNCHANGED << P, nw, drops, log, back >>

\* The connection at place i among the strangers completes a handshake. `as`: what the key it
\* proved is to this Mac. The watched connection proves its own key (HonestKey, when Paired);
\* nobody else can prove that one.
Proves(i, as) ==
    LET who    == S[i]
        a      == AddressAt(m.strangers, i)
        r      == Step(m, << "proved", << "stranger", i >>, as >>)
        ans    == r[2]
        in     == ans[1] = "moved"
        k      == IF in THEN ans[2] ELSE 0
        key    == as = "unpaired"
        \* By the truth: who must give way among the keys nobody paired; room among a paired key's own.
        must   == RightKeyGivesWay(m.unpaired, [j \in 1..Len(P) |-> P[j].asked], a)
        room   == as \in Keys /\ nw[as] < PairedWaiting
        pushed == in /\ key /\ k # 0 /\ k = WhereP
        bad    == (IF as \in Keys /\ in # room THEN {"keys"} ELSE {})
                  \cup (IF as \in {"mine", "retired"} /\ ans # << "close", as >> THEN {"retired"} ELSE {})
                  \cup (IF key /\ ~in /\ must >= 0 THEN {"newKey"} ELSE {})
                  \cup (IF key /\ in /\ k # must THEN {"oldestKey"} ELSE {})
                  \cup (IF key /\ in /\ k \in 1..Len(P) /\ P[k].asked THEN {"askedOut"} ELSE {})
                  \cup (IF pushed /\ w.st = "silent" /\ ~EnoughKeys(a) THEN {"enough"} ELSE {})
                  \cup (IF key /\ ~in THEN {"unpairedOut"} ELSE {})
                  \cup (IF who = "w" /\ ~in THEN {"watchedOut"} ELSE {})
    IN /\ i \in 1..Len(S)
       /\ IF who = "w" THEN as = (IF Paired THEN HonestKey ELSE "unpaired") ELSE as \in (Standings \cup Keys) \ {HonestKey}
       /\ (who = "x" /\ key /\ Quick /\ w.st = "silent" => ~EnoughKeys(a))
       /\ m' = r[1]
       /\ S' = Without(S, i)
       /\ P' = IF in /\ key THEN Append(Without(P, k), [who |-> who, asked |-> FALSE]) ELSE P
       /\ nw' = IF in /\ as \in Keys THEN [nw EXCEPT ![as] = @ + 1] ELSE nw
       /\ w' = IF who = "w" THEN (IF ~in THEN Went("turnedAway") ELSE IF key THEN Went("silent") ELSE Went("waiting"))
               ELSE IF pushed THEN Went("displaced")
               ELSE IF in /\ key /\ w.st = "silent" THEN OneMore(a)
               ELSE w
       /\ broken' = broken \cup bad
       /\ UNCHANGED << U, drops, log, back >>

(* ---- A connection that has a place moves on, or goes ------------------- *)

\* A connection of a paired key says what it came for, and is no longer counted.
SaysPurpose(who, c) ==
    LET r == Step(m, << "purpose", << "waiting", c >> >>)
    IN /\ c \in Keys
       /\ IF who = "w" THEN w.st = "waiting" /\ c = HonestKey ELSE c # HonestKey /\ nw[c] > 0
       /\ m' = r[1]
       /\ nw' = [nw EXCEPT ![c] = @ - 1]
       /\ w' = IF who = "w" THEN Went("through") ELSE w
       /\ UNCHANGED << S, U, P, drops, log, back, broken >>

\* The connection at place j among the keys nobody paired says what it came for (to pair: its
\* request has been read). It stays counted, for as long as it lasts; and from here it keeps
\* its place, whoever arrives.
Asks(j) ==
    LET r == Step(m, << "purpose", << "unpaired", j >> >>)
    IN /\ j \in 1..Len(P)
       /\ IF P[j].who = "w" THEN w.st = "silent" ELSE OthersAsk
       /\ m' = r[1]
       /\ P' = [P EXCEPT ![j].asked = TRUE]
       /\ w' = IF P[j].who = "w" THEN Went("asked") ELSE w
       /\ UNCHANGED << S, U, nw, drops, log, back, broken >>

\* The data connection at place j among the unattached proves which drop it belongs to.
Attaches(j) ==
    LET r == Step(m, << "attached", << "unattached", j >> >>)
    IN /\ j \in 1..Len(U) /\ drops > 0
       /\ m' = r[1]
       /\ U' = Without(U, j)
       /\ w' = IF U[j] = "w" THEN Went("attached") ELSE w
       /\ UNCHANGED << S, P, nw, drops, log, back, broken >>

\* Anyone but the watched connection goes away, or runs out of time and is closed.
Closes(c, i) ==
    LET who == IF c \in {"stranger", "unattached", "unpaired"} THEN << c, i >> ELSE << "waiting", c >>
        r   == Step(m, << "closed", who >>)
    IN /\ IF c = "stranger" THEN i \in 1..Len(S) /\ S[i] = "x"
          ELSE IF c = "unattached" THEN i \in 1..Len(U) /\ U[i] = "x"
          ELSE IF c = "unpaired" THEN i \in 1..Len(P) /\ P[i].who = "x"
          ELSE i = 1 /\ c \in Keys \ {HonestKey} /\ nw[c] > 0
       /\ m' = r[1]
       /\ S' = IF c = "stranger" THEN Without(S, i) ELSE S
       /\ U' = IF c = "unattached" THEN Without(U, i) ELSE U
       /\ P' = IF c = "unpaired" THEN Without(P, i) ELSE P
       /\ nw' = IF c \in Keys THEN [nw EXCEPT ![c] = @ - 1] ELSE nw
       /\ UNCHANGED << w, drops, log, back, broken >>

\* A fact about a connection that holds no place: it gave way a moment ago and its thread had
\* already read something, or it is long gone and its thread says so on the way out.
Late(e) ==
    LET r == Step(m, e)
    IN /\ m' = r[1]
       /\ broken' = broken \cup (IF r[1] # m \/ (e[1] \in {"data", "proved"} /\ r[2] # << "close", "gone" >>) THEN {"gone"} ELSE {})
       /\ UNCHANGED << S, U, P, nw, w, drops, log, back >>

LateFacts == {<< "data", << "nobody", 1 >>, d >> : d \in Drops}
             \cup {<< "proved", << "nobody", 1 >>, p >> : p \in Standings \cup Keys}
             \cup {<< kind, << "nobody", 1 >> >> : kind \in {"attached", "purpose", "closed"}}

\* A drop begins, or ends, and the listener says how many are in progress now. The places a drop
\* gave among the unattached end with it: whoever the machine says gives way is closed. (Until
\* 2026-11-24 the machine was not told, and nobody gave way: UnattachedWithinItsLimit found it.)
DropsChange(d) ==
    LET r      == Step(m, << "drops", d >>)
        n      == IF r[2][1] = "giveWay" THEN r[2][2] ELSE 0
        limit  == UnattachedPerDrop * d
        pushed == w.st = "unattached" /\ Where(U) <= n
        bad    == (IF n # (IF Len(m.unattached) > limit THEN Len(m.unattached) - limit ELSE 0) THEN {"ended"} ELSE {})
                  \cup (IF pushed /\ w.later < limit THEN {"enough"} ELSE {})
    IN /\ d \in Drops /\ d # drops
       /\ (Quick /\ w.st = "unattached" => w.later < limit)
       /\ drops' = d
       /\ m' = r[1]
       /\ U' = IF n <= Len(U) THEN SubSeq(U, n + 1, Len(U)) ELSE << >>
       /\ w' = IF pushed THEN Went("displaced") ELSE w
       /\ broken' = broken \cup bad
       /\ UNCHANGED << S, P, nw, log, back >>

Next == \/ \E who \in {"w", "x"}, a \in Addresses, g \in Gaps, j \in 0..SetBack: Arrive(who, a, g, j)
        \/ \E i \in 1..Len(S): SaysData(i) \/ \E as \in Standings \cup Keys: Proves(i, as)
        \/ \E who \in {"w", "x"}, c \in Keys: SaysPurpose(who, c)
        \/ \E j \in 1..Len(P): Asks(j)
        \/ \E j \in 1..Len(U): Attaches(j)
        \/ \E c \in {"stranger", "unattached", "unpaired"} \cup Keys, i \in 1..(Len(S) + Len(U) + Len(P) + 1): Closes(c, i)
        \/ \E e \in LateFacts: Late(e)
        \/ \E d \in Drops: DropsChange(d)

Spec == Init /\ [][Next]_vars

(***************************************************************************)
(* Properties of every state                                               *)
(***************************************************************************)

TypeOK == /\ w.st \in {"unborn", "refused", "stranger", "displaced", "noDrop", "unattached", "attached", "waiting", "turnedAway", "through",
                      "silent", "asked"}
          /\ \A j \in 1..Len(m.unpaired): m.unpaired[j].from \in Addresses /\ m.unpaired[j].asked \in BOOLEAN
          /\ \A k \in Keys: m.waiting[k] \in Nat
          /\ \A i \in 1..Len(m.arrivals): m.arrivals[i].from \in Addresses

\* No pool is ever over its limit, nor an address over its own.
PoolsWithinLimits ==
    /\ Len(m.strangers) <= Strangers
    /\ \A a \in Addresses: Number(m.strangers, a) <= StrangersPerAddress /\ Number(m.unattached, a) <= UnattachedPerAddress
    /\ Len(m.unpaired) <= Unpaired
    /\ \A a \in Addresses: Cardinality({j \in 1..Len(m.unpaired): m.unpaired[j].from = a}) <= UnpairedPerAddress
    /\ \A k \in Keys: m.waiting[k] <= PairedWaiting

\* The pool of data connections has so many places for each drop in progress: now, not when
\* each of them arrived. With no drop in progress it is empty.
UnattachedWithinItsLimit == Len(m.unattached) <= UnattachedPerDrop * drops

\* When a drop ends, exactly those over what is left give way, and they are the ones that have
\* waited longest (the listener closes the first so many: EveryPlaceIsHeldByItsConnection
\* fails if the machine dropped any others).
WhenADropEndsItsPlacesEndWithIt == "ended" \notin broken

\* By the true time: no more arrivals taken within a window than the rate, in all and from one address.
TheRateHolds == Len(log) <= Arrivals /\ \A a \in Addresses: Taken(log, a) <= ArrivalsPerAddress

\* Whatever the clock does, the machine counts no arrival from later than the time it was last
\* given. (Set back an hour, a clock used to leave the arrivals of the last second counted for
\* the hour. What a clock that can be set back still costs is in formal/check.py: the listener's
\* cannot be.)
NothingIsCountedFromLaterThanNow == \A i \in 1..Len(m.arrivals): m.arrivals[i].age >= 0

\* What the machine counts is what is there. Its pools are exactly the connections that have
\* not said what they are, the data connections that have not attached and the connections
\* that proved a key nobody paired, place for place, and of those last it knows truly which
\* have asked; its counts are the connections of each paired key still to be counted.
\* Nothing is kept that nobody holds; nothing is held uncounted.
EveryPlaceIsHeldByItsConnection ==
    /\ Len(m.strangers) = Len(S) /\ Len(m.unattached) = Len(U) /\ Len(m.unpaired) = Len(P)
    /\ \A j \in 1..Len(P): j <= Len(m.unpaired) => m.unpaired[j].asked = P[j].asked
    /\ \A k \in Keys: m.waiting[k] = nw[k]
    /\ (w.st = "stranger") = (Where(S) # 0) /\ (w.st = "unattached") = (Where(U) # 0) /\ (w.st \in {"silent", "asked"}) = (WhereP # 0)
    /\ (Where(S) # 0 => AddressAt(m.strangers, Where(S)) = Honest)
    /\ (Where(U) # 0 => AddressAt(m.unattached, Where(U)) = Honest)
    /\ (WhereP # 0 /\ WhereP <= Len(m.unpaired) => m.unpaired[WhereP].from = Honest /\ P[WhereP].asked = (w.st = "asked"))
    /\ (Paired => nw[HonestKey] = IF w.st = "waiting" THEN 1 ELSE 0)

(***************************************************************************)
(* An address decides who waits and nothing else: nothing a PAIRED key     *)
(* gets depends on one. Take any state and forget where every connection   *)
(* came from (as if all had one address): every fact about a paired key,   *)
(* about this Mac's own or a retired one, and every fact about a           *)
(* connection that has a place, gets the same answer and leaves the same   *)
(* state behind. (Not so a key nobody paired proving itself: it has proved *)
(* nothing that counts here, and which of those waits is what an address   *)
(* does decide.)                                                           *)
(***************************************************************************)
Forget(s) == [s EXCEPT !.strangers = [i \in 1..Len(@) |-> Honest],
                       !.unattached = [i \in 1..Len(@) |-> Honest],
                       !.unpaired = [i \in 1..Len(@) |-> [@[i] EXCEPT !.from = Honest]],
                       !.arrivals = [i \in 1..Len(@) |-> [@[i] EXCEPT !.from = Honest]]]
Same(s, t) == /\ Len(s.strangers) = Len(t.strangers) /\ \A i \in 1..Len(s.strangers): s.strangers[i] = t.strangers[i]
              /\ Len(s.unattached) = Len(t.unattached) /\ \A i \in 1..Len(s.unattached): s.unattached[i] = t.unattached[i]
              /\ Len(s.unpaired) = Len(t.unpaired) /\ \A i \in 1..Len(s.unpaired): s.unpaired[i] = t.unpaired[i]
              /\ Len(s.arrivals) = Len(t.arrivals) /\ \A i \in 1..Len(s.arrivals): s.arrivals[i] = t.arrivals[i]
              /\ s.waiting = t.waiting
FactsAboutKeys(s) == {<< "proved", who, p >> : who \in Whos(s), p \in {"mine", "retired"} \cup Keys}
                     \cup {<< kind, who >> : kind \in {"attached", "purpose", "closed"}, who \in Whos(s)}
AnAddressDecidesOnlyWhoWaits ==
    \A e \in FactsAboutKeys(m):
        /\ Step(Forget(m), e)[2] = Step(m, e)[2]
        /\ Same(Step(Forget(m), e)[1], Forget(Step(m, e)[1]))

(***************************************************************************)
(* Properties of every step (a step that breaks one writes its name down)  *)
(***************************************************************************)

\* F1. A newcomer from the local network that is within the rate, by the true time, always gets
\* a place: whatever the pools hold, however long those in them have waited.
ANewcomerWithinTheRateGetsAPlace == "newcomer" \notin broken

\* Over the rate the newcomer is closed and nobody gives way for it.
OverTheRateTheNewcomerIsClosed == "rate" \notin broken

\* The one that gives way is the oldest from the newcomer's address when that address holds as
\* many places as it may, and otherwise the oldest of all; and nobody gives way while there is room.
TheOldestGivesWay == "oldest" \notin broken

\* A connection from outside the local network gets nothing, costs nothing and counts for nothing.
ElsewhereCountsForNothing == "outside" \notin broken

\* A data connection has a place if and only if a drop is in progress.
NoDropNoPlace == "noDrop" \notin broken

\* A connection that proves a paired key is turned away only when as many of THAT key's own
\* connections are waiting as may be. Nothing else comes into it: no other key, no key nobody
\* paired, no stranger, no address.
AKeysPlacesAreItsOwn == "keys" \notin broken

\* F1 again, for the keys nobody paired (anyone can make one). A connection that proves such a
\* key is turned away only when nobody may give way for it: its address holds its share and
\* every one of them has asked, or the pool is full and everyone in it has. Keys that say
\* nothing keep nobody out, however many and however long they wait.
AKeyNobodyPairedGetsAPlaceWhileAnyoneCanGiveWay == "newKey" \notin broken

\* The one that gives way there is the oldest that has asked for nothing: of the newcomer's
\* address when that address holds its share, and otherwise of all.
TheOldestKeyThatHasAskedForNothingGivesWay == "oldestKey" \notin broken

\* A connection that has said what it came for (a request to pair that has been read, and may
\* be in front of a person for minutes) is never the one that gives way.
OneThatHasAskedKeepsItsPlace == "askedOut" \notin broken

\* This Mac's own key and a retired key are closed on proving themselves.
ARetiredKeyGetsNothing == "retired" \notin broken

\* A fact about a connection that holds no place changes nothing, and it is closed.
OneThatGaveWayGetsNothingMore == "gone" \notin broken

(***************************************************************************)
(* The watched Mac                                                         *)
(***************************************************************************)

\* It loses its place among those that have proved nothing only when as many connections were
\* given places after it as the pool holds (counting the newcomer it gives way to), or as many
\* from its own address as one address may hold. What the pool of data connections holds is so
\* many for each drop in progress AT THAT MOMENT: a drop that ends makes fewer newcomers enough.
\* And among the keys nobody paired, the places held by connections that have asked are not
\* there to be had: one that has asked for nothing gives way when those that have asked and
\* those given places after it are as many as the pool holds (EnoughKeys). How many can have
\* asked and last is not this machine's to say: the queue of requests to pair is one on screen
\* and four behind it.
GivesWayOnlyAfterAPoolOfNewcomers == "enough" \notin broken

\* So one that moves on before that (Quick) is never the one that gives way.
TheWatchedMacIsNeverPushedOut == w.st # "displaced"

\* It is turned away on arrival only on its own address's account or when the others could
\* fill the rate between them: with n other addresses on the local network, only if its own
\* address has arrived as often in the window as one address may, or often enough to fill
\* what n addresses at their limit leave of the rate.
KeptOutByTheRateOnlyOnItsOwnAccount == "account" \notin broken

\* So when the other addresses cannot fill the rate between them, a Mac none of whose
\* connections arrived in the last window is always given a place.
NotKeptOutByOthers == "keptOut" \notin broken

\* Once it has proved its paired key nothing anyone else does costs it its place: it is never
\* turned away for what other keys or strangers hold.
APairedMacIsNotTurnedAwayForOthers == Paired => "watchedOut" \notin broken /\ w.st # "turnedAway"

\* A Mac nobody has paired is not turned away either, when the others who proved such keys say
\* nothing more (not OthersAsk): which is what one host holding every place did.
TheWatchedMacIsNotTurnedAway == w.st # "turnedAway"

(* What must be reachable, written as invariants that must be VIOLATED. *)
TheWatchedMacNeverSaysWhatItCameFor == w.st # "through"
TheWatchedMacNeverAttaches == w.st # "attached"
TheWatchedMacNeverAsksToPair == w.st # "asked"

(* What is NOT true, written as invariants that must be violated too (formal/check.py says why each is). *)
AKeyNobodyPairedIsNeverTurnedAway == "unpairedOut" \notin broken

=============================================================================
