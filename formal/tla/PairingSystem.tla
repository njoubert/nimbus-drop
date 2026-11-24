--------------------------- MODULE PairingSystem ---------------------------
(***************************************************************************)
(* Two Macs that both keep to the pairing, each running the machine of     *)
(* PairingMachine.tla, with two people, over a connection that delivers in *)
(* order or is cut. (An other end that does NOT keep to it is Pairing.tla; *)
(* someone between the two is formal/tamarin/NimbusPairing.spthy.)         *)
(*                                                                         *)
(* The questions: do two honest Macs ever trip each other's guards? Can    *)
(* one store a pairing the other's person never confirmed? Does it end?    *)
(* And, stated rather than hoped: when can ONE Mac end up paired and the   *)
(* other not?                                                              *)
(***************************************************************************)
EXTENDS PairingMachine

CONSTANT ByNumber          \* pairing by identity number instead of codes

Sides == {"I", "R"}
Other(a) == IF a = "I" THEN "R" ELSE "I"
RoleOf(a) == IF a = "I" THEN "initiator" ELSE "responder"

VARIABLES m,        \* each side's machine
          wire,     \* wire[a]: what is on its way TO a, in order
          cut,      \* the connection is gone
          why,      \* why[a]: the reason a's machine failed, or "none"
          stored,   \* stored[a]: a stored the pairing
          typed     \* typed[a]: a's person has typed the right code

vars == << m, wire, cut, why, stored, typed >>

Init == /\ m = [a \in Sides |-> Start(RoleOf(a), ByNumber)]
        /\ wire = [a \in Sides |-> << >>]
        /\ cut = FALSE
        /\ why = [a \in Sides |-> "none"]
        /\ stored = [a \in Sides |-> FALSE]
        /\ typed = [a \in Sides |-> FALSE]

\* What the machine said to send, as it goes on the wire, in order.
Sent(effects) == SelectSeq(effects, LAMBDA x: x \in {"send commit", "send nonce", "send reveal", "send paired", "send failed"})
OnWire(x) == CASE x = "send commit" -> "commit" [] x = "send nonce" -> "nonce" [] x = "send reveal" -> "reveal"
               [] x = "send paired" -> "paired" [] x = "send failed" -> "failed"
Map(seq) == [i \in 1..Len(seq) |-> OnWire(seq[i])]
Reason(effects) == LET f == SelectSeq(effects, LAMBDA x: x \in {"fail didNotKeep", "fail damaged", "fail malformed",
                                                              "fail wrongCode", "fail theirsFailed", "fail timedOut"})
                   IN IF f = << >> THEN "none" ELSE f[1]
Stores(effects) == \E i \in 1..Len(effects): effects[i] = "store"

\* Side a's machine takes event e; what it sends goes on the wire to the other side.
Do(a, e, extra) ==
    LET r == Step(m[a], e) b == Other(a) IN
      /\ m' = [m EXCEPT ![a] = r[1]]
      /\ wire' = [wire EXCEPT ![b] = IF cut THEN << >> ELSE wire[b] \o extra \o Map(Sent(r[2])),
                              ![a] = IF e \in Received /\ ~cut THEN Tail(wire[a]) ELSE wire[a]]
      /\ why' = [why EXCEPT ![a] = IF why[a] = "none" THEN Reason(r[2]) ELSE why[a]]
      /\ stored' = [stored EXCEPT ![a] = stored[a] \/ Stores(r[2])]

\* The person at R says yes: R tells I to go ("pair-go") and begins.
Go == /\ m["R"].phase = "idle" /\ ~cut
      /\ Do("R", "begin", << "go" >>)
      /\ UNCHANGED << cut, typed >>

\* The next thing on the wire to a arrives. "go" is not the machine's: it is what lets I begin.
Deliver(a) ==
    /\ ~cut /\ wire[a] # << >> /\ ~Final(m[a])
    /\ IF Head(wire[a]) = "go"
          THEN /\ m[a].phase = "idle"
               /\ LET r == Step(m[a], "begin") IN
                    /\ m' = [m EXCEPT ![a] = r[1]]
                    /\ wire' = [wire EXCEPT ![a] = Tail(wire[a]), ![Other(a)] = wire[Other(a)] \o Map(Sent(r[2]))]
               /\ UNCHANGED << why, stored >>
          ELSE /\ m[a].phase # "idle"       \* nothing is read before the exchange has begun
               /\ Do(a, Head(wire[a]), << >>)
    /\ UNCHANGED << cut, typed >>

TypeRight(a) == /\ m[a].phase = "codes" /\ ~m[a].local
                /\ Do(a, "typedRight", << >>)
                /\ typed' = [typed EXCEPT ![a] = TRUE]
                /\ UNCHANGED cut

TypeWrong(a) == /\ m[a].phase = "codes" /\ ~m[a].local
                /\ Do(a, "typedWrong", << >>)
                /\ UNCHANGED << cut, typed >>

\* Time runs out at a, or a finds the connection gone.
Timeout(a) == /\ ~Final(m[a])
              /\ Do(a, "timeout", << >>)
              /\ UNCHANGED << cut, typed >>

Cut == /\ ~cut /\ cut' = TRUE
       /\ wire' = [a \in Sides |-> << >>]
       /\ UNCHANGED << m, why, stored, typed >>

Done == /\ \A a \in Sides: Final(m[a])
        /\ UNCHANGED vars

Next == Go \/ Cut \/ Done \/ \E a \in Sides: Deliver(a) \/ TypeRight(a) \/ TypeWrong(a) \/ Timeout(a)

\* Messages arrive, and time does run out for a Mac that is left waiting.
Fairness == /\ WF_vars(Go)
            /\ \A a \in Sides: WF_vars(Deliver(a)) /\ WF_vars(Timeout(a))

Spec == Init /\ [][Next]_vars /\ Fairness

TypeOK == /\ \A a \in Sides: m[a] \in States
          /\ \A a \in Sides: Len(wire[a]) <= 4

(***************************************************************************)
(* Properties                                                              *)
(***************************************************************************)

\* Two Macs that keep to the pairing never find each other not keeping to it: no message
\* arrives out of turn, twice, unreadable, or failing its commitment.
HonestMacsNeverTripTheGuards ==
    \A a \in Sides: why[a] \notin {"fail didNotKeep", "fail damaged", "fail malformed"}

\* A Mac stores only when BOTH PEOPLE typed the right code: its own, and (because the other
\* machine says "paired" only then) the other's.
StoredMeansBothPeopleConfirmed == \A a \in Sides: stored[a] => typed[a] /\ typed[Other(a)]

\* One Mac paired and the other not happens, and only one way: the second Mac ran out of time
\* or lost the connection before the first one's "paired" reached it. Nothing else does it.
\* (What then puts it right is outside this model: the hello's `paired: false`, see
\* Trust.notePairingGone and DropListener.serve.)
OneSidedOnlyWhenTimeOrTheLinkRanOut ==
    \A a \in Sides: (stored[a] /\ Final(m[Other(a)]) /\ ~stored[Other(a)]) => why[Other(a)] = "fail timedOut"

\* It ends, at both Macs, whatever the people and the link do.
ItEnds == <>(\A a \in Sides: Final(m[a]))

\* With the link up, time not running out and nobody mistyping three times, the two people get
\* what they came for. Checked as a goal that must be REACHABLE: NeverBothStored is expected
\* to be violated (formal/check.py runs it that way).
NeverBothStored == ~(\A a \in Sides: stored[a])

=============================================================================
