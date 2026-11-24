---------------------------- MODULE PairingGate ----------------------------
(***************************************************************************)
(* Two people each start a pairing with the other's Mac at the same        *)
(* moment. One of the two requests must go ahead; the failure this guards  *)
(* against is both Macs turning each other away and both people ending     *)
(* with nothing (seen in CI on 2026-11-23, and before that by hand).       *)
(*                                                                         *)
(* The code: PairingGate and PairingSession.initiate                       *)
(* (Sources/NimbusSecurityCore/Pairing.swift) and DropListener.request     *)
(* (Sources/NimbusTransferCore/Listener.swift):                            *)
(*                                                                         *)
(*   - a Mac's own pairing takes its gate when it starts, before it knows  *)
(*     whose key will answer (unless it was started for a key it had       *)
(*     already probed);                                                    *)
(*   - a request that arrives while this Mac's own pairing has not yet     *)
(*     proved who it is talking to WAITS for that (two seconds at most);   *)
(*   - if the two are the same pairing from both ends, the request from    *)
(*     the lower key goes ahead: the Mac with the lower key answers "busy, *)
(*     carry on with mine", the Mac with the higher key cancels its own    *)
(*     and shows the request;                                              *)
(*   - otherwise a Mac in the middle of a pairing shows nobody's request;  *)
(*   - a request that is SHOWN holds nothing. It takes the gate when the   *)
(*     person says yes (PairingSession.respond), and if this Mac's own     *)
(*     pairing has taken it meanwhile, the yes is answered "busy".         *)
(*                                                                         *)
(* The last of these was not in this model at first: Start required that   *)
(* no request be on screen, a guard with no line in the code (an           *)
(* independent review found it, 2026-11-24). A person CAN start a pairing  *)
(* of their own with a request on screen, so "a request is never on screen *)
(* beside the Mac's own pairing" was a property of the model and not of    *)
(* the app. What is true whatever a person starts: the gate holds one      *)
(* pairing, and a request is never PUT on screen beside a pairing that is  *)
(* under way. What is true only if they do not (StartsBesideARequest =     *)
(* FALSE, now an assumption with a name): that the two Macs never turn     *)
(* each other away. With it TRUE the model shows how they can: the person  *)
(* at the higher key starts a pairing with the very Mac whose request is   *)
(* on their screen and says yes to that request before their own has heard *)
(* that the lower key's tie-break turned it away, a few milliseconds       *)
(* later. Both are told "busy", nothing is paired, and they try again.     *)
(* The code is left as it is: making this Mac's own give way to the yes    *)
(* was tried here and loses in the mirror case (a yes to a request whose   *)
(* asker has just given way), which this model showed as well.             *)
(*                                                                         *)
(* Two Macs, "lo" and "hi" by the order of their keys. The people say yes  *)
(* to what they are shown (a no is a person's decision, and "both turned   *)
(* away" is about what the Macs do to each other, not what people choose). *)
(* Not modelled: a third Mac, the pause after refusals, and the queue of   *)
(* requests (ReviewTests has those as attacks).                            *)
(***************************************************************************)
EXTENDS Naturals

CONSTANTS Waits,           \* a request waits for this Mac's own pairing to prove its peer (TRUE in the code)
          PatienceRunsOut, \* the wait may give up first (it does, after two seconds)
          StartsBesideARequest  \* a person starts a pairing of their own with a request on screen (they can)

Macs == {"lo", "hi"}
Other(x) == IF x = "lo" THEN "hi" ELSE "lo"
Lower(x) == x = "lo"

VARIABLES own,       \* own[x]: x's own pairing: "none", "connecting", "asking", "going", "over"
          knows,     \* knows[x]: x's own pairing has proved whose key answered
          request,   \* request[x]: the request that reached x: "none", "arrived", "shown", "going", "refused"
          waited,    \* waited[x]: x's listener gave up waiting
          answer     \* answer[x]: what the other Mac said to x's request, on its way back: "none", "go", "busy"

vars == << own, knows, request, waited, answer >>

Init == /\ own = [x \in Macs |-> "none"] /\ knows = [x \in Macs |-> FALSE]
        /\ request = [x \in Macs |-> "none"] /\ waited = [x \in Macs |-> FALSE]
        /\ answer = [x \in Macs |-> "none"]

Mine(x) == own[x] \in {"connecting", "asking", "going"}        \* x's own pairing holds its gate
Active(x) == Mine(x) \/ request[x] = "going"                   \* PairingGate.active

\* The person at x starts a pairing with the other Mac: for a key already probed, or not.
\* Whenever the gate is free: a request that is only on screen does not hold it.
Start(x) == /\ own[x] = "none" /\ ~Active(x)
            /\ StartsBesideARequest \/ request[x] # "shown"
            /\ own' = [own EXCEPT ![x] = "connecting"]
            /\ \E k \in BOOLEAN: knows' = [knows EXCEPT ![x] = k]
            /\ UNCHANGED << request, waited, answer >>

\* x's handshake finishes: it knows who answered.
Prove(x) == /\ own[x] = "connecting" /\ ~knows[x]
            /\ knows' = [knows EXCEPT ![x] = TRUE]
            /\ UNCHANGED << own, request, waited, answer >>

\* x sends its request; it reaches the other Mac's listener.
Ask(x) == /\ own[x] = "connecting" /\ knows[x] /\ request[Other(x)] = "none"
          /\ own' = [own EXCEPT ![x] = "asking"]
          /\ request' = [request EXCEPT ![Other(x)] = "arrived"]
          /\ UNCHANGED << knows, waited, answer >>

\* The other Mac's answer reaches x's own pairing. Until it does, x's pairing is still asking:
\* the two ends do not learn of a refusal at the same moment.
Hear(x) == /\ own[x] \in {"asking", "over"} /\ answer[x] # "none"
           /\ own' = [own EXCEPT ![x] = IF answer[x] = "go" /\ own[x] = "asking" THEN "going" ELSE "over"]
           /\ answer' = [answer EXCEPT ![x] = "none"]
           /\ UNCHANGED << knows, request, waited >>

\* The two-second wait at y gives up.
GiveUpWaiting(y) == /\ PatienceRunsOut /\ request[y] = "arrived" /\ ~waited[y]
                    /\ own[y] = "connecting" /\ ~knows[y]
                    /\ waited' = [waited EXCEPT ![y] = TRUE]
                    /\ UNCHANGED << own, knows, request, answer >>

\* y's listener decides what to do with the request from x (DropListener.request).
Decide(y) ==
    LET x == Other(y)
        mustWait == Waits /\ own[y] = "connecting" /\ ~knows[y] /\ ~waited[y]
        samePairing == own[y] \in {"connecting", "asking"} /\ knows[y]
    IN /\ request[y] = "arrived" /\ ~mustWait
       /\ IF samePairing /\ Lower(y)
             THEN \* "carry on with the request from this Mac": x's own pairing is turned away
                  /\ request' = [request EXCEPT ![y] = "refused"]
                  /\ answer' = [answer EXCEPT ![x] = "busy"]
                  /\ UNCHANGED own
          ELSE IF samePairing
             THEN \* this Mac's own gives way, and the request is shown
                  /\ request' = [request EXCEPT ![y] = "shown"]
                  /\ own' = [own EXCEPT ![y] = "over"]
                  /\ UNCHANGED answer
          ELSE IF Active(y)
             THEN \* in the middle of a pairing of its own: nobody's request is put beside it
                  /\ request' = [request EXCEPT ![y] = "refused"]
                  /\ answer' = [answer EXCEPT ![x] = "busy"]
                  /\ UNCHANGED own
          ELSE /\ request' = [request EXCEPT ![y] = "shown"]
               /\ UNCHANGED << own, answer >>
       /\ UNCHANGED << knows, waited >>

\* The person at y says yes to the request on screen. Only now does it take the gate
\* (PairingSession.respond: `guard trust.gate.begin(self)`); if y's own pairing took it
\* meanwhile, the asker is told "busy".
Yes(y) == /\ request[y] = "shown"
          /\ IF Mine(y)
                THEN request' = [request EXCEPT ![y] = "refused"] /\ answer' = [answer EXCEPT ![Other(y)] = "busy"]
                ELSE request' = [request EXCEPT ![y] = "going"] /\ answer' = [answer EXCEPT ![Other(y)] = "go"]
          /\ UNCHANGED << own, knows, waited >>

Done == /\ \A x \in Macs: own[x] \in {"none", "going", "over"} /\ request[x] \notin {"arrived", "shown"} /\ answer[x] = "none"
        /\ UNCHANGED vars

Next == Done \/ \E x \in Macs: Start(x) \/ Prove(x) \/ Ask(x) \/ Hear(x) \/ GiveUpWaiting(x) \/ Decide(x) \/ Yes(x)

Spec == Init /\ [][Next]_vars /\ WF_vars(Next)

TypeOK == /\ own \in [Macs -> {"none", "connecting", "asking", "going", "over"}]
          /\ request \in [Macs -> {"none", "arrived", "shown", "going", "refused"}]

(***************************************************************************)
(* Properties                                                              *)
(***************************************************************************)

\* When both people asked, they do not both end with nothing: one request is on a screen, or
\* has gone ahead.
NotBothTurnedAway ==
    (\A x \in Macs: own[x] = "over") => \E y \in Macs: request[y] \in {"shown", "going"}

\* One pairing at a time on a Mac: the gate never holds this Mac's own pairing and a request's.
OnePairingAtATime == \A y \in Macs: ~(Mine(y) /\ request[y] = "going")

\* A request is never PUT on screen beside a pairing of this Mac's own that is under way
\* (the first review's F5): if the two are one pairing, this Mac's own gives way in the same step.
NeverShownBesideAPairingUnderWay ==
    [][\A y \in Macs: (request[y] = "arrived" /\ request'[y] = "shown") => ~(own'[y] \in {"connecting", "asking", "going"})]_vars

\* And never both requests going ahead: it is one pairing, not two.
OneOfTheTwo == ~(\A y \in Macs: request[y] = "going")

\* Every request is answered: it goes ahead, or is turned away.
EveryRequestIsAnswered == \A y \in Macs: request[y] = "arrived" ~> request[y] \in {"going", "refused"}

\* Reachability, to be VIOLATED: a pairing does go ahead at both ends; and a person does start
\* a pairing of their own with a request on screen (what the first model ruled out by fiat).
NeverGoesAhead == ~(\E x \in Macs: own[x] = "going" /\ request[Other(x)] = "going")
NeverStartsWithARequestOnScreen == \A x \in Macs: ~(Mine(x) /\ request[x] = "shown")

=============================================================================
