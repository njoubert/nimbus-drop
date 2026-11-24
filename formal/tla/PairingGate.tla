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
(*   - otherwise a Mac in the middle of a pairing shows nobody's request.  *)
(*                                                                         *)
(* Two Macs, "lo" and "hi" by the order of their keys. Not modelled: a     *)
(* third Mac, the pause after refusals, and the queue of requests          *)
(* (ReviewTests has those as attacks).                                     *)
(***************************************************************************)
EXTENDS Naturals

CONSTANTS Waits,           \* a request waits for this Mac's own pairing to prove its peer (TRUE in the code)
          PatienceRunsOut  \* the wait may give up first (it does, after two seconds)

Macs == {"lo", "hi"}
Other(x) == IF x = "lo" THEN "hi" ELSE "lo"
Lower(x) == x = "lo"

VARIABLES own,       \* own[x]: x's own pairing: "none", "connecting", "asking", "going", "over"
          knows,     \* knows[x]: x's own pairing has proved whose key answered
          request,   \* request[x]: the request that reached x: "none", "arrived", "shown", "refused"
          waited,    \* waited[x]: x's listener gave up waiting
          answer     \* answer[x]: what the other Mac said to x's request, on its way back: "none", "go", "busy"

vars == << own, knows, request, waited, answer >>

Init == /\ own = [x \in Macs |-> "none"] /\ knows = [x \in Macs |-> FALSE]
        /\ request = [x \in Macs |-> "none"] /\ waited = [x \in Macs |-> FALSE]
        /\ answer = [x \in Macs |-> "none"]

Active(x) == own[x] \in {"connecting", "asking", "going"}      \* PairingGate.active

\* The person at x starts a pairing with the other Mac: for a key already probed, or not.
Start(x) == /\ own[x] = "none" /\ request[x] # "shown"
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
                  /\ answer' = [answer EXCEPT ![x] = "go"]
          ELSE IF Active(y)
             THEN \* in the middle of a pairing of its own: nobody's request is put beside it
                  /\ request' = [request EXCEPT ![y] = "refused"]
                  /\ answer' = [answer EXCEPT ![x] = "busy"]
                  /\ UNCHANGED own
          ELSE /\ request' = [request EXCEPT ![y] = "shown"]
               /\ answer' = [answer EXCEPT ![x] = "go"]
               /\ UNCHANGED own
       /\ UNCHANGED << knows, waited >>

Done == /\ \A x \in Macs: own[x] \in {"none", "going", "over"} /\ request[x] # "arrived" /\ answer[x] = "none"
        /\ UNCHANGED vars

Next == Done \/ \E x \in Macs: Start(x) \/ Prove(x) \/ Ask(x) \/ Hear(x) \/ GiveUpWaiting(x) \/ Decide(x)

Spec == Init /\ [][Next]_vars /\ WF_vars(Next)

TypeOK == /\ own \in [Macs -> {"none", "connecting", "asking", "going", "over"}]
          /\ request \in [Macs -> {"none", "arrived", "shown", "refused"}]

(***************************************************************************)
(* Properties                                                              *)
(***************************************************************************)

\* When both people asked, they do not both end with nothing: one request is on a screen.
NotBothTurnedAway ==
    (\A x \in Macs: own[x] = "over") => \E y \in Macs: request[y] = "shown"

\* One pairing at a time on a Mac: a request is never on screen beside the Mac's own pairing.
OnePairingAtATime == \A y \in Macs: request[y] = "shown" => ~Active(y)

\* And never both requests on both screens: it is one pairing, not two.
OneOfTheTwo == ~(\A y \in Macs: request[y] = "shown")

\* Every request is answered: shown, or turned away.
EveryRequestIsAnswered == \A y \in Macs: request[y] = "arrived" ~> request[y] \in {"shown", "refused"}

=============================================================================
