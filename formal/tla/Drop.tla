-------------------------------- MODULE Drop --------------------------------
(***************************************************************************)
(* One accepted drop, from the first plan to the end: the rounds, with the *)
(* network doing its worst.                                                *)
(*                                                                         *)
(* The code: SendSession.run and reconnect (Sender.swift); ReceiveSession  *)
(* conduct, settle, awaitSender, receive and claim (Receiver.swift), in    *)
(* Sources/NimbusTransferCore. The conversation is                         *)
(*                                                                         *)
(*     plan ->  chunks on data connections  -> done -> plan | complete     *)
(*                                                                         *)
(* and when the connection carrying it is lost, both ends hold the drop,   *)
(* the sender reconnects and proves it is the same drop, and the receiver  *)
(* answers with a plan of what it holds (or, if it had finished, says so   *)
(* again).                                                                 *)
(*                                                                         *)
(* The network may, a bounded number of times: flip bits in a record on    *)
(* its way (Damage), cut a data connection with records still on it        *)
(* (CutData), and cut the conversation's own connection (CutControl).      *)
(*                                                                         *)
(* Abstracted: a file is its chunks; a round uses one data connection at a *)
(* time (the code uses many; they do not talk to each other); the          *)
(* handshake, the attach tag and the resume proof are taken as given       *)
(* (formal/tamarin/NimbusHandshake.spthy).                                 *)
(***************************************************************************)
EXTENDS Naturals, Sequences, FiniteSets

CONSTANTS Chunks,        \* what the drop consists of
          MaxFaults,     \* how many times the network misbehaves
          MaxConns,      \* connection numbers the model allows (large enough not to matter)
          ChecksTag,     \* the receiver opens a record before writing it (TRUE in the code)
          KeepsCounter,  \* connection numbers come from one counter for the whole drop (TRUE in the code)
          MayGiveUp      \* either end may stop waiting for the other

VARIABLES have,       \* receiver: chunks written to its partial folder and noted in the ledger
          wrong,      \* receiver: chunks written from a record that was altered on the way
          placed,     \* receiver: the drop has been moved into its destination
          r,          \* receiver: "reading", "awaitSender", "completed", "failed"
          s,          \* sender: "awaitReply", "sending", "reconnecting", "completed", "failed"
          jobs,       \* sender: chunks still to send in this round
          toS, toR,   \* the conversation: messages on their way to the sender, to the receiver
          ctl,        \* the conversation's connection is up
          sconn,      \* sender: the data connection it is writing to (0: none)
          rconns,     \* receiver: data connections attached and open
          claimed,    \* receiver: every connection number ever attached
          flight,     \* records on their way: [conn, chunk, ok]
          nextConn,   \* sender: the next connection number
          keyUse,     \* how many connections were ever opened under each number's key
          faults

vars == << have, wrong, placed, r, s, jobs, toS, toR, ctl, sconn, rconns, claimed, flight, nextConn, keyUse, faults >>

Plan(h) == [type |-> "plan", have |-> h]
Msg(t)  == [type |-> t, have |-> {}]

Init == /\ have = {} /\ wrong = {} /\ placed = FALSE
        /\ r = "reading" /\ s = "awaitReply" /\ jobs = {}
        /\ toS = << Plan({}) >> /\ toR = << >> /\ ctl = TRUE      \* the manifest has arrived; the first plan is on its way
        /\ sconn = 0 /\ rconns = {} /\ claimed = {} /\ flight = {}
        /\ nextConn = 1 /\ keyUse = [n \in 1..MaxConns |-> 0] /\ faults = 0

(* ---- The sender ------------------------------------------------------- *)

\* A plan: send what the receiver does not have.
SPlan == /\ s = "awaitReply" /\ ctl /\ toS # << >> /\ Head(toS).type = "plan"
         /\ jobs' = Chunks \ Head(toS).have
         /\ s' = "sending" /\ toS' = Tail(toS)
         /\ UNCHANGED << have, wrong, placed, r, toR, ctl, sconn, rconns, claimed, flight, nextConn, keyUse, faults >>

\* "It all arrived."
SComplete == /\ s = "awaitReply" /\ ctl /\ toS # << >> /\ Head(toS).type = "complete"
             /\ s' = "completed" /\ toS' = Tail(toS)
             /\ UNCHANGED << have, wrong, placed, r, jobs, toR, ctl, sconn, rconns, claimed, flight, nextConn, keyUse, faults >>

\* Opens a data connection under the next number; the receiver attaches it if that number is new.
Open == /\ s = "sending" /\ jobs # {} /\ sconn = 0 /\ nextConn <= MaxConns
        /\ sconn' = nextConn /\ nextConn' = nextConn + 1
        /\ keyUse' = [keyUse EXCEPT ![nextConn] = @ + 1]
        /\ IF nextConn \notin claimed /\ r \in {"reading", "awaitSender"}
              THEN rconns' = rconns \cup {nextConn} /\ claimed' = claimed \cup {nextConn}
              ELSE UNCHANGED << rconns, claimed >>
        /\ UNCHANGED << have, wrong, placed, r, s, jobs, toS, toR, ctl, flight, faults >>

Send(c) == /\ s = "sending" /\ c \in jobs /\ sconn # 0
           /\ flight' = flight \cup {[conn |-> sconn, chunk |-> c, ok |-> TRUE]}
           /\ jobs' = jobs \ {c}
           /\ UNCHANGED << have, wrong, placed, r, s, toS, toR, ctl, sconn, rconns, claimed, nextConn, keyUse, faults >>

\* The sender finds its data connection dead and will open another for what is left.
SNotice == /\ sconn # 0 /\ sconn \notin rconns
           /\ sconn' = 0
           /\ UNCHANGED << have, wrong, placed, r, s, jobs, toS, toR, ctl, rconns, claimed, flight, nextConn, keyUse, faults >>

\* Everything it had to send has been written to a socket: "done".
SDone == /\ s = "sending" /\ jobs = {} /\ ctl
         /\ toR' = Append(toR, Msg("done")) /\ s' = "awaitReply" /\ sconn' = 0
         /\ UNCHANGED << have, wrong, placed, r, jobs, toS, ctl, rconns, claimed, flight, nextConn, keyUse, faults >>

\* The conversation's connection is gone: stop, and try to get it back.
SLost == /\ s \in {"awaitReply", "sending"} /\ ~ctl
         /\ s' = "reconnecting" /\ jobs' = {} /\ sconn' = 0
         /\ UNCHANGED << have, wrong, placed, r, toS, toR, ctl, rconns, claimed, flight, nextConn, keyUse, faults >>

(* ---- The receiver ----------------------------------------------------- *)

\* A record arrives. Opened before it is written: one that was altered is thrown away and its
\* connection closed; what that connection had not delivered is asked for again at the next plan.
Receive(rec) ==
    /\ rec \in flight /\ rec.conn \in rconns
    /\ IF rec.ok \/ ~ChecksTag
          THEN /\ have' = have \cup {rec.chunk}
               /\ wrong' = IF rec.ok THEN wrong ELSE wrong \cup {rec.chunk}
               /\ flight' = flight \ {rec}
               /\ UNCHANGED rconns
          ELSE /\ rconns' = rconns \ {rec.conn}
               /\ flight' = {f \in flight: f.conn # rec.conn}
               /\ UNCHANGED << have, wrong >>
    /\ UNCHANGED << placed, r, s, jobs, toS, toR, ctl, sconn, claimed, nextConn, keyUse, faults >>

\* "done": the data connections are given time to deliver what is on them (settle); whatever is
\* left open after that is closed, and then the drop is judged. Whole: put in place, and say
\* so. Not whole: say what is here.
RDone == /\ r = "reading" /\ ctl /\ toR # << >> /\ Head(toR).type = "done"
         /\ \A f \in flight: f.conn \notin rconns
         /\ toR' = Tail(toR)
         /\ rconns' = {} /\ flight' = {}
         /\ IF have = Chunks
               THEN placed' = TRUE /\ r' = "completed" /\ toS' = Append(toS, Msg("complete"))
               ELSE UNCHANGED << placed, r >> /\ toS' = Append(toS, Plan(have))
         /\ UNCHANGED << have, wrong, s, jobs, ctl, sconn, claimed, nextConn, keyUse, faults >>

\* The conversation's connection is gone: hold the drop and wait for the sender.
RLost == /\ r = "reading" /\ ~ctl
         /\ r' = "awaitSender" /\ rconns' = {} /\ flight' = {}
         /\ UNCHANGED << have, wrong, placed, s, jobs, toS, toR, ctl, sconn, claimed, nextConn, keyUse, faults >>

(* ---- Getting the conversation back ------------------------------------ *)

\* The sender reconnects and proves it is the same drop. A receiver that is holding the drop
\* says what it has; one that had finished says so again.
Reconnect == /\ s = "reconnecting" /\ r \in {"awaitSender", "completed"}
             /\ ctl' = TRUE /\ s' = "awaitReply" /\ toR' = << >>
             /\ IF r = "completed" THEN toS' = << Msg("complete") >> /\ UNCHANGED r
                                   ELSE toS' = << Plan(have) >> /\ r' = "reading"
             /\ nextConn' = IF KeepsCounter THEN nextConn ELSE 1
             /\ UNCHANGED << have, wrong, placed, jobs, sconn, rconns, claimed, flight, keyUse, faults >>

\* Nobody came back in time.
GiveUp == /\ MayGiveUp
          /\ \/ s = "reconnecting" /\ s' = "failed" /\ UNCHANGED r
             \/ r = "awaitSender" /\ r' = "failed" /\ UNCHANGED s
          /\ UNCHANGED << have, wrong, placed, jobs, toS, toR, ctl, sconn, rconns, claimed, flight, nextConn, keyUse, faults >>

\* The receiver gave up; a sender that reconnects finds nothing to resume.
Refused == /\ s = "reconnecting" /\ r = "failed"
           /\ s' = "failed"
           /\ UNCHANGED << have, wrong, placed, r, jobs, toS, toR, ctl, sconn, rconns, claimed, flight, nextConn, keyUse, faults >>

(* ---- The network ------------------------------------------------------ *)

Damage(rec) == /\ faults < MaxFaults /\ rec \in flight /\ rec.ok
               /\ flight' = (flight \ {rec}) \cup {[rec EXCEPT !.ok = FALSE]}
               /\ faults' = faults + 1
               /\ UNCHANGED << have, wrong, placed, r, s, jobs, toS, toR, ctl, sconn, rconns, claimed, nextConn, keyUse >>

CutData(n) == /\ faults < MaxFaults /\ n \in rconns
              /\ rconns' = rconns \ {n} /\ flight' = {f \in flight: f.conn # n}
              /\ faults' = faults + 1
              /\ UNCHANGED << have, wrong, placed, r, s, jobs, toS, toR, ctl, sconn, claimed, nextConn, keyUse >>

CutControl == /\ faults < MaxFaults /\ ctl /\ s \notin {"completed", "failed"}
              /\ ctl' = FALSE /\ toS' = << >> /\ toR' = << >>
              /\ faults' = faults + 1
              /\ UNCHANGED << have, wrong, placed, r, s, jobs, sconn, rconns, claimed, flight, nextConn, keyUse >>

Over == /\ s \in {"completed", "failed"}
        /\ UNCHANGED vars

Protocol == SPlan \/ SComplete \/ Open \/ SNotice \/ SDone \/ SLost \/ RDone \/ RLost \/ Reconnect \/ Refused
            \/ (\E c \in Chunks: Send(c)) \/ (\E rec \in flight: Receive(rec))

Next == Protocol \/ GiveUp \/ Over \/ CutControl \/ (\E rec \in flight: Damage(rec)) \/ (\E n \in rconns: CutData(n))

Spec == Init /\ [][Next]_vars /\ WF_vars(Protocol)

TypeOK == /\ have \subseteq Chunks /\ wrong \subseteq Chunks /\ jobs \subseteq Chunks
          /\ r \in {"reading", "awaitSender", "completed", "failed"}
          /\ s \in {"awaitReply", "sending", "reconnecting", "completed", "failed"}
          /\ sconn \in 0..MaxConns /\ nextConn \in 1..(MaxConns + 1) /\ faults \in 0..MaxFaults
          /\ Len(toS) <= 2 /\ Len(toR) <= 2

(***************************************************************************)
(* Properties                                                              *)
(***************************************************************************)

\* THE ONE OUTCOME THAT MUST NEVER HAPPEN: bytes that are not the sender's, written.
NoWrongBytes == wrong = {}

\* Nothing is put in place that is not whole.
PlacedIsWhole == placed => have = Chunks /\ wrong = {}

\* The sender says "sent" only of a drop the receiver has put in place.
SentMeansSaved == s = "completed" => placed

\* A connection number, and so a stream key and its counter nonces, is used once in a drop:
\* also across a reconnect.
NoStreamKeyTwice == \A n \in 1..MaxConns: keyUse[n] <= 1

\* Nothing is written once the drop has been judged whole.
NothingWrittenAfterPlacing == [][placed => have' = have]_vars

\* It ends. And when neither end gives up, it ends with the drop in place: however the
\* network misbehaves, a bounded number of times.
ItEnds == <>(s \in {"completed", "failed"})
ItArrives == <>(s = "completed" /\ placed)

=============================================================================
