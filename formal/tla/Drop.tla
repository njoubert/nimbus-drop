-------------------------------- MODULE Drop --------------------------------
(***************************************************************************)
(* One drop, from the offer to the end, with the network doing its worst.  *)
(*                                                                         *)
(*   offer -> accept | decline -> manifest -> plan                         *)
(*         -> chunks on data connections -> done -> plan | complete        *)
(*                                                                         *)
(* THE TWO ENDS' DECISIONS ARE THE MACHINES': sm and rm are states of      *)
(* SenderStep and ReceiverStep (RoundMachine.tla), which RoundRefinement   *)
(* holds equal to Sources/NimbusCrypto/RoundMachine.swift. Nothing here    *)
(* says which message is acceptable when, what is answered, when the drop  *)
(* is judged or how it ends: each action hands a machine an event and does *)
(* what the machine says.                                                  *)
(*                                                                         *)
(* THE REST IS THE ENVIRONMENT, and is tied to the code by reading (and by *)
(* a mutant on each side, see formal/README.md):                           *)
(*   - the two shells (SendSession, ReceiveSession in                      *)
(*     Sources/NimbusTransferCore): which event each reports and when,     *)
(*     what a plan says (the ledger), which chunks a round sends;          *)
(*   - the conversation's connection: messages in order, or cut and both   *)
(*     queues lost; the sender reconnects and proves the drop (taken as    *)
(*     given: formal/tamarin/NimbusHandshake.spthy);                       *)
(*   - the data connections: their numbers, their records in flight, the   *)
(*     attach (taken only if the number is new and the receiving machine   *)
(*     says the drop takes data), and what is written;                     *)
(*   - the person, who answers the question.                               *)
(*                                                                         *)
(* The network may, a bounded number of times (MaxFaults): flip bits in a  *)
(* record on its way (Damage), cut a data connection with records still on *)
(* it (CutData), hold a data connection back so that it arrives after the  *)
(* receiver has stopped waiting for it (Hold, Release), and cut the        *)
(* conversation's own connection (CutControl, at most MaxCuts of them).    *)
(*                                                                         *)
(* Abstracted: a file is its chunks; a round uses one data connection at a *)
(* time (the code uses many; they do not talk to each other); the          *)
(* sender's "more than any plan before" is counted in chunks.              *)
(***************************************************************************)
EXTENDS RoundMachine, FiniteSets

CONSTANTS Chunks,        \* what the drop consists of
          MaxFaults,     \* how many times the network misbehaves
          MaxCuts,       \* of which cuts of the conversation's connection
          MaxConns,      \* connection numbers the model allows (large enough not to matter)
          Patience,      \* the sender's: reconnects in a row that find nothing new (3 in the app)
          IdleRounds,    \* the receiver's: rounds in a row that bring nothing new (5 in the app)
          Says,          \* what the person may answer: a subset of {"yes", "no"}
          Lies,          \* the sender's manifest may be something other than what it offered
          ChecksTag,     \* the receiver opens a record before writing it (TRUE in the code)
          KeepsCounter,  \* connection numbers come from one counter for the whole drop (TRUE in the code)
          KeepsOutLate,  \* a data connection is let in only while the machine says the drop takes data
                         \* (TRUE in the code since 2026-11-24; before, whenever the session was registered)
          CutsEarly,     \* the conversation may be cut before the sender has heard what the receiver holds
          MayGiveUp      \* either end may stop waiting for the other

\* The machines here are ones the equality with the Swift was checked for (RoundRefinement).
ASSUME CheckedPatience == Patience \in {1, 2, 3} /\ IdleRounds \in {1, 2, 3, 5}

VARIABLES sm, rm,     \* the two machines
          toS, toR,   \* the conversation: messages on their way to the sender, to the receiver
          ctl,        \* the conversation's connection is up
          jobs,       \* sender: chunks still to send in this round
          sconn,      \* sender: the data connection it is writing to (0: none)
          nextConn,   \* sender: the next connection number
          sbest,      \* sender: one more than the most chunks any plan said the receiver holds (0: none yet)
          yes,        \* the person said yes
          took,       \* receiver: the manifest it was given in its turn, as it was ("none" before)
          prepared,   \* receiver: the partial folder and the ledger exist
          rstart,     \* receiver: how many chunks it held when it last said a plan
          have,       \* receiver: chunks written to its partial folder and noted in the ledger
          wrong,      \* receiver: chunks written from a record that was altered on the way
          placed,     \* receiver: the drop has been moved into its destination
          late,       \* receiver: a record was written after the drop had been judged whole
          rconns,     \* receiver: data connections attached and open
          claimed,    \* receiver: every connection number ever attached
          flight,     \* records on their way: [conn, chunk, ok]
          held,       \* data connections the network is holding back: opened, not yet arrived
          keyUse,     \* how many connections were ever opened under each number's key
          faults, cuts

machines == << sm, rm >>
wire     == << toS, toR, ctl >>
sender   == << jobs, sconn, nextConn, sbest >>
disk     == << have, wrong, placed, late >>
person   == << yes, took, prepared >>
data     == << rconns, claimed, flight, held, keyUse >>
counts   == << faults, cuts >>
vars     == << sm, rm, toS, toR, ctl, jobs, sconn, nextConn, sbest, yes, took, prepared, rstart,
               have, wrong, placed, late, rconns, claimed, flight, held, keyUse, faults, cuts >>

Has(seq, x) == \E i \in 1..Len(seq): seq[i] = x

Msg(t)      == [type |-> t, have |-> {}, kind |-> ""]
Plan(h)     == [type |-> "plan", have |-> h, kind |-> ""]
Manifest(k) == [type |-> "manifest", have |-> {}, kind |-> k]

Init == /\ sm = SenderStart(Patience) /\ rm = ReceiverStart(IdleRounds)
        /\ toS = << >> /\ toR = << >> /\ ctl = TRUE        \* both keys proved, the hellos said
        /\ jobs = {} /\ sconn = 0 /\ nextConn = 1 /\ sbest = 0
        /\ yes = FALSE /\ took = "none" /\ prepared = FALSE /\ rstart = 0
        /\ have = {} /\ wrong = {} /\ placed = FALSE /\ late = FALSE
        /\ rconns = {} /\ claimed = {} /\ flight = {} /\ held = {}
        /\ keyUse = [n \in 1..MaxConns |-> 0] /\ faults = 0 /\ cuts = 0

(***************************************************************************)
(* Doing what a machine says.                                              *)
(***************************************************************************)

\* What a list of effects puts on the conversation, in order. (It gets there only if the
\* connection is up; said into a dead one, it is gone.)
SSaid(fx, kind) ==
    LET said == SelectSeq(fx, LAMBDA x: x \in {"send offer", "send manifest", "send done", "send error"})
    IN [i \in 1..Len(said) |-> CASE said[i] = "send offer" -> Msg("offer")
                                 [] said[i] = "send manifest" -> Manifest(kind)
                                 [] said[i] = "send done" -> Msg("done")
                                 [] OTHER -> Msg("error")]

RSaid(fx) ==
    LET said == SelectSeq(fx, LAMBDA x: x \in {"send accept", "send plan", "send complete", "send error", "send decline notReceiving",
                                                 "send decline declined", "send decline pairingRanOut"})
    IN [i \in 1..Len(said) |-> CASE said[i] = "send accept" -> Msg("accept")
                                 [] said[i] = "send plan" -> Plan(have)          \* what is here: the ledger's word
                                 [] said[i] = "send complete" -> Msg("complete")
                                 [] said[i] = "send error" -> Msg("error")
                                 [] OTHER -> Msg("decline")]

\* The sending machine is told e. What it says goes on the wire; the rest of what it says to
\* do is in the actions that hand it the event.
SDo(e, kind) == /\ sm' = SenderStep(sm, e)[1]
                /\ toR' = IF ctl THEN toR \o SSaid(SenderStep(sm, e)[2], kind) ELSE toR

\* The receiving machine is told e. Two things it says are followed at once by whether they
\* went out (ReceiveSession sends, and tells the machine `said` or `lost` in the same breath):
\* a decline, and the first plan.
RStep(e) == LET a == ReceiverStep(rm, e)
                b == IF a[1].phase \in {"declining", "planning"} /\ a[2] # << >>
                        THEN ReceiverStep(a[1], IF ctl THEN "said" ELSE "lost")
                        ELSE << a[1], << >> >>
            IN << b[1], a[2] \o b[2] >>

RDo(e) == /\ rm' = RStep(e)[1]
          /\ toS' = IF ctl THEN toS \o RSaid(RStep(e)[2]) ELSE toS
          /\ rstart' = IF Has(RStep(e)[2], "send plan") THEN Cardinality(have) ELSE rstart

\* A receiver that holds the drop for the sender, or has ended, has closed its data
\* connections; what was on them is gone. What the network is holding back is still out there.
Closed(p) == p \in {"awaitSender", "declined", "failed", "cancelled"}
RData == /\ rconns' = IF Closed(rm'.phase) THEN {} ELSE rconns
         /\ flight' = IF Closed(rm'.phase) THEN {f \in flight: f.conn \in held} ELSE flight

(***************************************************************************)
(* The sender's shell.                                                     *)
(***************************************************************************)

SBegin == /\ sm.phase = "idle"
          /\ SDo("begin", "")
          /\ UNCHANGED << rm, toS, ctl, sender, person, rstart, disk, data, counts >>

\* The next message, taken when the drop's thread is waiting for one. A plan is "more" when
\* it says the receiver holds more than any plan before it said; taken, it is what this round
\* sends. (The manifest, if this is the accept: what was offered, unless the sender lies.)
SReceive ==
    /\ ctl /\ toS # << >> /\ Head(toS).type # "error"
    /\ sm.phase \in {"awaitAnswer", "awaitPlan", "awaitVerdict", "reconnecting"}
    /\ LET m == Head(toS)
           more == Cardinality(m.have) + 1 > sbest
           e == CASE m.type = "plan" -> IF more THEN "planMore" ELSE "planSame"
                  [] m.type \in {"accept", "decline", "complete"} -> m.type
                  [] OTHER -> "other"
           taken == Has(SenderStep(sm, e)[2], "adopt")
       IN /\ \E kind \in (IF Lies THEN {"manifest", "manifestOther"} ELSE {"manifest"}): SDo(e, kind)
          /\ jobs' = IF taken THEN Chunks \ m.have ELSE jobs
          /\ sbest' = IF taken /\ more THEN Cardinality(m.have) + 1 ELSE sbest
    /\ toS' = Tail(toS)
    /\ UNCHANGED << rm, ctl, sconn, nextConn, person, rstart, disk, data, counts >>

\* The receiver's reason for stopping is acted on the moment it is read, whatever else is waiting.
SError == /\ ctl /\ ~Final(sm) /\ \E i \in 1..Len(toS): toS[i].type = "error"
          /\ SDo("error", "")
          /\ toS' = SelectSeq(toS, LAMBDA m: m.type # "error")
          /\ jobs' = {} /\ sconn' = 0
          /\ UNCHANGED << rm, ctl, nextConn, sbest, person, rstart, disk, data, counts >>

\* Whether the receiver lets a data connection in. The number must be new; and the machine
\* must say the drop takes data. (Before 2026-11-24: whenever the session was registered,
\* which it is from the folder's making to the end of putting the drop in place.)
Takes(n) == /\ n \notin claimed
            /\ IF KeepsOutLate THEN TakesData(rm)
                               ELSE rm.phase \in {"planning", "reading", "settling", "awaitSender", "placing"}

\* Opens a data connection under the next number. It arrives at once, or the network holds it back.
Open == /\ sm.phase = "sending" /\ jobs # {} /\ sconn = 0 /\ nextConn <= MaxConns
        /\ sconn' = nextConn /\ nextConn' = nextConn + 1
        /\ keyUse' = [keyUse EXCEPT ![nextConn] = @ + 1]
        /\ \/ /\ IF Takes(nextConn) THEN rconns' = rconns \cup {nextConn} /\ claimed' = claimed \cup {nextConn}
                                    ELSE UNCHANGED << rconns, claimed >>
              /\ UNCHANGED << held, faults >>
           \/ /\ faults < MaxFaults
              /\ held' = held \cup {nextConn} /\ faults' = faults + 1
              /\ UNCHANGED << rconns, claimed >>
        /\ UNCHANGED << machines, wire, jobs, sbest, person, rstart, disk, flight, cuts >>

Send(c) == /\ sm.phase = "sending" /\ c \in jobs /\ sconn # 0
           /\ flight' = flight \cup {[conn |-> sconn, chunk |-> c, ok |-> TRUE]}
           /\ jobs' = jobs \ {c}
           /\ UNCHANGED << machines, wire, sconn, nextConn, sbest, person, rstart, disk, rconns, claimed, held, keyUse, counts >>

\* The sender finds its data connection dead and will open another for what is left.
SNotice == /\ sconn # 0 /\ sconn \notin rconns /\ sconn \notin held
           /\ sconn' = 0
           /\ UNCHANGED << machines, wire, jobs, nextConn, sbest, person, rstart, disk, data, counts >>

\* Everything the round had to send has been written to a socket.
SWritten == /\ sm.phase = "sending" /\ jobs = {}
            /\ SDo("written", "")
            /\ sconn' = 0
            /\ UNCHANGED << rm, toS, ctl, jobs, nextConn, sbest, person, rstart, disk, data, counts >>

\* The conversation's connection is gone, and the drop's thread finds out.
SLost == /\ ~ctl /\ sm.phase \in {"awaitAnswer", "awaitPlan", "sending", "awaitVerdict"}
         /\ SDo("lost", "")
         /\ jobs' = {} /\ sconn' = 0
         /\ UNCHANGED << rm, toS, ctl, nextConn, sbest, person, rstart, disk, data, counts >>

(***************************************************************************)
(* The receiver's shell.                                                   *)
(***************************************************************************)

\* The offer arrives: a session is made for it, and it starts.
ROffer == /\ rm.phase = "idle" /\ ctl /\ toR # << >> /\ Head(toR).type = "offer"
          /\ toR' = Tail(toR)
          /\ RDo("begin") /\ RData
          /\ UNCHANGED << sm, ctl, sender, person, disk, claimed, held, keyUse, counts >>

\* The person answers.
RAnswer(a) == /\ rm.phase = "deciding"
              /\ yes' = (a = "yes")
              /\ RDo(a) /\ RData
              /\ UNCHANGED << sm, toR, ctl, sender, took, prepared, disk, claimed, held, keyUse, counts >>

\* The next message, taken when the session's thread is reading the conversation: while the
\* person decides, for the manifest, and for each round's "done".
RReceive ==
    /\ ctl /\ toR # << >> /\ rm.phase \in {"deciding", "awaitManifest", "reading"}
    /\ LET m == Head(toR)
           e == CASE m.type = "manifest" -> m.kind
                  [] m.type \in {"done", "error"} -> m.type
                  [] OTHER -> "other"
       IN /\ RDo(e)
          /\ took' = IF m.type = "manifest" /\ rm.phase = "awaitManifest" THEN m.kind ELSE took
    /\ toR' = Tail(toR)
    /\ RData
    /\ UNCHANGED << sm, ctl, sender, yes, prepared, disk, claimed, held, keyUse, counts >>

\* `prepare`: the partial folder and the ledger are made, and the session is registered.
RPrepare == /\ rm.phase = "preparing"
            /\ prepared' = TRUE
            /\ RDo("prepared") /\ RData
            /\ UNCHANGED << sm, toR, ctl, sender, yes, took, disk, claimed, held, keyUse, counts >>

\* `settle`: the data connections are given time to deliver what is on them; whatever is left
\* open after that is closed, and with none open the drop is judged (the ledger's word) and
\* the machine told. One step: ReceiveSession.settle judges under the lock that lets data
\* connections in.
RSettle == /\ rm.phase = "settling"
           /\ \A f \in flight: f.conn \notin rconns
           /\ RDo(IF have = Chunks THEN "whole" ELSE IF Cardinality(have) > rstart THEN "more" ELSE "nothingNew")
           /\ rconns' = {} /\ flight' = {f \in flight: f.conn \in held}
           /\ UNCHANGED << sm, toR, ctl, sender, person, disk, claimed, held, keyUse, counts >>

\* `place`: the drop is moved into its destination.
RPlace == /\ rm.phase = "placing"
          /\ placed' = TRUE
          /\ RDo("placed") /\ RData
          /\ UNCHANGED << sm, toR, ctl, sender, person, have, wrong, late, claimed, held, keyUse, counts >>

\* The conversation's connection is gone, and the session's thread finds out.
RLost == /\ ~ctl /\ rm.phase \in {"deciding", "awaitManifest", "reading"}
         /\ RDo("lost") /\ RData
         /\ UNCHANGED << sm, toR, ctl, sender, person, disk, claimed, held, keyUse, counts >>

\* A record arrives on a connection that was let in. Opened before it is written: one that was
\* altered is thrown away and its connection closed; what that connection had not delivered
\* is asked for again at the next plan.
Receive(rec) ==
    /\ rec \in flight /\ rec.conn \in rconns
    /\ IF rec.ok \/ ~ChecksTag
          THEN /\ have' = have \cup {rec.chunk}
               /\ wrong' = IF rec.ok THEN wrong ELSE wrong \cup {rec.chunk}
               /\ late' = (late \/ rm.phase \in {"placing", "completed"})
               /\ flight' = flight \ {rec}
               /\ UNCHANGED rconns
          ELSE /\ rconns' = rconns \ {rec.conn}
               /\ flight' = {f \in flight: f.conn # rec.conn}
               /\ UNCHANGED << have, wrong, late >>
    /\ UNCHANGED << machines, wire, sender, person, rstart, placed, claimed, held, keyUse, counts >>

(***************************************************************************)
(* Getting the conversation back.                                          *)
(***************************************************************************)

\* The sender reconnects and proves it is the same drop. A receiver that is holding the drop
\* says what it has; one that had finished says so again. Either is the machine's answer.
Reconnect == /\ sm.phase = "reconnecting" /\ ~ctl /\ rm.phase \in {"awaitSender", "completed"}
             /\ rm' = ReceiverStep(rm, "senderBack")[1]
             /\ toS' = RSaid(ReceiverStep(rm, "senderBack")[2])
             /\ rstart' = IF Has(ReceiverStep(rm, "senderBack")[2], "send plan") THEN Cardinality(have) ELSE rstart
             /\ ctl' = TRUE /\ toR' = << >>
             /\ nextConn' = IF KeepsCounter THEN nextConn ELSE 1
             /\ UNCHANGED << sm, jobs, sconn, sbest, person, disk, data, counts >>

\* A sender whose receiver has ended finds nothing to resume, and its time runs out.
Refused == /\ sm.phase = "reconnecting" /\ ~ctl /\ Final(rm) /\ rm.phase # "completed"
           /\ SDo("gaveUp", "")
           /\ UNCHANGED << rm, toS, ctl, sender, person, rstart, disk, data, counts >>

\* A receiver whose sender has ended waits its minute for nobody.
Abandoned == /\ rm.phase = "awaitSender" /\ Final(sm)
             /\ RDo("gaveUp") /\ RData
             /\ UNCHANGED << sm, toR, ctl, sender, person, disk, claimed, held, keyUse, counts >>

\* Nobody came back in time.
GiveUp == /\ MayGiveUp
          /\ \/ /\ sm.phase = "reconnecting" /\ ~ctl
                /\ SDo("gaveUp", "")
                /\ UNCHANGED << rm, toS, rstart, rconns, flight >>
             \/ /\ rm.phase = "awaitSender"
                /\ RDo("gaveUp") /\ RData
                /\ UNCHANGED << sm, toR >>
          /\ UNCHANGED << ctl, sender, person, disk, claimed, held, keyUse, counts >>

(***************************************************************************)
(* The network.                                                            *)
(***************************************************************************)

Damage(rec) == /\ faults < MaxFaults /\ rec \in flight /\ rec.ok
               /\ flight' = (flight \ {rec}) \cup {[rec EXCEPT !.ok = FALSE]}
               /\ faults' = faults + 1
               /\ UNCHANGED << machines, wire, sender, person, rstart, disk, rconns, claimed, held, keyUse, cuts >>

CutData(n) == /\ faults < MaxFaults /\ n \in rconns
              /\ rconns' = rconns \ {n} /\ flight' = {f \in flight: f.conn # n}
              /\ faults' = faults + 1
              /\ UNCHANGED << machines, wire, sender, person, rstart, disk, claimed, held, keyUse, cuts >>

\* A data connection that was held back arrives at last. Whether it is still let in is the
\* receiver's to say; turned away, what it carried is gone.
Release(n) == /\ n \in held
              /\ held' = held \ {n}
              /\ IF Takes(n) THEN rconns' = rconns \cup {n} /\ claimed' = claimed \cup {n} /\ UNCHANGED flight
                             ELSE flight' = {f \in flight: f.conn # n} /\ UNCHANGED << rconns, claimed >>
              /\ UNCHANGED << machines, wire, sender, person, rstart, disk, keyUse, counts >>

CutControl == /\ faults < MaxFaults /\ cuts < MaxCuts /\ ctl /\ ~Final(sm)
              /\ CutsEarly \/ sm.phase \in {"sending", "awaitVerdict", "reconnecting"}
              /\ ctl' = FALSE /\ toS' = << >> /\ toR' = << >>
              /\ faults' = faults + 1 /\ cuts' = cuts + 1
              /\ UNCHANGED << machines, sender, person, rstart, disk, data >>

Over == /\ Final(sm)
        /\ UNCHANGED vars

Protocol == SBegin \/ SReceive \/ SError \/ Open \/ SNotice \/ SWritten \/ SLost
            \/ ROffer \/ RReceive \/ RPrepare \/ RSettle \/ RPlace \/ RLost
            \/ Reconnect \/ Refused \/ Abandoned
            \/ (\E a \in Says: RAnswer(a)) \/ (\E c \in Chunks: Send(c)) \/ (\E rec \in flight: Receive(rec))

Next == Protocol \/ GiveUp \/ Over \/ CutControl
        \/ (\E rec \in flight: Damage(rec)) \/ (\E n \in rconns: CutData(n)) \/ (\E n \in held: Release(n))

Spec == Init /\ [][Next]_vars /\ WF_vars(Protocol)

TypeOK == /\ sm \in SenderStates /\ rm \in ReceiverStates
          /\ have \subseteq Chunks /\ wrong \subseteq Chunks /\ jobs \subseteq Chunks
          /\ sconn \in 0..MaxConns /\ nextConn \in 1..(MaxConns + 1)
          /\ faults \in 0..MaxFaults /\ cuts \in 0..MaxCuts
          /\ sbest \in 0..(Cardinality(Chunks) + 1) /\ rstart \in 0..Cardinality(Chunks)
          /\ took \in {"none", "manifest", "manifestOther"}
          /\ Len(toS) <= 3 /\ Len(toR) <= 3

(***************************************************************************)
(* Properties                                                              *)
(***************************************************************************)

\* THE ONE OUTCOME THAT MUST NEVER HAPPEN: bytes that are not the sender's, written.
NoWrongBytes == wrong = {}

\* Nothing is put in place that is not whole.
PlacedIsWhole == placed => have = Chunks /\ wrong = {}

\* The sender says "sent" only of a drop the receiver has put in place.
SentMeansSaved == sm.phase = "completed" => placed

\* A connection number, and so a stream key and its counter nonces, is used once in a drop:
\* also across a reconnect.
NoStreamKeyTwice == \A n \in 1..MaxConns: keyUse[n] <= 1

\* NOTHING IS WRITTEN BEFORE THE PERSON ACCEPTS: no folder, no data connection, no chunk.
NothingBeforeTheYes == (prepared \/ have # {} \/ claimed # {}) => yes

\* Consent means what was shown: the folder is made only for a manifest that is what was offered.
OnlyWhatWasOffered == prepared => took = "manifest"

\* A no is a no: a drop that was declined wrote nothing.
DeclinedWroteNothing == sm.phase = "declined" => ~prepared /\ have = {}

\* What is put in place is what was judged: nothing is written into the drop once it has been
\* judged whole, and nothing once it is in place.
NothingWrittenOnceJudged == ~late
NothingWrittenAfterPlacing == [][placed => have' = have]_vars

\* It ends. And when the person says yes, the sender does not lie, neither end gives up and
\* the network misbehaves fewer times than either end's patience, it ends with the drop in place.
ItEnds == <>Final(sm)
ItArrives == <>(sm.phase = "completed" /\ placed)

\* Checked as goals that must be REACHABLE (formal/check.py expects each to be violated).
NeverArrives == ~(sm.phase = "completed" /\ placed)
NeverDeclined == sm.phase # "declined"

=============================================================================
