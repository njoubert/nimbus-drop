---------------------------- MODULE RoundMachine ----------------------------
(***************************************************************************)
(* A drop's conversation, as two state machines: the sending end's and the *)
(* receiving end's.                                                        *)
(*                                                                         *)
(*   offer -> accept | decline -> manifest -> plan -> chunks... done       *)
(*         -> plan | complete                                              *)
(*                                                                         *)
(* This is Sources/NimbusCrypto/RoundMachine.swift written as a            *)
(* specification: SenderStep(s, e) is RoundMachine.Sender.step and         *)
(* ReceiverStep(s, e) is RoundMachine.Receiver.step. They are not sketches *)
(* of that code; they are held equal to it. RoundMachineTests walks every  *)
(* state each Swift machine can reach under every event and writes the two *)
(* transition relations to RoundImpl.tla, and RoundRefinement.tla has TLC  *)
(* check those relations against the two Steps, both ways.                 *)
(*                                                                         *)
(* THE ABSTRACTION CONTRACT: what "equal" is equality of.                  *)
(*                                                                         *)
(* 1. STATE. A Swift machine m is the state (RoundMachineTests.state):     *)
(*                                                                         *)
(*      Sender    [phase |-> m.phase, fruitless |-> m.fruitless,           *)
(*                 patience |-> m.patience]                                *)
(*      Receiver  [phase |-> m.phase, idle |-> m.idle,                     *)
(*                 patience |-> m.patience]                                *)
(*                                                                         *)
(*    Every stored property of the two Swift machines, and where it went:  *)
(*                                                                         *)
(*      Sender.phase       in the state.                                   *)
(*      Sender.fruitless   in the state.                                   *)
(*      Sender.patience    in the state. Fixed when a machine is made. The *)
(*                         relation is written out for 1, 2 and 3 (the     *)
(*                         app's is 3); for any other the equality is not  *)
(*                         checked, and what there is instead is a test of *)
(*                         the count itself (testALargerPatienceIsOnly...).*)
(*      Sender.best        ABSTRACTED AWAY. The most bytes any plan has    *)
(*                         said the receiver holds. It is used in one      *)
(*                         comparison, have > best, and the outcome of     *)
(*                         that comparison is in the EVENT's name          *)
(*                         (planMore / planSame). Safe if nothing else the *)
(*                         machine does depends on best or on have: by     *)
(*                         reading (it is two lines of `take`), and by the *)
(*                         random walks, which vary both over the whole of *)
(*                         Int64 and find every step in the relation.      *)
(*      Receiver.phase     in the state.                                   *)
(*      Receiver.idle      in the state.                                   *)
(*      Receiver.patience  in the state. Written out for 1, 2, 3 and 5     *)
(*                         (the app's is Tuning.idleRounds, 5); otherwise  *)
(*                         as for the sender's.                            *)
(*      Receiver.offered   ABSTRACTED AWAY. What the offer described       *)
(*                         (files, bytes, top-level names). It is used in  *)
(*                         one equality, with what a manifest describes,   *)
(*                         and the outcome is in the event's name          *)
(*                         (manifest / manifestOther). Safe on the same    *)
(*                         two grounds; the walks vary what was offered    *)
(*                         and in which way a manifest is not it.          *)
(*                                                                         *)
(*    There is nothing else in either machine: no clock, no randomness, no *)
(*    I/O (scripts/check-layers.py refuses them in that module).           *)
(*                                                                         *)
(* 2. EVENTS. A Swift event is the abstract event that THE NUMBERS make it *)
(*    in the machine as it stands before the step, never what the step     *)
(*    then did (RoundMachineTests.label):                                  *)
(*                                                                         *)
(*      either    .lost .gaveUp .silent .withdrawn .cancelled: that name   *)
(*                .stopped(tell): stopped if tell, else stoppedSilently    *)
(*      Sender    .begin .written: that name                               *)
(*                .received(.accept | .complete | .error | .other): the    *)
(*                    message's name                                       *)
(*                .received(.decline(readable)): decline if readable, else *)
(*                    declineMalformed                                     *)
(*                .received(.plan(have)): planMalformed if have is nil;    *)
(*                    planMore if have > m.best; else planSame             *)
(*      Receiver  .begin(askable): begin if askable, else beginNobody      *)
(*                .yes(paired): yes if paired, else yesUnpaired; .no: no   *)
(*                .said .prepared .placed .senderBack: that name           *)
(*                .settled(j): whole, more or nothingNew                   *)
(*                .received(.manifest(x)): manifestMalformed if x is       *)
(*                    unreadable; manifestInvalid if invalid; manifest if  *)
(*                    x = described(d) and d = m.offered; else             *)
(*                    manifestOther                                        *)
(*                .received(.done(readable)): done / doneMalformed         *)
(*                .received(.error(readable)): error / errorMalformed      *)
(*                .received(.other): other                                 *)
(*                                                                         *)
(*    Every abstract event can happen in every abstract state: the export  *)
(*    makes each happen in each and fails if it could not, so there is no  *)
(*    Enabled predicate to state. In one particular Swift machine an event *)
(*    may be impossible (no plan names more than Int64.max bytes, so a     *)
(*    sender whose best is that has no planMore); Step says what would     *)
(*    happen, which is more than can.                                      *)
(*                                                                         *)
(* 3. EFFECTS. A Swift effect is its name with the CLASS of what it        *)
(*    carries (RoundMachineTests.name): which message a send is ("send     *)
(*    offer", "send decline pairingRanOut"), how an end ends ("end         *)
(*    completed", "fail fruitless"). The machines' effects carry nothing   *)
(*    more. What a plan SAYS the receiver holds, a manifest's entries and  *)
(*    the words of a reason are made by the shell (from the ledger, the    *)
(*    scan, the error in hand) and are not the machines'; Drop.tla has a   *)
(*    plan's contents as the environment's.                                *)
(*                                                                         *)
(* 4. HOW MUCH OF THIS IS CHECKED, AND HOW.                                *)
(*    By enumeration (exhaustive): the relation of one Swift machine per   *)
(*    abstract state under every abstract event, equal to Step both ways   *)
(*    (RoundRefinement).                                                   *)
(*    By bounded random exploration: that the abstraction left out nothing *)
(*    that matters. From every abstract state, machines made afresh with   *)
(*    numbers of their own, given every event and then walked at random;   *)
(*    each step named by the numbers before it is taken (see               *)
(*    testRandomWalksStayInsideTheRelations for how many).                 *)
(*    By reading: 1 and 2 above as statements about the Swift source; and  *)
(*    everything below about what a shell means by an event.               *)
(*                                                                         *)
(* WHAT A SHELL MEANS BY AN EVENT. A machine is told what its shell        *)
(* learned (SendSession, ReceiveSession, in Sources/NimbusTransferCore);   *)
(* the shell is the connections, the disk, the person and the clock. That  *)
(* a shell reports truthfully, and does what it is told, is by reading:    *)
(*                                                                         *)
(*   a message        the type of a frame read from the conversation's     *)
(*                    connection, after the channel opened it (Noise;      *)
(*                    formal/tamarin). "...Malformed": its body could not  *)
(*                    be decoded. "other": any other frame type.           *)
(*   planMore /       a plan, read against the manifest, says the receiver *)
(*   planSame         holds more bytes than any plan before it said / no   *)
(*                    more.                                                *)
(*   manifest /       a manifest that passed Manifest.validate and whose   *)
(*   manifestOther /  file count, byte count and top-level names are       *)
(*   manifestInvalid  exactly the offer's / are not / that did not pass    *)
(*                    validate. The comparison is the machine's; validate  *)
(*                    (and SafeTree after it) is the storage core's.       *)
(*   yes, no          the person's answer, read by the session's thread.   *)
(*   yesUnpaired      a yes, with Trust.standing(of:) no longer "paired".  *)
(*   begin /          the session starts, with / without an onOffer to     *)
(*   beginNobody      show the question through.                           *)
(*   said             a send the machine asked for returned without        *)
(*                    throwing (a decline, the first plan).                *)
(*   prepared         the partial folder, the tree and the ledger were     *)
(*                    made, and the session registered with the listener   *)
(*                    (from then on data connections can attach).          *)
(*   whole / more /   after `settle` (the data connections given time to   *)
(*   nothingNew       finish, the rest closed): Ledger.isComplete / the    *)
(*                    ledger holds more bytes than when the last plan was  *)
(*                    said / it does not. THE LEDGER'S WORD: that the      *)
(*                    bytes on disk are the sender's is the data path's    *)
(*                    doing (each record opened before it is written),     *)
(*                    which Drop.tla has as the environment.               *)
(*   placed           finalize returned: every item moved into place.      *)
(*   written          every chunk of the round was taken by a data         *)
(*                    connection's thread and those threads have ended.    *)
(*   lost             a read or a write on the conversation's connection   *)
(*                    failed (sender: with an error that is the link's;    *)
(*                    receiver: with any error).                           *)
(*   senderBack       a new connection proved the same two keys and the    *)
(*                    drop's resume key (formal/tamarin), and the          *)
(*                    session's thread took it.                            *)
(*   gaveUp           Tuning.reconnectSeconds passed.                      *)
(*   silent           the watchdog: nothing moved or was said for too      *)
(*                    long.                                                *)
(*   stopped /        the drop cannot go on at this Mac for a reason of    *)
(*   stoppedSilently  its own, which the other Mac is / is not told (a     *)
(*                    source that changed, the disk, a key no longer       *)
(*                    paired; the link's fault, another session taking the *)
(*                    drop over).                                          *)
(*   withdrawn        Trust ended the session (Trust.withdrawLocked).      *)
(*   cancelled        the person stopped it.                               *)
(*                                                                         *)
(* WHAT STAYS OUTSIDE THE MACHINES: the handshake, the hellos, the resume  *)
(* proof and its answer; the data connections, their attach, their records *)
(* and their keys; the manifest's validity and every file operation; the   *)
(* deadlines themselves; what an effect's text says. And one decline the   *)
(* listener says before a session runs at all (too many offers waiting).   *)
(*                                                                         *)
(* Run: see formal/README.md, or ./build.sh verify                         *)
(***************************************************************************)
EXTENDS Naturals, Sequences

Final(s) == s.phase \in {"completed", "declined", "failed", "cancelled"}

(***************************************************************************)
(* The sending end.                                                        *)
(***************************************************************************)
SenderPhases == {"idle", "awaitAnswer", "awaitPlan", "sending", "awaitVerdict", "reconnecting",
                 "completed", "declined", "failed", "cancelled"}

\* What the receiver can say, as the sender's shell reports it.
SenderReceived == {"accept", "decline", "declineMalformed", "planMore", "planSame", "planMalformed",
                   "complete", "error", "other"}
SenderEvents == {"begin", "written", "lost", "gaveUp", "silent", "stopped", "stoppedSilently",
                 "withdrawn", "cancelled"} \cup SenderReceived

IsPlan(e) == e \in {"planMore", "planSame", "planMalformed"}

SenderStates == [phase: SenderPhases, fruitless: 0..3, patience: 1..3]

SenderStart(patience) == [phase |-> "idle", fruitless |-> 0, patience |-> patience]

\* Before the offer there is no conversation, and so nobody to say anything to.
SWord(s) == IF s.phase = "idle" THEN << >> ELSE << "send error" >>

\* Ends the drop, saying why when there is a conversation to say it on.
SFail(s, why) == << [s EXCEPT !.phase = "failed"], SWord(s) \o << "fail " \o why >> >>

\* A plan in its turn. back: it is the answer to a reconnect. Reconnect after reconnect to a
\* receiver that holds nothing new is not progress; a round that merely ends short is not counted.
STake(s, e, back) ==
    IF e = "planMalformed" THEN SFail(s, "malformed")
    ELSE LET f == IF e = "planMore" THEN 0 ELSE IF back THEN s.fruitless + 1 ELSE s.fruitless
             t == [s EXCEPT !.fruitless = f]
         IN IF f < s.patience
               THEN << [t EXCEPT !.phase = "sending"], << "adopt", "round" >> >>
               ELSE << [t EXCEPT !.phase = "failed"], << "adopt", "send error", "fail fruitless" >> >>

Reconnected(r) == << r[1], << "reconnected" >> \o r[2] >>

SenderStep(s, e) ==
    IF Final(s) THEN << s, << >> >>
    ELSE IF e = "cancelled" THEN << [s EXCEPT !.phase = "cancelled"], SWord(s) \o << "end cancelled" >> >>
    \* No farewell: a Mac that has stopped reading would hold whoever withdrew the trust.
    ELSE IF e = "withdrawn" THEN << [s EXCEPT !.phase = "failed"], << "fail withdrawn" >> >>
    ELSE IF e = "stopped" THEN << [s EXCEPT !.phase = "failed"], SWord(s) \o << "fail here" >> >>
    ELSE IF e = "stoppedSilently" THEN << [s EXCEPT !.phase = "failed"], << "fail here" >> >>
    ELSE IF e = "silent" THEN
        \* Under way, silence is taken for a lost connection; before that, for the end.
        IF s.phase \in {"sending", "awaitVerdict"} THEN << s, << "hangUp" >> >>
        ELSE SFail(s, "silent")
    ELSE IF e = "begin" THEN
        IF s.phase = "idle" THEN << [s EXCEPT !.phase = "awaitAnswer"], << "send offer" >> >>
        ELSE << s, << >> >>
    ELSE IF e = "written" THEN
        IF s.phase = "sending" THEN << [s EXCEPT !.phase = "awaitVerdict"], << "send done" >> >>
        ELSE << s, << >> >>
    ELSE IF e = "lost" THEN
        IF s.phase \in {"sending", "awaitVerdict"} THEN << [s EXCEPT !.phase = "reconnecting"], << "reconnect" >> >>
        ELSE IF s.phase = "reconnecting" THEN << s, << >> >>
        \* Nothing is held for it at the other end yet, and there is nobody to tell.
        ELSE << [s EXCEPT !.phase = "failed"], << "fail lost" >> >>
    ELSE IF e = "gaveUp" THEN
        IF s.phase = "reconnecting" THEN SFail(s, "couldNotGetBack")
        ELSE << s, << >> >>
    ELSE \* a message from the receiver
        IF e = "error" THEN SFail(s, "theirs")
        ELSE IF s.phase = "awaitAnswer" /\ e = "accept" THEN << [s EXCEPT !.phase = "awaitPlan"], << "send manifest" >> >>
        ELSE IF s.phase = "awaitAnswer" /\ e = "decline" THEN << [s EXCEPT !.phase = "declined"], << "end declined" >> >>
        ELSE IF s.phase = "awaitAnswer" /\ e = "declineMalformed" THEN SFail(s, "malformed")
        ELSE IF s.phase \in {"awaitPlan", "awaitVerdict"} /\ IsPlan(e) THEN STake(s, e, FALSE)
        ELSE IF s.phase = "awaitVerdict" /\ e = "complete" THEN << [s EXCEPT !.phase = "completed"], << "end completed" >> >>
        ELSE IF s.phase = "reconnecting" /\ IsPlan(e) THEN Reconnected(STake(s, e, TRUE))
        ELSE IF s.phase = "reconnecting" /\ e = "complete" THEN << [s EXCEPT !.phase = "completed"], << "reconnected", "end completed" >> >>
        \* Not an answer to a reconnect: that attempt got nowhere, and the next is made.
        ELSE IF s.phase = "reconnecting" THEN << s, << >> >>
        ELSE SFail(s, "unexpected")

(***************************************************************************)
(* The receiving end.                                                      *)
(***************************************************************************)
ReceiverPhases == {"idle", "deciding", "declining", "awaitManifest", "preparing", "planning", "reading",
                   "settling", "awaitSender", "placing", "completed", "declined", "failed", "cancelled"}

\* What the sender can say, as the receiver's shell reports it.
ReceiverReceived == {"manifest", "manifestOther", "manifestInvalid", "manifestMalformed",
                     "done", "doneMalformed", "error", "errorMalformed", "other"}
Judgements == {"whole", "more", "nothingNew"}
ReceiverEvents == {"begin", "beginNobody", "yes", "yesUnpaired", "no", "said", "prepared", "placed",
                   "lost", "senderBack", "gaveUp", "silent", "stopped", "stoppedSilently", "withdrawn", "cancelled"}
                  \cup Judgements \cup ReceiverReceived

ReceiverStates == [phase: ReceiverPhases, idle: 0..5, patience: 1..5]

ReceiverStart(patience) == [phase |-> "idle", idle |-> 0, patience |-> patience]

\* A question that is still up goes when the drop does.
Unask(s) == IF s.phase = "deciding" THEN << "unask" >> ELSE << >>

\* Ends the drop and tells the sender why.
RFail(s, why) == << [s EXCEPT !.phase = "failed"], << "send error", "fail " \o why >> >>

Nothing(s) == << s, << >> >>

ReceiverStep(s, e) ==
    \* The one thing a finished drop still answers: a sender that lost the conversation before it heard.
    IF s.phase = "completed" /\ e = "senderBack" THEN << s, << "send complete" >> >>
    ELSE IF Final(s) THEN Nothing(s)
    ELSE IF e = "cancelled" THEN << [s EXCEPT !.phase = "cancelled"], << "send error", "end cancelled" >> \o Unask(s) >>
    ELSE IF e = "withdrawn" THEN << [s EXCEPT !.phase = "failed"], << "fail withdrawn" >> \o Unask(s) >>
    ELSE IF e = "stopped" THEN << [s EXCEPT !.phase = "failed"], << "send error", "fail here" >> \o Unask(s) >>
    ELSE IF e = "stoppedSilently" THEN << [s EXCEPT !.phase = "failed"], << "fail here" >> \o Unask(s) >>
    ELSE IF e = "silent" THEN
        \* With the drop under way, silence is taken for a lost connection.
        IF s.phase \in {"reading", "settling", "awaitSender"} THEN << s, << "hangUp" >> >>
        ELSE << [s EXCEPT !.phase = "failed"], << "fail silent" >> \o Unask(s) >>
    ELSE IF e = "begin" THEN
        IF s.phase = "idle" THEN << [s EXCEPT !.phase = "deciding"], << "ask" >> >> ELSE Nothing(s)
    \* Nobody to ask means no.
    ELSE IF e = "beginNobody" THEN
        IF s.phase = "idle" THEN << [s EXCEPT !.phase = "declining"], << "send decline notReceiving" >> >> ELSE Nothing(s)
    ELSE IF e = "yes" THEN
        IF s.phase = "deciding" THEN << [s EXCEPT !.phase = "awaitManifest"], << "send accept" >> >> ELSE Nothing(s)
    \* The question was asked under a pairing: a yes after it ended starts nothing.
    ELSE IF e = "yesUnpaired" THEN
        IF s.phase = "deciding"
           THEN << [s EXCEPT !.phase = "failed"], << "send decline pairingRanOut", "send error", "fail pairingRanOut" >> >>
           ELSE Nothing(s)
    ELSE IF e = "no" THEN
        IF s.phase = "deciding" THEN << [s EXCEPT !.phase = "declining"], << "send decline declined" >> >> ELSE Nothing(s)
    ELSE IF e = "said" THEN
        IF s.phase = "declining" THEN << [s EXCEPT !.phase = "declined"], << "end declined" >> >>
        ELSE IF s.phase = "planning" THEN << [s EXCEPT !.phase = "reading"], << >> >>
        ELSE Nothing(s)
    ELSE IF e = "prepared" THEN
        IF s.phase = "preparing" THEN << [s EXCEPT !.phase = "planning"], << "send plan" >> >> ELSE Nothing(s)
    ELSE IF e \in Judgements THEN
        IF s.phase # "settling" THEN Nothing(s)
        ELSE IF e = "whole" THEN << [s EXCEPT !.phase = "placing"], << "place" >> >>
        \* Something is missing: the answer is what is here, not a failure. Until round after
        \* round delivers nothing.
        ELSE IF e = "more" THEN << [s EXCEPT !.idle = 0, !.phase = "reading"], << "send plan" >> >>
        ELSE IF s.idle + 1 < s.patience THEN << [s EXCEPT !.idle = s.idle + 1, !.phase = "reading"], << "send plan" >> >>
        ELSE RFail([s EXCEPT !.idle = s.idle + 1], "incomplete")
    ELSE IF e = "placed" THEN
        IF s.phase = "placing" THEN << [s EXCEPT !.phase = "completed"], << "send complete", "end completed" >> >>
        ELSE Nothing(s)
    ELSE IF e = "lost" THEN
        IF s.phase = "deciding" THEN << [s EXCEPT !.phase = "failed"], << "fail wentAway", "unask" >> >>
        \* Accepted and partly here: wait for the sender rather than ending it.
        ELSE IF s.phase = "reading" THEN << [s EXCEPT !.phase = "awaitSender"], << "hold" >> >>
        ELSE IF s.phase \in {"settling", "awaitSender", "placing"} THEN Nothing(s)
        ELSE RFail(s, "lost")
    ELSE IF e = "senderBack" THEN
        IF s.phase = "awaitSender" THEN << [s EXCEPT !.phase = "reading"], << "send plan" >> >> ELSE Nothing(s)
    ELSE IF e = "gaveUp" THEN
        IF s.phase = "awaitSender" THEN RFail(s, "didNotComeBack") ELSE Nothing(s)
    ELSE \* a message from the sender
        IF s.phase = "deciding" THEN
            \* Anything at all from a sender that is waiting for an answer is its giving up.
            IF e = "error" THEN << [s EXCEPT !.phase = "failed"], << "fail theirs", "unask" >> >>
            ELSE << [s EXCEPT !.phase = "failed"], << "fail wentAway", "unask" >> >>
        \* The person said yes to what the offer described, and to nothing else.
        ELSE IF s.phase = "awaitManifest" /\ e = "manifest" THEN << [s EXCEPT !.phase = "preparing"], << "prepare" >> >>
        ELSE IF s.phase = "awaitManifest" /\ e = "manifestOther" THEN RFail(s, "notAsOffered")
        ELSE IF s.phase = "awaitManifest" /\ e = "manifestInvalid" THEN RFail(s, "invalidManifest")
        ELSE IF s.phase = "awaitManifest" /\ e = "manifestMalformed" THEN RFail(s, "malformed")
        ELSE IF s.phase = "reading" /\ e = "done" THEN << [s EXCEPT !.phase = "settling"], << "settle" >> >>
        ELSE IF s.phase = "reading" /\ e \in {"doneMalformed", "errorMalformed"} THEN RFail(s, "malformed")
        ELSE IF s.phase = "reading" /\ e = "error" THEN RFail(s, "theirs")
        ELSE RFail(s, "unexpected")

=============================================================================
