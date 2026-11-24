------------------------------- MODULE Rounds -------------------------------
(***************************************************************************)
(* One end of a drop's conversation (RoundMachine.tla, which is            *)
(* RoundMachine.swift) against an other end, a person, a disk and a        *)
(* network that keep to nothing: every event, in every order, for ever.    *)
(* End says which machine a run is about; Patience is its patience.        *)
(*                                                                         *)
(* History variables record what actually happened, in terms of what went  *)
(* in (events) and what came out (effects), so that the properties are     *)
(* about the world and not about the machine's own phase: "the person said *)
(* yes" is a yes that arrived while a question the machine had asked for   *)
(* was still up, whatever the machine made of it.                          *)
(*                                                                         *)
(* Two honest ends and a network that misbehaves is Drop.tla.              *)
(***************************************************************************)
EXTENDS RoundMachine

CONSTANTS End,        \* "sender" or "receiver"
          Patience

VARIABLES m,      \* the machine
          last,   \* the step just taken: the phase it was taken in, the event, what the machine said
          h       \* what has happened so far

vars == << m, last, h >>

Has(seq, x) == \E i \in 1..Len(seq): seq[i] = x
Count(seq, S) == LET F[i \in 0..Len(seq)] == IF i = 0 THEN 0 ELSE F[i - 1] + (IF seq[i] \in S THEN 1 ELSE 0)
                 IN F[Len(seq)]

Sends == {"send offer", "send manifest", "send done", "send error", "send accept", "send plan", "send complete",
          "send decline notReceiving", "send decline declined", "send decline pairingRanOut"}
Endings == {"end completed", "end declined", "end cancelled"}
           \cup {"fail " \o w: w \in {"unexpected", "malformed", "theirs", "fruitless", "lost", "couldNotGetBack", "silent",
                                     "here", "withdrawn", "wentAway", "invalidManifest", "notAsOffered", "pairingRanOut",
                                     "incomplete", "didNotComeBack"}}
FinalPhases == {"completed", "declined", "failed", "cancelled"}
SaysNothing(seq) == \A i \in 1..Len(seq): seq[i] \notin Sends

(***************************************************************************)
(* The sending end against anything.                                       *)
(***************************************************************************)
SInit == [offers |-> 0,         \* times an offer went out
          offered |-> FALSE,    \* one did
          accepted |-> FALSE,   \* an "accept" arrived after it
          manifest |-> FALSE,   \* the manifest went out
          planHeard |-> FALSE,  \* a readable plan arrived after that
          round |-> FALSE,      \* chunks were sent
          asking |-> FALSE,     \* "done" or a reconnect is out and unanswered
          answered |-> FALSE,   \* the drop completed on a "complete" that answered one of those
          streak |-> 0,         \* reconnects in a row answered by a plan with nothing new in it
          ends |-> 0]           \* times the machine ended the drop

SNext == \E e \in SenderEvents:
    LET t == SenderStep(m, e) fx == t[2] IN
      /\ m' = t[1]
      /\ last' = [from |-> m.phase, event |-> e, effects |-> fx, holding |-> FALSE]
      /\ h' = [offers |-> h.offers + Count(fx, {"send offer"}),
               offered |-> h.offered \/ Has(fx, "send offer"),
               accepted |-> h.accepted \/ (e = "accept" /\ h.offered),
               manifest |-> h.manifest \/ Has(fx, "send manifest"),
               planHeard |-> h.planHeard \/ (e \in {"planMore", "planSame"} /\ h.manifest),
               round |-> h.round \/ Has(fx, "round"),
               asking |-> IF Has(fx, "send done") \/ Has(fx, "reconnect") THEN TRUE
                          ELSE IF Has(fx, "adopt") THEN FALSE ELSE h.asking,
               answered |-> IF Has(fx, "end completed") THEN e = "complete" /\ h.asking /\ h.planHeard ELSE h.answered,
               streak |-> IF Has(fx, "reconnected") /\ e = "planSame" THEN h.streak + 1
                          ELSE IF Has(fx, "adopt") /\ e = "planMore" THEN 0 ELSE h.streak,
               ends |-> h.ends + Count(fx, Endings)]

\* One drop, one offer.
OfferedOnce == h.offers <= 1

\* The manifest (every path in the drop) goes only to a receiver that said yes to the offer.
ManifestOnlyToAYes == h.manifest => h.accepted

\* Chunks go only for a plan, and a plan counts only after the manifest it answers.
ChunksOnlyForAPlan == h.round => h.planHeard

\* "Sent" is said only on the receiver's "complete", and that only as the answer to "done" or
\* to a reconnect, of a drop it had said something about.
CompleteOnlyAsAnAnswer == m.phase = "completed" => h.answered

\* A decline is the answer to the offer and to nothing later.
DeclinedOnlyAsTheAnswerToTheOffer == m.phase = "declined" => h.offered /\ ~h.manifest

\* So many reconnects in a row that find nothing new, and the drop is given up.
FruitlessReconnectsEndIt == h.streak <= Patience /\ (h.streak = Patience => m.phase = "failed")

\* And only those are counted: a round that ends short on a conversation never lost is not.
OnlyReconnectsCount == m.fruitless = h.streak

\* A lost conversation is got back once the receiver has said what it holds, and only then.
ReconnectOnlyUnderWay == Has(last.effects, "reconnect") => h.planHeard
UnderWayALossIsGotBack == (last.event = "lost" /\ last.from \in {"sending", "awaitVerdict"}) => last.effects = << "reconnect" >>

\* Only a reconnect is given up on: time running out means nothing to a drop that is not waiting.
OnlyAReconnectIsGivenUp == (last.event = "gaveUp" /\ last.from # "reconnecting") => last.effects = << >>

\* Under way, silence is a lost connection and never by itself the end.
SUnderWaySilenceIsNotTheEnd == (last.event = "silent" /\ last.from \in {"sending", "awaitVerdict"}) => ~Final(m)

\* What is not an answer to a reconnect neither ends the drop nor carries it on.
AnAttemptThatGotNowhereChangesNothing ==
    (last.from = "reconnecting" /\ last.event \in {"accept", "decline", "declineMalformed", "other"})
        => m.phase = "reconnecting" /\ last.effects = << >>

\* The receiver's reason for stopping, and a message that cannot be read, end the drop.
STheirWordEndsIt == (last.event \in {"error", "planMalformed"} /\ last.from \notin FinalPhases) => m.phase = "failed"

\* The link's own fault is not said on the link; before the offer there is nobody to say
\* anything to.
TheLinksFaultIsNotSaid == last.event \in {"lost", "stoppedSilently"} => ~Has(last.effects, "send error")
NothingIsSaidBeforeTheOffer == last.from = "idle" => \A i \in 1..Len(last.effects): last.effects[i] \in Sends => last.effects[i] = "send offer"

(***************************************************************************)
(* The receiving end against anything.                                     *)
(***************************************************************************)
Manifests == {"manifest", "manifestOther", "manifestInvalid", "manifestMalformed"}

RInit == [began |-> FALSE,       \* the session has started
          nobody |-> FALSE,      \* and it started with nobody to ask
          asks |-> 0,            \* times the question was put on screen
          asked |-> FALSE,       \* it was
          unasked |-> FALSE,     \* and taken away
          answer |-> "none",     \* the person's answer, given while it was up
          accept |-> FALSE,      \* "accept" went out
          manifest |-> "none",   \* the manifest that then arrived, as it was
          prepare |-> FALSE,     \* the folder and the ledger were asked for
          prepared |-> FALSE,    \* and made
          planSaid |-> FALSE,    \* a plan was to be said
          planOut |-> FALSE,     \* and one went out
          declineSaid |-> FALSE, \* a decline was to be said
          declineOut |-> FALSE,  \* and went out
          settling |-> FALSE,    \* a round is being judged
          settle |-> FALSE,      \* a round was ever judged
          twice |-> FALSE,       \* a round was judged a second time before the first judgement came
          whole |-> FALSE,       \* a round was judged whole
          place |-> FALSE,       \* the drop was to be put in place
          placed |-> FALSE,      \* and was
          complete |-> FALSE,    \* "complete" went out
          holding |-> FALSE,     \* the drop is held for the sender
          held |-> FALSE,        \* it ever was
          streak |-> 0,          \* rounds in a row judged to have brought nothing new
          ends |-> 0]

RNext == \E e \in ReceiverEvents:
    LET t == ReceiverStep(m, e) fx == t[2]
        up == h.asked /\ ~h.unasked /\ h.answer = "none"      \* the question is on screen
    IN
      /\ m' = t[1]
      /\ last' = [from |-> m.phase, event |-> e, effects |-> fx, holding |-> h.holding]
      /\ h' = [began |-> h.began \/ e \in {"begin", "beginNobody"},
               nobody |-> h.nobody \/ (e = "beginNobody" /\ ~h.began),
               asks |-> h.asks + Count(fx, {"ask"}),
               asked |-> h.asked \/ Has(fx, "ask"),
               unasked |-> h.unasked \/ Has(fx, "unask"),
               answer |-> IF up /\ e \in {"yes", "yesUnpaired", "no"} THEN e ELSE h.answer,
               accept |-> h.accept \/ Has(fx, "send accept"),
               manifest |-> IF h.manifest = "none" /\ h.accept /\ e \in Manifests THEN e ELSE h.manifest,
               prepare |-> h.prepare \/ Has(fx, "prepare"),
               prepared |-> h.prepared \/ (e = "prepared" /\ h.prepare),
               planSaid |-> h.planSaid \/ Has(fx, "send plan"),
               planOut |-> h.planOut \/ (e = "said" /\ h.planSaid),
               declineSaid |-> h.declineSaid \/ Has(fx, "send decline notReceiving") \/ Has(fx, "send decline declined"),
               declineOut |-> h.declineOut \/ (e = "said" /\ h.declineSaid),
               settling |-> IF Has(fx, "settle") THEN TRUE
                            ELSE IF e \in Judgements \/ Count(fx, Endings) > 0 THEN FALSE ELSE h.settling,
               settle |-> h.settle \/ Has(fx, "settle"),
               twice |-> h.twice \/ (Has(fx, "settle") /\ h.settling),
               whole |-> h.whole \/ (e = "whole" /\ h.settling),
               place |-> h.place \/ Has(fx, "place"),
               placed |-> h.placed \/ (e = "placed" /\ h.place),
               complete |-> h.complete \/ Has(fx, "send complete"),
               holding |-> IF Has(fx, "hold") THEN TRUE
                           ELSE IF e \in {"senderBack", "gaveUp"} \/ Count(fx, Endings) > 0 THEN FALSE ELSE h.holding,
               held |-> h.held \/ Has(fx, "hold"),
               streak |-> IF h.settling /\ e = "nothingNew" THEN h.streak + 1
                          ELSE IF h.settling /\ e = "more" THEN 0 ELSE h.streak,
               ends |-> h.ends + Count(fx, Endings)]

\* NOTHING IS ACCEPTED, PREPARED, WRITTEN OR JUDGED BEFORE THE PERSON SAID YES: a yes given to
\* a question that was on screen, under a pairing that still held.
NothingBeforeTheYes == (h.accept \/ h.prepare \/ h.planSaid \/ h.settle \/ h.place \/ h.complete) => h.answer = "yes"

\* Nobody to ask means no; and a drop is asked about once.
NobodyToAskMeansNo == h.nobody => ~h.asked /\ ~h.accept
AskedOnce == h.asks <= 1

\* The folder is made only for a manifest that passed validate and is what was offered.
OnlyWhatWasOffered == h.prepare => h.manifest = "manifest"

\* Nothing is said to be here, and nothing is judged, before there is a folder for it.
NothingArrivesBeforeTheFolder == (h.planSaid \/ h.settle) => h.prepared

\* The drop is put in place only when a round was judged whole, and each round is judged once.
PlacedOnlyWhenWhole == h.place => h.whole
OneJudgementARound == ~h.twice

\* "Complete" is said only of a drop that was judged whole and then put in place.
CompleteOnlyWhenInPlace == (h.complete \/ m.phase = "completed") => h.whole /\ h.placed

\* So many rounds in a row that bring nothing new, and the drop is given up; and only those count.
IdleRoundsEndIt == h.streak <= Patience /\ (h.streak = Patience => m.phase = "failed")
OnlyIdleRoundsCount == m.idle = h.streak

\* The drop is held for the sender only once the first plan went out, and from then on a lost
\* conversation is held for, not given up.
HeldOnlyUnderWay == h.held => h.planOut
UnderWayALossIsHeld == (last.event = "lost" /\ last.from = "reading") => last.effects = << "hold" >>

\* A sender is answered as having come back only by a drop that is being held for it or that
\* has finished; nobody gives up waiting who was not waiting.
BackOnlyToAHeldDrop == (last.event = "senderBack" /\ last.effects # << >>) => (last.holding \/ last.from = "completed")
NobodyGivesUpWhoWasNotWaiting == (last.event = "gaveUp" /\ ~last.holding) => last.effects = << >>

\* A decline is the end only once it has been said; and it is the person's no, or nobody's
\* being there to ask.
DeclinedOnlyOnceSaid == m.phase = "declined" => h.declineOut
DeclinedMeansNo == m.phase = "declined" => h.answer = "no" \/ h.nobody

\* A question still on screen goes when the drop does, and only then.
TheQuestionGoesWhenTheDropDoes == /\ (Final(m) /\ h.asked /\ h.answer = "none") => h.unasked
                                  /\ h.unasked => Final(m) /\ h.asked /\ h.answer = "none"

\* Whatever a sender says (or the link does) while the person is deciding is its giving up:
\* the drop ends and nothing is answered.
TheSendersGivingUpIsNotAnswered ==
    (last.from = "deciding" /\ last.event \in ReceiverReceived \cup {"lost"}) => m.phase = "failed" /\ SaysNothing(last.effects)

RUnderWaySilenceIsNotTheEnd == (last.event = "silent" /\ last.from \in {"reading", "settling", "awaitSender"}) => ~Final(m)

\* The sender's reason for stopping, and anything that cannot be read or is not what was
\* agreed to, end the drop.
RTheirWordEndsIt ==
    (last.event \in {"error", "errorMalformed", "doneMalformed", "manifestOther", "manifestInvalid", "manifestMalformed"}
        /\ last.from \notin FinalPhases) => m.phase = "failed"

\* A finished drop answers one thing, with one word: a sender that comes back is told
\* "complete" again.
AFinishedDropSaysOnlyCompleteAgain ==
    last.from \in FinalPhases =>
        \/ last.effects = << >>
        \/ last.from = "completed" /\ last.event = "senderBack" /\ last.effects = << "send complete" >>

(***************************************************************************)
(* Both.                                                                   *)
(***************************************************************************)
Init == /\ m = IF End = "sender" THEN SenderStart(Patience) ELSE ReceiverStart(Patience)
        /\ last = [from |-> "idle", event |-> "none", effects |-> << >>, holding |-> FALSE]
        /\ h = IF End = "sender" THEN SInit ELSE RInit

Next == IF End = "sender" THEN SNext ELSE RNext

Spec == Init /\ [][Next]_vars

TypeOK == /\ m \in (IF End = "sender" THEN SenderStates ELSE ReceiverStates)
          /\ \A i \in 1..Len(last.effects): last.effects[i] \in Sends \cup Endings
                 \cup {"adopt", "round", "reconnect", "reconnected", "hangUp", "ask", "unask", "prepare", "settle", "place", "hold"}

\* The drop is ended once, exactly when the machine reaches an end.
EndsOnce == h.ends <= 1 /\ (h.ends = 1 <=> Final(m))

\* Withdrawing trust says no farewell: a farewell is a write, and a Mac that has stopped
\* reading would hold whoever withdrew the trust (the review's F7).
AWithdrawalSaysNothing == last.event = "withdrawn" => SaysNothing(last.effects)

\* After an end nothing is said (but for a finished drop's one answer, above).
NothingIsSaidAfterAnEnd == (End = "sender" /\ last.from \in FinalPhases) => last.effects = << >>

\* Once ended, ended: nothing that arrives afterwards changes anything.
FinalIsFinal == [][Final(m) => m' = m /\ h'.ends = h.ends]_vars

=============================================================================
