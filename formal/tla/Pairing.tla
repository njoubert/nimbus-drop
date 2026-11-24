------------------------------ MODULE Pairing ------------------------------
(***************************************************************************)
(* One Mac's pairing transaction (PairingMachine.tla, which is             *)
(* PairingMachine.swift) against an other end that keeps to nothing: every *)
(* event, in every order, for ever.                                        *)
(***************************************************************************)
EXTENDS PairingMachine

(***************************************************************************)
(* The machine against anything: every event, in every order.              *)
(*                                                                         *)
(* History variables record what actually happened, so that the properties *)
(* are about the world and not about the machine's own flags.              *)
(***************************************************************************)
VARIABLES s,            \* the machine
          typedRight,   \* this Mac's person has typed the right code
          saidPaired,   \* times the other Mac's "paired" was TAKEN (not merely sent)
          opened,       \* a reveal that opens the commitment was taken (responder)
          committed,    \* a good commitment was taken (responder)
          wrong,        \* wrong entries so far
          stored,       \* times the machine said "store"
          took          \* the kinds of message taken without failing, in order

vars == << s, typedRight, saidPaired, opened, committed, wrong, stored, took >>

Has(seq, x) == \E i \in 1..Len(seq): seq[i] = x
Count(seq, x) == LET F[i \in 0..Len(seq)] == IF i = 0 THEN 0 ELSE F[i - 1] + (IF seq[i] = x THEN 1 ELSE 0)
                 IN F[Len(seq)]

Init == /\ \E r \in Roles, b \in BOOLEAN: s = Start(r, b)
        /\ typedRight = FALSE /\ saidPaired = 0 /\ opened = FALSE /\ committed = FALSE
        /\ wrong = 0 /\ stored = 0 /\ took = << >>

Next == \E e \in Events:
          LET r == Step(s, e) t == r[1] effects == r[2] live == ~Final(s) IN
            /\ s' = t
            /\ typedRight' = (typedRight \/ (live /\ e = "typedRight" /\ s.phase = "codes"))
            /\ wrong' = wrong + (IF live /\ e = "typedWrong" /\ s.phase = "codes" /\ ~s.local THEN 1 ELSE 0)
            /\ saidPaired' = saidPaired + (IF live /\ e = "paired" /\ t.phase # "failed" THEN 1 ELSE 0)
            /\ opened' = (opened \/ (live /\ e = "reveal" /\ s.phase = "awaitReveal"))
            /\ committed' = (committed \/ (live /\ e = "commit" /\ s.phase = "awaitCommit"))
            /\ stored' = stored + Count(effects, "store")
            /\ took' = IF live /\ e \in Received /\ t.phase # "failed" THEN Append(took, Kind(e)) ELSE took

Spec == Init /\ [][Next]_vars

TypeOK == s \in States

(***************************************************************************)
(* What a pairing rests on.                                                *)
(***************************************************************************)

\* A Mac stores a pairing only when its own person typed the right code AND the other Mac
\* said the same. Neither alone is enough, whatever else arrives and in whatever order.
StoresOnlyWhenBothAreTrue == stored > 0 => typedRight /\ saidPaired = 1

\* Stored at most once, and exactly when the machine ends as paired.
StoredOnce == stored <= 1 /\ (stored = 1 <=> s.phase = "paired")

\* A responder that shows codes has seen a commitment and then a reveal that opens it.
\* (Not for a pairing by identity number, which has no exchange.)
CodesOnlyAfterTheCommitmentIsOpened ==
    (s.role = "responder" /\ ~s.byNumber /\ s.phase \in {"codes", "paired"}) => committed /\ opened

\* Each message is taken at most once, and only in its order.
EachMessageOnceAndInOrder ==
    /\ \A k \in {"commit", "nonce", "reveal", "paired"}: Count(took, k) <= 1
    /\ took \in {<< >>, << "commit" >>, << "commit", "reveal" >>, << "commit", "reveal", "paired" >>,
                 << "nonce" >>, << "nonce", "paired" >>, << "paired" >>}
    /\ (s.role = "initiator" => ~Has(took, "commit") /\ ~Has(took, "reveal"))
    /\ (s.role = "responder" => ~Has(took, "nonce"))
    /\ (s.byNumber => took \in {<< >>, << "paired" >>})

\* Three wrong entries end it; there is never a fourth.
ThreeTries == wrong <= 3 /\ (wrong = 3 => s.phase = "failed") /\ s.tries = 3 - wrong

\* Nothing is typed into, and nothing is believed of, a pairing whose codes are not up.
NothingCountsBeforeTheCodes ==
    s.phase \in {"idle", "awaitCommit", "awaitNonce", "awaitReveal"} => ~s.local /\ ~s.remote /\ ~typedRight

\* Once ended, ended: nothing that arrives afterwards changes anything.
FinalIsFinal == [][Final(s) => s' = s /\ stored' = stored]_vars

=============================================================================
