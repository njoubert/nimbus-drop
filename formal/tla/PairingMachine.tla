--------------------------- MODULE PairingMachine ---------------------------
(***************************************************************************)
(* The pairing transaction at ONE Mac, as a state machine.                 *)
(*                                                                         *)
(* This is Sources/NimbusCrypto/PairingMachine.swift written as a          *)
(* specification: Step(s, e) is PairingMachine.step. It is not a sketch of *)
(* that code; the two are held equal. PairingMachineTests walks every      *)
(* state the Swift machine can reach under every event and writes the      *)
(* transition relation to PairingImpl.tla, and PairingRefinement.tla has   *)
(* TLC check that relation against Step, both ways.                        *)
(*                                                                         *)
(* What is abstracted: the values. A commitment, a nonce and a reveal are  *)
(* 32 bytes in the code; here an arriving one is "good", "damaged" (wrong  *)
(* length) or "malformed" (unreadable), and a reveal may also be "wrong"   *)
(* (it does not open the commitment). What a person types is right or      *)
(* wrong. Whether the right value can be FORGED is not this model's        *)
(* question (formal/tamarin/NimbusPairing.spthy asks that); this one asks  *)
(* what the machine does with every sequence of events whatever, which is  *)
(* to say against an other end that keeps to nothing.                      *)
(*                                                                         *)
(* Run: see formal/README.md, or ./build.sh verify                         *)
(***************************************************************************)
EXTENDS Naturals, Sequences

Roles  == {"initiator", "responder"}
Phases == {"idle", "awaitCommit", "awaitNonce", "awaitReveal", "codes", "paired", "failed"}

\* Everything that can happen to the machine.
Received == {"commit", "commitDamaged", "commitMalformed",
             "nonce", "nonceDamaged", "nonceMalformed",
             "reveal", "revealDamaged", "revealMalformed", "revealWrong",
             "paired", "failed", "other"}
Events   == {"begin", "typedRight", "typedWrong", "timeout"} \cup Received

\* The kind of message an arrival is, and what state its value is in.
Kind(e) == CASE e \in {"commit", "commitDamaged", "commitMalformed"} -> "commit"
             [] e \in {"nonce", "nonceDamaged", "nonceMalformed"} -> "nonce"
             [] e \in {"reveal", "revealDamaged", "revealMalformed", "revealWrong"} -> "reveal"
             [] OTHER -> e
Malformed(e) == e \in {"commitMalformed", "nonceMalformed", "revealMalformed"}
Damaged(e)   == e \in {"commitDamaged", "nonceDamaged", "revealDamaged"}

States == [role: Roles, byNumber: BOOLEAN, phase: Phases, tries: 0..3, local: BOOLEAN, remote: BOOLEAN]

Start(role, byNumber) ==
    [role |-> role, byNumber |-> byNumber, phase |-> "idle", tries |-> 3, local |-> FALSE, remote |-> FALSE]

Final(s) == s.phase \in {"paired", "failed"}

Fail(s, why) == << [s EXCEPT !.phase = "failed"], << "fail " \o why >> >>

\* Both true: the pairing is stored. Otherwise the effects so far and no more.
Settle(s, effects) ==
    IF s.local /\ s.remote THEN << [s EXCEPT !.phase = "paired"], Append(effects, "store") >>
                           ELSE << s, effects >>

ShowCodes(s) == [s EXCEPT !.phase = "codes", !.tries = 3]

\* A value of the exchange: readable and 32 bytes, or the pairing ends.
BadValue(s, e) == IF Malformed(e) THEN Fail(s, "malformed") ELSE Fail(s, "damaged")

(***************************************************************************)
(* Step(s, e): the state after event e, and what the machine says to do.   *)
(***************************************************************************)
Step(s, e) ==
    IF Final(s) THEN << s, << >> >>
    ELSE IF e = "timeout" THEN Fail(s, "timedOut")
    ELSE IF e = "begin" THEN
        IF s.phase # "idle" THEN << s, << >> >>
        ELSE IF s.byNumber THEN << ShowCodes(s), << "codes" >> >>
        ELSE IF s.role = "responder" THEN << [s EXCEPT !.phase = "awaitCommit"], << >> >>
        ELSE << [s EXCEPT !.phase = "awaitNonce"], << "send commit" >> >>
    ELSE IF e = "typedRight" THEN
        IF s.phase # "codes" \/ s.local THEN << s, << >> >>
        ELSE Settle([s EXCEPT !.local = TRUE], << "confirming", "send paired" >>)
    ELSE IF e = "typedWrong" THEN
        IF s.phase # "codes" \/ s.local THEN << s, << >> >>
        ELSE IF s.tries = 1 THEN << [s EXCEPT !.tries = 0, !.phase = "failed"], << "send failed", "fail wrongCode" >> >>
        ELSE << [s EXCEPT !.tries = s.tries - 1], << "codes" >> >>
    ELSE \* a message from the other Mac
        IF s.phase = "awaitCommit" /\ Kind(e) = "commit" THEN
            IF e # "commit" THEN BadValue(s, e)
            ELSE << [s EXCEPT !.phase = "awaitReveal"], << "send nonce" >> >>
        ELSE IF s.phase = "awaitNonce" /\ Kind(e) = "nonce" THEN
            IF e # "nonce" THEN BadValue(s, e)
            ELSE << ShowCodes(s), << "send reveal", "codes" >> >>
        ELSE IF s.phase = "awaitReveal" /\ Kind(e) = "reveal" THEN
            IF Malformed(e) \/ Damaged(e) THEN BadValue(s, e)
            ELSE IF e = "revealWrong" THEN Fail(s, "didNotKeep")
            ELSE << ShowCodes(s), << "codes" >> >>
        ELSE IF s.phase = "codes" /\ e = "paired" THEN
            IF s.remote THEN Fail(s, "didNotKeep")
            ELSE Settle([s EXCEPT !.remote = TRUE], << "otherTyped" >>)
        ELSE IF s.phase = "codes" /\ e = "failed" THEN Fail(s, "theirsFailed")
        ELSE Fail(s, "didNotKeep")

=============================================================================
