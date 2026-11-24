-------------------------- MODULE RoundRefinement --------------------------
(***************************************************************************)
(* The Swift code and its specification are the same two machines.         *)
(*                                                                         *)
(* RoundImpl.tla is generated from RoundMachine.swift: every state each of *)
(* the two machines reaches, under every event, with what it said to do    *)
(* (and `swift test` fails if the file is not what the code does now).     *)
(* RoundMachine.tla defines SenderStep and ReceiverStep. This module has   *)
(* TLC check, for each machine:                                            *)
(*                                                                         *)
(*   ImplIsSpec       every transition the code makes is the one Step      *)
(*                    defines, effects included;                           *)
(*   SpecIsImpl       at every state the specification reaches, every      *)
(*                    event's transition is one the code makes;            *)
(*   the same beginnings (one for each patience the relation was written   *)
(*   out for), and the code's states are exactly those its own transitions *)
(*   reach from them.                                                      *)
(*                                                                         *)
(* So over the abstraction RoundMachine.tla states (what each event stands *)
(* for), what is proved of the two Steps in Rounds.tla and Drop.tla is     *)
(* proved of the Swift machines, for the patience values listed here.      *)
(* What this does NOT cover: that the abstraction is the right one         *)
(* (RoundMachineTests' random walks test that the code's behaviour depends *)
(* on nothing outside it), and SendSession and ReceiveSession, which drive *)
(* the machines and do what they say.                                      *)
(***************************************************************************)
EXTENDS RoundMachine, RoundImpl, FiniteSets

VARIABLES s, r

\* The patience each relation was written out for: the app's own (3 fruitless reconnects,
\* Tuning.idleRounds = 5) and the smaller ones Drop.tla can afford to run with.
SenderPatience == {1, 2, 3}
ReceiverPatience == {1, 2, 3, 5}

States(Impl) == {t[1]: t \in Impl} \cup {t[3]: t \in Impl}

RECURSIVE Closure(_, _)
Closure(S, Impl) == LET N == S \cup {t[3]: t \in {u \in Impl: u[1] \in S}}
                    IN IF N = S THEN S ELSE Closure(N, Impl)

ASSUME SameBeginnings == /\ SenderImplInit = {SenderStart(p): p \in SenderPatience}
                         /\ ReceiverImplInit = {ReceiverStart(p): p \in ReceiverPatience}
ASSUME ImplIsSpec     == /\ \A t \in SenderImpl: SenderStep(t[1], t[2]) = << t[3], t[4] >>
                         /\ \A t \in ReceiverImpl: ReceiverStep(t[1], t[2]) = << t[3], t[4] >>
ASSUME ImplIsClosed   == /\ Closure(SenderImplInit, SenderImpl) = States(SenderImpl)
                         /\ Closure(ReceiverImplInit, ReceiverImpl) = States(ReceiverImpl)
ASSUME ImplIsTotal    == /\ \A x \in States(SenderImpl), e \in SenderEvents: \E t \in SenderImpl: t[1] = x /\ t[2] = e
                         /\ \A x \in States(ReceiverImpl), e \in ReceiverEvents: \E t \in ReceiverImpl: t[1] = x /\ t[2] = e

\* One machine moves at a time; neither knows of the other here.
Init == s \in SenderImplInit /\ r \in ReceiverImplInit
Next == \/ \E e \in SenderEvents: s' = SenderStep(s, e)[1] /\ UNCHANGED r
        \/ \E e \in ReceiverEvents: r' = ReceiverStep(r, e)[1] /\ UNCHANGED s
Spec == Init /\ [][Next]_<< s, r >>

SpecIsImpl == /\ \A e \in SenderEvents: << s, e, SenderStep(s, e)[1], SenderStep(s, e)[2] >> \in SenderImpl
              /\ \A e \in ReceiverEvents: << r, e, ReceiverStep(r, e)[1], ReceiverStep(r, e)[2] >> \in ReceiverImpl

=============================================================================
