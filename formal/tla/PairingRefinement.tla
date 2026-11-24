------------------------- MODULE PairingRefinement -------------------------
(***************************************************************************)
(* The Swift code and its specification are the same machine.              *)
(*                                                                         *)
(* PairingImpl.tla is generated from PairingMachine.swift: every state the *)
(* code reaches, under every event, with what it said to do (and           *)
(* `swift test` fails if the file is not what the code does now).          *)
(* PairingMachine.tla defines Step. This module has TLC check:             *)
(*                                                                         *)
(*   ImplIsSpec       every transition the code makes is the one Step      *)
(*                    defines, effects included;                           *)
(*   SpecIsImpl       at every state the specification reaches, every      *)
(*                    event's transition is one the code makes;            *)
(*   the same four beginnings, and the code's states are exactly those     *)
(*   its own transitions reach from them.                                  *)
(*                                                                         *)
(* So over the abstraction PairingMachine.tla states (values are good,     *)
(* damaged, malformed or wrong; an entry is right or wrong), what is       *)
(* proved of Step in Pairing.tla and PairingSystem.tla is proved of the    *)
(* Swift. What this does NOT cover: that the abstraction is the right one  *)
(* (PairingMachineTests' random walks test that the code's behaviour       *)
(* depends on nothing outside it), and PairingSession, which drives the    *)
(* machine.                                                                *)
(***************************************************************************)
EXTENDS PairingMachine, PairingImpl, FiniteSets

VARIABLE s

ImplStates == {t[1]: t \in Impl} \cup {t[3]: t \in Impl}

RECURSIVE Closure(_)
Closure(S) == LET N == S \cup {t[3]: t \in {u \in Impl: u[1] \in S}}
              IN IF N = S THEN S ELSE Closure(N)

ASSUME SameBeginnings == ImplInit = {Start(r, b): r \in Roles, b \in BOOLEAN}
ASSUME ImplIsSpec     == \A t \in Impl: Step(t[1], t[2]) = << t[3], t[4] >>
ASSUME ImplIsClosed   == Closure(ImplInit) = ImplStates
ASSUME ImplIsTotal    == \A x \in ImplStates, e \in Events: \E t \in Impl: t[1] = x /\ t[2] = e

Init == s \in ImplInit
Next == \E e \in Events: s' = Step(s, e)[1]
Spec == Init /\ [][Next]_s

SpecIsImpl == \A e \in Events: << s, e, Step(s, e)[1], Step(s, e)[2] >> \in Impl

=============================================================================
