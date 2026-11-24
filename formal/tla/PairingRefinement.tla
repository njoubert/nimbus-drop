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
(* What that is worth rests on two things this module cannot see. The      *)
(* header of PairingMachine.tla (THE ABSTRACTION CONTRACT) states both,    *)
(* and says what holds each:                                               *)
(*                                                                         *)
(*   - PairingImpl.tla has ONE machine for each state, with one handshake  *)
(*     hash, one value from each side and one identity number. It speaks   *)
(*     for every machine in that state only if what the code does depends  *)
(*     on the state and the event and on nothing else (CONGRUENCE). The    *)
(*     part of the code that decides is handed no value (argued, from its  *)
(*     types), and many machines for each state are held to this relation  *)
(*     (explored at random, bounded).                                      *)
(*   - Effects are compared here by NAME. What "send commit" sends and     *)
(*     which code "codes" shows is checked in PairingMachineTests, at      *)
(*     every step, against the protocol written a second time (PAYLOADS).  *)
(*                                                                         *)
(* So, over that abstraction, what is proved of Step in Pairing.tla and    *)
(* PairingSystem.tla is proved of Control.step, the Swift function that    *)
(* decides, by enumeration; and of whole machines as far as the argument   *)
(* is read and the walks went. Not covered at all: PairingSession, which   *)
(* drives the machine (the contract says what it stores, by reading).      *)
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
