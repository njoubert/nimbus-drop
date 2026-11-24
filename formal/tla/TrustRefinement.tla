-------------------------- MODULE TrustRefinement --------------------------
(***************************************************************************)
(* The Swift trust core and its specification are the same machine.        *)
(*                                                                         *)
(* TrustImpl.tla is generated from TrustCore.swift (`swift test` fails if  *)
(* the file is not what the code does now): what the code does to one key  *)
(* in every state it reaches, under every event that can happen there,     *)
(* and its two pieces of arithmetic on a grid. TrustCore.tla defines Step, *)
(* Enabled, Count and SaveDue. This module has TLC check:                  *)
(*                                                                         *)
(*   ImplIsSpec       every transition the code makes is the one Step      *)
(*                    defines, effects included, and is of an event the    *)
(*                    specification allows in that state;                  *)
(*   SpecIsImpl       at every state the specification reaches, every      *)
(*                    event it allows is a transition the code makes;      *)
(*   the same beginning, and the code's states are exactly those its own   *)
(*   transitions reach from it;                                            *)
(*   CountIsCount, SaveDueIsSaveDue   the arithmetic agrees at every point *)
(*                    of the grid.                                         *)
(*                                                                         *)
(* So over the abstraction TrustCore.tla states, what is proved of Step in *)
(* TrustWithdraw.tla and Expiry.tla is proved of the Swift core. What this *)
(* does NOT cover: that the abstraction is the right one (TrustCoreTests'  *)
(* random walks test that what the code does to the key depends on nothing *)
(* outside it, through clocks that jump, reboot and run backwards); that a *)
(* grid of small numbers speaks for all numbers; and Trust, the class      *)
(* that holds the lock and the disk and carries out what the core decides. *)
(***************************************************************************)
EXTENDS TrustCore, TrustImpl

VARIABLE s

ImplStates == {t[1]: t \in Impl} \cup {t[3]: t \in Impl}

RECURSIVE Closure(_)
Closure(S) == LET N == S \cup {t[3]: t \in {u \in Impl: u[1] \in S}}
              IN IF N = S THEN S ELSE Closure(N)

ASSUME SameBeginning  == ImplInit = {Start}
ASSUME ImplIsSpec     == \A t \in Impl: Enabled(t[1], t[2]) /\ Step(t[1], t[2]) = << t[3], t[4] >>
ASSUME ImplIsClosed   == Closure(ImplInit) = ImplStates
ASSUME ImplIsTotal    == \A x \in ImplStates, e \in Events: Enabled(x, e) => \E t \in Impl: t[1] = x /\ t[2] = e
ASSUME CountIsCount   == \A t \in CountTable: Count(t[1], t[2], t[3], t[4], t[5], t[6]) = t[7]
ASSUME SaveDueIsSaveDue == \A t \in SaveDueTable: SaveDue(t[1], t[2], t[3], t[4]) = t[5]

Init == s \in ImplInit
Next == \E e \in Events: Enabled(s, e) /\ s' = Step(s, e)[1]
Spec == Init /\ [][Next]_s

SpecIsImpl == \A e \in Events: Enabled(s, e) => << s, e, Step(s, e)[1], Step(s, e)[2] >> \in Impl

=============================================================================
