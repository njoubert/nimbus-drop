------------------------ MODULE AdmissionRefinement ------------------------
(***************************************************************************)
(* The Swift code and its specification are the same machine.              *)
(*                                                                         *)
(* AdmissionImpl.tla is generated from Admission.swift: every state the    *)
(* code reaches from an empty listener, under every event, with what it    *)
(* answered (and `swift test` fails if the file is not what the code does  *)
(* now). It holds four walks, each at its own small set of limits: `Pools` *)
(* (three places for strangers and two an address, a pool of data          *)
(* connections that grows with the drops in progress), `Rate` (three       *)
(* arrivals a window and two from one address, a clock that moves forward  *)
(* and back), `Keys` (three places for keys nobody paired and two an       *)
(* address, some having asked) and `Waiting` (two paired keys).            *)
(* Admission.tla defines Step. For the walk named by Walk, this module has *)
(* TLC check:                                                              *)
(*                                                                         *)
(*   ImplIsSpec       every transition the code makes is the one Step      *)
(*                    defines, answer included;                            *)
(*   SpecIsImpl       at every state the specification reaches, every      *)
(*                    event's transition is one the code makes;            *)
(*   the same beginning (an empty listener), the same events in every      *)
(*   state, and the code's states are exactly those its own transitions    *)
(*   reach from the beginning.                                             *)
(*                                                                         *)
(* So at those limits, and over the abstraction Admission.tla states       *)
(* (a connection is its place in a pool; time is a gap in whole ticks),    *)
(* what is checked of Step in AdmissionSystem.tla is checked of the Swift. *)
(* What this does NOT cover: other limits (the ones the listener runs      *)
(* with are 64, 8, 500 and 200: the code is the same lines whatever the    *)
(* numbers, which is by reading), that the abstraction is the right one    *)
(* (the contract is at the top of Admission.tla, and AdmissionTests' walks *)
(* at random test that the code's behaviour depends on nothing it leaves   *)
(* out), and DropListener, which drives the machine.                       *)
(***************************************************************************)
EXTENDS Integers, Sequences, FiniteSets, AdmissionImpl

CONSTANT Walk     \* "Pools", "Rate", "Keys" or "Waiting"

W == CASE Walk = "Pools" -> [limits |-> PoolsLimits, states |-> PoolsStates, events |-> PoolsEvents, answers |-> PoolsAnswers, steps |-> PoolsSteps]
       [] Walk = "Rate" -> [limits |-> RateLimits, states |-> RateStates, events |-> RateEvents, answers |-> RateAnswers, steps |-> RateSteps]
       [] Walk = "Keys" -> [limits |-> KeysLimits, states |-> KeysStates, events |-> KeysEvents, answers |-> KeysAnswers, steps |-> KeysSteps]
       [] OTHER -> [limits |-> WaitingLimits, states |-> WaitingStates, events |-> WaitingEvents, answers |-> WaitingAnswers, steps |-> WaitingSteps]
L == W.limits

M == INSTANCE Admission WITH
        Addresses <- L.addresses, Keys <- L.keys, Gaps <- L.gaps, Drops <- L.drops,
        Strangers <- L.strangers, StrangersPerAddress <- L.strangersPerAddress,
        Arrivals <- L.arrivals, ArrivalsPerAddress <- L.arrivalsPerAddress, Window <- L.window,
        UnattachedPerDrop <- L.unattachedPerDrop, UnattachedPerAddress <- L.unattachedPerAddress,
        Unpaired <- L.unpaired, UnpairedPerAddress <- L.unpairedPerAddress, PairedWaiting <- L.pairedWaiting

VARIABLE s

Numbers == 1..Len(W.states)

\* What each event did in the i-th state: << event, state after, answer >>, as numbers. (The file
\* has them three numbers a step, one step after another.)
Rows == [i \in Numbers |-> {<< W.steps[i][3 * k - 2], W.steps[i][3 * k - 1], W.steps[i][3 * k] >> : k \in 1..(Len(W.steps[i]) \div 3)}]

\* The code's transitions: << state, event, state after, answer >>.
Impl == UNION {{<< W.states[i], W.events[t[1]], W.states[t[2]], W.answers[t[3]] >> : t \in Rows[i]} : i \in Numbers}
ImplStates == {W.states[i] : i \in Numbers}

\* The states reached from the first through the code's own transitions, as numbers.
RECURSIVE Closure(_)
Closure(S) == LET N == S \cup UNION {{t[2] : t \in Rows[i]} : i \in S}
              IN IF N = S THEN S ELSE Closure(N)

ASSUME WalkIsNamed    == Walk \in {"Pools", "Rate", "Keys", "Waiting"}
ASSUME OneRowAState   == Len(W.steps) = Len(W.states) /\ Cardinality(ImplStates) = Len(W.states)
ASSUME SameBeginning  == W.states[1] = M!Start
ASSUME ImplIsSpec     == \A t \in Impl: M!Step(t[1], t[2]) = << t[3], t[4] >>
ASSUME ImplIsClosed   == Closure({1}) = Numbers
ASSUME SameEvents     == \A i \in Numbers: /\ {W.events[t[1]] : t \in Rows[i]} = M!Events(W.states[i])
                                           /\ Len(W.steps[i]) = 3 * Cardinality(M!Events(W.states[i]))

Init == s = M!Start
Next == \E e \in M!Events(s): s' = M!Step(s, e)[1]
Spec == Init /\ [][Next]_s

SpecIsImpl == \A e \in M!Events(s): << s, e, M!Step(s, e)[1], M!Step(s, e)[2] >> \in Impl

=============================================================================
