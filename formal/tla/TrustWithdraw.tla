--------------------------- MODULE TrustWithdraw ---------------------------
(***************************************************************************)
(* Withdrawing trust in a key, against everything else that is going on:   *)
(* sessions that key authenticated, a session that is just being opened,   *)
(* a disk that may refuse a write, two people pairing the key again, and   *)
(* the app dying at any moment.                                            *)
(*                                                                         *)
(* Every DECISION here is TrustCore.tla's Step, which TLC holds equal to   *)
(* the Swift (TrustRefinement.tla). What this module adds is what a        *)
(* decision is not a function of, and what Trust (the class in             *)
(* Sources/NimbusSecurityCore/Trust.swift) is for: the lock (`locked`),    *)
(* the `afterwards` list, the disk, the order in which what was decided is *)
(* carried out (`perform`), and Trust.commit before a retire notice is     *)
(* acknowledged (the `retire` case of DropListener.serve). That part is    *)
(* tied to the code by reading and by mutants, here and in                 *)
(* scripts/mutate.py.                                                      *)
(*                                                                         *)
(* One key is modelled. ForGood: the withdrawal is a retire notice from    *)
(* the other Mac, answered `retired`; otherwise it is a Forget. A session  *)
(* is a drop or a speed test that key authenticated. Opening one is two    *)
(* steps with the network in between, as in SendSession.open and           *)
(* DropListener.serve: ask the store whether the key is paired, and later  *)
(* tell the store to track the session.                                    *)
(***************************************************************************)
EXTENDS TrustCore

CONSTANTS ForGood,
          Eviction     \* the key's tombstone may be pushed out by two thousand later ones

VARIABLES core,         \* the trust core's state in memory (TrustCore.tla)
          disk,         \* what the trust file says of the key: [known, again, tomb]
          lock,         \* who holds the store's lock: "none", "W"
          sess,         \* each session: "none", "asked", "live", "ended", "refused"
          toEnd,        \* the `afterwards` list: sessions to end once the lock is free
          w,            \* where the withdrawing thread is
          acked,        \* `retired` has been said to the other Mac
          up,           \* the app is running
          pairings      \* how many times two people have paired the key since (ghost; counted to 2)

vars == << core, disk, lock, sess, toEnd, w, acked, up, pairings >>

Persist(c) == [known |-> c.known, again |-> c.again, tomb |-> c.tomb]
Load(d)    == [known |-> d.known, again |-> d.again, tomb |-> d.tomb, tracked |-> {}, unsaved |-> FALSE]

Has(effects, op) == \E i \in 1..Len(effects): effects[i].op = op
Who(effects, op) == IF Has(effects, op) THEN (CHOOSE x \in {effects[i]: i \in 1..Len(effects)}: x.op = op).who ELSE {}

(* The key starts paired, as two people left it. *)
Paired == [Start EXCEPT !.known = "current"]

Init == /\ core = Paired /\ disk = Persist(Paired)
        /\ lock = "none"
        /\ sess = [x \in Sessions |-> "none"]
        /\ toEnd = {}
        /\ w = "idle" /\ acked = FALSE /\ up = TRUE /\ pairings = 0

(* What a step of the core leaves on the disk: the write it asked for, if  *)
(* it asked for one and the disk took it.                                  *)
Written(result, d) == IF Has(result[2], "save") /\ d = "ok" THEN Persist(result[1]) ELSE disk

(* ---- A session being opened ------------------------------------------- *)

\* "Is this key paired?" A moment with the lock, then the handshake and the hellos go on.
Ask(x) == /\ up /\ lock = "none" /\ sess[x] = "none"
          /\ LET r == Step(core, Ev("standing", {}, FALSE, "ok"))
             IN sess' = [sess EXCEPT ![x] = IF r[2][1].op = "paired" THEN "asked" ELSE "refused"]
          /\ UNCHANGED << core, disk, lock, toEnd, w, acked, up, pairings >>

\* "Track this session." With the lock. The core decides: on the list, or ended here and now.
Track(x) == /\ up /\ lock = "none" /\ sess[x] = "asked" /\ x \notin core.tracked
            /\ LET r == Step(core, Ev("track", {x}, FALSE, "ok"))
               IN /\ core' = r[1]
                  /\ sess' = [sess EXCEPT ![x] = IF Has(r[2], "endNew") THEN "ended" ELSE "live"]
            /\ UNCHANGED << disk, lock, toEnd, w, acked, up, pairings >>

\* A session ends by itself (finished, failed, cancelled), and the store drops it at its next tick.
Finish(x) == /\ up /\ sess[x] = "live"
             /\ sess' = [sess EXCEPT ![x] = "ended"]
             /\ UNCHANGED << core, disk, lock, toEnd, w, acked, up, pairings >>

Prune(x) == /\ up /\ lock = "none" /\ x \in core.tracked /\ sess[x] = "ended"
            /\ core' = Step(core, Ev("prune", {x}, FALSE, "ok"))[1]
            /\ UNCHANGED << disk, lock, sess, toEnd, w, acked, up, pairings >>

(* ---- Withdrawing ------------------------------------------------------ *)

\* Takes the lock. The core decides; the file is written with the lock held, and may not
\* reach the disk; the sessions the core named are set down to be ended.
Withdraw == /\ up /\ w = "idle" /\ lock = "none"
            /\ \E d \in Disk:
                 LET r == Step(core, Ev(IF ForGood THEN "retire" ELSE "forget", {}, FALSE, d))
                 IN /\ core' = r[1]
                    /\ disk' = Written(r, d)
                    /\ toEnd' = Who(r[2], "end")
            /\ lock' = "W" /\ w' = "locked"
            /\ UNCHANGED << sess, acked, up, pairings >>

\* The outermost `locked` call lets go; only then is anything that touches a socket done.
Unlock == /\ up /\ w = "locked"
          /\ lock' = "none" /\ w' = "ending"
          /\ UNCHANGED << core, disk, sess, toEnd, acked, up, pairings >>

\* Ending the sessions: closing sockets. Done on the withdrawing thread before its call returns.
EndSessions == /\ up /\ w = "ending"
               /\ sess' = [x \in Sessions |-> IF x \in toEnd /\ sess[x] = "live" THEN "ended" ELSE sess[x]]
               /\ toEnd' = {} /\ w' = "returned"
               /\ UNCHANGED << core, disk, lock, acked, up, pairings >>

\* Trust.commit: written now, or the notice is not acknowledged.
Commit == /\ up /\ w = "returned" /\ lock = "none"
          /\ \E d \in Disk:
               LET r == Step(core, Ev("commit", {}, FALSE, d))
               IN /\ core' = r[1]
                  /\ disk' = Written(r, d)
                  /\ w' = IF d = "ok" THEN "committed" ELSE "silent"
          /\ UNCHANGED << lock, sess, toEnd, acked, up, pairings >>

Ack == /\ up /\ w = "committed" /\ ForGood
       /\ acked' = TRUE /\ w' = "done"
       /\ UNCHANGED << core, disk, lock, sess, toEnd, up, pairings >>

(* ---- Meanwhile -------------------------------------------------------- *)

\* A write that failed is tried again when the timer says so (Trust.tick).
Retry == /\ up /\ lock = "none" /\ core.unsaved
         /\ \E d \in Disk:
              LET r == Step(core, Ev("quiet", {}, TRUE, d))
              IN core' = r[1] /\ disk' = Written(r, d)
         /\ UNCHANGED << lock, sess, toEnd, w, acked, up, pairings >>

\* Two people pair the key again. The core says whether that is possible at all.
PairAgain == /\ up /\ lock = "none"
             /\ \E d \in Disk:
                  LET r == Step(core, Ev("store", {}, FALSE, d))
                  IN /\ core' = r[1] /\ disk' = Written(r, d)
                     /\ pairings' = IF Has(r[2], "save") /\ pairings < 2 THEN pairings + 1 ELSE pairings
             /\ UNCHANGED << lock, sess, toEnd, w, acked, up >>

\* The key's tombstone is the oldest of two thousand and one, and goes. In memory and, when
\* that withdrawal of some other key is written, on the disk.
Evict == /\ Eviction /\ up /\ lock = "none" /\ Enabled(core, Ev("evict", {}, FALSE, "ok"))
         /\ core' = Step(core, Ev("evict", {}, FALSE, "ok"))[1]
         /\ disk' \in {disk, Persist(core')}
         /\ UNCHANGED << lock, sess, toEnd, w, acked, up, pairings >>

(* ---- The app dies, and is started again ------------------------------- *)

Crash == /\ up
         /\ up' = FALSE /\ lock' = "none" /\ w' = "dead"
         /\ sess' = [x \in Sessions |-> IF sess[x] \in {"asked", "live"} THEN "ended" ELSE sess[x]]
         /\ toEnd' = {}
         /\ UNCHANGED << core, disk, acked, pairings >>

Restart == /\ ~up
           /\ up' = TRUE
           /\ core' = Load(disk)
           /\ UNCHANGED << disk, lock, sess, toEnd, w, acked, pairings >>

Next == Withdraw \/ Unlock \/ EndSessions \/ Commit \/ Ack \/ Retry \/ PairAgain \/ Evict \/ Crash \/ Restart
        \/ \E x \in Sessions: Ask(x) \/ Track(x) \/ Finish(x) \/ Prune(x)

Spec == Init /\ [][Next]_vars

TypeOK == /\ core.known \in {"no", "current", "ranOut"} /\ core.again \in {"no", "waiting", "pairedAgain"}
          /\ core.tomb \in {"none", "expired", "forGood"} /\ core.tracked \subseteq Sessions /\ core.unsaved \in BOOLEAN
          /\ acked \in BOOLEAN /\ up \in BOOLEAN /\ toEnd \subseteq Sessions /\ pairings \in 0..2
          /\ lock \in {"none", "W"}
          /\ w \in {"idle", "locked", "ending", "returned", "committed", "silent", "done", "dead"}
          /\ sess \in [Sessions -> {"none", "asked", "live", "ended", "refused"}]

(***************************************************************************)
(* Properties                                                              *)
(***************************************************************************)

\* What the other Mac was told is true for good: the tombstone is on the disk before `retired`
\* is said, so no crash, no restart and no later pairing brings the key back.
AcknowledgedMeansRefusedForGood ==
    acked => disk.tomb = "forGood" /\ disk.known = "no" /\ (up => core.tomb = "forGood" /\ core.known = "no")

\* When the call that withdrew the trust has returned, nothing that key authenticated is
\* still running: not what was running before, and not what was being opened meanwhile.
\* (Unless two people have paired the key again since, which is a new decision.)
NothingOutlivesTheWithdrawal ==
    (w \in {"returned", "committed", "silent", "done"} /\ core.known = "no") => \A x \in Sessions: sess[x] # "live"

\* A session is live only while the store counts the key as paired, or is on its way to ending it.
LiveMeansTrustedOrBeingEnded ==
    up => \A x \in Sessions: sess[x] = "live" => core.known # "no" \/ x \in toEnd

\* And the store knows of every live session, which is what lets a later withdrawal end it.
LiveIsOnTheList ==
    up => \A x \in Sessions: sess[x] = "live" => x \in core.tracked \/ x \in toEnd

\* Nothing that touches a socket is done with the store locked (the review's F7).
NoSocketWorkUnderTheLock == lock = "W" => w = "locked"

\* What the disk has refused for good it refuses for good.
ForGoodOnDiskIsForGood == [][disk.tomb = "forGood" => disk'.tomb = "forGood" /\ disk'.known = "no"]_vars

\* Whatever becomes of its tombstone, a key the running store counts as not paired becomes
\* paired again only by two people pairing it: nothing else brings trust back. (A restart can:
\* it loads the file, and a withdrawal that never reached the file is undone by it. That is
\* the `unsaved` state, which the store reports and retries, and why nothing is acknowledged
\* to another Mac before Trust.commit.)
NoSilentResurrection ==
    [][(up /\ up' /\ core.known = "no" /\ core'.known # "no") => pairings' # pairings \/ pairings = 2]_vars

\* Reachability, to be VIOLATED: a session does go live, and a notice does get acknowledged.
NeverLive  == \A x \in Sessions: sess[x] # "live"
NeverAcked == ~acked

=============================================================================
