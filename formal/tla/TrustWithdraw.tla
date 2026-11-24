--------------------------- MODULE TrustWithdraw ---------------------------
(***************************************************************************)
(* Withdrawing trust in a key, against everything else that is going on:   *)
(* sessions that key authenticated, a session that is just being opened,   *)
(* a disk that may refuse a write, and the app dying at any moment.        *)
(*                                                                         *)
(* The code: Trust.withdrawLocked, Trust.locked (the `afterwards` list),   *)
(* Trust.track, Trust.commit (Sources/NimbusSecurityCore/Trust.swift), and *)
(* the `retire` case of DropListener.serve, which acknowledges a retire    *)
(* notice only after all of it.                                            *)
(*                                                                         *)
(* One key is modelled: the one being withdrawn (a retire notice from the  *)
(* other Mac, which is answered `retired`; Forget is the same without the  *)
(* answer). A session is a drop or a speed test that key authenticated.    *)
(* Opening one is two steps with the network in between, as in             *)
(* SendSession.open and DropListener.serve: ask the store whether the key  *)
(* is paired, and later tell the store to track the session.               *)
(***************************************************************************)
EXTENDS Naturals, FiniteSets

CONSTANTS Sessions,         \* sessions the key may open
          TrackChecks       \* Trust.track refuses a key that is no longer paired (TRUE in the code)

VARIABLES trusted,      \* in memory: the key is paired
          tomb,         \* in memory: the key is refused for good
          disk,         \* what the trust file says: [trusted, tomb]
          lock,         \* who holds the store's lock: "none", "W"
          sess,         \* each session: "none", "asked", "live", "ended", "refused"
          tracked,      \* sessions the store knows of
          toEnd,        \* the `afterwards` list: sessions to end once the lock is free
          w,            \* where the withdrawing thread is
          acked,        \* `retired` has been said to the other Mac
          up            \* the app is running

vars == << trusted, tomb, disk, lock, sess, tracked, toEnd, w, acked, up >>

Init == /\ trusted = TRUE /\ tomb = FALSE
        /\ disk = [trusted |-> TRUE, tomb |-> FALSE]
        /\ lock = "none"
        /\ sess = [s \in Sessions |-> "none"]
        /\ tracked = {} /\ toEnd = {}
        /\ w = "idle" /\ acked = FALSE /\ up = TRUE

(* ---- A session being opened ------------------------------------------- *)

\* "Is this key paired?" A moment with the lock, then the handshake and the hellos go on.
Ask(s) == /\ up /\ lock = "none" /\ sess[s] = "none"
          /\ sess' = [sess EXCEPT ![s] = IF trusted THEN "asked" ELSE "refused"]
          /\ UNCHANGED << trusted, tomb, disk, lock, tracked, toEnd, w, acked, up >>

\* "Track this session." With the lock: a key that has stopped being paired since it was asked
\* about gets no session; the session ends there. Without that check (as the code was until
\* this model was run against it) the session lives on, known to a store that will never be
\* asked to end it again.
Track(s) == /\ up /\ lock = "none" /\ sess[s] = "asked"
            /\ IF trusted \/ ~TrackChecks
                  THEN /\ sess' = [sess EXCEPT ![s] = "live"]
                       /\ tracked' = tracked \cup {s}
                  ELSE /\ sess' = [sess EXCEPT ![s] = "ended"]
                       /\ UNCHANGED tracked
            /\ UNCHANGED << trusted, tomb, disk, lock, toEnd, w, acked, up >>

\* A session ends by itself (finished, failed, cancelled).
Finish(s) == /\ up /\ sess[s] = "live"
             /\ sess' = [sess EXCEPT ![s] = "ended"]
             /\ UNCHANGED << trusted, tomb, disk, lock, tracked, toEnd, w, acked, up >>

(* ---- Withdrawing ------------------------------------------------------ *)

\* Takes the lock. In memory the key is refused from here; the write may or may not reach the
\* disk; the sessions it authenticated leave the list and are set down to be ended.
Withdraw == /\ up /\ w = "idle" /\ lock = "none"
            /\ lock' = "W"
            /\ trusted' = FALSE /\ tomb' = TRUE
            /\ \/ disk' = [trusted |-> FALSE, tomb |-> TRUE]
               \/ UNCHANGED disk                              \* the disk is full
            /\ toEnd' = tracked /\ tracked' = {}
            /\ w' = "locked"
            /\ UNCHANGED << sess, acked, up >>

\* The outermost `locked` call lets go; only then is anything that touches a socket done.
Unlock == /\ up /\ w = "locked"
          /\ lock' = "none" /\ w' = "ending"
          /\ UNCHANGED << trusted, tomb, disk, sess, tracked, toEnd, acked, up >>

\* Ending the sessions: closing sockets. Done on the withdrawing thread before its call returns.
EndSessions == /\ up /\ w = "ending"
               /\ sess' = [s \in Sessions |-> IF s \in toEnd /\ sess[s] = "live" THEN "ended" ELSE sess[s]]
               /\ toEnd' = {} /\ w' = "returned"
               /\ UNCHANGED << trusted, tomb, disk, lock, tracked, acked, up >>

\* Trust.commit: written now, or the notice is not acknowledged.
Commit == /\ up /\ w = "returned" /\ lock = "none"
          /\ \/ disk' = [trusted |-> trusted, tomb |-> tomb] /\ w' = "committed"
             \/ UNCHANGED disk /\ w' = "silent"               \* could not be written: say nothing
          /\ UNCHANGED << trusted, tomb, lock, sess, tracked, toEnd, acked, up >>

Ack == /\ up /\ w = "committed"
       /\ acked' = TRUE /\ w' = "done"
       /\ UNCHANGED << trusted, tomb, disk, lock, sess, tracked, toEnd, up >>

(* ---- The app dies, and is started again ------------------------------- *)

Crash == /\ up
         /\ up' = FALSE /\ lock' = "none" /\ w' = "dead"
         /\ sess' = [s \in Sessions |-> IF sess[s] \in {"asked", "live"} THEN "ended" ELSE sess[s]]
         /\ tracked' = {} /\ toEnd' = {}
         /\ UNCHANGED << trusted, tomb, disk, acked >>

Restart == /\ ~up
           /\ up' = TRUE
           /\ trusted' = disk.trusted /\ tomb' = disk.tomb
           /\ UNCHANGED << disk, lock, sess, tracked, toEnd, w, acked >>

Next == Withdraw \/ Unlock \/ EndSessions \/ Commit \/ Ack \/ Crash \/ Restart
        \/ \E s \in Sessions: Ask(s) \/ Track(s) \/ Finish(s)

Spec == Init /\ [][Next]_vars

TypeOK == /\ trusted \in BOOLEAN /\ tomb \in BOOLEAN /\ acked \in BOOLEAN /\ up \in BOOLEAN
          /\ lock \in {"none", "W"}
          /\ w \in {"idle", "locked", "ending", "returned", "committed", "silent", "done", "dead"}
          /\ sess \in [Sessions -> {"none", "asked", "live", "ended", "refused"}]

(***************************************************************************)
(* Properties                                                              *)
(***************************************************************************)

\* What the other Mac was told is true for good: the tombstone is on the disk before `retired`
\* is said, so no crash and no restart brings the key back.
AcknowledgedMeansRefusedForGood == acked => disk.tomb /\ ~disk.trusted /\ (up => tomb /\ ~trusted)

\* When the call that withdrew the trust has returned, nothing that key authenticated is
\* still running: not what was running before, and not what was being opened meanwhile.
NothingOutlivesTheWithdrawal ==
    w \in {"returned", "committed", "silent", "done"} => \A s \in Sessions: sess[s] # "live"

\* A session is live only while the store counts the key as paired, or is on its way to ending it.
LiveMeansTrustedOrBeingEnded ==
    \A s \in Sessions: sess[s] = "live" => trusted \/ s \in toEnd

\* Nothing that touches a socket is done with the store locked (the review's F7).
NoSocketWorkUnderTheLock == lock = "W" => w = "locked"

=============================================================================
