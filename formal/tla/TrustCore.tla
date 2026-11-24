----------------------------- MODULE TrustCore -----------------------------
(***************************************************************************)
(* What the trust store decides about one key, as a function:              *)
(*                                                                         *)
(*     Step(state, event) = << state', effects >>                          *)
(*                                                                         *)
(* The code: TrustCore (Sources/NimbusCrypto/TrustCore.swift), which is    *)
(* pure. TrustCoreTests writes that code's transitions out as              *)
(* TrustImpl.tla, and TrustRefinement.tla has TLC check them EQUAL to      *)
(* this Step. TrustWithdraw.tla and Expiry.tla prove their properties of   *)
(* this Step, with the lock, the disk, the clocks and the sessions around  *)
(* it.                                                                     *)
(*                                                                         *)
(* THE ABSTRACTION. One key K, other than this Mac's own. Of the store:    *)
(*                                                                         *)
(*   known    "no"       K is not on the Known list                        *)
(*            "current"  it is, and its elapsed end is ahead               *)
(*            "ranOut"   it is, and its elapsed end has passed             *)
(*   again    "no" / "waiting" / "pairedAgain": K's entry on the           *)
(*            pair-again list                                              *)
(*   tomb     "none" / "expired" / "forGood": K's tombstone, by reason     *)
(*   tracked  the sessions the store knows K to have authenticated         *)
(*   unsaved  the last write of the file failed                            *)
(*                                                                         *)
(* Names, dates, counts and every other key are abstracted away.           *)
(*                                                                         *)
(* An event is [e, who, due, disk]. `who`: the session tracked or pruned;  *)
(* for a tick, the sessions still waiting for a person's yes. `disk`:      *)
(* whether a write made in this step reaches the disk ("ok") or not        *)
(* ("full"); the store learns that at once, as Trust.perform has it.       *)
(*                                                                         *)
(* Time is abstracted to WHAT a tick finds, which is the event's name:     *)
(*                                                                         *)
(*   quiet   nothing runs out                                              *)
(*   k       K's end, counted in elapsed time, passes at this tick         *)
(*   wallK   K's calendar date passes at this tick; its elapsed end has    *)
(*           not                                                           *)
(*   late    the time allowed to K's sessions after its end passes at      *)
(*           this tick (K's elapsed end with it, if it had not already)    *)
(*                                                                         *)
(* and `due`: the timer says the file should be written (an hour since it  *)
(* was, or thirty seconds since a write failed). It is recorded only where *)
(* it decides anything: on a tick that changes nothing.                    *)
(*                                                                         *)
(* Which of these a pair of clock readings amounts to is arithmetic, and   *)
(* is not in Step: it is Count and SaveDue below (the code's               *)
(* TrustCore.count and TrustCore.saveDue, checked as tables by             *)
(* TrustRefinement) and the comparisons Expiry.tla makes with them.        *)
(*                                                                         *)
(* The store keeps a bounded number of tombstones (2000), and the oldest   *)
(* goes when another is made. That is the event "evict": K's tombstone is  *)
(* pushed out by other keys' withdrawals. After it K is an unknown key:    *)
(* nothing trusts it, and nothing but two people pairing it afresh can     *)
(* change that. So "refused for good" means: for as long as the tombstone  *)
(* is among the newest 2000 (TrustWithdraw.tla has the run that shows it). *)
(* One case of it is left out, and TrustCoreTests found why: a key that is *)
(* on neither list while a session of its old pairing is still running out *)
(* its day of grace. If its tombstone went THEN and two people paired it   *)
(* again, that session would keep a deadline that has nothing to do with   *)
(* the new pairing's end, which this abstraction cannot say. It would take *)
(* two thousand withdrawals inside that one day; the code then lets the    *)
(* old session run to its old deadline and ends it, which is harmless.     *)
(*                                                                         *)
(* NOT in this machine: this Mac's own key running out on schedule (it     *)
(* shares `rotate` with "reset", which is), setLifetime, names.            *)
(***************************************************************************)
EXTENDS Naturals, FiniteSets, Sequences

Sessions == {"s1", "s2"}
Disk == {"ok", "full"}

Eff(op, who) == [op |-> op, who |-> who]
Ev(e, who, due, disk) == [e |-> e, who |-> who, due |-> due, disk |-> disk]

Simple == {"standing", "retire", "forget", "replaced", "gone", "store", "removeAgain", "reset", "commit", "evict"}
TickKinds == {"quiet", "k", "wallK", "late"}

Events == {Ev(e, {}, FALSE, d): e \in Simple, d \in Disk}
          \cup {Ev(e, {x}, FALSE, d): e \in {"track", "prune"}, x \in Sessions, d \in Disk}
          \cup {Ev(k, W, b, d): k \in TickKinds, W \in SUBSET Sessions, b \in BOOLEAN, d \in Disk}

Start == [known |-> "no", again |-> "no", tomb |-> "none", tracked |-> {}, unsaved |-> FALSE]

(* What K is to this Mac: Trust.standing(of:). *)
Standing(s) ==
    IF s.tomb = "forGood" THEN "retired"
    ELSE IF s.known = "current" THEN "paired"
    ELSE IF s.known = "ranOut" THEN "expired"
    ELSE IF s.tomb = "expired" THEN "retired"
    ELSE IF s.again = "waiting" THEN "renew"
    ELSE "unknown"

MayPair(s) == Standing(s) \in {"paired", "renew", "unknown"}

(* K's elapsed end passes at a "k" or a "late" tick, or passed before.     *)
RunsOutNow(s) == s.known = "current" \/ s.again # "no"

(* K ran out, is still on the Known list, and its tombstone was pushed     *)
(* out: the next tick, of whatever kind, makes it another.                 *)
Untombed(s) == s.known = "ranOut" /\ s.tomb = "none"

(* An event that cannot happen in a state: a session tracked twice, a tick *)
(* that finds K's end passing when K has none ahead. And `due` is recorded *)
(* only on a tick that changes nothing.                                    *)
Enabled(s, ev) ==
    CASE ev.e = "track" -> ev.who \cap s.tracked = {}
      [] ev.e = "prune" -> ev.who \subseteq s.tracked
      [] ev.e \in TickKinds ->
            /\ ev.who \subseteq s.tracked
            /\ CASE ev.e = "quiet" -> ev.due => ~Untombed(s)
                 [] ev.e = "k"     -> ~ev.due /\ (s.known = "current" \/ (s.known = "no" /\ s.again # "no"))
                 [] ev.e = "wallK" -> ~ev.due /\ s.known = "current"
                 [] ev.e = "late"  -> s.tracked # {} /\ (ev.due => ~(RunsOutNow(s) \/ Untombed(s)))
      [] ev.e = "evict" -> s.tomb # "none" /\ ~(s.known = "no" /\ s.tracked # {})
      [] OTHER -> TRUE

(* Every withdrawal of trust: the key is refused from here, what it had    *)
(* authenticated leaves the list to be ended, the listeners are to be      *)
(* told. Written to disk first.                                            *)
Withdrawn(s, forGood) ==
    [s EXCEPT !.known = "no", !.again = "no", !.tracked = {},
              !.tomb = IF forGood THEN "forGood" ELSE @]

WithdrawEffects(s) == << Eff("save", {}), Eff("end", s.tracked), Eff("tell", {}), Eff("changed", {}) >>

(* K's elapsed end passes: refused for good from here, on whichever list   *)
(* it was.                                                                 *)
RunOut(s) ==
    [s EXCEPT !.known = IF @ = "current" THEN "ranOut" ELSE @,
              !.again = "no",
              !.tomb = IF RunsOutNow(s) /\ @ = "none" THEN "expired" ELSE @]

(* A session that has not begun does not begin under a pairing that is     *)
(* over (the review's F6).                                                 *)
Unbegun(s, waiting) ==
    IF s.known # "current" /\ (s.tracked \cap waiting) # {} THEN << Eff("endUnbegun", s.tracked \cap waiting) >> ELSE << >>

(* What is decided, before the disk has its say. *)
Decide(s, ev) ==
    LET e == ev.e IN
    IF e = "standing" THEN << s, << Eff(Standing(s), {}) >> >>

    \* Trust.track: the question and the registration are one decision.
    ELSE IF e = "track" THEN
        IF s.known # "no" THEN << [s EXCEPT !.tracked = @ \cup ev.who], << >> >>
        ELSE << s, << Eff("endNew", ev.who) >> >>
    ELSE IF e = "prune" THEN << [s EXCEPT !.tracked = @ \ ev.who], << >> >>

    ELSE IF e = "retire" THEN << Withdrawn(s, TRUE), WithdrawEffects(s) >>
    ELSE IF e = "forget" THEN << Withdrawn(s, FALSE), WithdrawEffects(s) >>
    \* Another key was paired in K's place.
    ELSE IF e = "replaced" THEN
        IF s.known # "no" THEN << Withdrawn(s, TRUE), WithdrawEffects(s) >>
        ELSE << s, << Eff("save", {}), Eff("changed", {}) >> >>
    \* K proved itself and said it no longer has this Mac paired.
    ELSE IF e = "gone" THEN
        IF s.known = "current" THEN << [Withdrawn(s, FALSE) EXCEPT !.again = "waiting"], WithdrawEffects(s) >>
        ELSE << s, << >> >>

    \* Two people have paired K.
    ELSE IF e = "store" THEN
        IF MayPair(s) THEN << [s EXCEPT !.known = "current", !.again = IF @ = "no" THEN "no" ELSE "pairedAgain"],
                              << Eff("save", {}), Eff("changed", {}) >> >>
        ELSE << s, << Eff("refused", {}) >> >>
    \* Remove, on the pair-again list. A Mac that is only there is forgotten, and what it still
    \* had running ends; one that was paired again since just loses the old entry.
    ELSE IF e = "removeAgain" THEN
        IF s.known # "no" THEN << [s EXCEPT !.again = "no"], << Eff("save", {}), Eff("changed", {}) >> >>
        ELSE << Withdrawn(s, FALSE), WithdrawEffects(s) >>

    \* Reset Identity: this Mac's key is replaced; a current K is to be paired again; whatever
    \* K had authenticated ends, whichever list K is on or none.
    ELSE IF e = "reset" THEN
        IF s.known # "no" \/ s.again # "no" \/ s.tracked # {}
            THEN << [s EXCEPT !.known = "no", !.again = IF s.known = "current" THEN "waiting" ELSE @, !.tracked = {},
                              \* A key that had run out leaves its tombstone behind, made again if it was pushed out.
                              !.tomb = IF Untombed(s) THEN "expired" ELSE @],
                    << Eff("save", {}), Eff("end", s.tracked), Eff("tell", {}), Eff("changed", {}) >> >>
            ELSE << s, << Eff("save", {}), Eff("changed", {}) >> >>

    \* Trust.commit: written now, for what is about to be acknowledged to another Mac.
    ELSE IF e = "commit" THEN << s, << Eff("save", {}) >> >>

    \* K's tombstone is the oldest of too many, and goes. Nothing is said or written for K.
    ELSE IF e = "evict" THEN << [s EXCEPT !.tomb = "none"], << >> >>

    \* Time passing.
    ELSE IF e = "quiet" THEN
        IF Untombed(s) THEN << [s EXCEPT !.tomb = "expired"], << Eff("save", {}) >> \o Unbegun(s, ev.who) \o << Eff("changed", {}) >> >>
        ELSE << s, (IF ev.due THEN << Eff("save", {}) >> ELSE << >>) \o Unbegun(s, ev.who) >>
    ELSE IF e = "k" THEN
        LET t == RunOut(s) IN << t, << Eff("save", {}) >> \o Unbegun(t, ev.who) \o << Eff("changed", {}) >> >>
    \* The calendar alone ends the pairing and no more: K is to be paired again (F3).
    ELSE IF e = "wallK" THEN
        LET t == [s EXCEPT !.known = "no", !.again = "waiting"]
        IN << t, << Eff("save", {}) >> \o Unbegun(t, ev.who) \o << Eff("changed", {}) >> >>
    ELSE IF e = "late" THEN
        LET changed == RunsOutNow(s) \/ Untombed(s)
            t == [RunOut(s) EXCEPT !.tracked = {}, !.tomb = IF Untombed(s) THEN "expired" ELSE @]
        IN << t, (IF changed \/ ev.due THEN << Eff("save", {}) >> ELSE << >>) \o << Eff("endLate", s.tracked) >>
                  \o (IF changed THEN << Eff("changed", {}) >> ELSE << >>) >>
    ELSE << s, << >> >>

(* And then the disk: a write that was asked for either holds or does not, *)
(* and the store knows which before anything else happens.                 *)
Step(s, ev) ==
    LET d == Decide(s, ev)
        saves == \E i \in 1..Len(d[2]): d[2][i].op = "save"
        full == ev.disk = "full"
    IN IF saves THEN << [d[1] EXCEPT !.unsaved = full], d[2] \o (IF s.unsaved # full THEN << Eff("changed", {}) >> ELSE << >>) >>
       ELSE d

(***************************************************************************)
(* The arithmetic of time, as the code does it.                            *)
(***************************************************************************)
Max(a, b) == IF a > b THEN a ELSE b
Monus(a, b) == IF a > b THEN a - b ELSE 0

(* TrustCore.count: the seconds counted so far. Same boot: the continuous  *)
(* clock is exact. After a reboot: at least the time since boot, and the   *)
(* calendar's gap if that is more. Never less than before.                 *)
Count(elapsed, sameBoot, lastContinuous, continuous, lastWall, wall) ==
    elapsed + (IF sameBoot THEN Monus(continuous, lastContinuous) ELSE Max(continuous, Monus(wall, lastWall)))

(* TrustCore.saveDue: whether the file is written at this tick.            *)
SaveDue(changed, unsaved, sinceSave, sinceTry) ==
    changed \/ (sinceTry >= 30 /\ (unsaved \/ sinceSave > 3600))

=============================================================================
