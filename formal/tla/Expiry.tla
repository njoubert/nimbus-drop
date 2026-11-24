------------------------------- MODULE Expiry -------------------------------
(***************************************************************************)
(* A key's end, against clocks that lie.                                   *)
(*                                                                         *)
(* A pairing lasts until its key's end. The end is counted on this Mac's   *)
(* own elapsed-time counter, which Trust.tick advances from three clocks:  *)
(* the boot session, the continuous clock (runs through sleep, cannot be   *)
(* set) and the calendar (which anyone who controls a time server can      *)
(* set). The count is kept in the trust file and written down now and      *)
(* then. This model lets real time pass, lets the calendar be set to       *)
(* anything at any moment, lets the Mac be restarted and rebooted without  *)
(* warning, and asks what a pairing's end is then worth.                   *)
(*                                                                         *)
(* What is decided at a tick, a pairing or the start of a session is       *)
(* TrustCore.tla's Step, and the counting is its Count: both held equal to *)
(* the Swift by TrustRefinement.tla. What this module adds, by reading     *)
(* TrustCore.tick and TrustCore.store: which event a pair of clock         *)
(* readings amounts to (three comparisons), and how the two ends of a      *)
(* pairing are set (two `min`s). Each has a mutant in formal/check.py.     *)
(*                                                                         *)
(* Real time is in whole units. Life, Grace and Hour are the code's 90     *)
(* days (or what the other Mac said it had left), one day, and one hour,   *)
(* shrunk. This Mac's own key does not run out here.                       *)
(*                                                                         *)
(* WHAT HOLDS, AND WHAT DOES NOT. Time the Mac is switched off is not      *)
(* counted unless the calendar says so (CLAUDE.md says as much). And the   *)
(* model shows one thing more, which was not written down before: the      *)
(* count is on the disk only as of the last write, which is up to an hour  *)
(* behind (TheFileIsLessThanAnHourBehind). So an unclean reboot under a    *)
(* calendar that is being held back loses the up-time since that write:    *)
(* under an hour each time, and all of it for someone who can both hold    *)
(* the calendar and cut the power more often than hourly. `lost` is that   *)
(* time, and every property below is stated net of it. With an honest      *)
(* calendar nothing is lost (HonestCalendar = TRUE: lost stays 0).         *)
(***************************************************************************)
EXTENDS TrustCore

CONSTANTS Life,            \* how long a pairing's key lasts
          Grace,           \* how long a running session may go on after its key's end
          Hour,            \* how often the count is written down
          MaxUp,           \* real time the Mac is up, in all (the bound of the model)
          MaxWall,         \* the calendar reads 0..MaxWall
          MaxBoots,        \* unclean reboots
          HonestCalendar   \* the calendar follows real time

VARIABLES upTime,     \* real time this Mac has been up since the store was made
          c,          \* the continuous clock: time since this boot
          boot,       \* the boot session
          wall,       \* the calendar, as the Mac reads it
          mem,        \* the count in memory: [elapsed, lastBoot, lastC, lastWall, lastSave]
          core,       \* the trust core's state in memory (TrustCore.tla)
          ends,       \* the key's ends in memory: [e, w], and its sessions' deadline [d]
          disk,       \* the trust file: [mem, core, ends], and as ghosts [up, lost] when it was written
          fresh,      \* a tick has been made since anything last happened
          asked,      \* a session has asked whether the key is paired, and was told yes
          lost,       \* up-time that no clock this Mac can trust accounts for (ghost)
          born,       \* [up, lost] when the pairing's end was set (ghost)
          ranOut      \* the count has reached the key's end (ghost)

vars == << upTime, c, boot, wall, mem, core, ends, disk, fresh, asked, lost, born, ranOut >>

Min(a, b) == IF a < b THEN a ELSE b
Persisted(k) == [known |-> k.known, again |-> k.again, tomb |-> k.tomb]
Loaded(d) == [known |-> d.known, again |-> d.again, tomb |-> d.tomb, tracked |-> {}, unsaved |-> FALSE]
Saves(effects) == \E i \in 1..Len(effects): effects[i].op = "save"

Init == /\ upTime = 0 /\ c = 0 /\ boot = 0 /\ wall = 0
        /\ mem = [elapsed |-> 0, lastBoot |-> 0, lastC |-> 0, lastWall |-> 0, lastSave |-> 0]
        /\ core = Start
        /\ ends = [e |-> 0, w |-> 0, d |-> 0]
        /\ disk = [mem |-> mem, core |-> Persisted(Start), ends |-> ends, up |-> 0, lost |-> 0]
        /\ fresh = TRUE /\ asked = FALSE /\ lost = 0 /\ born = [up |-> 0, lost |-> 0] /\ ranOut = FALSE

Listed(k) == k.known # "no" \/ k.again # "no"

(* ---- Time, and whoever sets the calendar ------------------------------ *)

Pass == /\ upTime < MaxUp
        /\ upTime' = upTime + 1 /\ c' = c + 1
        /\ wall' \in IF HonestCalendar THEN {Min(wall + 1, MaxWall)} ELSE 0..MaxWall
        /\ fresh' = FALSE
        /\ UNCHANGED << boot, mem, core, ends, disk, asked, lost, born, ranOut >>

(* ---- Trust.tick ------------------------------------------------------- *)

\* What the tick finds, by the three comparisons TrustCore.tick makes.
Counted    == Count(mem.elapsed, boot = mem.lastBoot, mem.lastC, c, mem.lastWall, wall)
Ahead      == core.known = "current" \/ (core.known = "no" /\ core.again # "no")
EndPasses  == Ahead /\ Counted >= ends.e
\* The same thing, for the ghost below: stated twice so that a model in which the tick takes
\* something else for the end of a key cannot also fool the property about it.
TheCountReachesTheEnd == (core.known = "current" \/ (core.known = "no" /\ core.again # "no")) /\ Counted >= ends.e
DatePasses == core.known = "current" /\ Counted < ends.e /\ wall >= ends.w
Late       == core.tracked # {} /\ Counted > ends.d
Kind       == IF Late THEN "late" ELSE IF EndPasses THEN "k" ELSE IF DatePasses THEN "wallK" ELSE "quiet"
Due        == (Kind = "quiet" \/ (Kind = "late" /\ ~RunsOutNow(core))) /\ Counted - mem.lastSave >= Hour
TickEvent  == Ev(Kind, {}, Due, "ok")

Tick ==
    LET r == Step(core, TickEvent)
        m == [elapsed |-> Counted, lastBoot |-> boot, lastC |-> c, lastWall |-> wall,
              lastSave |-> IF Saves(r[2]) THEN Counted ELSE mem.lastSave]
    IN /\ core' = r[1] /\ mem' = m
       /\ ranOut' = (ranOut \/ TheCountReachesTheEnd)
       /\ disk' = IF Saves(r[2]) THEN [mem |-> m, core |-> Persisted(r[1]), ends |-> ends, up |-> upTime, lost |-> lost] ELSE disk
       /\ fresh' = TRUE
       /\ UNCHANGED << upTime, c, boot, wall, ends, asked, lost, born >>

(* ---- Trust.store: two people pair the key ----------------------------- *)

Store ==
    /\ fresh
    /\ LET r == Step(core, Ev("store", {}, FALSE, "ok"))
           life == mem.elapsed + Life
           e == IF Listed(core) THEN Min(life, ends.e) ELSE life
           w == IF core.known # "no" THEN Min(wall + Life, ends.w)
                ELSE IF core.again # "no" THEN (IF wall < ends.w THEN Min(wall + Life, ends.w) ELSE Min(wall + Life, wall + (e - mem.elapsed)))
                ELSE wall + Life
           n == [ends EXCEPT !.e = e, !.w = w]
       IN /\ Saves(r[2])                         \* refused otherwise: nothing changes
          /\ core' = r[1] /\ ends' = n
          /\ mem' = [mem EXCEPT !.lastSave = mem.elapsed]
          /\ disk' = [mem |-> mem', core |-> Persisted(r[1]), ends |-> n, up |-> upTime, lost |-> lost]
          /\ born' = IF Listed(core) THEN born ELSE [up |-> upTime, lost |-> lost]
    /\ UNCHANGED << upTime, c, boot, wall, fresh, asked, lost, ranOut >>

(* ---- A session the key authenticates ---------------------------------- *)

\* Opening one is two steps, with the network between them: "is this key paired?", and later
\* "track this session". Time passes in between, and the key may run out in it; a session
\* begun under a pairing may finish, within the time allowed after its key's end.
Ask == /\ fresh /\ ~asked /\ Standing(core) = "paired"
       /\ asked' = TRUE
       /\ UNCHANGED << upTime, c, boot, wall, mem, core, ends, disk, fresh, lost, born, ranOut >>

Begin == /\ asked /\ "s1" \notin core.tracked
         /\ LET r == Step(core, Ev("track", {"s1"}, FALSE, "ok"))
            IN /\ core' = r[1]
               /\ ends' = IF r[1].tracked # core.tracked THEN [ends EXCEPT !.d = ends.e + Grace] ELSE ends
         /\ asked' = FALSE /\ fresh' = FALSE
         /\ UNCHANGED << upTime, c, boot, wall, mem, disk, lost, born, ranOut >>

(* ---- The app dies; the Mac dies ---------------------------------------- *)

\* The app is killed and started again in the same boot: what was in memory is gone.
Restart == /\ mem' = disk.mem /\ core' = Loaded(disk.core) /\ ends' = disk.ends
           /\ fresh' = FALSE /\ asked' = FALSE
           /\ UNCHANGED << upTime, c, boot, wall, disk, lost, born, ranOut >>

\* The Mac loses power and comes up again. Under an honest calendar the time away is on the
\* calendar. Under a dishonest one the calendar says whatever it is made to say, and the
\* up-time since the last write is gone: nothing this Mac can trust accounts for it.
Reboot == /\ boot < MaxBoots
          /\ boot' = boot + 1 /\ c' = 0
          /\ mem' = disk.mem /\ core' = Loaded(disk.core) /\ ends' = disk.ends
          /\ wall' \in IF HonestCalendar THEN {wall} ELSE 0..MaxWall
          /\ lost' = IF HonestCalendar THEN lost ELSE disk.lost + (upTime - disk.up)
          /\ fresh' = FALSE /\ asked' = FALSE
          /\ UNCHANGED << upTime, disk, born, ranOut >>

Next == Pass \/ Tick \/ Store \/ Ask \/ Begin \/ Restart \/ Reboot

Spec == Init /\ [][Next]_vars

TypeOK == /\ upTime \in 0..MaxUp /\ c \in 0..MaxUp /\ boot \in 0..MaxBoots /\ wall \in 0..MaxWall
          /\ fresh \in BOOLEAN /\ asked \in BOOLEAN /\ ranOut \in BOOLEAN /\ lost \in 0..MaxUp

(***************************************************************************)
(* Properties                                                              *)
(***************************************************************************)

\* What a tick finds is always one of the events the trust core knows.
TickIsAnEvent == Enabled(core, TickEvent) /\ (Late /\ Ahead => EndPasses)

\* The count never falls short of the time the Mac has been up, but for what an unclean
\* reboot under a lying calendar took.
TheCountCoversTheTimeUp == fresh => mem.elapsed + lost >= upTime

\* And the file is never an hour behind the count: that is all such a reboot can take.
TheFileIsLessThanAnHourBehind == fresh => mem.elapsed - disk.mem.elapsed < Hour

\* THE CLAIM: a key is treated as paired for no more real up-time than its life, net of that.
PairedNoLongerThanItsLife ==
    (fresh /\ Standing(core) = "paired") => upTime - born.up < Life + (lost - born.lost)

\* Only the count refuses a key for good; the calendar alone never does (the review's F3).
OnlyTheCountRefusesForGood == core.tomb = "expired" => ranOut

\* A key whose end the count has reached is never paired again, on whichever list it was
\* when that happened (the review's F2), and not after a restart or a reboot either.
PastItsEndIsNeverPaired == ranOut => Standing(core) # "paired" /\ ~MayPair(Loaded(disk.core))

\* An existing pairing's end is never moved later, by the count or by the calendar's date.
EndsNeverMoveLater == [][(Listed(core) /\ Listed(core')) => ends'.e <= ends.e]_vars

\* A session does not run past the time allowed after its key's end.
NoSessionPastItsGrace == (fresh /\ core.tracked # {}) => mem.elapsed <= ends.d

\* With an honest calendar nothing is ever lost.
NothingIsLost == lost = 0

\* Reachability, to be VIOLATED: a key does get paired, does run out, and a pairing whose
\* calendar date passed does get made again.
NeverPaired == Standing(core) # "paired"
NeverRunsOut == ~ranOut
NeverPairedAgain == core.again # "pairedAgain"

=============================================================================
