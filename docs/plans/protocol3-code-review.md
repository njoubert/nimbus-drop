# Nimbus Drop protocol 3 (0.3.0, unreleased): review of the code against the plan

Phase 5 of `docs/plans/secure-drops-plan.html`. Reviewed at `d1863b8` (branch `secure-drops`), 2026-11-23, in a detached worktree. Nothing was committed, pushed, launched or sent beyond loopback; the CLI was not run, so no `cli-review-*` folders exist.

PoC tests and fuzzers: `Tests/NimbusDropCoreTests/ReviewPoCTests.swift` (new file), saved as
`/private/tmp/claude-501/-Users-njoubert-Code-nimbus-drop/966c9c33-7547-4a2a-ac6d-17d1ac45c1e3/scratchpad/protocol3-code-review-pocs.patch`.
Every `testPoC_…` (9) asserts something the plan claims and **fails** on the code as it is; every `testFuzz_…` (3) passes; the 109 existing core tests pass beside them. The file is also still in the worktree (`.claude/worktrees/agent-ae2b023ffb054eaad`, detached at `d1863b8`), untracked. Extra mutation checks: `/private/tmp/claude-501/-Users-njoubert-Code-nimbus-drop/966c9c33-7547-4a2a-ac6d-17d1ac45c1e3/scratchpad/review_mutate.py`.

## Verdict

I found no way for anyone without a paired key to read a drop, alter one, write a byte to disk, or get a key paired without two people typing codes: the handshake, the key schedule, the pairing transaction, the attach and resume proofs and the record path do what the plan says, and about 1,800 malformed connections, messages and records thrown at the parsers trapped nothing. It is safe to put on four Macs on a home LAN as far as confidentiality, integrity and who-is-who go. Fix before release: F1 (any host on the LAN can keep every paired Mac out with 64 idle connections, which P11 and P13 say cannot happen), F7 (a paired Mac, or just a frozen one plus a click on Forget, hangs the app for good), F2 and F6 (two holes in "no key is for ever"), and F4 if the command line is used for anything but tests.

## Findings

Severity is for the plan's threat model. CONFIRMED means a test in `ReviewPoCTests.swift` fails on it today.

### F1. A stranger can keep every paired Mac out, and starve a running drop (medium, availability) — CONFIRMED
`testPoC_F1_SilentConnectionsDoNotKeepAPairedMacOut`, `testPoC_F1_StrangersCannotTakeTheDataConnectionSlotsOfADrop`

- `Sources/NimbusDropCore/Receiver.swift:137-146` (`admit`), `:162-168` (unattached slots).
- Every accepted socket, whatever it turns out to be, first needs one of 64 global stranger slots and a place in the global 500-a-second arrival count. An attacker who is merely on the LAN (no ARP spoofing, no key) opens 64 TCP connections, says nothing, and reopens them every 10 s. From then on a paired sender's control connection, its data connections, its reconnect and every probe are closed on arrival: the PoC's drop ends `failed("The connection closed")`, and tiles on the other Macs lose their Paired mark. 500 connections a second does the same through the arrival count.
- Second pool: while a drop is in progress, 16 connections that send `NDATA` and nothing else hold all 16 unattached slots for 5 s at a time. The sender's own data connections then get no challenge. A drop that needs a replacement connection or a second round gets none, falls into reconnect, and gives up after three fruitless ones (`Sender.swift:159-161`).
- Breaks P11 ("anyone else is turned away … and cannot end the drop") and the point of P13/R2 ("limits follow authorisation"): the limits are global, so the unauthorised spend the authorised's budget. The existing flood test (`testCompletingAHandshakeWithAFreshKeyEarnsNothing`) only covers 50 completed handshakes against 4 unpaired slots.
- Smallest fix: keep the global caps, add per-source-address caps under them (say 8 strangers, 4 unattached, 50 arrivals/s per address), and when a pool is full close the oldest connection that has proved nothing rather than refuse the newest. An address is a label, but this is admission order, not trust. It raises the cost from one host to many addresses; it does not make a LAN attacker unable to deny service, and the plan should stop saying so in P11.

### F7. Withdrawing trust can lock the trust store for ever (medium, availability) — CONFIRMED
`testPoC_F7_APairedMacCannotLockTheTrustStoreByRetiringItselfMidDrop`

- `Trust.swift:494-515` (`withdrawLocked` → `endSessions`, lock held) → `Sender.swift:313-316` (`withdrawn`) → `Sender.swift:295-300` (`fail` sends `.error` on the control channel) → `Channel.swift:211-225` (takes the write lock, blocking `write`).
- A paired Mac that turns hostile accepts a drop and stops reading. The sender blocks in `control.send(.manifest)` once the socket buffers are full (the PoC uses a 400,000-file manifest over loopback; over a LAN a receiver with a small receive buffer needs a few MB, tens of thousands of files). It then connects again and sends `retire`, as any paired key may. The listener thread takes the trust lock, ends the key's sessions, and `SendSession.fail` tries to write a farewell on the channel whose write lock the blocked thread holds. The trust lock is never released: `standing(of:)` never returns again, so every handshake thread stalls (the 64 stranger slots fill), and the main thread stalls the next time a tile or Settings asks who a key is. Only killing the app clears it.
- Not only hostile: a receiver that froze or slept mid-manifest, then the person clicks Forget for it, takes the same path. So does `endSessionsPastGrace` from `tick()`.
- Smallest fix: `SendSession.withdrawn` must not say a farewell: mark the error as the link's (`connection = true`) before `super.withdrawn`, so `fail` skips the send and goes straight to closing sockets. Better: never call into a session with the trust lock held (collect under the lock, end after releasing it, before the public method returns; the ordering the plan asks for survives).

### F4. The command line sends to whichever paired Mac answers under a name (medium) — CONFIRMED for the engine half, the CLI half by reading
`testPoC_F4_ADropAimedAtOneMacIsNotTakenByAnotherPairedMac`

- `Sources/NimbusDrop/CLI.swift:107-119` (`locate`: the first Bonjour result whose TXT `name` equals the target) and `:287-288` (`SendSession` with no `expect`); `Sender.swift:335-344` (with no expected key, any paired key will do).
- `NimbusDrop --send air-cli files…` goes to the address of whatever record says `name=air-cli`. If the Mac there proves any key this identity is paired with, the offer is made to it. A paired Mac that turns hostile announces another's name and is offered what was meant for the other (it accepts its own offers). Two honest Macs with the same name do it by accident; with `--unattended-from` at the wrong one the files land without anyone being asked.
- Breaks the ground rule "nothing decides who a Mac is but the key it proved" and P7's "where its tile points". The app is not affected: `AppModel.begin` always passes `expect: peer.key`.
- Smallest fix: `--send TARGET` resolves TARGET to one Known Mac (its name here, or its key tag), probes the candidates, and passes that key as `expect`; a bare address with no Known Mac named stays "whoever is paired" only behind an explicit flag.

### F2. A key that runs out on the pair-again list is forgotten, not refused (low) — CONFIRMED
`testPoC_F2_AKeyThatRunsOutOnThePairAgainListStaysRefused`, `testPoC_F2_TheSameAfterAReset`

- `Trust.swift:305-308`: `file.again.removeAll { … }` drops the entry at its end date and leaves no tombstone. (`tick` and `rotate` do leave one for entries still in `known`.)
- After this Mac's own key rotates (expiry, or Reset Identity, which moves every Known Mac there), each peer key waits on the pair-again list. When the deadline recorded for it passes it becomes `.unknown`: someone holding a copy of that dead key is shown as a New Mac, can be paired for a fresh 90 days, and using it raises no "retired identity" notice. It still takes two people and codes, which is why this is low.
- Breaks P16 ("no Mac begins … a pairing with a key after the deadline it recorded for it") and Key expiry ("cannot be paired again; the record of it is kept as a tombstone when the rest of its entry is dropped").
- Fix: in `tick`, append an `expired` tombstone for each `again` entry removed.

### F6. An offer made before its key ended can be accepted after (low) — CONFIRMED
`testPoC_F6_AnOfferStillWaitingWhenItsKeyEndsIsWithdrawn`

- `Receiver.swift:644-659` (`conduct` waits for the person and never asks the trust store again); `Trust.swift:478-485` (a tracked session is ended only a day past the key's end).
- The offer panel stays up when the sender's key reaches the deadline recorded for it; Accept then starts and completes a drop under that key, up to 24 hours later. The Admission table says "the sender's key ending withdraws it"; P16 says no drop begins after the deadline.
- Fix: in `conduct`, after the person accepts, `guard listener.trust.standing(of: control.remote).isPaired` or decline; and have `tick` end sessions still in `.waitingForAccept` when their key ends.

### F3. One forward jump of the calendar poisons every pairing for good (low; medium on a LAN with no time server) — CONFIRMED
`testPoC_F3_ACalendarSetForwardOnceCostsARenewalAndNoMore`

- `Trust.swift:296-304` and `:318-328`: a peer key whose calendar date has passed gets an `expired` tombstone at once, and a tombstoned key can never be paired again (`mayPair`).
- The plan prices a calendar set forward at "a renewal". The code's price: this Mac's key rotates, and every peer's key, still good for weeks on its own Mac, is refused here permanently, also after the calendar is put right. Pairing again fails with "cannot be paired" until each *other* Mac does Reset Identity; meanwhile their attempts raise "a retired identity was used" notices here. A forged time server is in the threat model; so is no time server at all (D10), where the ordinary case is a Mac that was paired while its clock was years behind and is then set right.
- Fix: let the calendar end the pairing (move the entry to pair-again, keeping its elapsed deadline) and let only the elapsed deadline write the tombstone.

### F8. An unknown key under an expired Mac's name is called "The same Mac you paired with before" (low) — BY READING
- `Sources/NimbusDrop/PairingPanel.swift:86-89` (`isRenewal` is true for `clash?.expected`), `:324`, `:342` (the green line), `:92` and `AppModel.swift:455-457` (`replacing` set without the person being asked).
- An impostor who waits for a paired Mac's key to run out and announces its name gets a "Renew pairing" tile (as the plan intends) and then, in the pairing window on both roles, the sentence "The same Mac you paired with before", which the plan reserves for a Mac that proves the *same key* (`.renew` standing). A name earns a statement about identity. The codes still decide, so no trust is created; the wording is what a hurried person reads.
- Fix: `isRenewal` only for `case .renew = session.standing`; the expected-new-key case gets screen 10's wording ("a new one was expected; the codes will show whether this is that Mac").

### F5. A stranger's request is shown beside this Mac's own pairing in progress (low) — CONFIRMED
`testPoC_F5_NoRequestIsShownWhileThisMacIsItselfPairing`

- `Receiver.swift:315-363` (`request`) looks at `showing` (requests from others) and at the tie-break, never at `trust.gate.active`.
- While this Mac's person waits in their own "Pair with dads-imac" window, anyone on the LAN can raise "dads-imac wants to pair with this Mac" next to it. The gate stops the second transaction if they click Pair…, so nothing is stored; but the plan says "a request arriving meanwhile is answered busy", and this is the "slip in beside a genuine pairing" its reviewers' brief asks about. Refusing it also starts the quiet period, which then turns away the genuine Mac's request for 10 s and more.
- Fix: after the tie-break, `if trust.gate.active != nil { return busy(…) }`.

### F9. Requests to pair can be denied to everyone by one stranger (low, availability) — BY READING
- `Pairing.swift:53-59`, `Receiver.swift:329-330`, `:352`.
- A request that is shown and then abandoned starts the quiet period (10 s, doubling to 10 min) for every key, paired or renewing ones included. One stranger sending one request every ten minutes, and hanging up, keeps a Mac permanently unable to be asked; doing it to both Macs stops them pairing at all, since one of the two must be asked. The rationing is the plan's (P17); that it is also a lever is not stated.
- Fix: the quiet period does not apply to a key on the Known or pair-again list (a renewal), and Settings shows the pause with a button that lifts it.

### F10. `control` is replaced on one thread and read on others (low) — BY READING
- `Receiver.swift:565-578` (`resume(on:)`, listener thread, reads `control`), `:614-615` (session thread assigns it), `:499` (`farewell`), `:860` (stream threads); the same shape in `Sender.swift:268-269` against `fail`.
- An unsynchronised read of a class reference racing its assignment is undefined in Swift and can crash on a double release. A paired sender that reconnects in a tight loop (each resume is valid) is the one who can aim at it. Not reproduced.
- Fix: read and write `control` under `lock`.

## Spec and code disagree, without a vulnerability

1. **Handshake payloads.** Plan: "anything else in a handshake payload ends the connection". Code discards the payload unread (`Channel.swift:150, 187, 189`).
2. **"1 KB in all" before a key is proved.** Each of the two frames may be 1,024 bytes, plus an opening of up to 22.
3. **"16 KB in all" for an unpaired key** is 16 KB per message (`Receiver.swift:222`), any number in its 10 s.
4. **Highest major per key.** `KnownMac.major` is recorded (`Trust.seen`) and never compared. Moot while there is one major.
5. **Paired key before its offer** is in no counted class: no stranger slot, no unpaired slot, 10 s. A paired Mac can hold a few thousand threads.
6. **"Replaces or another Mac … asks you to name the new one differently."** Nobody is asked; `uniqueName` compares case-insensitively, not with `Trust.fold`, so "macstudio" and "ｍａｃｓｔｕｄｉｏ" can both be Known Macs.
7. **Look-alike folding** (`Trust.fold`) covers case, accents, width and script; not I/l/1, O/0, rn/m.
8. **A recorded end date "is never moved later"**: Forget drops the entry and its date; pairing the same key again gives it a fresh 90 days.
9. **Manifest validation** does not check that chunk counts fit their u32 fields (a file over chunk size × 2^32). `Ledger` clamps; nothing traps on the receiver.
10. **Stream key budget**: the receiver enforces 2^24 seals, not the 2^38 bytes; only the sender counts bytes.
11. **"Wipes the master and every stream key"**: `keys = nil` drops `DropKeys`, but `Channel.master` is a `let` on the control channel and lives as long as the session object (a minute in the window). Nothing is zeroised anywhere.
12. **Trust file, `device` present and `trust` missing** is treated as a first run: a new identity, tombstones forgotten, nothing said (`EnclaveStorage.swift:107`). The command line starts afresh on a damaged file without asking (`CLI.swift:53-56`).
13. **"Not acted on until the write has returned"**: only `retire` checks (`commit()`); Forget, replace and `store` log a failed write and carry on, so a restart undoes them.
14. **The lock file** is held for the write only, not load-change-write: two processes on one identity lose each other's changes.
15. **Elapsed time when the app is not running.** Uptime between the last hourly save and a reboot is counted only through the calendar; with a held calendar and the app quit for a month before a reboot, that month is not counted. The stated limit names only time switched off.
16. **Own key replaced mid-drop**: a reconnect uses the new key (`Sender.swift:245`) and is refused; "finishes on the keys it started with" holds only while the control connection does.
17. **P9 for Macs added by address**: `AppModel.probeManual` (every 5 s) runs `Probe.hello`, a full handshake that shows this Mac's key and name to whatever answers there, proved or not.
18. **Withdrawal step 3**: only the request on screen is cancelled. A queued request, or a pairing this Mac started, with that key goes on; `store` refuses a tombstoned key, and after Forget it simply pairs again.
19. **The retired-identity notice** for a run-out key on the pair path carries the name the caller announced (`Receiver.swift:283`), while its text says the name is this Mac's own for it.
20. **`notePairingGone`** (new today) is sound: reachable only after the responder proved a key whose standing is `.paired`, from its sealed hello, and it touches that entry alone. Two side effects worth knowing: it ends every other drop with that key in both directions, and a script that sends in the same millisecond a pairing completes can meet the other Mac before it has stored and be demoted.

## Test gaps

Guards whose removal no test in `ProtocolTests`, `SecurityTests`, `PairingTests`, `TrustTests` or `DropTests` notices (run with `review_mutate.py`; each line is one mutation):

| Guard broken | File | Result |
|---|---|---|
| A record's length need only fit the buffer, not equal what the manifest implies | `Receiver.swift:903` | MISSED |
| The end marker need not have chunk 0 and length 0 | `Receiver.swift:895` | MISSED |
| A finished drop's remembered answer (its file names) is given to any paired key that names the session, with no proof | `Receiver.swift:266-267` | MISSED |
| Withdrawing trust leaves a finished drop's resume key and answer behind | `Receiver.swift:385` | MISSED |
| The receiver takes an offer although the sender's hello says `paired: false` | `Receiver.swift:234` | MISSED |
| With no expected key, the sender completes the handshake (shows its key) to a responder that is not paired | `Sender.swift:342` | MISSED |
| Data connections that have not attached are not counted | `Receiver.swift:163` | MISSED |
| Strangers are not counted | `Receiver.swift:140` | MISSED |
| Arrivals are not rationed | `Receiver.swift:140` | MISSED |
| More than 64 data connections per drop | `Receiver.swift:831` | MISSED |
| The codes never run out of time | `Pairing.swift:385` | MISSED |
| A request to pair from a run-out key (still a Known Mac) is shown | `Receiver.swift:282` | MISSED (the test of that name covers a retired key, which is closed earlier) |
| An all-zero key agreement is accepted | `Crypto.swift:160` | MISSED; CryptoKit seems to refuse it by itself, so `testALowOrderKeyAgreesWithNobody` passes with or without the guard and does not show which |
| The sender offers although the receiver says `paired: false` | `Sender.swift:350` | caught (three tests) |
| A key at or above the field prime is accepted | `Crypto.swift:64` | caught |
| A request is shown during the quiet period | `Receiver.swift:330` | caught |

13 of 16 missed. The first is the one that matters most: with that check gone entirely, a paired sender's header is a length the receiver reads into a buffer of one chunk.

By reading:
- No test fills the stranger pool or the arrival count and then tries a paired drop (F1); none holds unattached slots.
- No test of a key on the pair-again list reaching its end (F2), of an offer outliving its key (F6), or of a calendar put back after a forward jump (F3).
- No test sends a record sealed under the right stream key that names a file, chunk or length the manifest does not have. `testJunkOnDataConnectionsDoesNotEndADrop` sends bytes that fail to open, which exercises the seal and none of the checks at `Receiver.swift:901-903`; the length check there is the only thing between a paired sender and a write past the chunk buffer. `testFuzz_RecordsFromAPairedSenderThatMeansHarm` now does (697 combinations).
- Nothing fuzzed the handshake, fragment or pairing parsers before this review. The three `testFuzz_…` tests are a start, not coverage-guided.
- `mutate.py`'s "an unpaired Mac may send an offer" replaces a whole line with one that stores a pairing; it would be caught by almost any change. The narrower mutations above are the ones to add.

## Examined and found sound

- **Noise XX** (`Crypto.swift:245-379`): message patterns, MixKey/MixHash order, nonce = counter from zero per key, AD = h, the three-output Split, turn and step checks, canonical static keys, all-zero agreement refused, self-connection refused on both sides. Prologue binds both openings (`Channel.swift:134`).
- **P9 for drops**: the expected key and its standing are checked after message 2 and before message 3 (`Channel.swift:170-178`, `Sender.swift:335-344`); the app always passes `expect`.
- **Control framing** (`Channel.swift:229-247`): total checked against the limit on the first fragment before anything is reserved; lying totals, more-flags, type changes and empty fragments end the connection; no arithmetic on attacker numbers that can trap. 15,000-deep JSON, 1e999, Int.min, NULs and bidi marks in a hello do nothing.
- **Pairing** (`Pairing.swift`): commit, then Nr made after it, then Ns checked against the commit; codes from one KDF over `Ns ‖ Nr` and h; each value exactly once and 32 bytes; `paired` accepted once and only after the codes exist; stored only on `localRight && remoteRight`, with the key of this connection; `store` re-checks `mayPair`; three tries; `otherTyped` drives the window only. The one-code-at-a-time window does not weaken either Mac's own check. Verify by number compares against the proved key.
- **Attach** (`Receiver.swift:160-189, 517-523`): tag over a fresh challenge checked before the number is claimed, claimed once, nothing read before. **Resume**: proof over the new h, same static key required, also for a finished drop's remembered answer.
- **Records** (`Receiver.swift:880-932`): header opened first; file, kind, chunk and exact length checked before a byte of the chunk is read; chunk opened whole into a private buffer; `isOver` checked before the write. One connection number, one key, on both sides; the sender's counter survives reconnects (`Sender.swift:453`).
- **Retire**: only from a key on record, only itself, written and sessions ended before the answer (`Receiver.swift:291-304`). Retired keys are closed at the handshake with a rationed notice.
- **Offer and manifest agreement, `validate`, `SafeTree`, quarantine, link rule**: unchanged from 0.2.2 and still applied to paired keys.
- **Discovery**: no key material in Bonjour; a tile's standing comes only from the key its address proved; an address change clears it; a stale Paired mark (up to 30 s) cannot send anything because the send proves the key again.
- **The app layer**: nothing is sent, shown from, or stored for a key before it is proved; the Accept and Pair buttons take no Return key; the offer panel shows this Mac's own name for the sender.
- **`--unattended-from`**: full 80-bit tag equality against a currently paired key, one at a time, byte cap, refused with `--any-network`.
- **EnclaveStorage**: AES-GCM with a fresh nonce and the stated associated data, atomic replace with fsync of file and folder, foreign hardware and damage told apart.

## Not examined

- Anything on screen, live: no window was opened and nothing was clicked. F8 and the app-layer notes are from the source.
- Two real Macs, Bonjour and `NWBrowser` behaviour, the Secure Enclave on real hardware under failure, migration and restore.
- `nimbus-updater`, `build.sh`, signing, notarisation, the Finder service.
- The chaos tests (not run), performance, and the speed gate.
- `scripts/vectors.py` was read for what it covers (handshake bytes, master, derived keys, a record, codes, identity number), not re-derived by hand.
- Timing side channels beyond noting that tags, proofs and codes are compared in constant time.
- A cryptographer's proof of the composition (the third Split output, the two-code derivation): by reading they are used as the plan specifies.
