# Claims, and the evidence for each

Every security claim Nimbus Drop makes, what supports it, and what kind of support that is.
The attacker is in `threat-model.md`; what has to be trusted regardless is in `tcb.md`.
`./build.sh verify` re-runs everything named here, and `formal/check.py` keeps what it ran
(tool versions, source revision, raw output) under `formal/.results/`.

**No claim here says the Swift application is verified.** The kinds of evidence, strongest
first, and what each is worth:

| Status | Means |
|---|---|
| **proved (symbolic)** | Tamarin: no attack in the symbolic model, any number of sessions, under the stated assumptions. Says nothing of the bytes or the Swift. |
| **checked (bounded)** | TLC: holds in every reachable state of the model at the bounds given. Says nothing beyond them. |
| **same machine** | The Swift decision code's transition relation, exported by a test, is EQUAL to the model's `Step` (TLC, both ways), over the stated abstraction. The abstraction's adequacy is tested by seeded random walks, not proved. Covers the pure machine, not the class that drives it. |
| **argued** | A written argument with its assumptions. Not machine-checked. |
| **tested** | The attack is a test and fails; a mutation of the guard makes the test fail. |
| **compiler** | The compiler refuses the program that would break it. |
| **by reading** | Inspection, with a mutant on each side where one exists. |
| **not established** | Said so. |

## The channel

| # | Claim | Evidence | Status |
|---|---|---|---|
| C-1 | A drop's `master` and the control channel's keys are known to nobody but the two Macs; this stays true if either static key leaks later, and one's own key leaking does not let anyone pass as someone else to it. Assumes: the peer's key was made by a Mac and not given away before the handshake finished. | `master_is_secret_for_the_initiator/responder`, `transport_keys_are_secret_...`; mutants `NoEE`, `NoSE`, `MasterFromHash` | proved (symbolic) |
| C-2 | When a handshake finishes, exactly one handshake of the Mac it names finished with it, on the same keys, hash and openings. Same assumption. | `the_responder_agrees_with_the_initiator`, `the_initiator_agrees_with_the_responder`, `the_handshake_hash_binds_both_static_keys` (no assumption) | proved (symbolic) |
| C-3 | The Swift computes that handshake and those keys. | The published Noise vector (`CryptoTests`), `scripts/vectors.py` (a second implementation, `VectorTests`), Wycheproof X25519 (`WycheproofTests`, 518 vectors) | tested. That the Swift calls the functions in the order the model's rules say: by reading. |
| C-4 | A data connection is taken, and a drop is resumed, only from the Mac that holds the drop's keys, for that connection and that handshake. | `only_the_sender_attaches_a_data_connection`, `only_the_sender_resumes_a_drop`, `only_the_receiver_confirms_a_resume`; `ProtocolTests`, `ReviewTests` | proved (symbolic); tested |
| C-5 | What is written is what the sender sealed, on that connection at that count; a chunk is secret. | `what_is_written_is_what_the_sender_sealed`, `a_chunk_is_secret`; `ReviewTests.testFuzzRecords...` | proved (symbolic); tested |
| C-6 | A probe's answer comes from a holder of the key it reports. | `a_probe_is_answered_by_the_key_it_reports`; mutants `NoMessage2Check`, `NoES` | proved (symbolic) |
| C-7 | What a connection is for (drop, pair, resume, retire, speed) is what its initiator said on that handshake; nothing sealed for a speed test is ever written for a drop; a sealed chunk is written at most once, and only where it was sealed for. | `both_ends_agree_what_a_connection_is_for`, `what_is_sealed_for_one_purpose_is_never_written_for_another`, `what_a_speed_test_sends_back_is_never_written`, `a_sealed_chunk_is_written_once`, `..._only_where_it_was_sealed_for` | proved (symbolic) |
| C-8 | The stream key depends on the connection number, a record's header is bound to its chunk, and the resume proof to the handshake hash. | The lemmas hold with these guards; the four mutants that would show the lemmas NEED them did not settle (`formal/README.md`). `ReviewTests`, `ProtocolTests`, `scripts/mutate.py`. | tested. From the symbolic model: **not established** |

## Pairing

| # | Claim | Evidence | Status |
|---|---|---|---|
| P-1 | What a Mac stores as "the Mac my person was pairing with" is that Mac's own key, with someone in the middle of every connection who hears the codes and can steer a short code whenever they hold its last input. | `a_stored_pairing_is_with_the_mac_the_person_meant`; its two mutants produce the attack | proved (symbolic) |
| P-2 | Luck: at most two in a million per pairing carried through, whatever the attacker computes. | `formal/computational/pairing-bound.md`; `formal/sas-bound.py` (the bias counted exactly; the game played) | argued (random oracles) |
| P-3 | The transaction: each message once and in order, the codes only after the commitment is opened, three tries at one fixed code, stored only when this person typed right AND the other Mac said so. | `Pairing.tla`, `PairingSystem.tla`; `PairingMachine.swift` = `PairingMachine.tla` (`PairingRefinement.tla`) | checked (bounded); same machine |
| P-4 | One pairing at a time on a Mac; two people asking each other at once leaves one going. | `PairingGate.tla`; `PairingTests` | checked (bounded); by reading |
| P-5 | A pairing does not outlive the identity it was made with (Reset Identity mid-pairing). | `IndependentReviewTests`; `Trust.store(under:)` | tested |

## Trust

| # | Claim | Evidence | Status |
|---|---|---|---|
| T-1 | A session authenticated by a key exists only while the store counts that key as paired, or is on its way to being ended; and the store knows of every live session. Registration and the question are one decision. | `TrustWithdraw.tla`: `LiveMeansTrustedOrBeingEnded`, `LiveIsOnTheList`; `TrustCore.swift` = `TrustCore.tla` (`TrustRefinement.tla`); `ModelFindingsTests`, `TrustShellTests` (raced 400 times) | checked (bounded); same machine for the decision; the lock and the order by reading and tested |
| T-2 | When a withdrawal returns, nothing the key authenticated is running; the file is written before anything is ended; nothing that touches a socket runs with the store locked. | `NothingOutlivesTheWithdrawal`, `NoSocketWorkUnderTheLock`; `TrustShellTests`, `ReviewTests` (F7) | checked (bounded); tested |
| T-3 | A retire notice is acknowledged only after the refusal is on disk; what the disk refuses for good stays refused. "For good": while the tombstone is among the newest 2000 (`trust-lifetime.md`). After that, trust returns only by two people pairing. | `AcknowledgedMeansRefusedForGood`, `ForGoodOnDiskIsForGood`, `NoSilentResurrection` (with eviction), and the run that shows the limit | checked (bounded) |
| T-4 | A key is treated as paired for no more of this Mac's up-time than its life, under a calendar that says anything, restarts and unclean reboots; net of the up-time between the last hourly write and an unclean reboot under a held calendar. | `Expiry.tla`: `PairedNoLongerThanItsLife`, `TheCountCoversTheTimeUp`, `TheFileIsLessThanAnHourBehind`; `TrustCore.count` as a table | checked (bounded: 5 units of time, 2 reboots, a calendar of 5 values) |
| T-5 | Only the count of elapsed time refuses a key for good (never the calendar alone); a key past its end is never paired again, whichever list it was on; a pairing's end is never moved later; a session does not run past its day of grace. | `OnlyTheCountRefusesForGood`, `PastItsEndIsNeverPaired`, `EndsNeverMoveLater`, `NoSessionPastItsGrace`; `TrustTests` | checked (bounded); tested |
| T-6 | Time the Mac is switched off under a calendar someone controls is counted. | | **not established**, and not claimed |
| T-7 | The trust file cannot be put back from an older copy. | | **not established**, and not claimed (software running as the user) |

## A drop

| # | Claim | Evidence | Status |
|---|---|---|---|
| D-1 | Bytes that are not the sender's are never written; nothing is put in place that is not whole; the sender is told "sent" only of a drop that was put in place; nothing is written once it has been judged (false until 2026-11-24: a data connection could attach while the drop was being placed). Under damaged records, cut and held-back data connections and a lost conversation. It arrives, within its patience: a conversation cut before the sender heard the first plan is not got back, and three fruitless reconnects or five idle rounds end it. | `Drop.tla` (2 or 3 chunks, 2 or 3 faults; 179,000 states in the largest run); `RoundMachine.swift` = `RoundMachine.tla` (`RoundRefinement.tla`); `Rounds.tla`; `ChaosTests` (29), `ModelFindingsTests` | checked (bounded); same machine for the conversation; the data path by reading and tested |
| D-2 | Nothing is accepted, prepared or written before the person said yes; a yes under a pairing that has since ended starts nothing; a manifest that is not what was offered is refused. | `RoundMachine`; `SecurityTests`, `ReviewTests` (F6), `IndependentReviewTests` | same machine; tested |
| D-3 | A connection number, and so a stream key and its nonces, is used once in a drop, also across a reconnect. | `Drop.tla`: `NoStreamKeyTwice`; `ProtocolTests` | checked (bounded); tested |
| D-4 | What a partial folder holds between attempts is what was received. | The ledger's word. After a power cut mid-drop the ledger can be ahead of the data it speaks for, and a resume would then place a file with a hole. Process death and sleep are fine (the page cache survives them). | **not established.** Reported for the owner's decision; see below. |
| D-5 | A hostile number in a manifest, a plan or a record does not crash the receiver. | `SecurityTests`, `FuzzTests`, `ReviewTests`' three fuzzers; AddressSanitizer and ThreadSanitizer over the suite | tested |

## The disk

| # | Claim | Evidence | Status |
|---|---|---|---|
| F-1 | Every file operation a remote Mac can cause stays inside the folder the person chose; nothing that was there is overwritten; only what the manifest names appears. Against a paired sender that means harm. | `ContainmentTests` (sentinels outside the destination, a snapshot before and after), `SecurityTests`; `docs/security/filesystem-containment.md` | tested |
| F-2 | The same against a local actor rearranging the destination while a drop runs. | As far as `filesystem-containment.md` says, and no further | tested in part |

## Who gets in

| # | Claim | Evidence | Status |
|---|---|---|---|
| A-1 | No pool exceeds its limit; a local connection within the arrival rate (by true time) gets a place whatever the pools hold; it gives way only after a pool's worth of newcomers arrived after it; one that has proved a paired key never gives way, and nothing it gets depends on an address; a key nobody paired is not kept out by silent ones, and a request to pair that has been read keeps its place. | `AdmissionSystem.tla` (small limits; up to 450,000 states); `Admission.swift` = `Admission.tla` at four sets of small limits (`AdmissionRefinement.tla`); that the code is the same at 64 / 8 / 500 / 200 is by reading and by walks at random limits; `ReviewTests`, `AdmissionTests` | checked (bounded); same machine |
| A-2 | A paired Mac always gets in; a flood from many addresses cannot stop a drop or a pairing. | Three addresses at 167 arrivals a second each fill the rate, and the model shows it. | **not claimed** |

## The person's say

| # | Claim | Evidence | Status |
|---|---|---|---|
| Y-1 | A drop, a pairing and a speed test each wait for a yes from the person at that Mac, and a yes is spent only on what was shown. | `SpeedTests`, `SecurityTests` (offer against manifest), `IndependentReviewTests` (the yes against the pairing; Retry by key) | tested; the panels themselves by reading |

## Secrets

| # | Claim | Evidence | Status |
|---|---|---|---|
| S-1 | A key's bytes cannot be read outside `NimbusCrypto`, which does no I/O; outside the engine's package the types that hold keys cannot be named. | `scripts/test-capabilities.py` (programs that must not compile); `scripts/check-layers.py` (purity) | compiler; the purity by lint |
| S-2 | Nothing secret is logged or said to the other Mac. | `SecretsTests` (the whole log of a pairing, a drop, a speed test and a reset, searched); the lint | tested |
| S-3 | A process that set out to read a key in its own memory cannot. | | **not claimed**: access control is not isolation |

## Open for the owner

Decisions, not defects. Each is written up where it arose; nothing here was changed without
being asked.

1. **D-4, a resume after a power cut.** The cheap fix (believe a ledger only within the boot it
   was written in; a resume across a reboot starts over) changes what a resume does, so it was
   not made. A middle one keeps a CRC-32 of each chunk beside its ledger record and reads the
   chunks back before a resume believes them: nothing on the wire, and next to nothing on the
   data path (zlib's CRC-32 runs at 41 GB/s on one core of the MacBook Pro), at the cost of
   reading the partial data once on resume. The thorough one is a hash of each file in the
   manifest, which changes the wire and costs speed: SHA-256 runs at 3.0 GB/s (24 Gbit/s) on
   one core here, against about 8 GB/s for the AES-GCM the data path already pays, so one
   connection on a fast link would be held to the hash.
2. **T-3, "for good".** Leave the 2000, raise it, or never evict a tombstone made by a retire
   or a replacement (`trust-lifetime.md`).
3. **T-4, the hourly write.** Writing the count more often (every five minutes) shrinks what
   an unclean reboot under a held calendar can take, at the cost of a small file write.
4. **A limit was changed: keys nobody paired, two to an address** (`Tuning.unpairedPerAddress`,
   commit f012e61, which can be taken or left by itself). Without it one host keeps every Mac
   from asking to pair. With five requests to pair lasting, a key that has not asked gives way
   after three newer ones, not eight.
5. **Two new limits on a drop**: a minute of silence before the manifest
   (`Tuning.manifestSeconds`; a sender that trickles still holds its room), and at most two
   unread messages at a sender.
6. **A folder that still holds an unfinished drop's partial folder can no longer be sent**: a
   manifest may not name anything as a partial folder is named (it was a way to pre-seed
   another sender's drop). `Scanner` still offers such a folder, and the receiver refuses it.
   Options: leave it; have `Scanner` leave partial folders out; name partial folders from
   something another Mac cannot compute.
7. **A pipe where a file belongs stalls a drop** (someone with access to the destination
   folder only). `O_NONBLOCK` would refuse it at once; whether that open can then fail on a
   file kept in iCloud whose contents are not local was not checked.
8. **`Trust.store(pairing:)` is `public`** (`authority.md`): narrow it, and give the rendered
   windows their own way to make made-up Macs.
9. **What is said to the other Mac when something fails here names local paths** ("Cannot
   write to /Users/…"). Not a secret in this model; worth a generic text.
10. **Four guards the symbolic model could not be made to speak about** (C-8).
11. **Private vulnerability reporting** is off for the repository; `SECURITY.md` points at it.
12. **Release provenance**: releases are built and signed on one Mac; there is no reproducible
    build and no attestation (`tcb.md`).
