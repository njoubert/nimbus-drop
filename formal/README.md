# How Nimbus Drop is checked

Nimbus Drop moves a person's files between their Macs, so it has to do two things without
fail: deliver exactly the bytes that were sent, only to the Mac that was meant, and never let
another machine do anything on this one that its person did not agree to. Here are the many
approaches we deploy to make sure the system works as designed and is safe and secure.

There are twenty of them. No single one is enough, and each is here because it catches
something the others cannot: a proof says the design is sound and nothing about the code; a
test says the code survived one attack and nothing about the next; a fuzzer finds the input
nobody thought of and cannot say there is not another. They are layered so that each one's
blind spot is in another's sight.

This page lists them all, says for each what question it answers and what it cannot tell
you, names the gaps that are left and the work that would close them, and then describes the
formal models (what this folder holds) in detail. Every claim that results, with the kind of
evidence behind it, is in `docs/security/claims.md`.

**None of this makes the application "verified", and nothing here says so.** What it does is
make specific claims checkable by a machine, every time, and say plainly where a claim rests
on a proof, where on a bounded search, where on a test, and where on someone's reading.

## The twenty approaches at a glance

| | Approach | The question it answers | Where | Today |
|---|---|---|---|---|
| | **The design** | | | |
| 1 | Symbolic proofs (Tamarin) | Can someone who owns the network read a drop, pass as another Mac, or get a pairing the two people did not make? | `tamarin/` | 43 lemmas in 2 theories |
| 2 | Model checking (TLA+, TLC) | Does it hold in every order things can happen: two people at once, a cut at any moment, a clock that lies, a restart? | `tla/` | 203 runs, the largest 5.5 million states |
| 3 | A written argument | What is a six-digit code worth to someone who can keep trying? | `computational/`, `sas-bound.py` | at most two in a million per pairing |
| | **The code against the design** | | | |
| 4 | Refinement | Is the Swift that decides the same machine as its model, transition for transition? | `tla/*Impl.tla`, `tla/*Refinement.tla` | 4 machines, 74,838 transitions |
| 5 | Random walks | Does anything the model leaves out change what the code does? | `Tests/NimbusCryptoTests` | 1.5 million steps a run, seeds printed |
| 6 | A second implementation and published vectors | Does the cryptography compute what the specification says, byte for byte? | `scripts/vectors.py`, `VectorTests`, `CryptoTests`, `WycheproofTests` | a Python implementation, the Noise vector, 518 Wycheproof vectors |
| | **The running application** | | | |
| 7 | Tests that are attacks | Does each attack we know of fail, against a real listener and a real sender? | `Tests/NimbusDropCoreTests` | 232 tests |
| 8 | Containment tests | Can a drop touch anything outside what the person chose, or anything that was already there? | `ContainmentTests` | 33 tests |
| 9 | Chaos tests | Through a failing network, does a drop arrive identical or stop, and never arrive altered? | `Tests/NimbusDropChaosTests`, `Sources/NimbusDropChaos` | 29 tests |
| 10 | Fuzzing | Does input nobody thought of crash it, or get past a gate? | `FuzzTests`, `ReviewTests` | 8 seeded generators, one new seed every run |
| 11 | Sanitizers | Are there data races or memory errors anywhere in the suite? | `swift test --sanitize=thread`, `=address` | by hand, before a release |
| | **The structure** | | | |
| 12 | Layers and purity | Does the core stay pure (no socket, file, clock, lock, thread or log), and does each module import only what is under it? | `scripts/check-layers.py` | 9 modules, on every commit |
| 13 | Programs that must not compile | Can any code outside the core read a key, or make something that stands for authority? | `scripts/test-capabilities.py`, `SecretsTests` | 32 programs, and a whole session's log searched |
| | **The checks themselves** | | | |
| 14 | Mutation of the code | If this guard were removed, would any test notice? | `scripts/mutate.py` | 266 guards |
| 15 | Mutation of the models | Does the model say anything, or does it hold because it is empty? | `check.py` | 146 TLA+ mutants, 15 Tamarin mutants, 14 reachability runs, 12 runs that show a known limit |
| 16 | A runner that fails closed | Can a proof run pass by accident? | `check.py`, `tamarin/lemmas.json`, `test_check.py` | 41 tests of the runner, 20 of the layer checker |
| | **People, machines, numbers** | | | |
| 17 | Independent review | What did everyone who built it miss? | `IndependentReviewTests`, `ReviewTests` | after every large change |
| 18 | Another machine and toolchain (CI) | Does it hold anywhere but the Mac it was written on? | `.github/workflows/ci.yml` | every push; the proofs weekly |
| 19 | Two real Macs | Does it work over a real network, with a real cable pulled? | `nimbus-chaos`, CLAUDE.md "Measured" | by hand, before a release |
| 20 | Measurement | Is it still as fast as it was? | `scripts/bench-loopback.py` | before and after every change to the data path |

## What each one is, and what it cannot tell you

### The design

**1. Symbolic proofs.** Tamarin is given the handshake, the keys derived from it, what they
are used for, and the pairing with its two spoken codes, and an attacker who controls every
message on the network (and, for the pairing, hears the codes). It proves 43 lemmas for any
number of sessions: the keys are secret, both ends agree on who they are talking to and what
the connection is for, only the Mac holding a drop's keys can attach a connection or resume
it, and a pairing stores the key of the Mac the person was actually pairing with. *It cannot
tell you* that the Swift does what the theory describes, and its cryptography is ideal: no
side channels, no malformed curve points.

**2. Model checking.** TLC explores every reachable state of a TLA+ model, in every order.
That is where the bugs of concurrency and failure live: a session that begins in the instant
its Mac is being forgotten, a data connection that attaches while a drop is being put in
place, a calendar set back an hour. The models cover pairing, the trust store, key expiry,
a drop from offer to end, and admission at the listener. *It cannot tell you* anything beyond
its bounds (a handful of chunks, faults, sessions and units of time), and by itself it is
about a model, not the code.

**3. A written argument.** No proof removes the chance that a six-digit code agrees by luck.
`computational/pairing-bound.md` argues, under random oracles, that it is at most two in a
million per pairing and that the commitment stops an attacker doing better; `sas-bound.py`
counts the bias exactly and plays the game. *It is an argument, read by people, not a
machine-checked proof.*

### The code against the design

**4. Refinement.** The four decisions the security rests on (what a pairing message means,
who a key is to this Mac, what each message of a drop means, which connection gives way) are
each a pure Swift value type. A test drives each through every state and event, writes its
whole transition relation to `tla/*Impl.tla`, and TLC checks that relation EQUAL to the
specification's, in both directions. Change the code or the model without the other and the
build fails. This is what carries a result about a model over to the Swift. *It cannot tell
you* about the classes around the machines, which own the locks, clocks and sockets.

**5. Random walks.** Equality of relations is only the whole truth if nothing the model
leaves out matters. So each machine is also walked at random with many concrete machines per
abstract state, varying everything the abstraction omits: values, limits, histories, clocks
that jump and reboot. Seeds are printed, and one comes from the clock so every run looks
somewhere new. One defect took some 1,500 walks to appear.

**6. A second implementation and published vectors.** `scripts/vectors.py` implements the
key schedule, the codes and the record format again, in Python, from the plan and not from
the Swift; the two must agree byte for byte. The Noise handshake is held to its published
vector and X25519 to Wycheproof's 518, which include the malformed keys a symbolic model
cannot see. *The rule:* never "fix" the Python to match the Swift.

### The running application

**7. Tests that are attacks.** Most tests here are an attack that once worked or would have:
an impostor under a familiar name, a replayed connection, someone in the middle who hears
both codes, a paired Mac sending a manifest that climbs out of its folder. They run whole
drops over loopback with a real listener and a real sender. *A test tells you* one attack
failed once.

**8. Containment tests.** The whole tree is read before and after a drop: sentinels outside
the destination, hostile manifests, links planted between attempts, two drops finishing at
once. They hold the rule that nothing is written outside what the person chose and nothing
that existed is replaced. These showed two file names that the disk treats as one becoming
a single file of mixed bytes, reported complete.

**9. Chaos tests.** `ChaosProxy` sits between a sender and a receiver and throttles, stalls,
cuts, refuses and flips bits. Every test asserts the one thing that must always be true: a
drop may stop, and it may not arrive altered.

**10. Fuzzing.** Seeded generators make hostile manifests, ledger files, trust files,
handshake frames, sealed messages, records from a paired sender that means harm, and names
and numbers to be shown. Each run uses fixed seeds, so a failure can be had again, and one
from the clock, so it also looks somewhere new. That last seed found, when CI ran it, a trust
file that could never be written again. *A fuzzer cannot tell you* it has run out of things
to find.

**11. Sanitizers.** The whole suite under ThreadSanitizer and AddressSanitizer, for the
engine's threads and locks. Run by hand; the reports so far are all on values the tests
themselves write.

### The structure

**12. Layers and purity.** A lint holds each module to the ones under it and holds the core
to being pure: it can decide, and it cannot touch a socket, a file, a clock, a lock, a thread
or the log. Purity is what makes the refinement in 4 possible, and what makes 13 mean
something.

**13. Programs that must not compile.** A key's bytes are `internal` to the pure core, which
does no I/O, so no other code can write them anywhere. That is the compiler's doing, and 32
small programs keep it that way: most try to read a key or forge an authority and must be
refused, for the stated reason; a few must compile, so the check is known to tell the
difference. Beside it, a test searches the log of a whole session for key material.

### The checks themselves

**14. Mutation of the code.** A test that passes whether or not its guard exists is saying
nothing. `scripts/mutate.py` removes each of 266 guards in turn and expects a named test to
fail. The first run here missed 4 of 17; a reviewer then removed 16 more by hand and 13 went
unnoticed. Each has a test now.

**15. Mutation of the models.** The same for the models: each has mutants with one guard
removed, and each must fail on the property named for it. Reachability runs check the other
half, that the good outcome can happen at all. A model that holds the first time has usually
said nothing.

**16. A runner that fails closed.** Tamarin exits 0 when a lemma is falsified, and a summary
cut short looks like a short summary. `check.py` counts a run only when the tool's exit code
agrees with what it printed, the output is whole, and the lemmas are exactly those in the
register. It has its own tests: the list of ways it must refuse.

### People, machines, numbers

**17. Independent review.** A reader given the code and not the conclusions. Reviews of the
plan found a man in the middle the first design allowed; a review of the code on 2026-11-24
found twelve things the models and tests had not, one of them a crash on one accepted drop.

**18. Another machine and toolchain.** CI builds with a different compiler and runs the
models on Linux. It has caught what passed on the Mac the code was written on, more than
once.

**19. Two real Macs.** Loopback is not a network. Before a release, drops go between two Macs
with `nimbus-chaos` between them cutting and corrupting, and both trees are compared by
checksum.

**20. Measurement.** Speed is the point of the app, so a change on the data path is measured
before and after. Safety that made it slow would be a failure of the design.

## How they fit together

```
what must hold                      the plan: docs/plans/secure-drops-plan.html
      |   proved, model-checked, argued                         1  2  3
the models                          formal/
      |   equal, transition for transition; pinned by vectors   4  5  6
the code that decides               Sources/NimbusCrypto (pure)
      |   which nothing else can reach into                     12  13
the code that acts                  sockets, disk, clocks, the app
      |   attacked, cut, flooded, fed nonsense                  7  8  9  10  11
a drop on a real Mac                                            19  20

and beside all of it: are the checks themselves any good?       14  15  16
                      and what did we all miss?                 17  18
```

## The gaps, and the work that would close them

Twenty approaches still leave things uncovered. These are the gaps we know of, most
important first, each with what would close it. A gap is not a known defect: it is a place
where the evidence is weaker than we would like, or where there is none.

### Where the evidence is weakest

| | The gap | What stands there today | What would close it |
|---|---|---|---|
| G1 | **The classes around the four machines are not tied to their models by any machine.** `Trust`, `SendSession`, `ReceiveSession`, `DropListener`, `PairingSession` and `Channel` own the locks, clocks and sockets; that they do what the system models say is by reading. | Tests under threads, a mutant on each side, review. | Trace validation: have a real run log each step it takes and check the log is a behaviour of the TLA+ system model. And keep moving decisions out of the classes into the machines. |
| G2 | **A resume takes the ledger's word.** After a power cut a ledger can claim chunks the disk never kept, and nothing checks a file's contents against anything. A drop interrupted that way can finish with a hole in it. | Stated as a limit (`claims.md`, D-4). The one outcome the project forbids may be reachable here, by a power cut and not by an attacker. | A CRC-32 of each chunk beside its ledger record, read back before a resume believes it. Nothing on the wire; next to nothing on the data path. The owner's decision. |
| G3 | **The disk gate is tested, not modelled.** `Manifest.validate` and `SafeTree` are held by 33 containment tests and the fuzzers. There is no model of the races between a drop and someone rearranging its folder. | Adversarial tests, each with a mutation line. | A small model of placement and of the walk by descriptor; a property-based generator of hostile trees. |
| G4 | **The fuzzers are not coverage-guided.** This toolchain has no libFuzzer for macOS, so the generators are seeded tests that go where their author pointed them. One found its defect only with the seed it takes from the clock, on the day CI happened to run it. | 8 seeded generators, one new seed a run. | Build the pure core and the parsers on Linux and put libFuzzer or AFL++ on them, with the corpus kept. |
| G5 | **Four guards of the handshake could not be made to speak.** With the stream key without its connection number, the header not bound to its chunk, the resume proof without the hash, or one resume label, Tamarin neither proved nor refuted within 12 GB. | Tests and mutation lines hold those four guards. Nothing is claimed of them from the lemmas. | More memory or time, or the theory restructured with helper lemmas so the search ends. |
| G6 | **The proofs are symbolic, and the cryptography in them is ideal.** There is no computational proof of the handshake or of the pairing's bound. | The Noise pattern's own published analysis; Wycheproof's vectors; a written argument for the code. | CryptoVerif for the pairing's two-in-a-million bound, the one place where the number matters. |
| G7 | **Model checking stops at its bounds.** A handful of chunks, faults, sessions and units of time. Admission is equal to its model at four sets of small limits, not at the shipped 64 / 8 / 500 / 200. | Random walks at random limits; reading. | An inductive argument (TLAPS or Apalache) for the admission invariants at any limit. |
| G8 | **Not modelled at all**: discovery, the retire and Forget notices as messages, this Mac's own key running out inside the trust machine, a third Mac at the pairing gate. | Tests (`ProtocolTests`, `ForgetReviewTests`, `PairingTests`). | Models of each, smallest first: Forget as a message. |

### What a machine does not run today

| | The gap | What would close it |
|---|---|---|
| G9 | **The app's own glue is not tested by any machine.** Panels, clicks, which Mac a tile means. Two defects of exactly this kind were found by review, and four fixes there have not been clicked by a person. | A UI test target that drives the panels; until then the list in CLAUDE.md, "Not verified by a person yet". |
| G10 | **Sanitizers and the mutation run are by hand.** Neither is in CI: the mutation run takes two hours. | A weekly CI job for each, beside the weekly proofs. |
| G11 | **The weekly Tamarin job has not been seen to pass in CI.** It passes on the Mac it was written on. | Start it once by hand and fix what a different machine finds. |
| G12 | **Real packet loss, a real radio, a link above gigabit.** Loss is imitated above TCP; Wi-Fi dropping mid-drop is tested through a proxy. | `dnctl`/`pfctl` (needs root) between two Macs; a drop over Wi-Fi with the radio switched off. |

### Outside what is defended, by decision

These are not gaps in the checking. They are the edges of the threat model
(`docs/security/threat-model.md`), listed so that nobody takes silence for a claim.

- **Software already running as the user.** It has the user's whole account; the app is not
  sandboxed. With no Secure Enclave, the trust file's key is beside it.
- **A flood from many addresses.** Three addresses at the arrival rate can keep a Mac out.
  One address cannot.
- **Volume and timing.** Who sends how much to whom, and when, is visible on the network.
- **Time under someone else's control while the Mac is off**, and the trust file put back
  from an older copy.
- **"Refused for good" is the newest 2,000 tombstones**, and the count of elapsed time is on
  disk as of its last hourly write. Both are stated limits, and both could be made
  guarantees (the owner's decision).

### No outside audit, and no release provenance

Everything on this page was done by the people (and agents) who built the app, or by
reviewers they chose. **Nobody independent has audited it.** Releases are built and signed
on one Mac with no reproducible build and no attestation, and the updater's own checks live
in another repository that this work did not review. Private vulnerability reporting is
described in `SECURITY.md`.

### In the order we would do the work

1. Decide G2 (what a resume believes), and with it the tombstones and the hourly write.
2. Run this build between two Macs and click through the app's glue (G9, G12).
3. Put the sanitizers and the mutation run in CI, and see the Tamarin job pass there (G10, G11).
4. Trace validation for the classes around the machines (G1).
5. Coverage-guided fuzzing of the pure core and the parsers on Linux (G4).
6. A model of the disk gate (G3), then of Forget as a message (G8).
7. Settle the four handshake guards (G5); CryptoVerif for the pairing bound (G6).
8. An outside audit, once the above has made it cheap to do well.

## Running it

```
./build.sh verify                    all of it that a machine runs: 12, 16, 3, 1, 2, 15, 4, 5, 6, 7-10, 13
./build.sh verify quick              about a minute: no Tamarin, and of the tests the pure core's
python3 formal/check.py              the models: 1, 2, 4, 15 (TLA+ in minutes, Tamarin in minutes)
python3 formal/check.py tla | tamarin | register | Drop     one kind, or whatever has "Drop" in its name
python3 formal/test_check.py         the runner's own judgement, against canned tool output (16)
python3 formal/sas-bound.py          what a six-digit code is worth: counted, and played (3)
swift test                           the tests: 4-10
python3 scripts/mutate.py [word]     break each guard, expect a test to fail (14); about two hours for all
python3 scripts/check-layers.py      the layers and the purity of the core (12)
python3 scripts/test-capabilities.py programs that must not compile (13); needs a build
swift test --sanitize=thread --build-path .build-tsan       the suite under ThreadSanitizer (11)
NIMBUS_WALK_SEEDS=300 swift test --filter TrustCoreTests    a long hunt with the random walks (5)
NIMBUS_SEED=n swift test --filter FuzzTests                 one fuzzer seed again (10)
python3 scripts/bench-loopback.py OLD NEW                   the data path, one build against another (20)
```

The models need Java (`brew install openjdk`), and the proofs Tamarin
(`brew trust tamarin-prover/tap && brew install tamarin-prover/tap/tamarin-prover`). TLC itself is
fetched once into `formal/.tools/` and checked against a pinned SHA-256.

## The formal models in detail

The specification the models are *of* is `docs/plans/secure-drops-plan.html`; this folder is
that plan's claims, written so that a tool can refuse them.

### The runner fails closed

A run counts only when the tool exited as it does for the outcome it printed, the output is
whole, and what it says is exactly what was required.

- **`tamarin/lemmas.json` is the register of every lemma the theories must prove**: what each
  claims, under what, about which Swift, exercised by which tests. A lemma missing from a
  summary, one not in the register, one twice, one left incomplete or falsified, a theory that
  is not well-formed, a summary cut short, a non-zero exit, a timeout: each fails. A mutant
  must falsify the lemma named for it; one that verifies it has survived, and that fails too.
  A lemma is added or retired in the register in the same change as the theory.
- TLC's exit code must agree with what it printed. Asking for something that matches nothing
  is an error.
- A run that must fail is asked for the one thing it must fail on. Where a model can fail in two
  ways, which one TLC reports first depends on the machine: a mutant that deadlocks on a Mac
  was reported on CI by a liveness property it also breaks.
- `test_check.py` is the list of ways the runner must refuse (41 cases, no prover).
- Every run's raw output, command, tool versions, source revision and input hashes are kept
  under `formal/.results/` (not in git).
- A theory's lemmas are asked for six at a time: all at once, the handshake theory passed
  20 GB; this way 5.6 GB.

### What is modelled, and what is claimed

| Model | About | Claims (each a named lemma or property the tool checks) |
|---|---|---|
| `tamarin/NimbusHandshake.spthy` | Noise XX with the prologue and the third Split output (`master`); the hello that says what a connection is for; the drop's keys; a data connection taken before any record; a record; resuming; a speed test both ways. | 38 lemmas (`lemmas.json`), 4.5 minutes. Every one's only escape is the OTHER Mac's key given away before the handshake finished: this Mac's own may be known from the start, and either may leak later. Secrecy of `master`, the transport keys and what is written; injective agreement on keys, hash and openings; the purpose the responder acts on is the one the initiator said; a data connection attaches, a record is written and a drop resumes only for the Mac holding the drop's keys; nothing sealed for a speed test is written for a drop. 13 mutants, each a flag that removes one guard, each falsifying its lemma. |
| `tamarin/NimbusPairing.spthy` | commit / nonce / reveal and two spoken codes, with someone in the middle of every connection who hears the codes and can steer a short code whenever they hold its last input. Pairing by identity number. | 5 lemmas, 15 s. What a Mac stores as "the Mac my person was pairing with" is that Mac's own key, and is one exchange (same hash, same two values), in either role, in any number of pairings at once. Two mutants (the reveal not checked; the hash left out) each falsify two lemmas. |
| `tla/PairingMachine.tla`, `Pairing.tla` | The pairing transaction at one Mac, as a state machine, against an other end that keeps to nothing. | stores only when its own person typed right AND the other said so; each message once and in order; codes only after the commitment is opened; three tries; final is final |
| `tla/PairingSystem.tla` | Two Macs that keep to the pairing, two people, a connection that may be cut, time that may run out. | honest Macs never trip each other's guards; stored means both people confirmed; one-sided only when time or the link ran out; it ends; both can store |
| `tla/PairingGate.tla` | Two people asking each other at once: the gate, the wait, the tie-break, and the yes as its own step. | the gate holds one pairing; a request is never put on screen beside a pairing under way; every request is answered. That the two never turn each other away holds if nobody starts a pairing with a request on screen (an assumption with a name; the run with it false shows how). |
| `tla/TrustCore.tla` | What the trust store decides about one key: standing, pairing, every way trust is withdrawn, what the passing of time ends, a tombstone pushed out, when the file is written. | (the machine itself; the properties are in the next two) |
| `tla/TrustWithdraw.tla` | That machine with the lock, the `afterwards` list, a disk that refuses writes, two people pairing again, a restart. | a live session means the key is paired or the session is being ended; every live session is on the list; nothing outlives the withdrawal; acknowledged means refused on disk; no socket work under the lock; trust returns only by two people pairing |
| `tla/Expiry.tla` | A key's end against a calendar that says anything, restarts and unclean reboots. | paired for no more up-time than its life (net of what an unclean reboot under a held calendar loses: less than the hour between writes); only the count refuses for good; past its end never paired again; ends never move later; no session past its grace |
| `tla/RoundMachine.tla`, `Rounds.tla` | A drop's conversation at each end, as a machine, against anything. | 19 properties of the sending end and 24 of the receiving end: nothing before the yes; only what was offered; each message in its turn; complete only as an answer and only when in place; a withdrawal says nothing; patience ends it |
| `tla/Drop.tla` | Two of those machines and a network: damaged records, cut data connections, a lost conversation, a data connection held back, a person who may say no, a sender that may lie. From the offer to the end. | no wrong bytes; nothing placed that is not whole; "sent" means saved; no stream key twice; nothing before the yes; nothing written once judged; it ends, and (within its patience) arrives |
| `tla/Admission.tla`, `AdmissionSystem.tla` | Which connection has a place at the listener and which gives way; a listener that asks that machine, one honest Mac, and everyone else. | no pool over its limit; a newcomer within the rate gets a place; the oldest gives way and has proved nothing; a paired key never gives way; an address decides only who waits; when a drop ends its places end with it |
| `tla/*Refinement.tla` | **The Swift code is that machine**, four times: `PairingMachine`, `TrustCore`, `RoundMachine`, `Admission`. | the two transition relations are equal, both ways |

### How a model is tied to the Swift

Three strengths of tie, and each claim has exactly one of them.

1. **The same machine.** `PairingMachine.swift`, `TrustCore.swift`, `RoundMachine.swift` and
   `Admission.swift` are pure value types in `NimbusCrypto`. For each, a test in
   `NimbusCryptoTests` drives the Swift through every state of the specification under every
   event that can happen there and writes the transition relation out (`tla/*Impl.tla`,
   generated; `swift test` fails if a file is stale, or if an event the specification allows
   could not be made to happen), and TLC checks that relation EQUAL to the specification's
   `Step` (`*Refinement.tla`): every transition the code makes is the specification's, and at
   every state the specification reaches every event is a transition the code makes. So what
   is checked of `Step` in the system models is checked of the Swift machine, over the
   abstraction each `.tla` states at its top (what of the Swift state the specification sees,
   what it does not, and why that is safe).

   That is only the whole truth if what the code does depends on nothing the abstraction
   leaves out, and effects are compared by more than their names. So each machine's test
   also (a) walks at random with many concrete machines per abstract state, varying
   everything the abstraction omits (values, limits, histories, clocks that jump and reboot),
   labelling each step by what the numbers say, with seeds that are printed
   (`NIMBUS_WALK_SEEDS=300` for a long hunt); and (b) checks what each effect carries against
   the protocol. Twice the walks found what one machine per state had not: a session of an
   earlier pairing whose deadline belonged to nothing (after some 1,500 walks).

   | Machine | States | Transitions | Random walk, ordinary run | Longest hunt |
   |---|---|---|---|---|
   | `PairingMachine` | 99 | 1,683 | 760,000 steps | 76.5 million |
   | `TrustCore` | 52 | 2,016 | 80,000 steps | 4.8 million |
   | `RoundMachine` | 51 sending, 109 receiving | 918 and 3,052 | 386,000 steps | 3.4 million |
   | `Admission` | 501, 381, 553, 81 (four sets of small limits) | 67,169 | 330,000 steps | |

   After a deliberate change: `NIMBUS_WRITE_IMPL=1 swift test --filter NimbusCryptoTests`,
   change the `.tla` to match, `./build.sh verify`.

2. **Pinned by vectors.** The cryptographic functions the Tamarin models name are the ones
   `scripts/vectors.py` (a second implementation), the published Noise vector and Wycheproof's
   X25519 vectors hold the Swift to, byte for byte (`VectorTests`, `CryptoTests`,
   `WycheproofTests`). The models treat those functions as ideal. That the Swift calls them
   in the order the model's rules say is by reading: each rule names the function it stands for.

3. **By reading, with a mutant on each side.** The classes around the machines (`Trust`,
   `PairingSession`, `SendSession`, `ReceiveSession`, `DropListener`) own the locks, the
   clocks and the sockets and carry out what a machine decides; the system models
   (`TrustWithdraw`, `Expiry`, `Drop`, `AdmissionSystem`, `PairingGate`) say how. Nothing
   mechanical ties a class to its model. What there is: each guard the model depends on is a
   line whose removal must make the model fail (`check.py`), the same guard in the Swift has
   a line in `scripts/mutate.py` whose removal must make a test fail, and tests that drive
   the class under threads (`TrustShellTests`, `ModelFindingsTests`, the chaos tests).

### Mutants

A model that holds may hold because it says nothing. Every model has mutants (one guard removed
each) in `check.py`, and each must fail on the property named for it; a mutant that passes is a
failure of the run. Several are the code's own history: `TrustCore.tla` with the track check
gone is `Trust.track` before 2026-11-24; `PairingGate` with `Waits = FALSE` is
`DropListener.request` before the both-asking fix; `Drop` with `KeepsOutLate = FALSE` is the
receiver before it refused late data connections; `AdmissionSystem`'s "a full pool turns the
newcomer away" is the listener before the first review. Mutants that passed on their first run
each exposed a model that said nothing, and the model was made to say it.

### What the models found

- **`TrustWithdraw.tla`, first round.** A session asked "is this key paired?" at the start of
  its handshake and registered at the end; a withdrawal in between ended nothing. Fixed in
  `Trust.track`.
- **`TrustCore.tla`, writing it.** Reset Identity ended only the sessions of keys still on a
  list: a key whose calendar date and then elapsed end had both passed is on neither, and its
  drop ran on under the identity being destroyed. And Remove on the pair-again list left that
  Mac's running drop alone (found by the random walks). Both fixed.
- **`TrustCore`, as a function of its inputs.** A failed hourly write of the trust file was
  tried again at every tick, not twice a minute. Fixed.
- **`Expiry.tla`.** A limit, now written down: the count of elapsed time is on disk as of its
  last hourly write, so an unclean reboot under a held calendar loses the time since.
- **`Drop.tla`, rebuilt on the machines.** A data connection could attach, and write, while
  the drop was being put in place (an independent review found the same by reading). Fixed.
  And two limits the old model did not have: a conversation cut before the sender has heard
  the first plan is not got back, and patience is counted (three fruitless reconnects, five
  idle rounds).
- **`AdmissionSystem.tla`, its first run.** When a drop ended, the places it had given to data
  connections stayed taken. Fixed. And, making time an argument: the arrival rate was timed on
  the calendar, which can be set back. Fixed.
- **`PairingGate.tla`, made honest.** The model had a guard with no line in the code. With it
  gone: a yes given in the instant this Mac's own pairing with that same Mac is being turned
  away leaves both with "busy". Left as it is; stated.
- **The Tamarin theories.** No trace the Swift would allow. Of the theory itself: with the
  openings out of the hash every old lemma still held, and a lemma now notices.

## What is not claimed

- Nothing about `Trust`, `PairingSession`, `Channel`, the sender, the receiver or the listener
  is *proved* of the Swift; see tie 3. The machine-checked tie is the four machines, over
  their stated abstractions, at their stated bounds.
- TLC results are for the bounds in `check.py` (a handful of chunks, faults, sessions, units
  of time; small limits for admission) and say nothing beyond them.
- The handshake lemmas are about a peer key that some Mac made. A key the attacker invented
  completes a handshake too, as Noise XX intends; that it then counts for nothing is `Trust`'s
  doing, which Tamarin does not see.
- Four mutant flags in the handshake theory did not settle within 12 GB, for or against: the
  stream key without the connection number (and with it the header not bound to its chunk),
  the resume proof without the hash, one resume label. They are in the file, marked, and not
  run. Nothing is claimed from the lemmas about those four guards; `scripts/mutate.py` and the
  tests hold them.
- "No two handshakes share a `master`" is proved per end for a peer whose key was not given
  away; the unconditional form did not finish.
- Tamarin's cryptography is ideal. Small subgroups, non-canonical encodings, nonce limits and
  side channels are outside it; the code's guards for those are tests, not proofs.
- A six-digit code agrees by luck twice in a million pairings. No proof removes that; the
  commitment is what stops anyone improving on it (`computational/pairing-bound.md`: an
  argument under random oracles, not a machine-checked proof).
- Not modelled: the manifest and `SafeTree` (tested adversarially: `ContainmentTests`,
  `docs/security/filesystem-containment.md`), discovery, retire and the Forget notice as
  messages, this Mac's own key running out on schedule inside the trust machine.
- Software running as the user, as everywhere else in this project.
