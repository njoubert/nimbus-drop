# Formal models of Nimbus Drop

What is here is checked by a machine, every time: `./build.sh verify` (or `python3 formal/check.py`).
The specification the models are *of* is still `docs/plans/secure-drops-plan.html`; this folder is
that plan's claims, written so that a tool can refuse them. Each claim, with the kind of evidence
it has and its limits, is in `docs/security/claims.md`.

```
python3 formal/check.py            everything (TLA+ in minutes, Tamarin in minutes)
python3 formal/check.py tla        the TLA+ models and their mutants
python3 formal/check.py tamarin    the Tamarin models and their mutants
python3 formal/check.py register   the lemma register against the theories (no prover)
python3 formal/check.py Drop       whatever has "Drop" in its name
python3 formal/test_check.py       the runner's own judgement, against canned tool output
python3 formal/sas-bound.py        what a six-digit code is worth: counted, and played
```

Needs Java (`brew install openjdk`), and for the proofs Tamarin
(`brew trust tamarin-prover/tap && brew install tamarin-prover/tap/tamarin-prover`). TLC itself is
fetched once into `formal/.tools/` and checked against a pinned SHA-256.

## The runner fails closed

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

## What is modelled, and what is claimed

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

## How a model is tied to the Swift

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

## Mutants

A model that holds may hold because it says nothing. Every model has mutants (one guard removed
each) in `check.py`, and each must fail on the property named for it; a mutant that passes is a
failure of the run. Several are the code's own history: `TrustCore.tla` with the track check
gone is `Trust.track` before 2026-11-24; `PairingGate` with `Waits = FALSE` is
`DropListener.request` before the both-asking fix; `Drop` with `KeepsOutLate = FALSE` is the
receiver before it refused late data connections; `AdmissionSystem`'s "a full pool turns the
newcomer away" is the listener before the first review. Mutants that passed on their first run
each exposed a model that said nothing, and the model was made to say it.

## What the models found

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
