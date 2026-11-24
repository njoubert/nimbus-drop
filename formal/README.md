# Formal models of Nimbus Drop

What is here is checked by a machine, every time: `./build.sh verify` (or `python3 formal/check.py`).
The specification the models are *of* is still `docs/plans/secure-drops-plan.html`; this folder is
that plan's claims, written so that a tool can refuse them.

```
python3 formal/check.py            everything (TLA+ in seconds, Tamarin in minutes)
python3 formal/check.py tla        the TLA+ models and their mutants
python3 formal/check.py tamarin    the Tamarin models and their mutants
python3 formal/check.py Drop       whatever has "Drop" in its name
python3 formal/sas-bound.py        what a six-digit code is worth, by simulation
```

Needs Java (`brew install openjdk`), and for the proofs Tamarin
(`brew trust tamarin-prover/tap && brew install tamarin-prover/tap/tamarin-prover`). TLC itself is
fetched once into `formal/.tools/` and checked against a pinned SHA-256.

## What is modelled, and what is claimed

| Model | About | Claims (each a named property the tool checks) |
|---|---|---|
| `tamarin/NimbusHandshake.spthy` | Noise XX with the prologue and the third Split output (`master`); the drop's keys; attaching a data connection; a record; resuming. `NimbusCrypto`: `Noise`, `DropKeys`, `RecordHeader`. | For a peer key that some Mac made and that was not given away before the handshake finished: `master` and both transport keys are secret (this Mac's own key being known does not help, nor either key leaking later); the responder agrees with exactly one initiator on both keys, the hash and everything Split gives; a probe's answer comes from the holder of the key it reports; one handshake hash means both ends hold each other's real static key (no condition at all); a data connection attaches, a record is written and a drop resumes only from the Mac holding the drop's keys; a chunk is secret. 20 lemmas, about a minute. |
| `tamarin/NimbusPairing.spthy` | commit / nonce / reveal and two spoken codes, with someone in the middle of every connection who hears the codes and can steer a short code whenever they hold its last input. `PairCodes`, `PairingMachine`. | Whatever a Mac stores as "the Mac my person was pairing with" is that Mac's own key, in either role, in any number of pairings at once. Pairing by identity number likewise. Two mutants (the reveal not checked; the handshake hash left out) must each produce the attack, and do. |
| `tla/PairingMachine.tla`, `Pairing.tla` | The pairing transaction at one Mac, as a state machine, against an other end that keeps to nothing: every event in every order. | stores only when its own person typed right AND the other said so; each message once and in order; codes only after the commitment is opened; three tries; nothing counts before the codes; final is final |
| `tla/PairingRefinement.tla` | **The Swift code is that machine.** `PairingImpl.tla` is generated from `PairingMachine.swift` (every state it reaches, every event, every effect) and checked against `Step`, both ways. | the two transition relations are equal |
| `tla/PairingSystem.tla` | Two Macs that keep to the pairing, two people, a connection that may be cut, time that may run out. | honest Macs never trip each other's guards; stored means both people confirmed; one-sided pairing only when time or the link ran out; it ends; both can store |
| `tla/PairingGate.tla` | Two people asking each other at once: the gate, the wait, the tie-break by key. | not both turned away; never a request beside a Mac's own pairing; every request answered |
| `tla/TrustWithdraw.tla` | Withdrawing trust against sessions running and being opened, a disk that refuses writes, the app dying anywhere. | acknowledged means refused for good, across any crash; nothing the key authenticated outlives the call; no socket work under the lock |
| `tla/Drop.tla` | A drop's rounds (plan, chunks, done, plan or complete; reconnect and resume) under damaged records, cut data connections and a lost conversation. | no wrong bytes written; nothing placed that is not whole; "sent" means saved; no stream key twice; nothing written after placing; it ends, and when nobody gives up it arrives |

## How a model is tied to the Swift

Three strengths of tie, and each claim above has exactly one of them:

1. **Checked equal.** `PairingMachine.swift` and `PairingMachine.tla`. `swift test` fails if
   `tla/PairingImpl.tla` is not what the code does (`PairingMachineTests`); TLC fails if
   `PairingImpl.tla` is not what `Step` says (`PairingRefinement.tla`). So what is proved of `Step`
   in `Pairing.tla` and `PairingSystem.tla` is proved of the Swift machine, over the abstraction
   those files state (a value is good, damaged, malformed or wrong; an entry is right or wrong).
   After a deliberate change: `NIMBUS_WRITE_IMPL=1 swift test --filter PairingMachineTests`, change
   `PairingMachine.tla` to match, `./build.sh verify`.
2. **Pinned by vectors.** The cryptographic functions the Tamarin models name are the ones
   `scripts/vectors.py` (a second implementation) and the published Noise vector hold the Swift
   to, byte for byte (`VectorTests`, `CryptoTests`). The models treat those functions as ideal.
   That the Swift calls them in the order the model's rules say is by reading: each rule names
   the function it stands for.
3. **By reading, with a mutant on each side.** `TrustWithdraw.tla`, `Drop.tla`, `PairingGate.tla`
   describe code that is threads, locks and sockets (`Trust`, `SendSession`, `ReceiveSession`,
   `DropListener`). Nothing mechanical ties them to it. What there is: each guard the model
   depends on is a constant or a line whose removal must make the model fail (`check.py`), and
   the same guard in the Swift has a line in `scripts/mutate.py` whose removal must make a test
   fail. A model and a test that both notice the same missing guard is the tie.

## Mutants

A model that holds may hold because it says nothing. Every model has mutants (one guard removed
each) in `check.py`, and each must fail on the property named for it; a mutant that passes is a
failure of the run. Some are the code's own history: `TrustWithdraw` with `TrackChecks = FALSE` is
`Trust.track` before 2026-11-24; `PairingGate` with `Waits = FALSE` is `DropListener.request`
before the both-asking fix; `NoSocketWorkUnderTheLock` is the review's F7.

## What the models found

- **2026-11-24, `TrustWithdraw.tla`, `LiveMeansTrustedOrBeingEnded`.** A session asked "is this
  key paired?" at the start of its handshake and registered with the trust store at the end of
  it, with the network in between; a withdrawal of trust in that gap ended every session of the
  key and found none. The drop then ran: to a Mac just forgotten, or to whoever held a key just
  retired. Fixed in `Trust.track` (it asks again, under the lock); the attacks are
  `ModelFindingsTests`.

## What is not claimed

- Nothing about `PairingSession`, `Channel`, `Trust`, the sender, the receiver or the listener is
  *proved* of the Swift; see tie 3. The machine-checked tie is the pairing machine.
- The handshake lemmas are about a peer key that some Mac made. A key the attacker invented
  completes a handshake too, as Noise XX intends; that it then counts for nothing is `Trust`'s
  doing (`expect`, `check`, `standing`), which Tamarin does not see. As first written the lemmas
  left that premise out, and two were falsified for that reason alone.
- The handshake theory has no mutants in `check.py` (two were run by hand: the attach tag
  without the challenge, and the initiator not checking message 2's seal; each falsified its
  lemma). The pairing theory's mutants are in the file, behind `-D=`.
- "No two handshakes share a `master`" is proved only for a peer key that was never given
  away; the unconditional form did not finish.
- Tamarin's cryptography is ideal. Small subgroups, non-canonical encodings, nonce limits and
  side channels are outside it; the code's guards for those are tests (`TrustTests`,
  `CryptoTests`), not proofs.
- A six-digit code agrees by luck twice in a million pairings. No proof removes that; the
  commitment is what stops anyone improving on it (`sas-bound.py` measures both).
- Admission (who waits when there are too many connections), expiry of keys against the clock,
  the manifest and `SafeTree`: not modelled. They have attacks in the tests.
- Software running as the user, as everywhere else in this project.
