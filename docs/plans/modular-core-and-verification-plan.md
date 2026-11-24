# A modular core, and machine-checked claims about it

Plan of 2026-11-23. Status and results are at the end and are kept true as the work lands.

## Why

Two futures to prepare for: (1) formally verifying the cryptographic platform, and (2) a core
protocol and library that is maintained apart from the app. Both need the same thing first: the
parts that carry the security argument must be small, have no I/O in them, and depend on nothing
above them, so that a model can be about *that code* and not about an engine with a socket in
every function.

Until now there was one module, `NimbusDropCore`, where `Trust` knew `Transfer`, the pairing
transaction lived inside a class that also dialled sockets and waited on people, and anything
could call anything.

## The modules

Dependencies point down only. SwiftPM enforces the graph (a target cannot import what it does
not declare); `scripts/check-layers.py` enforces the rest (which system frameworks a layer may
touch) and runs in prek and CI.

```
NimbusDrop (app, CLI)      NimbusDropCoreTests   NimbusDropChaosTests   nimbus-chaos
        │
NimbusDropCore             the umbrella: re-exports everything below; History, FileKinds, Leftovers
        │
NimbusTransferCore         Transfer, SendSession, DropListener, ReceiveSession, SpeedTest: scheduling,
        │                  rounds, progress, reconnecting, admission
NimbusDiscovery            Bonjour, Probe, PeerTable, PeerBrowser
        │
NimbusSecurityCore         Trust (+ clock, storage, Secure Enclave file), Channel (handshake and sealed
        │                  messages over a socket), PairingGate, PairingSession, Retirement
NimbusSafeStorageCore      Manifest.validate, SafeTree, Ledger, Quarantine, Scanner, Naming
        │                  (beside the security core, not above it: neither knows the other)
NimbusNet                  Socket, Deadline, LocalHost, LocalNetwork
        │
NimbusCrypto               PURE. Crypto (CryptoKit wrappers), PublicKey, KeyPair, CipherState, Noise XX,
        │                  DropKeys, RecordHeader, PairCodes, PairingMachine. No socket, no file, no
        │                  clock, no lock, no thread. Imports Foundation and CryptoKit only.
NimbusBase                 DropError, DropLog, Sanitize, Format, Locked, Tuning (the namespace; each
                           module adds its own knobs in an extension)
```

Decisions:

- **`package` access, not `public`**, for what one core module needs of another. The public
  surface (what the app sees) does not grow because of the split.
- **`Trust` no longer knows `Transfer`.** It tracks a `TrustedSession` (a protocol in the security
  core: is it over, is it waiting for a yes, end it). `Transfer` conforms.
- **The pairing transaction becomes a pure machine**, `PairingMachine` in `NimbusCrypto`:
  `(state, event) -> (state, [effect])`, no I/O. `PairingSession` keeps the sockets, the person
  and the deadlines and asks the machine what each message means. This is the piece the TLA+
  model is *about*, and the piece checked against it transition by transition.
- **No behaviour changes in the split.** The wire is byte for byte the same (the vectors in
  `scripts/vectors.py` and the whole test suite hold it to that); anything a model turns up is
  reported and fixed as its own change, by the rules in CLAUDE.md (plan, vector, attack, mutation).
- **The data path is measured before and after** (loopback, release build): the split puts
  `CipherState`, `Socket` and `Ledger` behind module boundaries.

## The models (`formal/`)

| Model | Tool | What it is about | What is claimed |
|---|---|---|---|
| `tamarin/NimbusHandshake.spthy` | Tamarin | Noise XX with our third Split output (`master`), prologue, the attach tag and the resume proof | secrecy of `master` and transport keys; mutual agreement on keys and `h`; an attach or resume is accepted only from the Mac that holds the drop's keys; all under compromise of *other* keys |
| `tamarin/NimbusPairing.spthy` | Tamarin | commit / nonce / reveal, two codes read aloud over a channel the attacker hears but cannot alter | if a Mac stores a pairing, the key it stored is the key of the Mac whose person read the code; hearing the codes gains nothing |
| `tla/Pairing.tla`, `PairingSystem.tla` | TLC | `PairingMachine` against an other end that keeps to nothing, and at both ends over a link that may be cut | stores only when its person typed right AND the other said so; every message at most once, in order; no deadlock; it ends |
| `tla/PairingGate.tla` | TLC | two Macs asking each other at once; the gate; the queue | never two pairings on one Mac; two simultaneous requests leave exactly one going, not zero |
| `tla/TrustWithdraw.tla` | TLC | withdraw: disk, store, sessions, listeners, acknowledgement; crash anywhere | once acknowledged the key is refused across any crash; no session of it outlives the call |
| `tla/Drop.tla` | TLC | rounds, plan, done, complete, with connections cut, chunks damaged and the control connection lost | wrong bytes never reach the destination; a stream key number is never reused; with a link that eventually holds, it completes |

**What ties a model to the Swift.** For `PairingMachine`: a test walks every state the Swift
machine can reach under every event, writes that transition relation out, and TLC checks it is
*equal* to the relation the TLA+ specification defines over the same states
(`formal/tla/PairingImpl.tla` is generated; `PairingRefinement.tla` checks it). For the
cryptography: `scripts/vectors.py` (the second implementation) and the published Noise vector
already pin the Swift to the functions the Tamarin model names; the model's rules are annotated
with the Swift function each stands for. That link is by reading, not by proof, and says so.

**What a symbolic proof does not say.** Tamarin treats a hash as perfect: it cannot count a
six-digit code's one-in-a-million. That number is argued separately (and checked by simulation in
`formal/sas-bound.py`): the commitment fixes one value before the other exists, so a man in the
middle gets one blind guess per pairing a person agrees to.

## The loop

`./build.sh verify` runs everything: layers, Tamarin (`--prove`, every lemma must say verified),
TLC on every model, the refinement check, `swift test`. A model that does not hold stops it.

## Order of work

1. Baseline: tests green, loopback numbers written down.
2. Split into modules; tests and mutation paths follow the files. Tests green, numbers compared.
3. Extract `PairingMachine`; tests green; mutation lines for its guards.
4. Models, each run until it holds or shows something real.
5. Refinement check, `build.sh verify`, CI, CLAUDE.md and README.

## Status (2026-11-24): done, on the branch `modular-verified-core`

What was built differs from the plan above in these ways:

- `PairingMachine` took its `prologue` companion with it: `Noise.prologue` is in `NimbusCrypto`
  (the plan's table called it `Handshake.prologue`).
- The handshake, attach, record and resume lemmas are one Tamarin theory, as planned, and each
  is stated for a peer key that some Mac made. The plan did not say that; without it two
  lemmas are false (a made-up key completes a handshake, which is Noise XX working).
- `PairingGate.tla` has two Macs and no queue: the queue and the pause stay with their tests.
- The Tamarin proofs are not in CI on every push (minutes, and a Homebrew install): weekly.

Results:

| | |
|---|---|
| Modules | 7 under `NimbusDropCore`; dependencies enforced by SwiftPM, frameworks and purity by `scripts/check-layers.py` |
| Tests | 168 + 29 chaos + 9 in `NimbusCryptoTests` (165 + 29 before); all 85 lines of `scripts/mutate.py` caught |
| Tamarin | `NimbusHandshake` 20 lemmas verified (54 s); `NimbusPairing` 2 verified (14 s), 2 mutants falsified |
| TLC | 6 specifications, 31 runs with mutants and reachability checks, all as they must be; the largest 26,542 states |
| Code = model | `PairingMachine.swift` = `PairingMachine.tla`: 99 states, 1,683 transitions, checked both ways |
| Found | one: a session could begin under a key whose trust was withdrawn during its handshake (`TrustWithdraw.tla`); fixed, with two attacks as tests |
| Data path | loopback, before and after, within noise on every line (CLAUDE.md, Measured) |

Not done, and worth doing next: a mechanical tie for `Trust` (its withdrawal order is tied to
`TrustWithdraw.tla` by reading and by mutants only; the store is a good candidate for the same
treatment `PairingMachine` got, a pure decision core driven by a shell that owns the lock and
the disk); the same for the round protocol; admission and key expiry as models; mutants for the
handshake theory in the file; the Tamarin job seen to pass in CI.
