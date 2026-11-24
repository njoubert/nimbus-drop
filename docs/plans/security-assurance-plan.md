# Security assurance: the second round

Plan of 2026-11-24, on the branch `security-assurance` (stacked on `modular-verified-core`).
Status and results are at the end and are kept true as the work lands.

Three inputs:

1. The four next steps the first round left open
   (`docs/plans/modular-core-and-verification-plan.md`): a pure decision core for `Trust` held
   equal to its model; the same for a drop's rounds; models of admission and of key expiry;
   mutants for the handshake theory in the repository.
2. An outside agent's pre-audit plan (twelve phases). Recommendations, not edicts: each is
   taken, adapted or declined below, with the reason.
3. Diodon (Arquint et al., ETH Zurich, *The Secrets Must Not Flow: Scaling Security
   Verification to Large Codebases*): prove a small Core against the protocol model, and
   discharge the rest of the codebase with cheap analyses that show it cannot leak the Core's
   secrets or break the Core's invariants.

Standing rules, unchanged: this machine only; nothing merged or installed for the owner; no
change to the wire or to what trust means without the owner; the tools are the arbiters, and
a timeout is not a pass.

## The shape: a Core and an Application (after Diodon)

Diodon verifies a Core of about 1% of a Go codebase with Gobra and shows by taint, escape and
alias analysis that the other 99% keeps its hands off. There is no Gobra for Swift. What
carries over is the shape, with the compiler and two lints standing in for the analyses, and
saying so:

| Diodon | Here |
|---|---|
| Core: the protocol implementation | `NimbusCrypto`: the primitives, the handshake, the keys, and every decision machine. Pure. |
| Core proved to refine the Tamarin model's role | Each machine's transition relation exported and checked EQUAL to its TLA+ `Step` by TLC. The cryptography: vectors against a second implementation; rules named for the functions they stand for. |
| I/O independence: no secret reaches Application I/O (taint analysis) | Secret bytes are a type whose contents are `internal` to `NimbusCrypto`: no other module can read them, so none can write them anywhere. The compiler enforces it. One declared exit: the trust file's plaintext, to `TrustStorage` only (lint). A test greps a whole pairing and drop's log for every secret. |
| Core does I/O only as the model says | The Core does no I/O at all (`check-layers.py`, purity). |
| C1 to C3: Core instances are made by validating constructors and not written from outside | `private(set)` state, failable or throwing initialisers, no memberwise `package init` on a type that carries authority (lint). |
| C4, C6 to C8: threads and aliasing | Machines are value types (`struct`), copied not shared; each shell holds its machine under one lock. By construction and by reading, not by analysis. |

Not carried over, and not claimed: a proof that the shells call the machines as the system
models assume. That stays "by reading, with a mutant on each side" (`formal/README.md`, tie 3).

## The four next steps

| | What | Tie to the Swift |
|---|---|---|
| 1 | `TrustCore` (pure, in `NimbusCrypto`): standing, store, withdraw, track, expiry, reset, the save bookkeeping. `Trust` keeps the lock, the clock, the disk, the weak references and the `afterwards` list. `TrustWithdraw.tla` is rebuilt on the core's `Step`. | checked equal |
| 2 | `RoundMachine` (pure): what each message and each loss means to the sender and to the receiver of a drop. `SendSession.run` and `ReceiveSession.conduct` keep sockets, threads and deadlines. `Drop.tla` is rebuilt on its `Step`. | checked equal |
| 3a | `Expiry.tla`: the elapsed count against a calendar that lies, a reboot, a clock held still; ends never move later; a tombstone is for good. Uses `TrustCore`'s `Step` and the counting function. | checked equal (the counting as a function table) |
| 3b | `Admission` (pure): which connection gets a slot and which gives way. `Admission.tla`: no pool over its limit, a newcomer under the rate always gets a slot, the one that gives way is the oldest and has proved nothing. | checked equal |
| 4 | Handshake mutants behind `-D=` in `NimbusHandshake.spthy`, run by `check.py`. | n/a |

## The outside plan, phase by phase

| Phase | Decision |
|---|---|
| 0 Inventory, threat model, claims | **Taken.** `docs/security/`: `threat-model.md`, `tcb.md`, `claims.md` (claim IDs, each with model, code, attack, status in the plan's vocabulary; no blanket green). |
| 1 Baselines | **Mostly there** (`bench-loopback.py`, the test suite, the vectors). Re-run before and after. Two Macs, Thunderbolt, 10 GbE: not run this round (this machine only) and labelled so. |
| 2 Extract cores | **Taken** (above). Time and randomness are injected already (`TrustClock`, `PairingMachine`'s `random`). Deterministic replay: the machines' tests. Capabilities: an audit of what can be constructed without proof, fixed where it can (C1 to C3 above). **Declined:** a Linux build of the core on Swift Crypto. It is a second dependency and a second crypto backend; the owner's rules are one dependency and CryptoKit only. Recorded as his to decide. XPC or a sandbox: out of scope, noted in the threat model. |
| 3 Tamarin | **Taken.** Mutants in the file. The plan's lemma families audited against the theory; the missing ones added (purpose and direction separation, drop and speed-test isolation, replay) or reported as not statable. Tool versions recorded by `check.py`. |
| 4 Quantitative pairing bound | **Adapted.** A written argument with exact assumptions and attack accounting (`formal/computational/pairing-bound.md`), the modulo bias computed exactly, and the simulation kept as a check on the argument's arithmetic, not as the argument. **Not attempted:** CryptoVerif. A machine-checked game proof of a short-authenticated-string protocol is a research project; the argument maps the protocol onto the published proofs instead and says where it leans on them. |
| 5 TLA+ | **Taken** for trust, expiry, admission and rounds. Every result labelled with its bounds. |
| 6 Model to code | **Adapted, and stronger where it applies:** equality of transition relations rather than replay of sampled traces, for every pure machine. The shells: reading and mutants. Every counterexample a model produces becomes a test. |
| 7 Independent implementation | **Mostly there:** `scripts/vectors.py` is the second implementation and the published Noise vector pins the handshake. **Added:** Wycheproof's X25519 vectors against `KeyPair.agree` (low-order and non-canonical inputs are ours to refuse). **Declined:** live interop with Snow (a Rust toolchain on the owner's Mac for what the published vector already fixes byte for byte). |
| 8 Fuzzing | **Adapted.** This toolchain has no libFuzzer (`-sanitize=fuzzer` is refused for macOS; checked). So: seeded fuzzers inside the tests, extended to the manifest, the plan, the ledger file and the trust file; and the whole suite under ThreadSanitizer and AddressSanitizer. |
| 9 Filesystem and stored bytes | **Taken where it is a fix, reported where it is a feature.** Fix: a resume ledger is believed only within the boot it was written in (after a power cut the ledger can be ahead of the data it speaks for). Reported for the owner: an authenticated content manifest (a hash per file) changes the wire and costs speed; the cost is measured and written down. |
| 10 Mutation and criticism | **Taken.** A mutant for every new guard in model and code. One independent critic pass over code and models, given the code and not the conclusions. |
| 11 Reproducibility, CI, supply chain | **Taken:** `./build.sh verify` gains a quick mode; tool versions printed; GitHub actions pinned by commit; `SECURITY.md`. **Left to the owner:** signed tags and release provenance (releases are built on his Mac with his keys). |

## Order of work

1. This plan. Baseline: `./build.sh verify` green, loopback numbers.
2. In parallel: `TrustCore` and expiry; `RoundMachine`; `Admission`; the Tamarin work; the critic.
3. Secret confinement (after the machines land: it touches the same files).
4. The ledger and the boot; fuzzers; sanitizers; Wycheproof.
5. The pairing bound; threat model, TCB, claims.
6. Whatever the critic, the sanitizers and the models found: each fixed as its own change,
   with an attack as a test and a mutation line.
7. CI, `SECURITY.md`, CLAUDE.md, README, the report. `./build.sh verify`, `scripts/mutate.py`,
   loopback before and after.

## Status

(filled in as the work lands)
