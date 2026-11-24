# Security assurance: the second round

Plan of 2026-11-24, on the branch `security-assurance` (stacked on `modular-verified-core`).
Status and results are at the end and are kept true as the work lands.

Four inputs (the fourth arrived while the work was under way, and controls where it and the
second disagree):

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

4. A second outside review, of the first round's branch: a work order of six findings and one
   machine (below, "The work order"). It rules two things OUT: making the Tamarin proofs a
   gate in CI, and any cryptographic checking of file contents or change to what a resume
   believes.

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
| 9 Filesystem and stored bytes | **Containment taken; stored bytes reported, not changed** (the work order below rules out changing what a resume believes). Reported for the owner: after a power cut the resume ledger can be ahead of the data it speaks for; and an authenticated content manifest (a hash per file) would change the wire and cost speed. |
| 10 Mutation and criticism | **Taken.** A mutant for every new guard in model and code. One independent critic pass over code and models, given the code and not the conclusions. |
| 11 Reproducibility, CI, supply chain | **Taken:** `./build.sh verify` gains a quick mode; tool versions printed; GitHub actions pinned by commit; `SECURITY.md`. **Left to the owner:** signed tags and release provenance (releases are built on his Mac with his keys). |

## The work order (the second outside review)

| Finding | What it asks | What is done about it |
|---|---|---|
| 1 Pairing correspondence | The abstraction written down; many concrete representatives per abstract state; payloads checked, not effect names; mutants that change a payload or add hidden state | Taken, and applied to every machine, not only pairing. |
| 2 Capabilities and narrow APIs | An inventory of what grants authority; opaque types that cannot be made without proof; what happens to authority already granted when trust goes; tests that an ordinary caller cannot make one | Taken as: secret bytes unreadable outside the Core (compiler), the types that carry authority constructible only by the code that proves it, a compile-negative fixture, and `docs/security/authority.md`. Authority is revoked through the trust store's registry of sessions (`Trust.track`), not a generation number: one mechanism, already modelled. |
| 3 Purity and dependencies | The pure core's whole dependency graph; runtime services out of what it can reach; the checker tested | Taken: the checker follows dependencies through and has its own tests; the log, the lock and the last-system-error leave the module under the pure one. Not SwiftSyntax: a third dependency for what the compiler's module graph already enforces. |
| 4 A runner that fails closed | A register of every required lemma; exact coverage; exit codes; fixtures | Taken (`formal/tamarin/lemmas.json`, `formal/test_check.py`). |
| 7 Trust lifetime | A policy table; tombstone eviction against "for good"; the points of decision; persistence and rollback said plainly | Taken (`docs/security/trust-lifetime.md`; eviction modelled). One decision left to the owner there. |
| The trust machine | `TrustCore`, in production, tied to an independent specification | Taken (the first of the four next steps). |
| 8 Filesystem containment | An adversarial harness that looks at the disk, with sentinels outside the destination | Taken (`ContainmentTests`, `docs/security/filesystem-containment.md`). |
| 5, 6 (out of scope) | Tamarin as a CI gate; content hashing | Not done. The first plan's phase 9 fix (a resume ledger believed only within its boot) changed what a resume believes, so it is NOT made: it is reported, with the evidence, for the owner. |

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

## Status (2026-11-24): done, on the branch `security-assurance`

| | |
|---|---|
| The four next steps | `TrustCore`, `RoundMachine` and `Admission` are pure machines in `NimbusCrypto`, each held equal to its TLA+ specification; `Expiry.tla` is new; thirteen handshake mutants are in the theory and run. Open: four more flags that did not settle. |
| The work order | Findings 1, 2, 3, 4, 7, 8 and the trust machine: done as the table above says. One piece of 2 is left (`Trust.store` is still `public`). Nothing of 5 or 6 was done. |
| Tests | 232 + 29 chaos + 74 in `NimbusCryptoTests` (168 + 29 + 9 before) |
| Models | Tamarin: 43 lemmas in two theories, 15 mutants. TLC: four refinements and their system models, with mutants and reachability runs (`formal/README.md`). The Tamarin job passed in CI the same day, started by hand, once its install step was fixed. |
| Mutation | 266 guards in `scripts/mutate.py` (85 before) |
| Found | 29 defects fixed, two of them in part, and five limits written down. From an independent review given the code and not the conclusions: twelve, one of them a crash on one accepted drop. From the containment tests: ten, two of them the review's leads. From building and checking the models: seven, one of them also the review's. From the fuzzers and from reading while fixing: three, one of them by the fuzzer's seed from the clock when CI ran it (a trust file that could not be written again). Listed in `formal/README.md`, `docs/security/filesystem-containment.md` and the commit messages. |
| Data path | loopback, before and after, within noise on every line (CLAUDE.md, Measured) |
| Not done | a run between two Macs; CryptoVerif; a Linux build of the core; content hashing (ruled out); the decisions in `docs/security/claims.md`, "Open for the owner" |

What was built differs from the plan above in these ways:

- The resume ledger was NOT bound to the boot (the work order rules out changing what a resume
  believes). It is the first item of "Open for the owner".
- Secret confinement went further than planned: `master` and the resume key are a type whose
  bytes only `NimbusCrypto` can read, and the log, the lock and the last system error moved to
  a module the pure one cannot import.
- The trust machine does not include this Mac's own key running out on schedule (it shares
  `rotate` with Reset, which is in it), and admission's equality is at four sets of small
  limits, not the shipped ones.
- Five agents worked in parallel in their own worktrees (the round machine, admission, the
  containment tests, the pairing contract, Tamarin) and a sixth reviewed the code without
  being told what anyone had concluded. Each branch was merged with the whole suite run.
