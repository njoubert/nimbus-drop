# What has to be trusted

For any claim in `claims.md` to hold, all of this has to be right. None of it is verified here.

## Outside the repository

| | Trusted to | Why it is not checked here |
|---|---|---|
| **CryptoKit** (X25519, AES-256-GCM, SHA-256, SHA-512, HKDF, HMAC, P-256) | be those functions, in constant time where it matters | Apple's. Checked only as far as the published Noise vector, `scripts/vectors.py` and Wycheproof's X25519 vectors reach: that the bytes are right, not that the code is. |
| **`SecRandomCopyBytes`** | give bytes nobody can predict | Every nonce, ephemeral and static key comes from it. |
| **The Secure Enclave** | use its key only on this Mac | Seals the trust file. On a Mac without one (a virtual machine) the file is protected by its permissions alone, and the log says so. |
| **macOS**: the kernel, APFS, `openat` and `O_NOFOLLOW`, `renamex_np`, the continuous clock, the boot session id, Bonjour, the firewall | do what their manual pages say | `SafeTree` rests on the first four; key lifetimes on the next two. |
| **The Swift compiler and runtime** | compile what is written; trap, not corrupt, on overflow and out-of-range | Access control (`internal`, `package`) is how secrets are kept inside the core. It is not process isolation: all of the app is one process. |
| **The build and release chain**: Xcode's toolchain, the owner's Mac, his Developer ID key, Apple's notary, GitHub's release storage, `nimbus-updater` | deliver the binary that was built from this source | Releases are built and signed on the owner's Mac. There is no reproducible build and no provenance attestation. The updater's checks (team id, HTTPS) are its own. |
| **The verification tools**: TLC, Tamarin, Maude, Python | not have a bug that turns "violated" into "holds" | `formal/check.py` fails closed on everything it can see (exit codes, a summary cut short, a lemma missing), and every model has mutants that must fail. A tool that lies consistently would get past both. |

## Inside the repository

The **Core** is `NimbusCrypto`: the handshake, the keys, and the four decision machines
(pairing, trust, a drop's rounds, admission). It is pure (no socket, file, clock, lock, thread
or log), about 2,000 lines, and it is what the models are about. Everything else is the
**Application** in the sense of `docs/plans/security-assurance-plan.md`: it cannot read secret
bytes (the compiler), and it carries out what the Core decides.

What is still trusted of the Application, because nothing mechanical checks it:

- **The shells** (`Trust`, `PairingSession`, `SendSession`, `ReceiveSession`, `DropListener`):
  that they call their machine for every decision and carry out its effects in order, under
  the lock the system models assume. Tied to the models by reading, by tests and by mutants.
- **`Channel`**: that it runs the handshake as `Noise` gives it and seals every message.
- **`SafeTree` and `Manifest.validate`**: every file operation on a drop. Tested adversarially
  (`ContainmentTests`, `SecurityTests`); not modelled.
- **`EnclaveStorage`**: whole-file write, fsync, rename, fsync of the folder.
- **The app's glue** (`AppModel`, the panels, the command line): that the question shown is
  the question answered. Two defects of exactly that kind were found by review on
  2026-11-24 and fixed; nothing but review looks there.
- **The lints** (`scripts/check-layers.py`): patterns in text. They catch a mistake; they do
  not prove purity, and say so.

## What each kind of evidence is worth

| Evidence | Says | Does not say |
|---|---|---|
| Tamarin proof | no attack exists in the symbolic model, for any number of sessions | anything about the bytes, the probabilities, or the Swift |
| TLC run | the property holds in every state of the model, at the stated bounds | anything beyond the bounds, or about the Swift |
| Refinement (`*Refinement.tla`) | the Swift machine and the model's `Step` are the same relation over the stated abstraction | that the abstraction is right (tested by varied random walks), or anything about the shell |
| Mutant | the property or test notices that guard being gone | that it notices every way of being wrong |
| Vector | the Swift computes the same bytes as a second implementation | that either is right where both agree |
| Test | this attack fails | that the next one does |
