**Nimbus Drop secure drops security review**

22 November 2026 · Review of protocol 3 draft 5

The design has a credible cryptographic foundation, but I would not approve this draft as the implementation specification. Three issues need resolution first: expiration does not work under the clock manipulation the draft allows; completing an unauthenticated Noise handshake can escape the stated resource limits; and retirement does not specify revoking sessions already authenticated by the retired identity.

I did not find a practical man-in-the-middle break in the intended commitment-based pairing exchange. That conclusion depends on accepting each pairing message exactly once and keeping its transcript, keys, codes and user interface immutable. Several other findings concern missing requirements or overstated guarantees, rather than demonstrated exploits in an implementation.

The source plan was treated as evidence to assess, including its previous review and “decided” recommendations. Those statements were not treated as instructions or as proof that a property holds.

**Scope and evidence**

The reviewed plan is `docs/plans/secure-drops-plan.html`, draft 5, with SHA-256 `bfb9daea0841a9f3292632b736ae08d9f9f9c17b08ac43d7aedc098177d67f6a`. Plan line numbers below refer to that file. The local implementation was at commit `71694e8eac02c52ac51b1caa5a2375d8d178ae8a`; the draft was untracked. Source comparison covered selected receiving, framing, manifest, resume and CLI paths. Protocol 3 is proposed, so this is a design review with implementation cross-checks, not an audit of completed encryption code.

Severity reflects the stated LAN attacker model. “High” includes a significant denial of service or a broken credential-revocation guarantee; it does not imply plaintext recovery. A small CryptoKit experiment confirmed the public-key encoding behavior described below. No active attack was run against another computer.

| Finding | Priority | Nature |
| --- | --- | --- |
| R1 Expiration can stop advancing | High | Counterexample to P16 under the stated clock model |
| R2 Unpaired peers escape admission limits | High | Missing resource and state requirements |
| R3 Retirement leaves existing authorization undefined | High | Missing revocation requirements |
| R4 Unreadable trust storage loses revocation history | Medium | Recovery and persistence design gap |
| R5 Custom pairing and key derivation need an exact specification | Medium | Assurance and state-machine gap |
| R6 CLI consent conflicts with the proposed policy | Medium | Existing behavior can survive migration |
| R7 AES-GCM usage limits need byte accounting | Medium | Extreme-volume cryptographic limit |
| R8 The in-place performance requirement conflicts with macOS 15 APIs | Medium | Feasibility and implementation-risk issue |
| R9 Attach authenticators permit a first-arrival replay race | Low | Availability and claim precision |
| R10 Identity encodings require an explicit policy | Low | Identity bookkeeping and claim precision |

**R1 — A stored maximum wall time cannot guarantee expiration**

Plan: Key expiry, lines 710–716; P16, line 804.

The proposed time is `max(latestTimeEverSeen, currentWallClock)`. This prevents time from decreasing. It does not ensure time advances.

Suppose B has paired with A and recorded A’s expiration. An attacker has copied A’s private key and can keep B’s time source below that expiration. B’s recorded maximum then stops advancing. The copied key remains acceptable after its intended lifetime in real elapsed time. Repeated backward adjustments can have the same effect. This is a counterexample to the draft’s clock model, rather than a claim that an arbitrary LAN host can directly set every Mac’s clock.

Change the specification to require an elapsed-time deadline while the system is running, using a clock that advances through sleep. Define how elapsed lifetime is preserved across process restarts and how reboot or time uncertainty is handled. Either require a trustworthy source of calendar time or fail closed when the remaining lifetime cannot be established. A high-water mark over an untrusted wall clock cannot replace that assumption. Apple provides an appropriate running-system primitive in [ContinuousClock](https://developer.apple.com/documentation/swift/continuousclock/clock-implementations); persistence across boots is a separate design problem.

Also narrow the lifetime guarantee. Line 710 caps expiration at 90 days from pairing, based on a date asserted by the key holder. It does not authenticate when that key was originally created. A thief cannot extend an already pinned deadline, but can assert a fresh date to a verifier that has never trusted that identity. Fresh human pairing is still required. State the guarantee per verifier’s original trust grant, and retain expired-key tombstones when ordinary entries are removed.

Scheduled expiration explicitly permits existing drops to finish. Consequently, “the copy is worthless after that date” is too strong even with a correct clock. Specify whether expiration prevents new authorization only or also limits active sessions. If sessions may finish, give them an absolute maximum lifetime; continued progress alone must not keep an authenticated session alive indefinitely.

Acceptance tests must cover a frozen clock, repeated rollback, sleep, process restart, reboot, forward jumps, and a session started just before expiration.

**R2 — Noise completion is not authorization to consume unlimited resources**

Plan: lines 617, 626–630, 660, 671 and 696; P13 and P17.

The 1 KB, ten-second and 64-connection limits end at handshake completion. Any LAN attacker can generate a static key and complete Noise XX. That proves possession of an arbitrary key, not membership in Known Macs. The attacker can then leave connections waiting in hello, pairing or identity-verification states. Throttling panels does not bound sockets, workers, cryptographic operations or retained state.

Keep separate admission classes for incomplete handshakes, completed handshakes from unpaired keys, paired peers, and accepted drops. Specify global limits and absolute deadlines for every class. Acquire admission before spawning a worker. Keep unpaired peers under a global connection and memory budget until their authorization actually changes. Apply rate limits across addresses and identities, since both are cheap to vary.

Bound outbound discovery probes as well. Forged Bonjour advertisements can trigger expensive outbound work and cache churn. The “one key agreement” estimate at line 630 is inaccurate: constructing XX message 2 includes both `ee` and `es`, plus ephemeral-key generation.

Per-object limits also need an aggregate budget. A 512 MB control message can require substantially more memory after decoding and indexing; stream buffers, manifests, jobs and ledgers accumulate across drops. Bound total allocated bytes, pending fragments, event history and log amplification. A person accepting a tiny advertised drop must not implicitly authorize arbitrary metadata allocation.

The current receiver releases its stranger slot after its first frame, so simply adapting that structure is insufficient. See [Receiver.swift, lines 80–95](https://github.com/njoubert/nimbus-drop/blob/71694e8eac02c52ac51b1caa5a2375d8d178ae8a/Sources/NimbusDropCore/Receiver.swift#L80-L95).

Acceptance test: repeatedly complete handshakes with fresh keys and leave them unpaired, including through `verify`; demonstrate bounded sockets, tasks, memory, probe activity and logs without human interaction.

**R3 — Retirement must revoke active sessions and pending decisions**

Plan: immediate-stop promises at lines 219 and 483–488; session lifetime at 750–752; retirement at 758–765.

A thief can establish a session with the copied identity before the legitimate owner sends a retirement notice. The draft retires the Known Macs entry, but does not require terminating that existing session, cancelling its pending offer, invalidating its attach/resume keys or rejecting a later accept-panel callback. An implementation can follow the written steps while preserving authorization after the interface says the identity has stopped working.

Define retirement as an atomic authorization transition. Persist the tombstone, prevent new authorization, cancel pending offers and pairing transactions, terminate the identity’s other active control/data sessions, invalidate attach and resume capabilities, and only then acknowledge success on the retirement connection and close it. Coordinate in-flight disk operations so callbacks cannot publish a completed drop after revocation. Already delivered files remain delivered; retirement cannot undo their disclosure.

Apply an explicit policy to local Forget, replacement and Reset too. A compromised peer must not retain access through an object that was authenticated before its trust entry changed. Keep scheduled expiry’s optional grace distinct from a compromise-driven reset.

Test retirement while data is flowing, while an offer awaits consent, during reconnect, and concurrently with the last completion message. Restart after every persistence boundary and verify that an acknowledged retirement survives.

**R4 — Unreadable trust storage must not silently become a new trust database**

Plan: lines 598–606, 712 and 758–764; P12 and P14.

The draft treats an unreadable identity as a new identity and an unreadable Known Macs store as empty. Disk corruption, interrupted writes or a temporary enclave-access failure can therefore erase retirement and expiry history through the normal recovery path. Previously paired keys are no longer trusted automatically, which is a useful safeguard, but the stronger promises that retired or expired identities cannot be paired again no longer hold.

Distinguish first installation, expected migration, temporary access failure, damaged state and an explicit identity reset. Preserve damaged files and make recovery explicit before permitting new trust decisions. A conservative recovery policy stops trust-changing operations while the database is unavailable; another policy must clearly disclose that revocation history was lost. Do not regenerate identity merely because the enclave is temporarily unavailable. This is a recovery-policy issue, not an automatic authentication bypass.

Specify authenticated schema and identity binding, a nonce policy for every encrypted rewrite, atomic replacement and durability ordering, interprocess exclusion for app/CLI access, and crash recovery spanning identity and trust-store updates. Retirement acknowledgements must follow durable storage. Explain which wrapping material survives normal X25519 rotation and which survives Reset, so retaining the old database is actually possible.

Keep the accepted rollback limitation explicit: encryption detects modification, not restoration of an older valid file. That limitation must qualify the absolute retirement claims. It does not require treating ordinary corruption as a fresh installation.

**R5 — Specify and review this exact cryptographic composition**

Plan: lines 244, 578, 587–593, 604, 657 and 674–700.

The commitment-based short authentication string is a sensible approach. I found no better-than-guessing attack on the intended sequence. A commitment fixes the sender’s nonce before the receiver contributes its fresh nonce; the final Noise handshake hash binds the codes to the keys and channel. Hearing the codes adds no secret information. This rationale is consistent with [ZRTP’s commitment discussion](https://www.rfc-editor.org/rfc/rfc6189#section-4.4.1.1), but the draft’s two-directional HKDF construction is its own protocol composition.

Replace “we do not invent any” with an accurate description of the custom parts. Define a normative pairing state machine: one final `h`, one commitment, one `Nr`, one `Ns`, one purpose, one deadline and one UI transaction. Reject duplicates, replacements, restarts, unexpected message types and callbacks from an earlier transaction. Bind the stored key and replacement decision to the same transaction the person verified.

A permissive implementation that accepts a replacement `Nr` after `Ns` is revealed permits a malicious responder to search candidate nonces offline for a targeted six-digit code. That is dangerous implementation latitude, not a demonstrated break in the intended exact-once protocol. The two typing retries are reasonable only while the expected code remains immutable.

Clarify P4’s probability. Approximately one in a million applies to one designated honest endpoint. Across two honest endpoints, either can store the attacker’s key independently because the attacker can send its own `paired {}`. The probability that at least one accepts is approximately `2 × 10^-6 − 10^-12` for one joint attempt, under the intended independent-code model. The two six-digit codes do not give each endpoint a twelve-digit authentication guarantee.

Write out the third Split output precisely. Standard Noise Split returns two transport states; the extra master is a Nimbus extension. I found no attack merely because it is a third HKDF output, but ordinary Noise vectors do not test it. Explicitly distinguish Noise’s HKDF argument conventions from the application `KDF` helper. Specify handshake framing and payloads, serialization, empty values, error handling, key destruction and counter ownership. Define exactly how the 30-digit identity number is encoded and iterated.

Require independently generated vectors for the complete construction, including master, all application keys, records, pairing and resume. Remove the blanket prohibition on third-party cryptographic code as a security principle: compare the maintenance and audit burden of a mature implementation with the burden of implementing Noise locally. Operating-system primitives alone do not validate a protocol composition. [Noise’s specification](https://noiseprotocol.org/noise.html#the-symmetricstate-object) defines the standard Split operation.

**R6 — Bring CLI authorization into agreement with the consent promise**

Plan: line 259, line 770 and decision D6 at line 903.

The current CLI automatically calls `accept(destination:)` on every offer and supports `--any-network`. Constraining it to paired keys still leaves unattended acceptance. That contradicts the proposed statement that pairing is not permission and the recommendation to defer unattended/nonlocal use. See [CLI.swift, lines 65–83](https://github.com/njoubert/nimbus-drop/blob/71694e8eac02c52ac51b1caa5a2375d8d178ae8a/Sources/NimbusDrop/CLI.swift#L65-L83).

Choose an explicit policy. For the stated 0.3 design, require per-drop terminal confirmation and the same local-network restrictions as the GUI. If unattended receiving is a product requirement, define it as a separate deliberate authorization grant, disabled by default and scoped to particular peer keys, destination, lifetime, volume and concurrency limits. Qualify the universal consent claims accordingly. A paired or compromised peer can otherwise fill disk without a new human decision.

Tests should verify that completing pairing never implicitly accepts a pending drop and that CLI flags cannot silently restore an authorization path the GUI forbids.

**R7 — Bound encrypted bytes as well as records**

Plan: lines 733–744.

The proposed maximum permits `2^32 × 64 MiB = 2^58` plaintext bytes under one stream key, before accounting for header encryptions. The [Noise AES-GCM guidance](https://noiseprotocol.org/noise.html#security-considerations) gives a `2^56`-byte ceiling because security degrades with volume. This is an extreme-volume specification problem, not a practical attack on an ordinary photo transfer.

Use conservative per-key byte/block and invocation budgets, and rotate the connection with a fresh connection number before either budget is reached. Count the separately sealed headers and bodies. Specify checked arithmetic, the final valid counter and exhaustion behavior for both stream and control encryption. A unique nonce is necessary but is not the whole AES-GCM usage policy.

Preserve the current receiver’s exact expected chunk length check. Line 742 only says a length must not exceed the configured chunk size; require equality to the manifest’s expected length for that particular chunk. Specify valid file kinds, canonical end-marker fields, no data after the end marker, and representable file/chunk counts. See [Receiver.swift, lines 595–597](https://github.com/njoubert/nimbus-drop/blob/71694e8eac02c52ac51b1caa5a2375d8d178ae8a/Sources/NimbusDropCore/Receiver.swift#L595-L597).

**R8 — Change the performance gate before it encourages unsafe cryptographic work**

Plan: macOS 15 minimum, line 832’s mandatory in-place reusable buffers, and line 838’s throughput gate.

The installed Apple SDK exposes `AES.GCM.seal(inPlace:...)` and `open(inPlace:...)` with availability annotations requiring macOS 27. The older public APIs accept input and return a sealed box or new `Data`. Thus, the draft cannot assume that the explicit in-place API is available on its minimum supported OS. This was checked in the local CryptoKit interface; Apple’s [AES.GCM documentation](https://developer.apple.com/documentation/cryptokit/aes/gcm) shows both API forms.

Prototype the supported macOS 15 path before fixing the allocation requirement. Permit measured buffer allocation or copying if it meets the application throughput and memory targets. If another supported primitive is necessary, document and review that choice. Do not respond to an allocation gate by implementing GCM yourself or adopting private APIs.

Keep decrypted buffers private until authentication succeeds, including with an in-place API that may modify output before returning failure. Measure the complete disk/network pipeline, not only the AES microbenchmark. Define application goodput separately from physical link rate: a 10 Gbit/s physical link cannot deliver 10 Gbit/s of file payload after framing and transport overhead. The comparison with the measured unencrypted baseline is the useful requirement.

**R9 — An attach MAC is a one-use bearer capability until accepted**

Plan: lines 732, 740 and P11 at line 799.

The attach authenticates `session_id || conn`, but has no fresh receiver contribution. An observer who obtains a valid attach can race the original connection. If its socket arrives first, it consumes that number and stream resources. A replay cache prevents later reuse; it does not establish live key possession by the first arriving socket. Observed ciphertext can also be relayed without knowing the stream key.

This does not reveal plaintext or permit record forgery. An active network-path attacker already has the power to drop traffic, so this should not be presented as a new confidentiality break.

Either add a fresh per-socket receiver challenge to the attach proof, with bounded challenge state, or narrow P11 to the actual record-authentication guarantee and accept the bounded race as an availability limitation. In either case, make connection-number claiming atomic and bound the number of claimed numbers, idle streams and failed attempts. A challenge does not prevent an on-path attacker from relaying or suppressing traffic.

**R10 — Define what constitutes the same X25519 identity**

Plan: lines 603–606, 660, 712 and 762–763.

X25519 accepts multiple public-key encodings with the same DH behavior. In particular, the high bit of the final byte is ignored by the DH operation. A local CryptoKit experiment generated a public key, flipped that bit, constructed a second public-key object and compared DH results. CryptoKit retained the different raw bytes while producing the same shared secret; hashing those raw bytes produced different identity hashes. This agrees with [RFC 7748 sections 5 and 7](https://www.rfc-editor.org/rfc/rfc7748#section-5).

A holder of a retired private scalar can build a fresh, internally consistent handshake with the alternate encoding. A lookup using the original raw bytes can then classify it as New rather than Retired. This does not restore paired standing or bypass human verification; the attacker could already generate a wholly new identity. It is a correctness issue in the absolute identity and retirement claims.

Define the accepted identity representation before computing tags, numbers, trust lookups and tombstones. Do not assume the CryptoKit constructor canonicalizes it. Canonical encoding alone does not handle every cofactor-related equivalence discussed by RFC 7748; either narrowly define retirement for the accepted canonical identity or use an independently reviewed representation/validation policy. Test the selected policy and retain transcript binding.

**Other claims and boundaries to correct**

- The Secure Enclave P-256 wrapping key is hardware-bound. The X25519 identity is unwrapped into application memory. Replace “identity key cannot be copied” and “never leaves it” at lines 221 and 233 with “copying the stored identity file alone does not make it usable on different hardware.” Same-user malware can recover the unwrapped identity, as line 600 effectively acknowledges. [Apple’s storage documentation](https://developer.apple.com/documentation/cryptokit/storing-cryptokit-keys-in-the-keychain) distinguishes ordinary key representations from the enclave’s opaque representation.
- P1 should promise encryption of names, directory metadata and contents while acknowledging size and timing inference. No padding is specified. A one-file transfer already reveals its approximate size through total volume. Sealed headers remain worthwhile; they do not prove zero information about individual file sizes.
- Scope P9’s expected-key privacy to connections aimed at an already known identity. Initial pairing necessarily reveals an initiator key before human verification, and the design intentionally exposes the responder identity to active probes. Removing Bonjour key tags does not prevent active tracking.
- Retired-key notifications need a global and per-identity limit, not only “once per address per day.” A thief can prove one retired key from many addresses and create repeated alerts. Aggregate repeated failures in a bounded, nonmodal summary; attribution of attacks to announced names must remain visibly unverified.
- Encryption of a new connection does not validate bytes retained in a partial folder. The existing ledger accepts chunks based on ledger entries and file length, and explicitly disclaims power-loss durability. If completed resumed files are promised to match the sender’s contents, add authenticated content digests and verify retained bytes, with defined write ordering and source-change behavior. Otherwise state the narrower transit-integrity guarantee. See [Ledger.swift, lines 6–46](https://github.com/njoubert/nimbus-drop/blob/71694e8eac02c52ac51b1caa5a2375d8d178ae8a/Sources/NimbusDropCore/Ledger.swift#L6-L46). This is a persistence/integrity boundary, not an AEAD forgery.

**What should stay**

Keep mandatory human verification for unknown identities, unconditional encryption, no protocol-2 fallback, and the expected responder-key check before sending the initiator’s key on a known-peer connection. Keep names and addresses out of trust decisions. Preserve per-drop forward secrecy, distinct keys for monotonically allocated data connections, authenticated headers before trusting lengths, and verification of an entire chunk before disk writes.

The reconnect design is coherent in principle: fresh control-channel keys, proofs bound to the new handshake hash, and the original drop master retained for surviving streams. I found no version-stripping attack against binding both exact openings into the handshake. Neither observation substitutes for state-machine and implementation tests.

**Changes required before approval**

First resolve R1–R4 and make the authorization states, time assumptions, session revocation and durable trust transitions explicit. Then freeze the complete byte-level protocol and exact pairing state machine, settle CLI policy, and implement conservative key-usage limits. Validate the supported minimum-OS encryption path before imposing an allocation rule.

The next review should receive the normative specification, independent full-protocol vectors and an implementation with adversarial tests for duplicate/reordered pairing messages, post-handshake unpaired floods, malformed fragmentation, atomic attach races, revocation during active drops, clock uncertainty and crash recovery. Continue to test hostile authenticated peers against filesystem confinement, consent and quarantine. Passing tests against the implementation’s own assumptions is insufficient; tests should exercise the counterexamples above.

No critical cryptographic break was established in the intended handshake or pairing algorithm. The high-priority findings are sufficient to withhold approval of this draft, and are specific enough to turn into specification changes and regression tests.
