# Nimbus Drop — notes for agents

A macOS app that sends files and folders to another Mac on the LAN: a menu bar icon that opens
a small window (there is no dropdown; the window is the app), and a headless command line. Pure SwiftPM, no Xcode project, one dependency:
`NimbusUpdater` (https://github.com/njoubert/nimbus-updater, MIT, ours). A sibling of
`../nimbus-ups-bar`, `../nimbus-net-bar` and `../nimbus-leviton-bar`: same build pipeline, same
conventions; their CLAUDE.md files cover the shared traps (DMG layout, notarization, the updater,
Login Items and the dev bundle id) in more depth than this one repeats. `README.md` is the
user-facing description; read it first and keep it true when behaviour changes. This file is the
rest: how to work here, how the engine is put together, and what was measured.

## Ground rules

- **Speed is the point.** A change on the data path (`SendSession.runStream`,
  `ReceiveSession.receive`, `Socket`, `Ledger.record`) gets measured before and after, over
  loopback and over the LAN (below). Do not add a copy, a lock per byte or a syscall per small
  write there without a number.
- **Nothing one Mac has another Mac do happens without a yes from the person at that Mac**
  (the owner, 2026-11-23, as a core tenet: "interactions between machines need consent").
  Being paired is who a Mac is, not permission for what it asks: a drop is asked about, a
  pairing is asked about, and a speed test is asked about (as first built it was not: a
  paired Mac could start one on another with nobody approving, and the owner called that
  "no good"). A new kind of request between Macs gets its question, with no Return key on the
  yes, taken away if the asker gives up, and declined when there is nobody to ask. The
  argument "it writes nothing and its cost is bounded" is not a substitute for asking. What
  needs no yes is only what a Mac says about itself: proving its key to a probe, and
  withdrawing its own trust (retire, Forget). The one standing grant is the command line's
  `--unattended-from`, which a person types for one key.
- **Nothing is sent to, or shown from, a key that is not paired**, and nothing decides who a
  Mac is but the key it proved. Names, addresses and Bonjour records are labels. A change that
  lets a name, an address or a record affect what a paired key may do, or where its tile
  points, is a vulnerability (the first plan had one; see The protocol). The one use of an
  address is in admission: which connection that has proved nothing, or that has proved only
  a key nobody here has paired, gives way when there are too many (`Admission`). It decides
  who waits, never who a Mac is, and nothing a paired key gets depends on it.
- **The plan is the specification**: `docs/plans/secure-drops-plan.html`, with the two reviews
  it went through. A change to the cryptography, the pairing, the key schedule or the admission
  limits is a change to the plan first, a vector in `scripts/vectors.py` (a second
  implementation, in Python; never "fix" it to match the Swift), an attack in the tests, and a
  line in `scripts/mutate.py` that breaks the new guard and names the test that must notice.
  The first mutation run missed 4 of 17: tests that passed whether or not their guard existed.
  The review of the code (2026-11-23) then removed 16 more guards by hand and 13 went
  unnoticed; each has a test in `ReviewTests` and a line in `mutate.py` now.
- **A change to what a model is about is a change to the model first** (`formal/`, and
  Verification below): the pairing transaction (`PairingMachine`, which TLC holds EQUAL to its
  specification, so the build fails until both say the same), the order of a withdrawal of
  trust, the rounds of a drop, the tie-break when two Macs ask at once, the handshake and the
  keys derived from it. Then `./build.sh verify`. A new guard gets a mutant in
  `formal/check.py` as well as a line in `scripts/mutate.py`: a model that holds with the
  guard removed was saying nothing about it. A new Tamarin lemma gets an entry in
  `formal/tamarin/lemmas.json` (what it claims, under what, about which code): the runner
  refuses a run whose lemmas are not exactly the register's, and it fails closed on anything
  it cannot read (`formal/test_check.py` is the list of ways it must refuse).
- **A claim is in the register with its kind of evidence** (`docs/security/claims.md`):
  proved in a symbolic model, checked at stated bounds, the same machine as its model,
  argued, tested, the compiler's, by reading, or not established. Do not write "verified" of
  the Swift application anywhere; say which of those it is.
- **The layers hold.** A module imports only what is under it; `NimbusCrypto` stays pure
  (decisions about a protocol go there as functions of their inputs, and whoever owns the
  socket and the clock calls them); the trust store knows a session only as a
  `TrustedSession`. `scripts/check-layers.py` says no; do not teach it to say yes. A new way
  of not being pure is a new pattern there and a new case in `scripts/test-check-layers.py`.
- **The secrets must not flow** (after Diodon; `docs/plans/security-assurance-plan.md`). A
  key's bytes are `internal` to `NimbusCrypto`, which does no I/O, so no other module can
  write them anywhere; the types that hold them are `package`, so nothing outside the engine
  can name them. The one way out is the trust file's plaintext (`TrustCore.encoded`), asked
  for in `Trust.swift` alone. Do not widen an access level to get at a key: add the operation
  to the pure module and hand back what is public. `scripts/test-capabilities.py` is the list
  of programs that must not compile; a new type that carries a secret or an authority gets a
  line there. Nothing that is logged or said to the other Mac names a secret (the lint, and
  `SecretsTests`, which searches a whole session's log).
- **A decision is a machine; a machine is tied to its model.** Pairing, trust, a drop's
  conversation and admission are each a pure value type in `NimbusCrypto`
  (`(state, event) -> effects`) with a class around it that owns the lock, the clock and the
  sockets and does what the machine says. A new protocol decision goes in the machine, not in
  the class. Each machine's test writes its transition relation to `formal/tla/*Impl.tla`
  and TLC holds that EQUAL to the specification's `Step`. The abstraction a machine is
  compared under is written at the top of its `.tla`, and its random walks vary what the
  abstraction leaves out, with a seed that is printed: one concrete machine per abstract
  state proves equality only if nothing else matters, and twice in this work something else
  did (a session of an earlier pairing, found after some 1,500 walks).
- **No cryptography of our own making.** Primitives from CryptoKit only. Speed is never a
  reason to write a cipher or call a private API.
- **Never write outside what the person chose.** A manifest is input from another machine and
  its paths become paths here. There are two gates and both must hold: `Manifest.validate()`
  (the text) and `SafeTree` (the disk). **Every file operation a receiver performs on a drop
  goes through `SafeTree`**; a `open`, `mkdir`, `symlink`, `chmod` or `stat` on a path built from
  a manifest anywhere else is a vulnerability, as it was until 0.2.2 (see Security). A change
  to either gate without an attack in `SecurityTests.swift` is not finished. Nothing existing
  is ever overwritten: collisions get a "keep both" name.
- **Everything from the other machine is hostile until checked**: names (through
  `Sanitize.label` before they are shown or logged), numbers (bounded in `validate` before any
  arithmetic; Swift traps on overflow and a trap is a crash), sizes (a frame from a connection
  not yet let in is held to `firstFrameBytes`), and counts (`Tuning.strangers`,
  `pendingOffers`, `streamsPerDrop`).
- **Nothing is written before the person accepts.** The Accept panel's answers are Save to
  Downloads (one click), Save to… (then the folder chooser; cancelling it declines) and Decline.
  `--receive` (the CLI) asks on the terminal for each drop; `--unattended-from <key tag>` is the
  one standing grant (one paired key, one folder, a byte limit) and exists for tests between Macs.
- **It works with no internet** (owner's requirement, 2026-11-23): no server, no trusted time,
  no download at run time. Anything that would need one is designed out, not made optional.
- **Grill me relentlessly** before building a feature: every question whose answer would change
  the work, with the facts already checked. Decisions, not options.
- **Be concise.** Short reports, the salient facts only.
- **`prek` (pre-commit) must pass.** `prek install` once, then `prek run --all-files` before
  claiming done. Shellcheck at its default severity. Never disable a hook to get past it.
- **`swift test` must pass**, and a change to the protocol, the ledger or the naming without a
  test is not finished. The tests run whole drops over loopback; they are cheap.
- **A change to how the engine copes with trouble gets a chaos test**, and the test gets a
  mutation check: break the thing it guards (drop a checksum, stop replacing connections) and
  watch it fail. The first header-corruption test passed against a build with the header
  checksum removed, because a misdirected chunk was later overwritten by the right one; only
  the exact, deliberate flips in `testAChunkRedirectedByOneFlippedBitIsNotWritten` caught it.
- **The one outcome that must never happen is wrong bytes in the destination.** A drop may stop;
  it may not arrive altered. Every chaos test asserts one or the other.
- **The wire is versioned.** Anything that changes what two copies say to each other is a new
  `protocolVersion` (breaking) or `protocolMinor` (ignorable by an older copy); see The protocol.
  Protocol 2 is not spoken at all (owner's decision: it ran on four Macs, all his).
- **Licence headers.** Every new Swift file starts with `// Copyright (C) 2026 Niels Joubert` /
  `// SPDX-License-Identifier: GPL-3.0-or-later`. GPL-3.0-or-later; don't vendor incompatible code.
- **It talks to the LAN, and to GitHub only for updates.** README must keep saying exactly this.
- **Install nothing on the owner's behalf.** `build.sh install` registers a Login Item; that is
  the owner's call. `build.sh run` (the dev bundle) is fine.

## Workflow

- **Changes go up as pull requests**: branch from `main`, push, `gh pr create`; the owner
  reviews and merges. (The initial scaffold was committed straight to `main`, with the owner's
  say-so, on 2026-11-22.)
- **Check that a push arrived**: compare `git rev-parse HEAD` with
  `git ls-remote origin refs/heads/<branch>`.
- **A PR that touches anything the owner sees gets a screenshot**: `--dump-window`, `--dump-bar`,
  `--render-icon`, `--render-dmg-background`. The siblings' CLAUDE.md say where the images live
  (the orphan `pr-assets` branch).

## Layout

The engine is nine modules in layers, each a SwiftPM target that may import only the ones under
it (Package.swift; `scripts/check-layers.py` holds each to its system frameworks too, as a prek
hook). No AppKit anywhere in them. What one layer needs of another is `package`, never `public`.

```
Sources/NimbusBase/          PURE values, under everything, and knows nothing of the protocol
  Errors.swift              DropError (its message is what the user reads)
  LogLevel.swift            how much a log line matters
  Sanitize.swift            text from another machine, made fit to show and to log (and to compare)
  Format.swift              bytes, byte rates, bit rates (Mbps), durations, counts
  Tuning.swift              the namespace only: each module adds the knobs it owns in an extension
Sources/NimbusRuntime/       what a value is not. BESIDE the pure module, which cannot import it
  Log.swift                 DropLog (the engine's and the app's debug lines, to whatever sink the
                            app sets), LogFile (stamped, appended from any thread, rotated), Locked
  SystemError.swift         errnoError
Sources/NimbusCrypto/        PURE: no socket, file, clock, lock, thread or log (check-layers.py
                            refuses one, and the compiler refuses NimbusRuntime). Foundation and
                            CryptoKit only. THE CORE: what formal/ is about. Key bytes are
                            `internal` here: no other module can read them.
  Crypto.swift              KDF, PublicKey (canonical form, tag, identity number), Secret (bytes
                            nobody else can read), KeyPair, CipherState (AES-GCM with a counter
                            nonce and a limit), Noise XX
  Version.swift             protocolVersion / protocolMinor; Noise.prologue
  DropKeys.swift            DropKeys (everything derived from `master`); RecordHeader (a data
                            record on the wire)
  PairCodes.swift           the commitment and the two six-digit codes
  PairingMachine.swift      the pairing transaction: classify (what an event IS), Control.step
                            (what it MEANS, with no value in reach), effect (the values)
  TrustRecords.swift        KnownMac, Tombstone, Renewal, KeyStanding, ClockReading
  TrustCore.swift           everything the trust store decides: standing, store, every withdrawal,
                            what time ends (count, tick), sessions and their deadlines, when to save
  RoundMachine.swift        a drop's conversation at each end: RoundMachine.Sender, .Receiver
  Admission.swift           which connection has a place at the listener, and which gives way
                            (each of the four machines is held EQUAL to its formal/tla/*.tla)
Sources/NimbusNet/           Socket (blocking TCP: connect, listen, exact read/write, writev,
                            keepalive, shutdown-to-cancel), Deadline, LocalHost, LocalNetwork
Sources/NimbusSafeStorageCore/   a manifest, and every file operation a receiver performs
  Manifest.swift            Manifest (+ validate, key, chunk arithmetic); Scanner (walks what is
                            being sent); Naming.unique ("keep both")
  SafeTree.swift            every file operation a receiver performs on a drop, by descriptor,
                            following no link: the tree, the folder it is in, the ledger beside it,
                            finishing (mode, time, quarantine), placing (a move that replaces
                            nothing), and that two entries are never one thing on disk; see Security
  Ledger.swift, Plan.swift  which chunks are on the receiver's disk: the resume record, and what
                            it tells the sender
  Quarantine.swift          the mark macOS puts on what came from elsewhere
Sources/NimbusSecurityCore/  who a Mac is, and the channel that proves it. Knows no drop.
  Trust.swift               the SHELL around TrustCore: the lock, the clock, the disk, the weak
                            references to sessions, and the order what was decided is carried out
                            in (`perform`). TrustClock, TrustStorage, MemoryStorage; TrustedSession
  EnclaveStorage.swift      the trust file on disk, sealed under a Secure Enclave key agreement
  Channel.swift             the opening, the handshake both ways, probe, sealed and fragmented
                            control messages
  Messages.swift            FrameType and the messages of the channel and of pairing
  Pairing.swift             PairingGate (one at a time, rationing), PairingSession (the
                            connection, the person and the clock around a PairingMachine)
  Retirement.swift          the retire notice, Trust.reset; Trust.paired() for tests
  Identity.swift            Identity (name, id, app version)
Sources/NimbusDiscovery/     Advertiser (dns_sd register; no key material); Probe (ask an address
                            to prove a key), Prober (the same, rationed); PeerTable (pure: one peer
                            per browse result); PeerBrowser (NWBrowser + resolve + probe);
                            Peer.asItIsNow (a drop is sent to a key, never to a name)
Sources/NimbusTransferCore/  drops: scheduling, rounds, progress, reconnecting, admission
  Tuning.swift              the engine's patience and its admission limits, shortened by the tests
  Messages.swift            offer, done, complete, resume, resumed
  Transfer.swift            TransferState, TransferProgress, TransferStats; Transfer, the base
                            both sessions share (thread-safe state, progress, cancel, the silence
                            watchdog)
  Sender.swift              SendSession, the shell around RoundMachine.Sender: scan → offer →
                            manifest → rounds of (plan → N stream threads → done); replaces failed
                            connections; closes stalled ones
  Listener.swift            DropListener, the shell around Admission (accept loop; routes offers,
                            data streams, hellos, requests to pair)
  Receiver.swift            ReceiveSession, the shell around RoundMachine.Receiver (decision, tree,
                            streams, rounds, settle, finalize)
  SpeedTest.swift           the speed test (the plan's Addendum B): SpeedWire (a drop's records
                            with no file at either end), SpeedTest (the Mac that asks),
                            SpeedResponder (the Mac that is asked), DataSession (what data
                            connections attach to: a drop being received, or a speed test)
Sources/NimbusDropCore/      the umbrella: re-exports all of the above, so the app and the tests
                            `import NimbusDropCore`; and what only an app needs of the engine
  History.swift             HistoryEntry, HistoryStore (one JSON file, newest first, 500 at most)
  FileTypes.swift           FileKinds (which kinds of file a drop holds, by what macOS takes the
                            extension to mean); ScannedDrop.keeping(kinds:) (send only some)
  Leftovers.swift           everything a copy keeps on a Mac, for the uninstaller: one list
Sources/NimbusDropChaos/    testing only, never in the app
  ChaosProxy.swift          a TCP proxy that throttles, stalls, cuts connections, refuses new
                            ones and flips bits, on triggers by bytes carried or by time. Knows
                            nothing of the protocol.
Sources/nimbus-chaos/       the proxy from the command line, to put between two real Macs
Sources/NimbusDrop/         the app
  main.swift                flags, AppDelegate, one-copy rule, Login Item on first launch
  CLI.swift                 --receive / --send / --peers / --watch-peers / --print /
                            --check-update / --preflight
  AppModel.swift            destinations (found + added by address), transfer rows, the receiving
                            switch, the save prompt, notifications, the sleep hold
  StatusBarController.swift the status item: a click opens (or closes) the window, a right-click
                            brings a short menu; --dump-bar
  MainMenu.swift            the app's menu bar while the window is open. `fill(_:)` is THE menu:
                            the app menu and the menu bar icon's right-click menu are both made
                            by it, so an item added there is in both. Never build either by hand.
  MainWindow.swift          the window (SwiftUI in an NSWindow): This computer, Destinations and
                            Add by Address, the drops, the kinds-of-file sheet; --dump-window,
                            --dump-kinds
  SettingsWindow.swift      Settings (⌘,): parallel connections, Open at login, updates, the
                            version and protocol. Nothing of the kind is on the main window.
  Diagnostics.swift         the flight recorder: every log line, in memory, from launch (3000)
  InternalsPanel.swift      Internals (⌘I), after Nimbus Leviton Bar's: live status (this Mac,
                            destinations, each drop and each of its connections) over the log as
                            it is written, with filter, Pause, Copy, Clear; --dump-internals
  HistoryWindow.swift       every drop that has ended (HistoryStore in the core keeps it in
                            ~/Library/Application Support/<bundle id>/history.json); --dump-history
  OfferPanel.swift          the Accept / Decline panel for an incoming drop; --dump-offer
  PairingPanel.swift        PeerStanding (what a tile is), the pairing window at either Mac in
                            every stage; --dump-pairing writes all of them
  Palette.swift             the Nimbus colours: icon blue out, icon green in, coral, amber
  Settings.swift            UserDefaults: deviceID, receiving, streams, manualDestinations
  Uninstall.swift           ServiceMenu (whether macOS shows "Nimbus Drop To…": the switch in
                            Settings) and Uninstaller (Settings › Uninstall, `--uninstall`)
  LoginItem.swift, AppIcon.swift, DMGBackground.swift, Updates.swift   as in the siblings
Tests/NimbusCryptoTests/    74 tests, depending on NimbusCrypto alone: the four machines attacked,
                            written out as the relations TLC checks (formal/tla/*Impl.tla), and
                            walked at random with seeds; Wycheproof's X25519 vectors (Vectors/)
Tests/NimbusDropCoreTests/  232 tests. ContainmentTests (the whole tree read before and after a
                            drop), IndependentReviewTests and RoundReviewTests (what the review of
                            2026-11-24 found), TrustShellTests (the trust store's lock, disk and
                            order), SecretsTests (a whole session's log searched for key material),
                            FuzzTests (manifest, ledger file, trust file, what is shown),
                            ModelFindingsTests (what the formal models found, as attacks),
                            SpeedTests, ReviewTests (the first review, its fuzzers, admission),
                            DropTests (whole drops), SecurityTests (a hostile paired sender against
                            the disk), ProtocolTests (impostors, replay, floods, retirement
                            mid-drop), PairingTests, TrustTests (expiry against a clock that lies),
                            VectorTests (against scripts/vectors.py), CryptoTests (the published
                            Noise vector)
Tests/NimbusDropChaosTests/ 29 tests: whole drops through ChaosProxy (about 140 s)
scripts/vectors.py          the second implementation; scripts/mutate.py, the mutation checks
                            (266 guards); check-layers.py, the modules held to their layers, and
                            test-check-layers.py, the checker held to its job; test-capabilities.py,
                            programs that must not compile; bench-loopback.py, the data path as
                            numbers, one build against another
formal/                     the models (README.md there): tamarin/ (the handshake, the pairing,
                            and lemmas.json, the register of every lemma), tla/ (four machines,
                            their refinements, and the systems around them), check.py (runs every
                            model and every mutant, and fails closed), test_check.py, sas-bound.py,
                            computational/pairing-bound.md (two in a million, argued)
docs/security/              threat-model.md, tcb.md, claims.md (every claim and its kind of
                            evidence), trust-lifetime.md, filesystem-containment.md, authority.md
build.sh                    build / test / verify / run / stop / app / dmg / release / install /
                            uninstall / status / icon / clean
```

Swift 5 language mode (`swift-tools-version:5.10`) with the Swift 6 compiler. The app's classes
are `@MainActor`; the engine is plain threads and locks (`@unchecked Sendable`), and its callbacks
(`Transfer.onChange`, `DropListener.onOffer`, `ReceiveSession.onWithdrawn`) arrive on engine
threads: hop to main before touching the model. `PeerBrowser` is the exception: it lives on the
main queue.

## Build, run, test

```
./build.sh run [--fg]        debug build as dist/debug/Nimbus Drop Dev.app (quits any running copy first)
./build.sh test              swift test
swift build -c release       measure with this, never the debug build
.build/release/NimbusDrop --receive DIR [--once] [--no-advertise] [--name N] [--port P]    asks per drop
.build/release/NimbusDrop --unattended-from TAG --receive DIR      accepts from that one paired key
.build/release/NimbusDrop --pair TARGET | --verify TARGET          codes | identity numbers
.build/release/NimbusDrop [--streams N] --send TARGET PATH…    TARGET: a name from --peers, HOST, HOST:PORT
.build/release/NimbusDrop --peers | --print | --identity | --known | --forget TAG | --reset-identity
python3 scripts/mutate.py [word…]                                   break each guard, expect a test to fail
./build.sh verify [word…]    the layers, every formal model and its mutants, the tests (see Verification)
./build.sh verify quick      the part that takes about a minute: no Tamarin, and of the tests the pure core's
python3 formal/check.py register | tla | tamarin | WORD            the lemma register; the models; whatever has WORD in its name
python3 formal/test_check.py; python3 scripts/test-check-layers.py   the runner's and the layer checker's own tests
python3 scripts/test-capabilities.py                                programs that must not compile (needs a build)
NIMBUS_WALK_SEEDS=300 swift test --filter TrustCoreTests            a long hunt with the machines' random walks
swift test --sanitize=thread --build-path .build-tsan               the suite under ThreadSanitizer (address likewise)
python3 scripts/bench-loopback.py BIN [BIN…]                        the data path over loopback, builds side by side
.build/debug/NimbusDrop --dump-window P     the window with made-up data → P, P-light, P-empty
.build/debug/NimbusDrop --dump-bar P        the status item's three looks, light and dark
```

`--send` takes everything up to the next `--flag` as its arguments, so other flags go before it.
`--send NAME` means the Known Mac this identity calls NAME (or its key tag; see `--known`):
the network is searched for the Mac that proves that key, and the drop is sent expecting it.
What a Mac announces itself as picks nothing (it did until 2026-11-23: the review's F4). An
address (`HOST`, `HOST:PORT`) still means whoever answers there, provided it is paired.
The CLI never uses the app's identity: its trust file is in
`~/Library/Application Support/<bundle id or com.njoubert.nimbusdrop.cli>/cli-<name or default>/`,
one per `--name`. Two names on one Mac are two Macs to each other, which is how the whole
protocol is exercised on a single machine: `--name a --pair 127.0.0.1:PORT` against
`--name b --port PORT --no-advertise --receive DIR`, each reading the other's code from its
terminal (a script can drive both through pipes; that is how 0.3 was checked end to end).

**The second Mac is `macbookairm4`** (ssh works, Apple silicon, gigabit Ethernet to the same
switch, checkout at `~/Code/nimbus-drop`). A LAN test:

```
.build/release/NimbusDrop --name pro-cli --identity          # note its key tag, then pair the two once:
ssh -t macbookairm4 '… NimbusDrop --name air-cli --receive /tmp/nd-recv'   and   --name pro-cli --pair air-cli
ssh macbookairm4 'cd ~/Code/nimbus-drop && git pull && swift build -c release && \
  (nohup .build/release/NimbusDrop --name air-cli --unattended-from <pro-cli tag> --receive /tmp/nd-recv >/tmp/nd-recv.log 2>&1 &)'
.build/release/NimbusDrop --name pro-cli --send air-cli <paths>
```

then compare both trees (`find … -type f -print0 | sort -z | xargs -0 shasum | shasum`). Kill
the sender mid-way and send again to exercise the resume.

**What an agent cannot do here:** click. The save prompt, the Local Network prompt and a drag
onto a tile need a person. What can be checked without one: that the prompt window exists
(`CGWindowListCopyWindowInfo` lists a window named "Incoming Drop" for the app's process, no
Screen Recording permission needed) and that it goes away when the sender gives up.

## The protocol (version 3.1)

The specification is `docs/plans/secure-drops-plan.html` (draft 6); this is the map. Encrypted
and authenticated end to end; not one byte in common with protocol 2.

```
every connection      "NDROP" count majors…  (control)   or   "NDATA"  (data), in the clear
control               Noise_XX_25519_AESGCM_SHA256, prologue = "nimbus-drop/3" ‖ both openings
                      -> e      <- e, ee, s, es      -> s, se        (frames: [u16 n][u16 ~n] bytes)
                      the initiator checks the responder's key after message 2, before it says anything
                      Split gives two transport keys and, as our one extension, a third output: master
                      hello {minor, app, name, remaining, paired, purpose} each way, sealed
                      purpose: drop | pair | verify | resume | retire        (nil: hello and hang up)
a message             plaintext [u8 type][u8 more?][u32 total, first fragment] JSON; fragments of 65,519
drop                  offer -> accept | decline -> manifest -> plan -> … done -> plan | complete
                      (as protocol 2, minus the token; sizes bounded by what was accepted)
keys of a drop        session_id, attach_key, resume_key, stream_key(conn) = KDF(master, label…)
data connection       <- 16 random bytes      -> session_id ‖ conn u64 ‖ HMAC(attach_key, … ‖ challenge)[:16]
                      records: seal(header 12 bytes) ‖ seal(chunk, ad = header); nonce = a counter
                      end: a sealed header with file 0xFFFFFFFF, chunk 0, length 0
resume                new handshake (same static keys), resume {session, HMAC(resume_key, "resume" ‖ h)}
                      <- resumed {HMAC(resume_key, "resumed" ‖ h)}, then plan. master does not change.
pair                  pair-request -> (a person says yes) pair-go -> commit -> nonce -> reveal
                      codes = KDF(Ns ‖ Nr, label ‖ h, 16): two six-digit codes, one shown on each Mac
                      each types the other's; paired {} each way; stored when both are true
verify                the same without the exchange: each enters the other's 30-digit identity number
retire                retire {} -> the key is tombstoned, its sessions ended -> retired {}
speed (3.1)           speed {seconds, streams} -> speed-go (as granted) | busy; 2n data connections
                      up: records {file 0} on 1…n for `seconds` -> speed-up-done -> speed-count
                      down: speed-down -> records on n+1…2n -> speed-done. Nothing read or written.
```

- **Who a Mac is.** `Trust.standing(of:)`: mine, paired, expired, retired, renew, unknown.
  `AppModel.standing(peer)` turns that and `Trust.nameClash` into a tile's `PeerStanding`.
  Bonjour carries a name, the major and `i` (random per launch, to leave one's own record out);
  each address found is probed (`Channel.probe`: opening and two handshake messages, with a
  throwaway key) and a peer is one browse result, never merged by what it claims.
- **Pairing is one transaction**: each message once, in order, nothing recomputed
  (`PairingSession`). A second `Nr` after `Ns` is known would let a responder choose its code;
  `testAMacThatDoesNotKeepToThePairingIsDropped` is that and three more. A Mac stores a pairing
  only when its own person typed the right code AND the other said the same. One pairing at a
  time per Mac (`PairingGate`); requests from others are shown one at a time, at most four
  waiting, with a pause after each refusal that doubles (`Tuning.pairQuiet…`). While this
  Mac's own pairing is in progress a request from anyone else is answered busy, not shown
  beside it. The pause is for requests nobody here asked for: one from a key on the Known or
  pair-again list, or from a key this Mac's person started a pairing with in the last two
  minutes (`PairingGate.asked` / `expects`), is shown regardless. A Mac that turns a request
  away for the pause says for how long (`Reason.pause`, held to ten minutes on receipt), and
  the asking Mac's tile says "Pair from that Mac" for that long (`PeerStanding.paused`,
  `AppModel.watchForPause`). Before this, one stranger asking every ten minutes kept two
  Macs from ever pairing (the review's F9). "The same Mac you paired with before" is said only of a key that is on the
  pair-again list (`PairingModel.isSameMac`), never of a new key under a familiar name.
- **The window shows one code at a time** (`PairingStage.read` / `.type`): the Mac that asked
  reads its code out and the Mac that was asked types it, then they swap. The wire and the
  engine take the two entries in either order, as before; the order is the window's, driven
  by `PairingSession.otherTyped` (which is a hint and proves nothing: a `paired {}` from the
  other end still stores nothing by itself). Both codes were on screen at once at first, and
  whoever pressed Return first lost sight of the code the other still had to type (the owner,
  2026-11-23). The command line still prints its code and asks in one go; a terminal keeps it.
- **A pairing that works shows no success window**: the window closes, the Mac's tile pulses
  "✓ Pairing successful" for five seconds (`AppModel.celebrate`, `PairedPulse`), the main
  window is brought up to show it, and whatever was dropped to start the pairing is sent
  without a second question (the other Mac's person is still asked to accept). Only a failure
  stays on screen (the owner, 2026-11-23).
- **The first plan read the code aloud into a PAKE** (CPace, libsodium). A PAKE's code is a
  secret; the plan's own assumption was that the room may hold the attacker. The first review
  found a man in the middle within earshot pairing with both Macs, silently. Now the codes are
  a commitment-bound fingerprint of the connection: hearing them is worth nothing.
  `testSomeoneInTheMiddleWhoHearsBothCodesStillFails`.
- **Keys end.** Every key has an end, 90 days by default down to an hour, no "never". A
  pairing lasts until either key does. Time is counted on the continuous clock
  (`mach_continuous_time`: runs through sleep, cannot be set), with the calendar only as a
  second way to end sooner; the trust file records boot session, continuous and wall time, and
  after a reboot counts the larger of time-since-boot and the calendar's gap. The second review
  showed the earlier rule (never let the calendar go back) kept a key alive under a calendar
  held still. Not counted: time switched off under someone who controls the clock.
  At a key's end nobody is asked anything; the next drop needs a pairing. The other Mac knows
  the date (each states its `remaining` in the hello, capped at 90 days), so a new key under
  that name after it reads as a renewal and before it as a surprise.
  Only the elapsed count refuses a key for good (a tombstone). The calendar reaching a paired
  key's date first ends the pairing and puts the Mac on the pair-again list, with its elapsed
  deadline kept: until 2026-11-23 it wrote the tombstone, and one forward jump of the calendar
  cost every pairing permanently, also after the calendar was put right (the review's F3). A
  key that runs out while on the pair-again list is tombstoned like any other (F2; it used to
  be dropped and came back as a New Mac). An offer still unanswered when its pairing ends is
  withdrawn, and a yes is checked against the pairing before anything starts (F6).
- **Nothing that touches a socket runs with the trust store locked.** Everything in `Trust`
  goes through `locked { }`; ending sessions and telling listeners is set down in
  `afterwards` and done when the outermost call lets go, before it returns. And a withdrawal
  says no farewell (`SendSession.withdrawn`): a paired Mac that stopped reading its control
  connection and then sent `retire` (or a frozen one, plus a click on Forget) used to leave the
  store locked for good, every handshake and every tile waiting on it (the review's F7).
  `testEndingASessionDoesNotHoldTheTrustStore` is the rule; the F7 test is the attack.
- **Withdrawing trust is one ordered procedure** (`Trust.withdrawLocked`): written to disk,
  then the store refuses the key, then every session it authenticated is ended and its keys
  wiped (`Transfer.withdrawn`), then listeners drop what it had waiting, and only then is a
  retire notice acknowledged. Retire and "It Replaces…" leave a tombstone (refused for good);
  Forget does not. It tells the other Mac when it can (`Trust.forget(_:telling:identity:)`: a
  connection that proves this Mac's key, hello `paired: false`, no purpose; three seconds at
  most, best effort), and a responder that has the proved key paired and reads
  `paired: false` in its hello drops its half there and then, whatever the purpose but
  `resume` (`DropListener.serve`; a reconnect after the sender's own key was replaced on
  schedule says `paired: false` truthfully, and `testADropFinishesOnTheKeyItStartedWith`
  failed on the first version of this). An independent review the same day found no way to
  end an established pairing without one of the two keys, and three smaller things, now
  `ForgetReviewTests`: the responder's reply to a `resume` from a run-out key said
  `paired: false` and the sender took that for a Forget (a drop in its grace died at its
  first reconnect; the chaos test moved only the sender's clock); the notice had a deadline
  per read, not in all; and a truthful `paired: false` sealed just before a pairing could
  end it just after (ignored now for `Tuning.strangerSeconds` after pairing). Otherwise the forgotten Mac learns at its next drop, when the key
  it has paired proves itself and says `paired: false` (`Trust.notePairingGone`: its half is
  withdrawn the same way and the Mac goes on the pair-again list, so the tile says so; until
  2026-11-23 it stayed "Paired" and every drop failed). The same is read from the hello of a
  reconnect: a Forget at the receiver mid-drop used to leave the sender a minute of
  "trying to get it back"; now the first attempt ends the drop, for that reason. The app then asks at once
  (`AppModel.offerToPairAgain`): pair again and send, or not now. Scheduled expiry is different on purpose: a running drop may finish, within
  a day or one key lifetime, whichever is shorter.
- **Admission** (`Admission` in the pure module decides; `DropListener` keeps the sockets, the
  lock and the clock and does what it says): a slot before a thread. Not yet a
  key: 64 at once (8 from one address), 500 a second (200 from one address), 1 KB, 10 s. A key
  nobody paired: 8 at once (2 from one address), 16 KB, pair/verify only. A data connection
  before its attach is accepted: 16 per drop in progress (4 from one address), 5 s, none when
  no drop is, and when a drop ends the places it gave end with it. A paired key that has not
  yet said what it came for: 8 per key, its own, whatever address it comes from.
  **In the pools that have proved nothing, and among keys nobody paired that have asked for
  nothing, the oldest gives way to the newcomer**; at an address's own limit, that address's
  oldest. They were global and refused the newcomer, and 64 silent connections from one host
  kept every paired Mac out (the review's F1); the pool of unpaired keys was left that way
  until 2026-11-24, and eight silent fresh keys from one host kept every Mac from asking to
  pair. A request to pair that has been read keeps its place. An honest
  Mac proves itself in milliseconds; waiting is what loses the place. The rate cannot work
  that way (nothing to close), so over it the newcomer is closed; it is counted on the
  continuous clock (on the calendar, set back, the last second's arrivals were never
  forgotten). What holds of an honest Mac, exactly (`AdmissionSystem.tla`): within the rate it
  gets a place; it gives way only after a pool's worth of newcomers arrived after it; once it
  has proved a paired key it never gives way. Not claimed (P11 was narrowed): that a flood
  from many addresses cannot stop a drop. Three addresses at 167 arrivals a second each fill
  the rate. The per-address arrival
  limit is 200, not the 50 first proposed: several drops at once on 32 connections each open
  more than a hundred in a second. Tests whose two ends share 127.0.0.1 and arrive faster
  raise `Tuning.arrivalsPerAddress` (and `unpairedPerAddress`). After accept: a manifest of
  64 KB + 2 KB per file offered, out of 1 GB shared, and a minute of silence before it at
  most (`Tuning.manifestSeconds`); a sender holds at most two messages its receiver sent and
  it has not read.
  The arrival rate was 50 a second at first, and fifty strangers in a second kept a paired
  sender out (`testCompletingAHandshakeWithAFreshKeyEarnsNothing` failed on it).
- **One master per drop.** A reconnect proves the same two Macs and re-keys control only;
  data connections that outlive a control connection (it happens: see below) keep their keys.
  A connection number is taken from one counter for the whole drop and never reused, so a
  replacement for a failed connection has a new key, never an old one from counter zero.
  A stream key carries at most 2^38 bytes and 2^24 seals, then the sender moves on (`spent`).
- **A record that fails to open is a damaged chunk**: that connection closes, the chunk is
  asked for again. It never ends a drop by itself (an earlier draft's three-strikes rule would
  have let anyone stop one). The receiver's data-path checks are in `ReceiveSession.receive`.
- **A change to trust that could not be written stays in force and is retried** (twice a
  minute, in `tick`) until it holds; `Trust.unsaved` says so and the app warns once
  (`AppModel.warnIfUnsaved`). It used to be logged and no more, and the next launch undid
  it: a forgotten Mac paired again without anyone deciding so.
- **The trust file** (`EnclaveStorage`): `device` (a Secure Enclave P-256 key's opaque form,
  a public key `w`, this Mac's hardware UUID; written once) and `trust` (AES-GCM under the
  key agreed between them). Every write is whole-file, fsync, rename, fsync the folder. It is
  never quietly replaced: foreign hardware → set aside and start fresh; enclave failing → throw
  and change nothing; damaged → the app asks (`AppModel.askAboutDamagedIdentity`). On a Mac
  with no enclave (CI's virtual machines) it falls back to a key in the device file and says so.
- **Reconnecting, rounds, patience, cancel and the drop's key** work as in protocol 2 (the
  notes on them from 2026-11-22 still describe the engine): a lost control connection sends
  both sides into `.reconnecting` for `Tuning.reconnectSeconds`; the two ends do not learn of
  a dead control connection at the same time; silence is treated as a lost connection; a
  finished drop remembers its answer for five minutes (now with its `resume_key`, the one key
  kept); one session per partial folder. The drop's key is SHA-256 over the sender's static
  key, the chunk size and every entry, so a resume needs the same sender key: after a key is
  replaced, an interrupted drop starts over.
- **The speed test** (`--speed TARGET`, a paired tile's right-click › Request Speed Test…): a
  paired key only, and the person at the other Mac is asked (`SpeedResponder.accept` /
  `decline`; the Allow / Decline panel is `OfferPanel(speed:)`; nothing attaches, is sent or
  is counted before the yes). Bounded as well: one question or test at a time on a Mac, 30 s
  each way and 32 connections each way at most, an absolute deadline once allowed, 10 s
  before the same key may ask again (`Tuning.speedPauseSeconds`), and every connection closed
  when it ends (`Transfer.closeAll`; `finish(.completed)` closes nothing by design, which is
  right for a drop and left a finished test's data connections open for as long as the tester
  liked). An independent review found that, a way for a third test in beside a second, and no
  gap between tests (a thousand served to one key in two seconds): `SpeedReviewTests`. The Mac
  is not held awake for a test another Mac asked for. Each rate is counted by the end
  that receives. It is the drop's data path with the files taken out, so the difference
  between it and a real drop is the two disks. A 3.0 copy does not know the purpose and hangs
  up; the tester says it may need a newer Nimbus Drop. Its first version deadlocked on itself
  (it read `peerName`, which takes `Transfer.lock`, inside that lock).
- **Not proved:** bytes left in a partial folder between attempts (the ledger's word, as
  before). Not hidden: volume and timing. Not claimed: anything against software running as
  the user.

## Security (reviewed 2026-11-22)

The question asked was: can someone on the network get code running on a Mac through this?
Until 0.2.2, yes, with one accepted drop.

- **The hole (0.1.0 to 0.2.1).** `validate` required every path to be unique and to have a
  folder of the manifest for a parent, comparing strings. A Mac's volume is case-insensitive.
  A manifest with `Photos/x` (a symlink to `../../../../Library/LaunchAgents`) and `Photos/X`
  (a folder) and `Photos/X/evil.plist` (a file) passed; `mkdir("…/X")` returned EEXIST, which
  was taken for "already made"; and the file was opened through the symlink (`O_NOFOLLOW`
  guards only the last component). One accept wrote a LaunchAgent. The same end could be
  reached across two drops sharing a partial folder, whose name carried only 48 bits of the key.
  `testASymlinkAndAFolderThatDifferOnlyInCaseDoNotWriteOutsideTheDrop` is the attack; it wrote
  the file before the fix.
- **The fix.** `validate` compares names as the disk does (`Manifest.folded`: case, and how
  accents are composed). `SafeTree` does every operation by walking from the drop's root with
  `openat(O_NOFOLLOW | O_DIRECTORY)`, and what is already in place must be exactly what the
  manifest says (a folder that exists must be a folder, a file must be an ordinary file with one
  link). Partial folders are named with 128 bits of the key. Either gate alone stops the attack.
- **Consent means what was shown.** The manifest must match the offer (file count, bytes,
  top-level names) or the drop is refused; before, a "1 file, 5 bytes" offer could be followed
  by anything. The accept button has no Return key: the panel takes the keyboard, and a person
  typing elsewhere would have accepted with the Return they were about to press.
- **Crashes were reachable** (after an accept): a size near `Int64.max`, a date of `1e300`, both
  into arithmetic that traps. Bounded in `validate` now.
- **A stranger's reach** (no accept needed) was: a frame header promising 512 MB, allocated on
  the spot; a connection kept open for ever a byte at a time; any number of offers, each a panel
  on screen. Now 1 MB, ten seconds in all, 64 at once, and two questions per address.
- **Through 0.2.2 there was no encryption and no authentication of either end**: a name was a
  claim, someone on the path could read a drop, and with the token they saw go by could attach
  a data connection or resume a control connection. Protocol 3 (0.3.0) is the answer to that;
  everything above this line still applies to a paired Mac that means harm.
- **Decided by the owner the same day, in 0.2.2:** everything received is quarantined
  (`Quarantine.value()` has macOS itself make the attribute once per drop, by marking a scratch
  file through `URLResourceValues.quarantineProperties` and reading it back:
  `0081;<time>;Nimbus\x20Drop;<uuid>`; `SafeTree.finish` puts it on every file and folder with
  `fsetxattr`, so an app bundle's folder carries it); a symlink that points out of its drop is
  not recreated (`Manifest.linkStaysInside`: relative, `..` only at the start and no more than
  there are folders to climb; the receiver counts them in `stats.skippedLinks`); and the
  listener takes connections only from the local network unless Settings says otherwise
  (`LocalNetwork.isLocal`: this Mac, link-local, or the same subnet as one of its interfaces;
  anything else is closed unread, logged once per address). `--any-network` for the CLI.
- The updater's own checks (Developer ID team, HTTPS) live in nimbus-updater and were not part
  of this review. The app is not sandboxed: anything that got code running would have the
  user's whole account, which is why the gates above are what they are.

## The chaos harness

`ChaosProxy` (in `NimbusDropChaos`) sits between a sender and a receiver. Connections are
numbered as they arrive: 0 is the drop's control connection, the rest are data. Conditions
change with `set { }`; triggers are `whenForwarded(bytes:)` (repeatable) and `after(seconds:)`;
`kill(.data)`, `killOneData()`, `plantFlip(connection:offset:bit:)` act at once.

- **Real:** bandwidth (a shared token bucket), cut connections, refused connections, stalls
  (`blackhole`: nothing moves, nothing closes), corruption (after TCP's checksum is satisfied).
- **Imitated:** packet loss. Above TCP there are no packets; `loss` charges a timeout per lost
  1460-byte segment, which is what loss looks like to an application. Real per-packet loss needs
  `dnctl`/`pfctl` and root; sudo on this machine wants a password, so it has not been run.
- The tests set `Tuning` in `setUp` (a 60 s stall becomes 1.5 s) and put it back in `tearDown`.
  A test that needs a cut to land mid-drop has to send more than the kernel will buffer: with
  8 MB everything is in flight before the first trigger fires.
- `blackhole` holds back the end of a stream as well as its bytes. It did not at first, and on a
  slower machine (CI) the receiver's give-up reached the sender as "The connection closed"
  through a link that was meant to carry nothing.
- A test that asserts no connection was closed for stalling must give connections room
  (`Tuning.stallSeconds = 15`): under a low cap the bucket can starve one of four for seconds.
- **The cut-and-reattach tests** are the ones the owner asked for after the Wi-Fi failure:
  `testTheNetworkGoesSilentThenComesBack` (blackhole, then lifted),
  `testTheNetworkComesBackAndEveryOldConnectionIsReset` (blackhole, then everything cut as it
  lifts: what he saw), `testEverythingDropsForAMomentAndTheDropCarriesOn`,
  `testTheReceiverComesBackAtAnotherAddress` (a second proxy stands in for the new address),
  `testALinkThatStaysDownEndsTheDropCleanlyAndItResumes`, and
  `testTheAnswerThatItAllArrivedIsLostAndAskedForAgain`. On two Macs at default timings:
  `nimbus-chaos … --at 8s kill=all refuse=on --at 38s refuse=off` between the MacBook Pro and the
  Air, 6 GB: reconnected after the 30 s, arrived identical (2026-11-22).
- `nimbus-chaos --to HOST:PORT --listen P [setting…] [--at WHEN setting…]…` is the same proxy
  for two real Macs; `--at` takes seconds (`5s`) or bytes carried (`400MB`).

## Verification (2026-11-24)

`./build.sh verify` runs all of it; `formal/README.md` lists every way the system is checked
(twenty of them, from proofs to fuzzing), the gaps that are left and the work that would
close them, and is the map of the models. Keep it true: a new kind of check, or a gap closed,
is a line there. `docs/security/claims.md` says for every claim what kind of evidence it has (proved in a
symbolic model, checked at bounds, the same machine as its model, argued, tested, the
compiler's, by reading, or not established). The plans for the work are
`docs/plans/modular-core-and-verification-plan.md` and `docs/plans/security-assurance-plan.md`.
**Nothing here makes the Swift application "verified", and no document may say so.**

- **The Core and the Application** (after Diodon: Arquint et al., *The Secrets Must Not
  Flow*). The Core is `NimbusCrypto`: the cryptography and the four decision machines, pure,
  about 2,400 lines. Everything else carries out what it decides and cannot read a key: the
  compiler holds that (`scripts/test-capabilities.py`), two lints stand beside it
  (`scripts/check-layers.py`), and `SecretsTests` searches a whole session's log.
- **Four machines are held EQUAL to their models**: `PairingMachine` (99 states, 1,683
  transitions), `TrustCore` (52; 2,016), `RoundMachine` (51 and 109; 918 and 3,052),
  `Admission` (four sets of small limits; 67,169). `swift test` writes each relation out
  (`formal/tla/*Impl.tla`) and fails if a file is stale; TLC checks it against the
  specification's `Step`, both ways. Change one without the other and `verify` fails. After a
  deliberate change: `NIMBUS_WRITE_IMPL=1 swift test --filter NimbusCryptoTests`, edit the
  `.tla` to match, verify. The classes around the machines are tied to the system models by
  reading, tests and mutants; do not describe them as proved.
- **Equality of relations is not the whole of it.** One concrete machine per abstract state
  proves equality only if nothing the abstraction leaves out matters. The walks (seeded,
  many machines per state, everything omitted varied) found two things the enumeration had
  not, one of them after some 1,500 walks. When a walk fails it prints its seed and the whole
  walk; `NIMBUS_WALK_SEEDS=300` (or `=40` for the rounds) is the long hunt.
- **Tamarin** proves two theories against a register of 43 lemmas (`formal/tamarin/lemmas.json`):
  the handshake with the hello, the drop's keys, attach, records, resume and a speed test
  (38 lemmas, 4.5 minutes, 5.6 GB asked for six at a time; all at once it passed 20 GB), and
  the pairing (5 lemmas, 15 s). 13 handshake mutants and 2 pairing mutants each falsify the
  lemma named for them. Four handshake flags did not settle either way and are not run;
  nothing is claimed of those guards from the lemmas.
- **TLC** checks the system models at stated bounds: the largest are `Expiry` (5.5 million
  states, a minute), `AdmissionSystem` (450,000) and `Drop` (179,000).
- **The runner fails closed** (`formal/check.py`, `formal/test_check.py`): a lemma missing,
  unregistered, twice, incomplete or falsified; a summary cut short; an exit code that does
  not match what was printed; a request that matches nothing. Each is a failure, never a
  pass. Raw output and versions are kept in `formal/.results/`.
- **Every model has mutants** (`formal/check.py`), and every guard in the Swift has a line in
  `scripts/mutate.py` (266). A mutant that passes fails the run.
- **What the models and the review found** is listed in `formal/README.md` and in the
  commits of 2026-11-24. The lessons, for the next model: write each step where code asks a
  question and acts on the answer later as two steps; a guard in a model with no line in the
  code is an assumption, and gets a name; a model that holds the first time has usually said
  nothing (check that the good outcome is reachable, and that each mutant fails).
- **An independent review, given the code and not the conclusions, found twelve things the
  models and tests had not** (a crash on one accepted drop among them). Do that again after
  the next large change.
- **Sanitizers**: `swift test --sanitize=thread --build-path .build-tsan` reports races only
  on values tests write (the `Tuning` knobs, `DropKeys.streamBytes`, `DropLog.sink`) while
  engine threads of the previous test wind down; `--sanitize=address` is clean. This
  toolchain has no libFuzzer for macOS, so the fuzzers are seeded tests (`FuzzTests`, and
  three in `ReviewTests`).
- **Not modelled**: the manifest and `SafeTree` (tested: `ContainmentTests`), discovery,
  retire and the Forget notice as messages. `PairingGate` has two Macs and no third, no
  pause, no queue.
- **Open, for the owner** (`docs/security/claims.md`, the last section): what a resume
  believes after a power cut; whether "refused for good" outlives 2000 later tombstones; how
  often the elapsed count is written; the name rule for partial folders; a pipe where a file
  belongs; private vulnerability reporting; release provenance.
- **Tools.** TLC needs a Java; `/usr/bin/java` on a Mac is an invitation to install one and
  fails when run (`check.py` takes the first that works: `brew install openjdk`). The jar is
  fetched once to `formal/.tools/` against a pinned SHA-256. Tamarin is
  `brew trust tamarin-prover/tap && brew install tamarin-prover/tap/tamarin-prover` (Homebrew
  refuses its `maude` formula until the tap is trusted). Both were installed on the MacBook
  Pro on 2026-11-23 for this.
- **`scripts/mutate.py` edits the sources while it runs** and puts each back afterwards from
  memory: do not edit, build or commit under `Sources/` until it has finished (about two
  hours for the whole list; a word, or `File.swift`, narrows it).
- **Agents in worktrees** did the round machine, admission, the containment tests, the
  pairing contract and the Tamarin work in parallel, each in its own git worktree, merged
  one at a time with the whole suite run after each. A worktree is cut from `main` unless
  told otherwise: each agent had to move to the working branch first.
- **CI** runs the layers and the checkers' own tests, the register, the simulation and the
  TLA+ models on every push (`lint`, `models`, on Linux), and what must not compile after
  the tests (`build`); the Tamarin proofs weekly and on request (`proofs`), a job nobody had
  seen run when it was written.
- **CI is not this Mac**: its Swift is older (the `macos-15` image) and its TLC runs on
  Linux. The first push of this round failed there three ways, all green here: an expression
  the older compiler typed as `[Any]?` (write the types out), built modules in `<bin>/Modules`
  where `test-capabilities.py` did not look, and a mutant with two ways to fail reporting the
  other one (a run that must fail now asks TLC for the one thing it must fail on:
  `check.py`, `asked_for`). A green `./build.sh verify` is not a green CI: wait for it.
- **A fuzzer's seed from the clock is a different test every run**, and the next push's was
  the one that found something: a trust file with a count and a lifetime near the largest
  number there is opened, the next key's end was their sum (infinite), and the file could
  never be written again. Four fixed seeds and a dozen local runs had not. It is not a flaky
  test: a failure names its seed, and `NIMBUS_SEED=n` runs it alone.

## Platform facts (checked 2026-11-22, macOS 27)

- **Bonjour registration is `DNSServiceRegister` (dns_sd), not `NWListener`**, because the
  listening socket is our own POSIX one. Passing no callback is fine; the registration lives as
  long as the `DNSServiceRef`. Browsing is `NWBrowser` with `.bonjourWithTXTRecord`.
- **Resolving a peer is a throwaway `NWConnection`** to the browse result's endpoint, IPv4-only
  (`NWProtocolIP.Options.version = .v4`), read `currentPath.remoteEndpoint`, cancel. The listener
  therefore sees connections that open and close without a word; `DropListener.serve` gives a
  connection ten seconds to send a first frame and drops it silently otherwise.
- **An interface going away strips every browse result of its TXT record** (Wi-Fi switched off
  with Ethernet still up, found by the owner 2026-11-22): `NWBrowser` reports each result again
  with `metadata == .none`. The browser used to identify peers by that record alone and so
  dropped everyone, for good. `PeerTable` now remembers who was behind each result, and a result
  without its record triggers a fresh browse (`restartSoon`), which also re-resolves addresses.
  `--watch-peers` prints everything Bonjour reports, for the next surprise of this kind.
- **A finished drop leaves the window after a minute** (`AppModel.lingerSeconds`), its Retry
  button with it; it is written to the history the moment it ends. The poll timer therefore
  runs while anything is listed (four times a second while something moves, once a second
  otherwise) and stops when the list is empty; the sleep hold is only for drops that are moving.
- **The Internals list is the log file's tail plus this run**: `Diagnostics.seed` reads the
  last 3000 lines (the rotated file first) at launch. It used to start empty, and the owner
  took that for the log resetting on relaunch (2026-11-22); the file never did. Lines from
  another day show their date. Clear empties the list, not the file.
- **Internals is the first place to look, and the first thing to ask an owner to copy.** Its
  status text is `AppModel.internalsStatus()` (plain text on purpose: Copy puts it, and the lines
  listed, on the clipboard). Per-connection figures come from `Transfer.dataConnections`
  (`streamOpened` / `streamCarried` / `streamClosed` in the engine). A drop's last lines are a
  `summary:` (bytes, time, rate, chunks, retransmitted, rounds, connections dropped, reconnects
  and attempts) on each side; each round logs how many chunks it sent.
- **Log levels are set where a line is written, and are the only thing that colours it.**
  `debug` (step-by-step detail: connections opened, what a round sent, an address looked up),
  `info` (the story: offered, accepted, moving, done, a Mac found), `warn` (trouble a drop is
  getting past: a connection lost, a damaged chunk, the control connection gone, a reconnect
  attempt that failed), `error` (trouble that ended something: a drop failed, reconnecting given
  up, cannot listen). The first version of the panel coloured by keywords and painted a clean
  drop's summary red for containing "0 damaged" and "connections lost 0" (the owner asked what
  had gone wrong; nothing had). `testLogLevelsSayWhatHappenedNotWhatWordsWereUsed` holds that a
  good drop logs nothing at `warn` or above. A new line gets a level on purpose:
  `log("…", .warn)`. The file holds every level, as `<time> LEVEL <line>`; the panel's picker
  chooses the least important one listed.
- **The debug log** is `~/Library/Logs/<bundle name>/nimbus-drop.log` (so "Nimbus Drop Dev" for
  the development copy), 4 MB then rotated to `.1`. Read it first when a drop misbehaves: every
  line about a drop starts with its tag (`[3F9A2C send]`), and a state change that ends or
  interrupts a drop carries the byte counts and the trouble counts. `--verbose` prints the same
  lines for the command line. When something new can go wrong in the engine, give it a
  `log(...)` line; `testADropLeavesItsStoryInTheLog` shows the shape.
- **Each offer owns its questions** (`AppModel.asking`, by drop id): its Accept panel, then its
  folder chooser, independent of any other drop. A sender giving up removes exactly its own. The
  first version queued offers behind one shared "a question is open" flag, and a withdrawn offer
  left the flag set: no later offer was ever shown (found by the owner, 2026-11-22).
- **Checking prompts on the owner's screen competes with the owner.** Counting "Incoming Drop"
  windows while they are at the keyboard gives nonsense (they click Accept). Say so before
  sending test offers to a Mac someone is using, and prefer the Air.
- **Services ("Nimbus Drop To…")**: declared as `NSServices` in the Info.plist build.sh writes
  (`NSSendFileTypes = public.item`, `NSMessage = dropService`, `NSPortName` = the bundle's name)
  and answered by `AppDelegate.dropService(_:userData:error:)`, registered with
  `NSRegisterServicesProvider` under that same name. The development bundle's item is
  "Nimbus Drop Dev To…", so the two can be told apart. `/System/Library/CoreServices/pbs -update`
  then `pbs -dump | grep -A12 "Nimbus Drop"` shows whether macOS has picked it up.
- **The Service cannot be removed from a signed app, only hidden**: it is declared in the
  Info.plist. Whether macOS shows it is kept in the `pbs` preferences, `NSServicesStatus`,
  under "<bundle id> - <menu item> - <message>" (`enabled_services_menu`,
  `enabled_context_menu`, `presentation_modes`); no entry means shown. `ServiceMenu` writes
  that and runs `pbs -update`: the same switch as System Settings › Keyboard › Keyboard
  Shortcuts › Services. Checked 2026-11-23 by reading the preference back; nobody has yet
  looked at Finder's menu after flipping it.
- **Uninstalling** (`Uninstaller`; Settings › Uninstall, or `--uninstall [--yes]` from the
  binary inside the app, which lists without `--yes`): tells the paired Macs (as Reset
  Identity does; the app only), unregisters the Login Item, removes the Service's entry and
  notifications, deletes what `Leftovers.library` lists and any partial folders beside saved
  drops and in Downloads, then a detached `sh` waits for the process to exit and removes what
  it rewrites on the way out (preferences, the log) and the app itself, with `lsregister -u`
  and `tccutil reset All`. **Something new the app writes outside a drop's destination goes
  in `Leftovers`**, and in `build.sh uninstall`, which repeats the list from outside. Not
  removable by anyone but macOS: the entry under Privacy & Security › Local Network. Tested
  on a throwaway copy with its own bundle id (planted files, then `--uninstall --yes`: all
  gone, the other copies' files untouched); never run from the Settings button.
- **A right-click on a status item that has no menu**: `sendAction(on: [.leftMouseUp,
  .rightMouseUp])`, and in the action, for a right-click, set `item.menu`, `performClick`, and
  unset it. A status item with a menu set shows it on every click.
- **A render command after a failed build runs the OLD binary**, which does not know the new
  flag, ignores it, and starts the whole app from the bare binary: a stray copy on the owner's
  screen and on the network (2026-11-22). Chain renders with `&&` after a build that is checked.
- **The window opens beneath the menu bar icon** (`MainWindowController.place`), from
  `item.button?.window?.frame`. Right after launch that frame is still at the origin, so a window
  shown then goes under the right end of the menu bar and is moved into place 0.4 s later. On
  macOS 27 the icon's window is not in this process's `CGWindowList`, so its position cannot be
  read back from outside to check; the window's own is (`x`, `y` just under the 30 pt bar).
- **A status item with no menu** takes its click through `button.target`/`action`; a click when
  the window is already key closes it, so the icon toggles.
- **A peer's port changes when its copy restarts** (the preferred port is taken while the old
  socket lingers, or a second copy is running), so `AppModel.send` resolves again every time.
- **A Mac found on several interfaces is resolved on the one that comes first in this Mac's
  service order** (System Settings › Network › Set Service Order; `PeerBrowser.preferred`,
  `serviceOrder`: `NWBrowser` lists the interfaces of each result, and the resolve sets
  `requiredInterface`; two seconds, then any interface). An interface that is no network
  service comes last. A Thunderbolt cable between two Macs brings up two links: the
  Thunderbolt Bridge, and USB networking (`en13` here, "type: USB Ethernet", in no service
  order). Left to macOS the Air resolved over the second, and the owner's first speed test
  in the app read 300 Mbit/s beside a 37 Gbit/s link (2026-11-23). The first fix preferred
  any interface named `bridge…`; the owner asked for nothing hardcoded. A speed
  test's row and the command line name the interface it went over (`Transfer.linkInterface`,
  `LinkName.display`), which is how to tell.
- **A Mac with two interfaces on one subnet** (Wi-Fi and Ethernet) shows whichever address the
  resolve picked; the kernel's route decides which interface carries the data. On the owner's
  MacBook Pro that is en9 (Ethernet), as it should be.
- **Local Network privacy** applies to the bundled app (the Info.plist carries
  `NSLocalNetworkUsageDescription` and `NSBonjourServices`); a binary run from a terminal or
  over ssh is not asked. Denied, the browser reports a problem and the window says so.
- **`NSOpenPanel` as the save prompt** also settles file access: a folder chosen in the panel is
  one the app may write to without a separate Downloads/Desktop/Documents prompt.
- **The offscreen `--dump-window` render needs an explicit background**; a bare `NSHostingView`
  draws text on transparency (white on nothing in dark mode).
- **`CGPath.normalized(using:)`** gives the union of overlapping shapes: the hollow cloud in the
  menu bar is the stroked union, not three stroked circles.

## Measured (2026-11-22, release build)

MacBook Pro → MacBook Air M4, gigabit Ethernet, 8 connections, 9.29 GB in 10,401 files:
protocol 1, 81.0 s = 115 MB/s; protocol 2 (frame CRCs, header-covered chunk CRC), 80.2 s =
927 Mbps (116 MB/s). Checksums identical on both sides each time. The wire is the limit either
way. Killed at 25 % and re-sent (protocol 1): "continuing: 1.60 GB already there", file identical.

The same 9.29 GB through `nimbus-chaos` on the LAN (`corrupt=400M`, 5 MB/s between 600 and
680 MB, `kill=one` at 1.5 GB, `kill=data` at 3 GB, 0.2 % loss between 5 and 5.6 GB): 25 bits
flipped, 32 connections lost, arrived identical in 173 s. That run showed connections decaying
from 8 to 1 within a round; with replacement (`carry`) a 6 GB file through 18 flips and 27 lost
connections held 8 throughout and took 67.6 s, identical.

Loopback on the MacBook Pro (source in the page cache), one 6 GB file. Protocol 2: 4.76 GB/s
(38 Gbps) with 1 connection, 2.97 GB/s with 8. Protocol 1: 3.87 with 1, 3.49 with 4, 3.21 with
8, 2.97 with 16 (the first figure moves with what else the Mac is doing; the checksums cost
nothing that shows). More connections do not help when the
memory bus is the limit; they are there for real links and for small files. 400 × 8 MB files:
3.1 GB/s. 10,000 files of 4 to 14 KB: 0.9 s, about 11,000 files a second, finalize included.

After the security changes (0.2.2): 10,000 small files in 1.1 s over loopback (the quarantine
mark is an `open` and an `fsetxattr` per file; `SafeTree` alone measured no cost), 200 × 8 MB at
4.6 GB/s.

**Protocol 3, encrypted (2026-11-23, release build, loopback on the MacBook Pro, both ends on
the one Mac, so sealing and opening share its cores):** one 6 GB file, 3.16 GB/s (25 Gbit/s)
with 8 connections and 2.58 GB/s with 1; 200 × 8 MB at 4.7 GB/s; 10,000 small files in 1.1 s.
Against protocol 2 on the same Mac: level or better with 8 connections, about half with one
(one thread now seals as well as reads). CryptoKit's in-place AES-GCM exists only from macOS 27;
on 15 a seal returns a new buffer and that is what was measured. The plan's gate (within 5% of
an unencrypted build on a real link, 9.0 Gbit/s of file bytes on 10 GbE) has NOT been run:
there is no unencrypted build of protocol 3, and gigabit cannot show the difference.

**Protocol 3 between two Macs (2026-11-23, MacBook Pro → MacBook Air M4, gigabit Ethernet,
8 connections, the command line at both ends, found and paired by Bonjour name):** one 6.29 GB
file in 56.2 s = 895 Mbps, 943 Mbps while moving; 832 MB in 5,100 files in 7.3 s = 913 Mbps.
The wire is the limit, as it was for protocol 2 (927 Mbps over 9.29 GB). Checksums identical.
Killed twice and sent again at once: "continuing: 3.79 GB already there", identical. Through
`nimbus-chaos` (`corrupt=300M`, `kill=one` at 800 MB, `kill=data` at 1.5 GB, everything cut and
refused from 25 s to 55 s): 19 bits flipped, 37 connections cut, one reconnect, identical in
87.9 s. An identity that is not paired was refused and wrote nothing. `--reset-identity` on the
Pro: the Air was told, forgot the pairing, and refused a copy of the old key by name
("a retired identity of pro-cli was used"). That run found the unattended grant declining a
re-send while the killed sender's drop was still held for its reconnect; `--unattended-from`
now lets an offer through when the drop in its way is only `.reconnecting`.

**Thunderbolt 4, MacBook Pro ↔ MacBook Air M4 (2026-11-23, release build, link-local over the
Thunderbolt Bridge, MTU 1500; iperf3 says the link carries 37.6 Gbit/s):**
the speed test (encrypted, no disk): 31 Gbit/s each way on one connection, 36 to 38 Gbit/s on
2 to 32. **The engine and the encryption fill the link.** Real drops of one 10.5 GB file of
random data, from the sender's page cache: to a RAM disk on the Air 20 to 23 Gbit/s whatever
the number of connections; Air to the Pro's SSD 17 Gbit/s overall (24 while moving, with a
one-second stall near 80 %); to the Air's own SSD (86 % full) 8.5 Gbit/s on one connection and
7.4 on eight. So above gigabit the disks are the limit, on the Air well under a 10 GbE wire,
and more connections do not help a disk-bound receiver (they hurt slightly). What holds a
real drop to about 20 Gbit/s with a RAM disk under it (reading the page cache, or every
connection writing one file) is not found yet.

**The engine in modules (2026-11-24, release build, loopback on the MacBook Pro,
`scripts/bench-loopback.py` with the build before the split and the build after it taking
turns, best of three; a Tamarin proof was using four cores throughout, so compare the columns
and not these figures with the ones above):** one 4 GB file on 8 connections 26.0 Gbit/s
before and 25.6 after; on 1 connection 21.5 and 20.8; 200 × 8 MB 42.3 and 41.8; 10,000 small
files 736 and 742 Mbit/s (1.0 s both); the speed test 46.1 and 46.0 up, 47.7 and 52.0 down.
The same run with only the split (before the pairing machine): 25.1 and 24.8, 19.0 and 20.1,
41.8 and 43.4, 730 and 725, 45.0 and 46.4, 46.9 and 50.0. No difference that is not noise:
`CipherState`, `Socket` and `Ledger` are each called once or twice a chunk, and a module
boundary costs nothing at that rate. A change that puts a cross-module call per byte or per
small write on the data path is a different matter; measure it the same way.

**After the second round (2026-11-24, release build, loopback, `scripts/bench-loopback.py`,
the build before it and the build after taking turns, best of three):** one 4 GB file on 8
connections 27.2 Gbit/s before and 26.6 after; on 1 connection 22.2 and 22.9; 200 × 8 MB 43.1
and 42.1; 10,000 small files 764 and 774 Mbit/s (1.0 s and 0.9 s); the speed test 52.3 and
53.9 up, 50.7 and 58.5 down. No difference that is not noise, with four machines consulted
and `SafeTree` now holding every file to one thing on disk (an `fstat` it already made, and
one more per file at the end).

**Not measured yet:** Wi-Fi, 10 GbE itself, a drop larger than the receiver's
RAM (whether `F_NOCACHE` on either side helps there), and whether an explicit socket buffer size
beats macOS's auto-tuning on a fast link. Measure before tuning any of them.

## Not verified by a person yet (as of 2026-11-23)

- **From 2026-11-24, in the app's glue, fixed by reading and tested only below the window**:
  Retry and "Pair Again and Send" following the key and not the tile's name
  (`Peer.asItIsNow` is tested; the click is not); an offer or a speed-test question that
  ended before its panel was shown no longer showing one; Settings › Remove on the pair-again
  list ending that Mac's running drop; the command line's question naming the drop. And
  nothing of this round was run between two Macs.

- **Everything on screen in 0.3**: the pairing panel in every stage on two real Macs, the
  familiar-name alert, Known Macs (Rename, Forget), Reset Identity, the identity number, the
  one-time "Drops are now encrypted" notice, the notification for a retired identity, the
  damaged-identity alert. The engine under all of it is tested; nobody has clicked any of it.
  The command line was driven end to end by a script on one Mac (pair, a wrong code first, a
  drop asked about, a decline, the unattended grant, a reset).
- Protocol 3 between two Macs **in the app**. The command line has done it (see Measured):
  Bonjour probing, pairing, drops, resume, chaos and retirement, Pro to Air.

- Accepting a drop (the Accept / Decline panel, then the folder chooser) and seeing it land;
  the notification afterwards.
- The right-click menu on the menu bar icon; Services › Nimbus Drop To… from Finder (macOS lists
  the service; nobody has chosen it); the "which kinds of file?" sheet on a real drop; Retry.
- A real Mac leaving Wi-Fi mid-drop and coming back, on the new build (the engine is tested
  through the proxy and across two Macs with connections cut, not with a radio).
- A drag from Finder onto a tile, and beside the tiles; a drop on the Dock icon followed by a
  click on a tile. The menu bar icon opening and closing the window.
- Add by Address in the window (the engine side, `Probe.hello`, is tested; the field is not).
- A tile for a Mac on another protocol major (rendered by `--dump-window`, never seen live).
- The Local Network prompt on a first launch, and the window's message when it is denied.
- The Login Item after a restart; the app starting in the menu bar only when launched that way.
- 0.1.0 installed from its DMG on a Mac that has never run the app: the first launch, the Local
  Network prompt, the Login Item registering itself. And the updater, which has had nothing to
  update to yet.

## Release and distribution

Same as the siblings: `VERSION=` in `build.sh`, `CFBundleVersion` = commit count,
`./build.sh release NOTES.md` builds the stapled app, the DMG and the updater's zip, tags
`v<VERSION>`, runs the preflight and publishes. Signing reads `SIGN_IDENTITY` / `NOTARY_PROFILE`
from the git-ignored `.signing` (copied from a sibling on this machine).

0.3 does not talk to 0.2, so every Mac is updated together; the auto-updater carries a 0.2
Mac to 0.3 without asking whether the others are ready, and from then on it and a 0.2 Mac
show each other as "Needs an update".

Releases: **0.3.1 on 2026-11-23** (protocol 3.1: the speed test, asked about at the other
Mac; Forget tells the other Mac; Uninstall and the Services switch in Settings; a Mac on
several interfaces is reached by the service order; a pairing that works pulses on the tile),
**0.3.0 on 2026-11-23** (protocol 3: encrypted and authenticated, pairing, key
expiry; reviewed against its plan the same day and the findings fixed before release; the
first release the auto-updater carries anyone to), **0.2.2 on 2026-11-22** (the security release: see Security; update everything to it),
**0.2.1 on 2026-11-22** (protocol 2.2: a receiver that is getting data no longer shows
or counts itself as waiting; chunks retransmitted, counted; Internals; log levels), **0.2.0 on 2026-11-22** (protocol 2.1: reconnecting, Retry, kinds of file, the Finder
service, Settings) and **0.1.0 on 2026-11-22** (DMG + zip, Developer ID, notarized, protocol 2.0). 0.1.0 was
published step by step rather than with `build.sh release`: `./build.sh dmg`, check the
artefacts (`spctl` on the app, on the DMG, on the app inside the mounted DMG, and on the app
unpacked from the zip; `stapler validate`; `--preflight`), then tag, push, `gh release create`.
Since then CI's `update-health` job fails a run when the published release loses its zip or no
longer matches the declared bundle id and team.

- **"A required agreement is missing or has expired" (HTTP 403) from `notarytool`** means the
  owner has an Apple Developer agreement to accept at developer.apple.com/account; nothing in
  the repo is wrong. After they accept it, it takes minutes to take effect and not all at once:
  on 2026-11-22 `notarytool history` succeeded about four minutes later while `submit` was still
  refused for a little longer. Check with a real `submit` before starting a build that needs two.
- `build.sh app` signs before it notarizes, so a notarization failure still leaves a correctly
  signed bundle in `dist/` to inspect (`spctl` says `Unnotarized Developer ID`).
- The next release is the first one the auto-updater will carry people to; nobody has seen the
  update flow in this app yet. No `SocialCard.swift` yet; port it from a sibling.
