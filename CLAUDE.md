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
- **Nothing is sent to, or shown from, a key that is not paired**, and nothing decides who a
  Mac is but the key it proved. Names, addresses and Bonjour records are labels. A change that
  lets a name, an address or a record affect what a paired key may do, or where its tile
  points, is a vulnerability (the first plan had one; see The protocol).
- **The plan is the specification**: `docs/plans/secure-drops-plan.html`, with the two reviews
  it went through. A change to the cryptography, the pairing, the key schedule or the admission
  limits is a change to the plan first, a vector in `scripts/vectors.py` (a second
  implementation, in Python; never "fix" it to match the Swift), an attack in the tests, and a
  line in `scripts/mutate.py` that breaks the new guard and names the test that must notice.
  The first mutation run missed 4 of 17: tests that passed whether or not their guard existed.
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

```
Sources/NimbusDropCore/     the engine; no AppKit. The tests drive it over loopback.
  Wire.swift                DropError; protocolVersion / protocolMinor; Tuning (the engine's
                            patience and its admission limits, shortened by the tests); Socket
                            (blocking TCP: connect, listen, exact read/write, writev, keepalive,
                            shutdown-to-cancel); the messages
  Crypto.swift              KDF, PublicKey (canonical form, tag, identity number), KeyPair,
                            CipherState (AES-GCM with a counter nonce and a limit), Noise XX
  Channel.swift             the opening, the handshake both ways, probe, sealed and fragmented
                            control messages; DropKeys (everything derived from `master`);
                            RecordHeader (a data record on the wire)
  Trust.swift               this Mac's key and what it knows of others': Known Macs, tombstones,
                            the pair-again list, expiry in elapsed time, withdrawing trust;
                            TrustClock, TrustStorage, MemoryStorage
  EnclaveStorage.swift      the trust file on disk, sealed under a Secure Enclave key agreement
  Pairing.swift             PairCodes, PairingGate (one at a time, rationing), PairingSession
  Retirement.swift          the retire notice, Trust.reset; Trust.paired() for tests
  Manifest.swift            Manifest (+ validate, key, chunk arithmetic); Scanner (walks what is
                            being sent); Naming.unique ("keep both"); checksum (zlib CRC-32)
  SafeTree.swift            every file operation a receiver performs on a drop, confined to its
                            folder (openat, no symlinks followed); see Security
  Ledger.swift              which chunks are on the receiver's disk: the resume record
  Transfer.swift            Identity (name, id, app version), TransferState, TransferProgress,
                            TransferStats; Transfer, the base both sessions share (thread-safe
                            state, progress, cancel, the silence watchdog)
  Sender.swift              SendSession: scan → offer → manifest → rounds of (plan → N stream
                            threads → done); replaces failed connections; closes stalled ones
  Receiver.swift            DropListener (accept loop; routes offers, data streams, hellos);
                            ReceiveSession (decision, tree, streams, rounds, settle, finalize)
  Discovery.swift           Advertiser (dns_sd register; no key material); Probe (ask an address to
                            prove a key), Prober (the same, rationed); PeerTable (pure: one peer
                            per browse result); PeerBrowser (NWBrowser + resolve + probe)
  Host.swift                LocalHost: the Bonjour host name, the IPv4 addresses
  Log.swift                 DropLog (the engine's and the app's debug lines, to whatever sink the
                            app sets) and LogFile (stamped, appended from any thread, rotated)
  History.swift             HistoryEntry, HistoryStore (one JSON file, newest first, 500 at most)
  FileTypes.swift           FileKinds (which kinds of file a drop holds, by what macOS takes the
                            extension to mean); ScannedDrop.keeping(kinds:) (send only some)
  Format.swift              bytes, byte rates, bit rates (Mbps), durations, counts
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
  LoginItem.swift, AppIcon.swift, DMGBackground.swift, Updates.swift   as in the siblings
Tests/NimbusDropCoreTests/  107 tests. DropTests (whole drops), SecurityTests (a hostile paired
                            sender against the disk), ProtocolTests (impostors, replay, floods,
                            retirement mid-drop), PairingTests (two people; a man in the middle
                            who hears both codes), TrustTests (expiry against a clock that lies,
                            the file), VectorTests (against scripts/vectors.py), CryptoTests
                            (the published Noise vector)
Tests/NimbusDropChaosTests/ 28 tests: whole drops through ChaosProxy (about 135 s)
scripts/vectors.py          the second implementation; scripts/mutate.py, the mutation checks
build.sh                    build / test / run / stop / app / dmg / release / install / uninstall /
                            status / icon / clean
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
.build/debug/NimbusDrop --dump-window P     the window with made-up data → P, P-light, P-empty
.build/debug/NimbusDrop --dump-bar P        the status item's three looks, light and dark
```

`--send` takes everything up to the next `--flag` as its arguments, so other flags go before it.
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

## The protocol (version 3.0)

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
  waiting, with a pause after each refusal that doubles (`Tuning.pairQuiet…`).
- **The window shows one code at a time** (`PairingStage.read` / `.type`): the Mac that asked
  reads its code out and the Mac that was asked types it, then they swap. The wire and the
  engine take the two entries in either order, as before; the order is the window's, driven
  by `PairingSession.otherTyped` (which is a hint and proves nothing: a `paired {}` from the
  other end still stores nothing by itself). Both codes were on screen at once at first, and
  whoever pressed Return first lost sight of the code the other still had to type (the owner,
  2026-11-23). The command line still prints its code and asks in one go; a terminal keeps it.
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
- **Withdrawing trust is one ordered procedure** (`Trust.withdrawLocked`): written to disk,
  then the store refuses the key, then every session it authenticated is ended and its keys
  wiped (`Transfer.withdrawn`), then listeners drop what it had waiting, and only then is a
  retire notice acknowledged. Retire and "It Replaces…" leave a tombstone (refused for good);
  Forget does not, and tells nobody: the forgotten Mac learns at its next drop, when the key
  it has paired proves itself and says `paired: false` (`Trust.notePairingGone`: its half is
  withdrawn the same way and the Mac goes on the pair-again list, so the tile says so; until
  2026-11-23 it stayed "Paired" and every drop failed). The app then asks at once
  (`AppModel.offerToPairAgain`): pair again and send, or not now. Scheduled expiry is different on purpose: a running drop may finish, within
  a day or one key lifetime, whichever is shorter.
- **Admission** (`DropListener.admit`, `serve`): a slot before a thread. Not yet a key: 64 at
  once, 500 a second, 1 KB, 10 s. A key nobody paired: 8 at once, 16 KB, pair/verify only.
  A data connection before its attach is accepted: 16 per drop in progress, 5 s, none when no
  drop is. After accept: a manifest of 64 KB + 2 KB per file offered, out of 1 GB shared.
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

**Not measured yet:** encryption on a link faster than gigabit, Wi-Fi, 10 GbE, a drop larger than the receiver's
RAM (whether `F_NOCACHE` on either side helps there), and whether an explicit socket buffer size
beats macOS's auto-tuning on a fast link. Measure before tuning any of them.

## Not verified by a person yet (as of 2026-11-23)

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

`VERSION` in build.sh is 0.3.0 and has not been released: 0.3 does not talk to 0.2, so every
Mac is updated together, and the auto-updater will carry a 0.2 Mac to it without asking whether
the others are ready.

Releases: **0.2.2 on 2026-11-22** (the security release: see Security; update everything to it),
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
