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
- **Never write outside what the person chose.** A manifest is input from another machine and
  its paths become paths here. `Manifest.validate()` is the gate; a change to it, or to how the
  receiver builds paths, without a case in `testAManifestThatReachesOutsideIsRefused` is not
  finished. Nothing existing is ever overwritten: collisions get a "keep both" name.
- **Nothing is written before the person accepts.** The app asks twice: Accept or Decline, then
  where to save; declining either declines the drop. `--receive` (the CLI) accepts everything and is for a machine the owner controls.
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
                            patience, shortened by the tests); Socket (blocking TCP: connect,
                            listen, exact read/write, keepalive, shutdown-to-cancel); control
                            frames with their two CRCs; the messages; ChunkHeader (seal, verifies)
  Manifest.swift            Manifest (+ validate, key, chunk arithmetic); Scanner (walks what is
                            being sent); Naming.unique ("keep both"); checksum (zlib CRC-32)
  Ledger.swift              which chunks are on the receiver's disk: the resume record
  Transfer.swift            Identity (name, id, app version), TransferState, TransferProgress,
                            TransferStats; Transfer, the base both sessions share (thread-safe
                            state, progress, cancel, the silence watchdog)
  Sender.swift              SendSession: scan → offer → manifest → rounds of (plan → N stream
                            threads → done); replaces failed connections; closes stalled ones
  Receiver.swift            DropListener (accept loop; routes offers, data streams, hellos);
                            ReceiveSession (decision, tree, streams, rounds, settle, finalize)
  Discovery.swift           Advertiser (dns_sd register); Probe.hello (who is at this address);
                            PeerTable (pure: who is on the network, from what Bonjour reports);
                            PeerBrowser (NWBrowser + resolve to IPv4 + restart on trouble)
  Host.swift                LocalHost: the Bonjour host name, the IPv4 addresses
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
  StatusBarController.swift the status item: no menu, a click opens (or closes) the window; --dump-bar
  MainMenu.swift            the app's own menu bar while the window is open: version, updates,
                            Receive Drops, Open at Login, Parallel Connections
  MainWindow.swift          the window (SwiftUI in an NSWindow): header, destinations and Add by
                            Address, drops, the settings footer; --dump-window
  Settings.swift            UserDefaults: deviceID, receiving, streams, manualDestinations
  LoginItem.swift, AppIcon.swift, DMGBackground.swift, Updates.swift   as in the siblings
Tests/NimbusDropCoreTests/  20 tests: whole drops, decline, collisions, resume, cancel, a hostile
                            manifest, version mismatch, hello, the peer table, arithmetic, naming
Tests/NimbusDropChaosTests/ 22 tests: whole drops through ChaosProxy (about 85 s)
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
.build/release/NimbusDrop --receive DIR [--once] [--no-advertise] [--name N] [--port P]
.build/release/NimbusDrop [--streams N] --send TARGET PATH…    TARGET: a name from --peers, HOST, HOST:PORT
.build/release/NimbusDrop --peers | --print
.build/debug/NimbusDrop --dump-window P     the window with made-up data → P, P-light, P-empty
.build/debug/NimbusDrop --dump-bar P        the status item's three looks, light and dark
```

`--send` takes everything up to the next `--flag` as its arguments, so other flags go before it.
`--name N` gives the CLI a separate identity (`cli-N`), which is what lets a headless receiver
and the app run on one Mac and see each other.

**The second Mac is `macbookairm4`** (ssh works, Apple silicon, gigabit Ethernet to the same
switch, checkout at `~/Code/nimbus-drop`). A LAN test:

```
ssh macbookairm4 'cd ~/Code/nimbus-drop && git pull && swift build -c release && \
  (nohup .build/release/NimbusDrop --receive /tmp/nd-recv --name air-cli >/tmp/nd-recv.log 2>&1 &)'
.build/release/NimbusDrop --send air-cli <paths>
```

then compare both trees (`find … -type f -print0 | sort -z | xargs -0 shasum | shasum`). Kill
the sender mid-way and send again to exercise the resume.

**What an agent cannot do here:** click. The save prompt, the Local Network prompt and a drag
onto a tile need a person. What can be checked without one: that the prompt window exists
(`CGWindowListCopyWindowInfo` lists a window named "Incoming Drop" for the app's process, no
Screen Recording permission needed) and that it goes away when the sender gives up.

## The protocol (version 2.0)

Control connection, sender → receiver. A frame is
`[u32 length][u32 CRC of the length][u8 type][JSON][u32 CRC of type + JSON]`, big-endian.

```
sender                               receiver
offer {version, minor, app, name, id, items, fileCount, totalBytes}
                                     another major: decline, naming both versions; nobody is asked
                                     (the person decides)
                                     accept {}  |  decline {message}
manifest {chunkSize, entries[]}
                                     validate, find or make the partial folder, read its ledger
                                     plan {token, completeFiles[], partialFiles[{file, chunks[]}]}
N data connections, each: attach {token}, then
  [u32 file][u32 chunk][u32 length][u32 crc] + bytes, repeated;      crc covers the first twelve
  file = 0xFFFFFFFF ends the stream                                   header bytes and the chunk
done {streams: data connections opened so far}
                                     settle: wait for those connections to finish, close the rest
                                     everything here → set times and modes, rename, complete {saved[]}
                                     something missing → plan {…} again, and the sender goes round
error {message} from either side, at any point, ends the drop
hello {} → hello {name, id, version, minor, app}: "who is at this address?", then close
```

- **Versions.** `protocolVersion` (major, now 2) changes when two copies can no longer exchange
  a drop; `protocolMinor` when something is added that an older copy ignores (JSON decoding skips
  unknown fields). The app version rides along for people to read and never decides anything.
  The same three are in the Bonjour TXT record (`v=2.0`, `app=…`), the offer and the hello.
  **Frozen for good**, because it is how any two versions find out that they differ: the control
  frame layout and the `version` field of `Offer` and `Hello`. (Version 1, 2026-11-22, was never
  released; it had neither frame CRCs nor rounds and its frames do not parse here.)
- **Why two CRCs on a frame:** a flipped bit in the JSON is a wrong file name or size; a flipped
  bit in the length leaves the reader waiting for bytes that never come. Both happened in the
  chaos tests before the checks existed (the first as a wrong drop delivered).
- **Why the chunk CRC covers the header:** one flipped bit in the file or chunk index sends
  intact bytes to the wrong, already-written place. A CRC over the bytes alone passes them.
- **Rounds.** A data connection that dies, stalls or carries damage ends alone: the receiver
  counts it (`TransferStats`), throws away the chunk in hand, and closes it (after damage the
  framing cannot be trusted). The sender replaces a failed connection at once (`carry`), up to
  three replacements that deliver nothing. After `done` the receiver's `settle` waits for the
  connections the sender opened, then closes any still attached so nothing writes into a drop
  being judged. Missing chunks go in the next plan. `Tuning.idleRounds` (5) rounds in a row that
  deliver nothing end the drop.
- **Patience (`Tuning`).** A data connection silent for `stallSeconds` (60) is closed by the
  sender. A drop with no byte and no message for 3× that is given up by either side; a sender
  waiting for `complete` allows 10×, because the receiver may be putting a million files in
  place. TCP's own timeouts (keepalive 10 s + 3×5 s on a read, `TCP_RXT_CONNDROPTIME` 30 s on a
  write) catch a peer that is gone; the watchdog is for one that is there and frozen, which TCP
  will wait on for ever (a zero window is answered politely).
- **The last answer can be lost.** If the control connection dies after the receiver has
  everything, the receiver finishes correctly and the sender reports a failure. No protocol
  closes that gap. Sending again then delivers a second copy ("keep both").
- **The drop's key** is SHA-256 over the sender's id, the chunk size and every entry's path,
  kind, size, mtime and link. Same key + same destination folder = a resume. The partial folder
  is `<first item>.<key, 12 hex>.nimbusdrop-partial/` holding `items/` (the tree being built)
  and `ledger` (8 bytes per finished chunk, appended after the `pwrite`).
- **The ledger survives the process, not a power cut**: its records and the data reach the page
  cache, and nothing is fsynced (that would cost the speed this exists for). On load a record is
  kept only if its file is still there and long enough.
- **Cancel** is a best-effort `error` frame, then `shutdown()` on every socket 0.3 s later, so
  the other side reads "Cancelled on the other Mac" rather than "The connection closed". The
  sender reads the control connection on a thread of its own for the whole drop, so a reason
  sent mid-transfer is heard.

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
- **Each offer owns its questions** (`AppModel.asking`, by drop id): its Accept panel, then its
  folder chooser, independent of any other drop. A sender giving up removes exactly its own. The
  first version queued offers behind one shared "a question is open" flag, and a withdrawn offer
  left the flag set: no later offer was ever shown (found by the owner, 2026-11-22).
- **Checking prompts on the owner's screen competes with the owner.** Counting "Incoming Drop"
  windows while they are at the keyboard gives nonsense (they click Accept). Say so before
  sending test offers to a Mac someone is using, and prefer the Air.
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

**Not measured yet:** Wi-Fi, 10 GbE, a drop larger than the receiver's
RAM (whether `F_NOCACHE` on either side helps there), and whether an explicit socket buffer size
beats macOS's auto-tuning on a fast link. Measure before tuning any of them.

## Not verified by a person yet (as of 2026-11-22)

- Accepting a drop (the Accept / Decline panel, then the folder chooser) and seeing it land;
  the notification afterwards.
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

Releases: **0.1.0 on 2026-11-22** (DMG + zip, Developer ID, notarized, protocol 2.0). It was
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
