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
- **Nothing is written before the person accepts.** The Accept panel's answers are Save to
  Downloads (one click), Save to… (then the folder chooser; cancelling it declines) and Decline. `--receive` (the CLI) accepts everything and is for a machine the owner controls.
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
  Palette.swift             the Nimbus colours: icon blue out, icon green in, coral, amber
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

## The protocol (version 2.2)

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
done {streams: data connections opened so far, resent: chunks sent twice so far (2.2)}
                                     settle: wait for those connections to finish, close the rest
                                     everything here → set times and modes, rename, complete {saved[]}
                                     something missing → plan {…} again, and the sender goes round
error {message} from either side, at any point, ends the drop
resume {token} on a NEW connection, after the control connection was lost (2.1):
                                     the session waiting under that token takes the connection
                                     as its control and answers plan {…}; a drop that finished
                                     meanwhile answers complete {…} again
hello {} → hello {name, id, version, minor, app}: "who is at this address?", then close
```

- **Reconnecting (2.1).** Losing the control connection used to end the drop; the owner sent
  to a Mac that changed Wi-Fi networks and it died with "connection reset by peer" the moment
  the Mac came back (0.1.0, 2026-11-22). Now a connection-level failure (`DropError.connection`:
  closed, timed out, refused, a damaged frame) on the control connection sends both sides into
  `.reconnecting` for `Tuning.reconnectSeconds` (60): the receiver holds the session under its
  token (`awaitSender`), the sender loops (`reconnect`): ask `relocate` where the receiver is
  now (the app answers from Bonjour, so a new address is found), connect, `resume {token}`, take
  the `plan`. A decision (`error` frame: cancelled, declined, disk full) still ends it at once;
  a sender that fails for a reason of its own says so first (`SendSession.fail`), so the
  receiver does not wait out the minute. A 2.0 receiver drops the unknown `resume` frame and the
  sender's minute runs out: no worse than before.
- **The two ends do not learn of a dead control connection at the same time**, and the gap
  can be the rest of the drop. The owner pulled a cable for a minute on 0.2.0 (2026-11-22):
  the receiver's keepalive timed its control connection out, the sender's never did, the
  sender's data connections were replaced, and 5 GB crossed while the receiver sat in
  `.reconnecting`. The sender found out only on writing `done` (Broken pipe), then resumed in
  half a second. Two consequences, both fixed after 0.2.0: the receiver showed "lost the
  connection, waiting" throughout, and its minute was running against a sender that was plainly
  there (a remainder longer than a minute would have ended the drop). Now a data connection
  attaching while the receiver waits puts it back in `.transferring`, and the minute is counted
  from the last byte that arrived. `ChaosProxy.killFarSide` models it (dead on the target's
  side; the client finds out when it writes), in
  `testTheReceiverGivesTheConversationUpButTheSenderOnlyFindsOutAtTheEnd`, which fails against
  0.2.0's receiver. Why the sender's keepalive did not fire is not known; do not count on it.
- **Silence is treated as a lost connection.** The watchdog (`Transfer.silence`) closes the
  control connection instead of failing, which leads into the same reconnect. A link that went
  quiet and came back is thereby recovered; a peer that really is frozen costs one more minute.
  Three reconnects in a row that find no new bytes at the receiver end it.
- **A finished drop remembers its answer** for five minutes (`DropListener.remember`), so a
  sender whose connection died before it heard `complete` is told on reconnecting. This closed
  most of the "last answer lost" gap.
- **One session per partial folder** (`DropListener.claim`): a new offer of the same drop ends
  an earlier session still waiting on that folder before touching it.
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
- **The last answer can still be lost**, if the sender cannot get back within the minute: the
  receiver finished, the sender reports a failure, and sending again delivers a second copy
  ("keep both"). No protocol closes that gap entirely.
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
- **Internals is the first place to look, and the first thing to ask an owner to copy.** Its
  status text is `AppModel.internalsStatus()` (plain text on purpose: Copy puts it, and the lines
  listed, on the clipboard). Per-connection figures come from `Transfer.dataConnections`
  (`streamOpened` / `streamCarried` / `streamClosed` in the engine). A drop's last lines are a
  `summary:` (bytes, time, rate, chunks, retransmitted, rounds, connections dropped, reconnects
  and attempts) on each side; each round logs how many chunks it sent.
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

**Not measured yet:** Wi-Fi, 10 GbE, a drop larger than the receiver's
RAM (whether `F_NOCACHE` on either side helps there), and whether an explicit socket buffer size
beats macOS's auto-tuning on a fast link. Measure before tuning any of them.

## Not verified by a person yet (as of 2026-11-22)

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

Releases: **0.2.0 on 2026-11-22** (protocol 2.1: reconnecting, Retry, kinds of file, the Finder
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
