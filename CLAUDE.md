# Nimbus Drop — notes for agents

A macOS app that sends files and folders to another Mac on the LAN: a menu bar item, a small
window, and a headless command line. Pure SwiftPM, no Xcode project, one dependency:
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
- **Nothing is written before the person accepts.** The app's only way to accept is the folder
  chooser. `--receive` (the CLI) accepts everything and is for a machine the owner controls.
- **Grill me relentlessly** before building a feature: every question whose answer would change
  the work, with the facts already checked. Decisions, not options.
- **Be concise.** Short reports, the salient facts only.
- **`prek` (pre-commit) must pass.** `prek install` once, then `prek run --all-files` before
  claiming done. Shellcheck at its default severity. Never disable a hook to get past it.
- **`swift test` must pass**, and a change to the protocol, the ledger or the naming without a
  test is not finished. The tests run whole drops over loopback; they are cheap.
- **Licence headers.** Every new Swift file starts with `// Copyright (C) 2026 Niels Joubert` /
  `// SPDX-License-Identifier: GPL-3.0-or-later`. GPL-3.0-or-later; don't vendor incompatible code.
- **It talks to the LAN, and to GitHub only for updates.** README must keep saying exactly this.
- **Install nothing on the owner's behalf.** `build.sh install` registers a Login Item; that is
  the owner's call. `build.sh run` (the dev bundle) is fine.

## Workflow

- **Changes go up as pull requests** once the first version is in: branch from `main`, push,
  `gh pr create`; the owner reviews and merges. (The initial scaffold was committed straight to
  `main`, with the owner's say-so, on 2026-11-22.)
- **Check that a push arrived**: compare `git rev-parse HEAD` with
  `git ls-remote origin refs/heads/<branch>`.
- **A PR that touches anything the owner sees gets a screenshot**: `--dump-window`, `--dump-bar`,
  `--render-icon`, `--render-dmg-background`. The siblings' CLAUDE.md say where the images live
  (the orphan `pr-assets` branch).

## Layout

```
Sources/NimbusDropCore/     the engine; no AppKit. The tests drive it over loopback.
  Wire.swift                DropError; Socket (blocking TCP: connect, listen, exact read/write,
                            keepalive, shutdown-to-cancel); control frames; the messages; ChunkHeader
  Manifest.swift            Manifest (+ validate, key, chunk arithmetic); Scanner (walks what is
                            being sent); Naming.unique ("keep both"); checksum (zlib CRC-32)
  Ledger.swift              which chunks are on the receiver's disk: the resume record
  Transfer.swift            Identity, TransferState, TransferProgress; Transfer, the base both
                            sessions share (thread-safe state, progress, cancel)
  Sender.swift              SendSession: scan → offer → manifest → plan → N stream threads
  Receiver.swift            DropListener (accept loop, routes offers and data streams);
                            ReceiveSession (decision, tree, streams, finalize)
  Discovery.swift           Advertiser (dns_sd register); PeerBrowser (NWBrowser + resolve to IPv4)
  Host.swift                LocalHost: the Bonjour host name, the IPv4 addresses
  Format.swift              bytes, rates, durations, file counts
Sources/NimbusDrop/         the app
  main.swift                flags, AppDelegate, one-copy rule, Login Item on first launch
  CLI.swift                 --receive / --send / --peers / --print / --check-update / --preflight
  AppModel.swift            peers, transfer rows, the receiving switch, the save prompt,
                            notifications, the sleep hold; the menu and the window both read it
  StatusBarController.swift the status item and its menu; --dump-bar
  MainWindow.swift          the window (SwiftUI in an NSWindow), MainMenu, --dump-window
  Settings.swift            UserDefaults: deviceID, receiving, streams
  LoginItem.swift, AppIcon.swift, DMGBackground.swift, Updates.swift   as in the siblings
Tests/NimbusDropCoreTests/  15 tests: whole drops, decline, collisions, resume, cancel, a hostile
                            manifest, chunk arithmetic, naming, formatting
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

## The protocol (version 1)

Control connection, sender → receiver. Frames are `[u32 length][u8 type][JSON]`, big-endian.

```
sender                               receiver
offer {version, name, id, items, fileCount, totalBytes}
                                     (the person decides)
                                     accept {}  |  decline {message}
manifest {chunkSize, entries[]}
                                     validate, find or make the partial folder, read its ledger
                                     plan {token, completeFiles[], partialFiles[{file, chunks[]}]}
N data connections, each: attach {token}, then
  [u32 file][u32 chunk][u32 length][u32 crc] + bytes, repeated;
  file = 0xFFFFFFFF ends the stream
done {streams}
                                     wait for N end markers, check the ledger is complete,
                                     set times and modes, rename into place
                                     complete {saved[]}
error {message} from either side, at any point, ends the drop
```

- A change to any message or to the chunk header is a new `protocolVersion`; a receiver declines
  a version it does not speak. Two Macs on different versions cannot exchange drops, so bump it
  only when the wire really changes.
- **The drop's key** is SHA-256 over the sender's id, the chunk size and every entry's path,
  kind, size, mtime and link. Same key + same destination folder = a resume. The partial folder
  is `<first item>.<key, 12 hex>.nimbusdrop-partial/` holding `items/` (the tree being built)
  and `ledger` (8 bytes per finished chunk, appended after the `pwrite`).
- **The ledger survives the process, not a power cut**: its records and the data reach the page
  cache, and nothing is fsynced (that would cost the speed this exists for). On load a record is
  kept only if its file is still there and long enough.
- **Cancel** is a best-effort `error` frame, then `shutdown()` on every socket 0.3 s later, so
  the other side reads "Cancelled on the other Mac" rather than "The connection closed". For the
  same reason a sender's stream thread waits 0.3 s before reporting its own failure: the
  receiver's reason, arriving on the control connection, should win.
- **A dead peer** is noticed by TCP keepalive (10 s idle, 3 probes 5 s apart) on a read and by
  `TCP_RXT_CONNDROPTIME` (30 s) on a write.

## Platform facts (checked 2026-11-22, macOS 27)

- **Bonjour registration is `DNSServiceRegister` (dns_sd), not `NWListener`**, because the
  listening socket is our own POSIX one. Passing no callback is fine; the registration lives as
  long as the `DNSServiceRef`. Browsing is `NWBrowser` with `.bonjourWithTXTRecord`.
- **Resolving a peer is a throwaway `NWConnection`** to the browse result's endpoint, IPv4-only
  (`NWProtocolIP.Options.version = .v4`), read `currentPath.remoteEndpoint`, cancel. The listener
  therefore sees connections that open and close without a word; `DropListener.serve` gives a
  connection ten seconds to send a first frame and drops it silently otherwise.
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

MacBook Pro → MacBook Air M4, gigabit Ethernet, 8 connections: 9.29 GB in 10,401 files in
81.0 s = 115 MB/s (the wire), checksums identical on both sides. Killed at 25 % and re-sent:
"continuing: 1.60 GB already there", the remaining 4.40 GB at 116 MB/s, file identical.

Loopback on the MacBook Pro (source in the page cache), one 6 GB file: 3.87 GB/s with 1
connection, 3.49 with 4, 3.21 with 8, 2.97 with 16. More connections do not help when the
memory bus is the limit; they are there for real links and for small files. 400 × 8 MB files:
3.1 GB/s. 10,000 files of 4 to 14 KB: 0.9 s, about 11,000 files a second, finalize included.

**Not measured yet:** Wi-Fi, 10 GbE, a drop larger than the receiver's RAM (whether `F_NOCACHE`
on either side helps there), and whether an explicit socket buffer size beats macOS's
auto-tuning on a fast link. Measure before tuning any of them.

## Not verified by a person yet (as of 2026-11-22)

- Accepting a drop in the app's folder chooser and seeing it land; the notification afterwards.
- A drag from Finder onto a tile; a drop on the Dock icon followed by a click on a tile.
- The Local Network prompt on a first launch, and the window's message when it is denied.
- The Login Item after a restart; the app starting in the menu bar only when launched that way.
- A signed, notarized build (`./build.sh dmg`); no release has been published, so the updater
  has nothing to find and CI has no `update-health` job yet (add the siblings' once v0.1.0 is out).

## Release and distribution

Same as the siblings: `VERSION=` in `build.sh`, `CFBundleVersion` = commit count,
`./build.sh release NOTES.md` builds the stapled app, the DMG and the updater's zip, tags
`v<VERSION>`, runs the preflight and publishes. Signing reads `SIGN_IDENTITY` / `NOTARY_PROFILE`
from the git-ignored `.signing` (copied from a sibling on this machine). No releases yet. No
`SocialCard.swift` yet; port it from a sibling when the first release goes out.
