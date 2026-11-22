<p align="center">
  <img src="docs/icon.png" alt="Nimbus Drop icon" width="128">
</p>

<h1 align="center">Nimbus Drop</h1>

<p align="center">
  Send large files and whole folders to another Mac on your local network, as fast as the
  network allows. Like AirDrop, but for 30 GB of photos over the LAN: you drag a folder onto
  the other Mac, the person there chooses where to save it, and it arrives checked and
  complete.<br>
  A menu bar item and a small window. Swift, SwiftPM, AppKit and SwiftUI. One dependency: our own
  <a href="https://github.com/njoubert/nimbus-updater">nimbus-updater</a>, which keeps it up to date.
</p>

<p align="center">
  <img src="docs/window.png" alt="The Nimbus Drop window: nearby Macs as drop targets, and drops under way" width="540"><br>
  <sub>Rendered by <code>--dump-window</code> with made-up Macs and drops.</sub>
</p>

```
./build.sh run            # debug build → dist/debug/Nimbus Drop Dev.app, launch it (add --fg for logs here)
./build.sh stop           # quit it
./build.sh test           # whole drops over loopback (swift test)
./build.sh install        # release build → /Applications/Nimbus Drop.app, register the Login Item, launch
./build.sh uninstall      # unregister the Login Item, remove the app and its preferences
./build.sh status         # running? installed? Login Item registered?
./build.sh app            # release build → dist/Nimbus Drop.app only
./build.sh dmg            # release build → dist/NimbusDrop-<version>.dmg, drag-to-Applications disk image
./build.sh icon           # re-render docs/icon.png
```

## What it does

**Receiving.** While *Receive Drops* is on (the menu, or the switch in the window), this Mac
announces itself on the local network and other Macs running Nimbus Drop can offer it files.
Nothing is written until you say so: an offer raises a folder chooser that says who is sending
(host name and IP address), what, how many files and how big, and asks where to save it,
starting in `~/Downloads`. *Cancel* declines. Turn receiving off and this Mac disappears from
everyone's list.

**Sending.** Open the window and every Mac found on the network is a tile showing its host name
and IP address. Drag a file, a folder, or a whole selection onto a tile; or click the tile, or
pick the Mac from the menu's *Send To*, and choose from a panel. The other person accepts, and
it goes.

**The drops list** shows each one's progress, speed and time left, and lets you stop it. A
received drop has a *Show in Finder* button. Both Macs get a notification when a drop finishes
or stops, and neither sleeps while one is under way.

**Nothing is overwritten.** If `~/Downloads/Christmas 2026` already exists, the new one lands as
`Christmas 2026 2`, the way Finder keeps both.

**An interrupted drop continues.** If the link drops, a lid closes, or someone quits, what
arrived stays in a `….nimbusdrop-partial` folder in the destination. Send the same items again,
save to the same folder, and only what is missing is sent. (If the files changed in between, it
is a new drop and starts over.) A partial folder you no longer want can simply be deleted.

**In the menu bar:** a cloud with an arrow while receiving is on, a hollow cloud while it is
off, and a percentage beside it while a drop moves. The app has a Dock icon only while its
window is open.

## How fast

The network is the limit. Measured 2026-11-22 between a MacBook Pro and a MacBook Air (both
Apple silicon, internal SSDs):

| | |
|---|---|
| Gigabit Ethernet, 9.29 GB in 10,401 files (one 6 GB file, 400 × 8 MB, 10,000 small) | 115 MB/s, the wire's ceiling |
| The same Mac to itself (no network), one 6 GB file | 3.2 GB/s with 8 connections, 3.9 GB/s with 1 |
| The same Mac to itself, 400 × 8 MB files | 3.1 GB/s |

So on gigabit, 30 GB takes a little over four minutes; on a faster link the engine has room up
to about 3 GB/s before the Macs themselves are the limit.

## How it works

- **Finding each other:** Bonjour, service type `_nimbusdrop._tcp`. The listener prefers port
  47823 and takes any free one otherwise.
- **A drop:** one control connection carries the offer, the answer, the manifest (every file,
  folder and symlink with size, time and mode) and the receiver's note of what it already has.
  Then 8 parallel TCP connections (*Parallel Connections* in the menu: 1 to 16) carry the data in
  4 MiB chunks. Every connection takes the next unsent chunk from one shared list, so a single
  huge file is spread across all of them and so is a folder of small ones.
- **Checked:** every chunk carries a CRC-32, verified before it is written. A damaged chunk
  stops the drop with a message; sending again continues it.
- **Written where it belongs:** each chunk is written straight to its offset in its file
  (`pwrite`), so nothing is reassembled afterwards. Modification times and permissions are set
  at the end and the finished items are moved into place in one rename each.
- **No encryption and no accounts,** by design: this is for a network you trust, and the
  safeguard is that a person at the receiving Mac approves every drop. Anyone on the same
  network can *offer* you a drop while receiving is on; nobody can make you take one. Data
  crosses the network in the clear.

Not carried over: extended attributes (Finder tags, quarantine flags), resource forks and
ownership. Symlinks are sent as symlinks. Sockets, devices and pipes are skipped.

## Setting up

Both Macs need Nimbus Drop running, Apple silicon and macOS 15 or later, on the same network.
The first launch asks for **Local Network** access; allow it, or the Macs cannot see each other
(System Settings › Privacy & Security › Local Network to change it later). Launched from
`/Applications` it adds itself to Login Items once, so the Mac is ready to receive after a
restart; turn that off in the menu (*Open at Login*) or in System Settings.

## From the command line

The same engine without the app, for scripts and for a Mac you reach over ssh:

```
NimbusDrop --receive ~/Incoming          # take every drop into that folder without asking (--once: just one)
NimbusDrop --send macstudio ~/Pictures/Christmas   # by the name --peers shows, or HOST, or HOST:PORT
NimbusDrop --peers                        # the Macs found in three seconds
NimbusDrop --print                        # this Mac's name, addresses and settings
```

`--receive` accepts everything offered to it. It is a tool for a machine you control, not
something to leave running on a network you do not.

## What it talks to

Other copies of Nimbus Drop on your local network, and nothing else, with one exception:
unless *Check for Updates Automatically* is off, it asks `api.github.com` once a day for the
newest release and downloads it from `release-assets.githubusercontent.com`. Your files never
leave your network.

## Licence

GPL-3.0-or-later. See [LICENSE](LICENSE).
