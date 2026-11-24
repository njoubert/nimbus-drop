# Filesystem containment

What a drop may do to the receiving Mac's disk, against whom that is held, and what is not
claimed. The evidence is `Tests/NimbusDropCoreTests/ContainmentTests.swift` (2026-11-24);
each guard has a line in `scripts/mutate.py` (`python3 scripts/mutate.py containment:`).

## The claim

Every change a drop makes to the disk is one that the destination the person chose and the
manifest they accepted allow.

1. **Outside the destination nothing is created, changed, replaced or removed**: not a
   file's bytes, not its mode, times or extended attributes, not a folder's entries.
2. **Inside it, nothing that was there is changed, replaced or removed.** A name that is
   taken stays as it was (whatever has it: a file, a folder, a link, a link to nowhere) and
   the newcomer gets a "keep both" name.
3. **What appears is what the manifest names**, as the kind it says, no larger than it says:
   each top-level item under its own name or a "keep both" one, with what the manifest puts
   in it; or, for a drop that has not finished, one partial folder holding a ledger and, under
   `items`, entries of the manifest. A link that points out of its drop is not made.
4. **Two entries of a manifest are never one thing on disk.** Names that the destination's
   volume takes for one name end the drop; they do not become one file holding both.

The one exception to 1 is the receiver's own scratch file for the quarantine mark, in the
user's temporary folder under a random name (`Quarantine.value`); nothing about it comes from
the other Mac. The log and the history are the app's, not a drop's.

## Against whom

**A paired Mac that means harm.** It holds valid keys, so everything it sends is
authenticated: any manifest, and any records under the drop's own keys. It may send several
drops, and may know what another paired Mac is about to send. The claim holds against it
without qualification.

**Somebody on this Mac changing the destination while a drop runs or between two attempts**,
with a lower bar: another account or a confined program that can write in the destination
folder but not elsewhere. (Software running as the user, unconfined, is outside every claim
this app makes.) In scope, and held:

- anything put in the destination or in a partial folder **before** an operation looks at it:
  a link, a folder, a file with a second name elsewhere (a hard link), a pipe, where the
  manifest has something else; a partial folder that is itself a link; a ledger that is a
  link, a second name for a file elsewhere, a pipe; a ledger that claims chunks that are not
  on disk, or files that have since become links or folders;
- a folder of the partial tree swapped for a link, or the `items` folder or the partial
  folder itself swapped or renamed away, **between two operations**: each operation starts
  again from descriptors the receiver has held since the drop began, follows no link, and
  what it finds must be what the manifest says;
- something appearing under the name a drop is about to take in the destination.

Not held (what a local actor can still do):

- **Move a folder the receiver has open.** The receiver holds a folder, not its name. If a
  folder of the partial tree is renamed away while files are being written into it, they go
  where it went (`testAFolderMovedAwayWhileOpenTakesOnlyItselfOutside` holds this to the
  moved folder alone: nothing that existed outside is touched).
- **Change what is in the partial folder**: alter bytes already received (nothing checks the
  contents of a file against anything; a resume takes the ledger's word for chunks whose file
  is there and long enough), put a different real folder where a folder was, add things that
  then travel with the drop or are cleared away with the partial folder.
- **Stall or stop a drop**: a pipe where a file belongs makes the receiver wait until its
  other end is opened (`testAPipeWhereAFileBelongsIsNotWrittenTo`); deleting the partial
  folder ends the drop.
- **Win a race inside one operation**: between the look at a top-level item and its move
  into place; between the check that the partial folder is still the drop's and its removal;
  and, on a volume that cannot move-without-replacing in one step (exFAT, MS-DOS: they answer
  `ENOTSUP`), between the look at a name and the move onto it.
- Whatever leads to the destination itself (its parent folders) is the person's choice and
  is followed as given.

## How it is held

- **The text** (`Manifest.validate`, before anything is made): relative paths of real names
  (no empty part, `.`, `..` or NUL, 255 bytes at most), each once as a Mac's disk compares
  names (case, composition), each inside a folder the manifest made, nothing named as a
  partial folder is (`….nimbusdrop-partial`, in any spelling a Mac's disk takes for it), and
  the manifest must be what was offered.
- **The disk** (`SafeTree`, for every operation of a drop): the partial folder and `items`
  are opened once, following no link, and held; every path is checked as text again and
  walked from that root with `openat(O_NOFOLLOW | O_DIRECTORY)`; a file is opened without
  following and must be an ordinary file with one name; a folder or link that is already
  there must be that folder or that link; each thing made, opened or finished is noted by
  device and inode, and a second entry arriving at the same thing ends the drop; mode, time
  and the quarantine mark are set through a descriptor of the thing after looking at what
  it is; the ledger is opened the same way, beside the root, and used through one descriptor.
- **Putting in place** (`SafeTree.place`): `renameatx_np(RENAME_EXCL)` from the held root into
  the destination's descriptor; on `EEXIST` the next "keep both" name. The partial folder is
  removed only if it is still the folder the tree holds.

Neither gate relies on the other. The text cannot match every disk (this Mac's APFS takes
`Maße` and `Masse` for one name, an exFAT volume beside it does not), so the disk refuses
what the text lets through; and `SafeTree` refuses `..` without having been spared it.

## Volumes

Everything above was run on APFS that does not tell case apart (the default). A test that
needs names to be folded says so and is skipped where they are not; on such a volume
`validate` still refuses names that differ only in case. Putting in place on a volume without
`RENAME_EXCL` is `testPlacingOnAVolumeThatCannotMoveWithoutReplacing`, skipped unless
`NIMBUS_CONTAINMENT_VOLUME` names a folder on one (run once against an exFAT disk image:
passes). Not run: whole drops onto exFAT, SMB or a case-sensitive volume.

## Open

- **`ReceiveSession.conduct` still makes `<partial>/items` with `FileManager`** before
  `SafeTree` is asked, and that follows a link: with the partial folder a link to a folder
  elsewhere, one empty folder named `items` is left there before the drop is refused.
  `SafeTree(root:)` makes both folders itself, following nothing; the fix is to delete the
  `createDirectory` call. `testAPartialFolderThatIsALinkIsNotBuiltIn` carries this as an
  expected failure that trips when it is done.
- **A folder that holds the partial folder of an unfinished drop can no longer be sent as it
  is** (the receiver refuses the manifest). `Scanner` could leave such folders out; or partial
  folders could have names another Mac cannot work out, which would make the rule unnecessary.
- **A pipe where a file belongs** stalls a drop (above). `O_NONBLOCK` on the open would refuse
  it at once; whether that open may then fail on a file whose contents are not on this Mac
  (iCloud) was not checked.
