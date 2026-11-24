# Trust: what a key is to this Mac, and how that ends

The policy, stated once. The code is `TrustCore` (`Sources/NimbusCrypto/TrustCore.swift`),
which is pure and is held equal to `formal/tla/TrustCore.tla`; the lock, the disk and the
order of effects are `Trust` (`Sources/NimbusSecurityCore/Trust.swift`), modelled in
`TrustWithdraw.tla`; time is `Expiry.tla`. Each row names what checks it.

## What a key can be (`Trust.standing(of:)`)

| Standing | Meaning | New drop or speed test | May be paired |
|---|---|---|---|
| `mine` | this Mac's own key | no | no |
| `paired` | two people paired it, and it is within its dates | yes, each asked about | yes (again: keeps its end) |
| `expired` | paired, and the count of elapsed time reached its end | no | **no, for good** |
| `retired` | given up (it said so), replaced (a successor was paired), or run out | no | **no, for good** |
| `renew` | was paired; the pairing ended without the key being refused: this Mac's key changed, or the calendar passed the date before the count did, or the other Mac forgot this one | no | yes, by two people |
| `unknown` | never seen, or forgotten | no | yes, by two people |

Being paired is who a Mac is. It is never permission for what it asks.

## How a pairing ends

| Event | Who can cause it | The key afterwards | What it had running | Checked by |
|---|---|---|---|---|
| **Its end, by the count** | time | `expired`, for good | may finish, within a day (or one key lifetime if shorter); what was still waiting for a yes is withdrawn | `Expiry.tla`: `PairedNoLongerThanItsLife`, `PastItsEndIsNeverPaired`, `NoSessionPastItsGrace` |
| **Its date, by the calendar, before the count** | time, or whoever sets the calendar | `renew`: to be paired again, not refused | as above | `OnlyTheCountRefusesForGood` (the first review's F3) |
| **Forget** | the person here | `unknown`; a key already refused stays refused | ended before Forget returns | `TrustWithdraw.tla` (Forget) |
| **The other Mac says it no longer has this one paired** | that key, proved, on its own entry only | `renew` | ended at once | `TrustCore.tla`: `gone` |
| **Retire** (the other Mac reset its identity) | that key, proved | `retired`, for good | ended; the notice is acknowledged only after the file is written | `AcknowledgedMeansRefusedForGood` |
| **It Replaces…** (a successor is paired in its place) | the person here | `retired`, for good | ended | `TrustCore.tla`: `replaced` |
| **Reset Identity here** | the person here | `renew` (it was current) or stays refused | **every** session ended, a pairing in progress too | `TrustCore.tla`: `reset`; `IndependentReviewTests` |
| **This Mac's own key reaching its end** | time | `renew` | may finish, within the time above | `TrustTests` (not in the equality-checked machine) |

## The points at which things are decided

Everything in `Trust` runs under one lock. The decision is `TrustCore`'s, made with the lock
held; so these are the moments at which a concurrent withdrawal either came first or did not.

| | Decided | Carried out |
|---|---|---|
| A session may exist | `Trust.track`, at the END of its handshake: on the list, or ended there. Asking "is this key paired?" at the start is not the decision (the first model's finding). | at once |
| A yes becomes a drop | `ReceiveSession.conduct` asks the standing again after the yes, then sends `accept` | the next message |
| A yes becomes a speed test | `SpeedResponder`, the same | the next message |
| A pairing is stored | `Trust.store`, which also refuses if this Mac's key is no longer the one the pairing's handshake used | written before it returns |
| Trust is withdrawn | the withdrawing call, under the lock: the key is refused from here | the file is written with the lock held; then, with it free and before the call returns, the sessions are ended and the listeners told |
| A retire notice is acknowledged | after `Trust.commit` has written the file, or not at all | |

An operation in flight when trust is withdrawn: its sockets are closed and its keys wiped, so
nothing more is read or sent. One write or one rename that was already inside the kernel
finishes. Nothing is put in place afterwards (`finalize` checks before each item).

## "For good", exactly

- A refused key is refused **while its tombstone is among the newest 2000**. The store keeps
  that many. A tombstone is only ever made for a key two people once paired, so pushing one
  out takes two thousand later pairings ended. After that the key is `unknown`: nothing trusts
  it, and only two people pairing it afresh can change that
  (`TrustWithdraw.tla`: `NoSilentResurrection` holds with eviction; the run named "known
  limit" shows `AcknowledgedMeansRefusedForGood` failing with it).
  **Open for the owner:** leave it, raise the number, or never evict a tombstone made by a
  retire or a replacement (only those made by expiry). The last costs a few bytes per key ever
  retired and makes "for good" literal.
- **A withdrawal that could not be written** (a full disk) is in force in memory and is not
  on disk: quitting then would undo it. The store says so (`Trust.unsaved`), the app warns,
  the write is tried again twice a minute, and nothing is acknowledged to another Mac
  meanwhile.
- **The trust file put back from an older copy** undoes whatever came after it. Sealing it to
  this Mac's hardware stops it being opened elsewhere; it does not stop an old copy being put
  back here by software running as the user. Not defended (`threat-model.md`).
- **Two processes on one trust file** (a second command-line run with the same `--name`) do
  not see each other's changes, and the last to write wins. The app is one process. A standing
  grant (`--unattended-from`) is therefore not revoked by a `--forget` typed in another
  terminal; stop the receiver.

## Telling the other Mac

Withdrawing trust here is immediate and needs nobody. Telling the other Mac is best effort:
Forget tries for three seconds, Reset for ten in all, and a Mac that is off or elsewhere
learns at its next contact, when this Mac's key proves itself and says `paired: false`, or
when it presents a key that is refused. There is no way to revoke trust on a Mac that cannot
be reached, and none is claimed.
