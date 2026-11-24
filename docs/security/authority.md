# Authority: what grants it, who can make it, where it is checked

An inventory. "Authority" here is anything that lets something happen on a Mac: a key counted
as proved, a pairing, a person's yes, a drop's keys, a place on the disk. For each: what
stands for it in the code, the one place it can come from, where it is checked again before
it is acted on, and how it ends. `scripts/test-capabilities.py` holds the "cannot be made
elsewhere" column to the compiler where the compiler can hold it.

Swift's access control is the mechanism, and it is not isolation: everything is one process,
and the app's own code is trusted for the decisions marked "the app" below.

## The flow

```
a connection ──Admission──▶ a place ──handshake──▶ Channel (a proved key)
                                                      │
                              Trust.standing(of: key) │  asked every time, never kept
                                                      ▼
              purpose in the sealed hello: drop │ resume │ pair │ verify │ retire │ speed
                                                      │
                 the person's yes (a panel; the terminal; the one standing grant)
                                                      │
                 Trust.track(session, key)  ◀── registered, or ended there and then
                                                      │
     DropKeys(master) ──▶ attach tag, stream keys, resume proof ──▶ SafeTree (the chosen folder)
```

## What stands for what

| Authority | In the code | Made only by | Checked again at | Ends when |
|---|---|---|---|---|
| A place at the listener | a ticket (`UInt64`) from `Admission` | `Admission.step(.arrive…)`; the listener holds the socket under that number | every later event names the ticket; one that gave way gets nothing more (`close(.gone)`) | it proves a paired key and says what it came for, or gives way, or closes |
| A proved key | `Channel` (`remote`, `local`, `h`) | a finished Noise XX handshake: `Channel`'s initialiser is `private`; `initiate` and `respond` are the only makers | nothing is taken from a `Channel` as proof of pairing: see the next row | the connection closes |
| Who that key is to this Mac | `KeyStanding`, from `Trust.standing(of:)` | `TrustCore`, from the trust file. A `KnownMac` has no initialiser a caller can reach (it can be decoded; nothing takes one as proof) | asked afresh at each decision: at the hello, after the yes (`ReceiveSession`, `SpeedResponder`), at `Trust.track`, at `Trust.store` | trust is withdrawn or the key runs out (`trust-lifetime.md`) |
| A pairing | an entry in the trust file | `Trust.store(pairing:…)`, called by `PairingSession` when its machine says `store`: this person typed right AND the other Mac said so, on this connection's proved key, under the key this Mac still has | `TrustCore.store` refuses a key that may not be paired | Forget, Remove, retire, replace, reset, expiry |
| A live session | registration in `TrustCore.sessions` | `Trust.track` (`package`): on the list only if the key is paired at that moment, else ended there | every withdrawal ends what is on the list; a tick ends what is past its grace or was never begun | it finishes, or trust in its key goes |
| A person's yes to a drop | `ReceiveSession.accept(destination:)` | the app: the Accept panel, the terminal's answer, or `--unattended-from` for one key | the round machine takes a yes only while deciding, and only with `paired: true` asked at that moment; then the manifest must be what was offered | spent once: the machine leaves `deciding` |
| A person's yes to a speed test | `SpeedResponder.accept()` | the app, likewise | the standing asked again; one test at a time; an absolute deadline | the test ends |
| A person's yes to pairing, and the code they type | `PairingSession.proceed()`, `.submit(_:)` | the app | the gate (one pairing); the machine (three tries at one fixed code) | the pairing ends |
| A drop's keys | `DropKeys`, from a `Secret` only `Noise.split` makes | `DropKeys(master: channel.master)`; the bytes are unreadable outside `NimbusCrypto` | the attach tag for each data connection (`claim`: once per number, only while the drop takes data); the resume proof for each reconnect | the drop ends or trust is withdrawn: the session drops them (`keys = nil`) |
| A record that may be written | the plaintext of a record that opened under the stream key, with the header as associated data, checked against the manifest (file, chunk, length) | `ReceiveSession.receive` | the machine's `takesData`, asked under the lock, before a connection is let in | the connection ends, or the drop is judged |
| A place on the disk | `SafeTree`: descriptors of the partial folder's holder and of `items`, held from the start | `SafeTree(root:)`, following no link | every operation walks from those descriptors with `O_NOFOLLOW`; what is there must be what the manifest says; two entries are never one thing; placing replaces nothing | `release`, and the partial folder removed only if it is still the one held |

## Where the compiler holds it

`scripts/test-capabilities.py`, 32 programs: outside the engine's package nothing can name
`KeyPair`, `Secret`, `DropKeys`, `CipherState`, `Noise`, `TrustCore`, `PairingMachine` or
`Channel`, register a session with the trust store, or make a Known Mac; inside the package
but outside `NimbusCrypto` nothing can read a key's bytes, make a `Secret` from bytes, or
derive a key.

## Where it is the app's to get right (trusted, not enforced)

- **The yes.** `accept`, `proceed`, `submit` and `SpeedResponder.accept` are `public` and do
  what they say. That they are called only from a panel's button (with no Return key), the
  terminal's answer or the one standing grant is the app's code, and is reviewed, not checked.
- **Withdrawing trust** (`Trust.forget`, `retire`, `removeFromAgain`, `completeReset`):
  `public`, a person's decision by way of the app. They only ever take authority away.
- **`Trust.store(pairing:)` is `public`.** The engine's own caller is `PairingSession`; the
  app calls it for the made-up Macs in rendered windows (`--dump-window`), on a store of its
  own. A caller that linked the engine could store any key. Narrowing it to `package` and
  giving the renders their own way in is a small change, left for after this round.
- **Which Mac a click means**: a tile, a row's Retry. Two defects of this kind were found by
  review on 2026-11-24 (`IndependentReviewTests`); the rule is `Peer.asItIsNow`: a drop is
  sent to a key.

## Stale authority

Nothing that was true when it was checked is assumed still true when it is used:

- pairing standing is not kept in a session: it is asked at the hello, again after the yes,
  and `Trust.track` decides registration under the store's lock (the first model's finding);
- a session that outlives its key's trust is ended by the store, which knows of every live
  session (`TrustWithdraw.tla`: `LiveIsOnTheList`);
- a drop's keys are dropped when the drop ends or trust goes, so an attach or a resume
  presented later proves nothing;
- a finished drop's one remaining key is kept five minutes and checked for age when asked;
- a data connection is let in only while the drop takes data, asked under the lock.

In flight when trust is withdrawn: the sockets are closed and the keys wiped; one write or
one rename already inside the kernel finishes; nothing is put in place afterwards.
