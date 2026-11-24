# Threat model

What Nimbus Drop is defended against, and what it is not. The claims that follow from this,
each with its evidence, are in `claims.md`; what has to be trusted for any of them to hold is
in `tcb.md`. The specification of the protocol is `docs/plans/secure-drops-plan.html`.

## What is protected

- **The contents of a drop**: nobody but the two Macs reads them, and what is saved is what
  was sent.
- **Who a Mac is**: nothing is sent to, shown from or accepted from a key that two people have
  not paired.
- **The receiver's disk**: nothing is written outside the folder its person chose, nothing
  there is overwritten, nothing is written before its person said yes.
- **The person's say**: nothing one Mac has another do happens without a yes from the person
  there.
- **The Mac staying usable**: no crash, no lockout, no flood of questions on another Mac's
  say-so, as far as the limits below reach.

## Who attacks

| Attacker | Can | Covered |
|---|---|---|
| **On the network** (the same LAN or anywhere on the path) | read, drop, delay, replay, reorder, alter and invent any packet; open any number of connections; advertise any name by Bonjour; run any number of sessions at once | Yes. This is the Tamarin models' attacker (`formal/tamarin`), and the tests' (`ProtocolTests`, `PairingTests`, `ReviewTests`). |
| **In the room during a pairing** | all of that, and hear both codes read out | Yes. The codes are a fingerprint of the connection, not a secret (`NimbusPairing.spthy`; `formal/computational/pairing-bound.md` for the two in a million). |
| **A paired Mac that means harm** | all of that, with a key the victim trusts: send any offer, any manifest, any authenticated record; stop reading; retire itself mid-drop; ask for anything | Yes for the disk, the yes, crashes and lockouts (`SecurityTests`, `ContainmentTests`, `ReviewTests`, `IndependentReviewTests`). It can always send its own bytes, and waste a person's attention up to the limits on questions. |
| **Whoever controls the clock** (a forged time server) | set the calendar to anything, at any time | Yes: lifetimes are counted on the continuous clock (`Expiry.tla`). With one stated limit, below. |
| **A holder of a key that was given up or has run out** | present it | Yes: refused, and its use is reported (`TrustWithdraw.tla`, `Expiry.tla`). |
| **A flood from many addresses** | fill every pool of connections that have proved nothing | Partly. One address cannot keep a paired Mac out (`Admission.tla`). Many can slow or stop new connections; that is conceded. |

## Compromise, and what survives it

- **A Mac's static key becomes known later**: drops already made stay secret (forward
  secrecy), and the attacker still cannot pass as someone else TO that Mac
  (`master_is_secret_...`, `the_responder_agrees_...`). It can pass AS that Mac from then on,
  until the key ends or is retired.
- **A drop's keys become known**: that drop only. Every drop has its own `master`.
- **Nothing survives** an attacker who has the static key before a handshake and the network
  during it, for that peer: the lemmas say "not given away before the handshake finished".

## Not defended, and said so

- **Software running as the user on either Mac.** It can read the files, ask the Secure
  Enclave what the app asks, write the trust file (or put an old one back: there is no
  protection against rollback of local state), and click. The app is not sandboxed.
- **Physical access.** Including: someone who can both hold the calendar back and cut the
  Mac's power more often than hourly can stop its count of elapsed time, and so keep a key
  from running out (`Expiry.tla`: the count is on disk as of its last hourly write).
- **Time the Mac is switched off under a calendar someone controls**: not counted.
- **Traffic analysis**: sizes and timing are visible. Bonjour shows a name.
- **Bytes at rest**: what is in a partial folder between attempts is believed (the ledger's
  word), and what is saved is as safe as the disk. After a power cut mid-drop the ledger can
  be ahead of the data it speaks for; see `claims.md`, D-4.
- **A person who is deceived**: who says yes to a pairing nobody they can hear asked for, or
  types a code from somewhere other than the other Mac's screen.
- **Withdrawing trust everywhere at once.** Forget and Reset act here at once and tell the
  other Mac when it can be reached. A Mac that is off or elsewhere learns at its next contact.
- **Availability against whoever controls the network**: they can always drop everything.

## Limits that bound what a stranger can cost (see `Tuning`)

Before any key is proved: 64 connections at once (8 from one address), 500 arrivals a second
(200 from one address), 1 KB, ten seconds. A key nobody paired: 8 at once, 16 KB, pairing
only. A paired key: 8 connections that have not said what they came for, two questions on
screen per address and six in all, one speed test at a time, a manifest of 64 KB plus 2 KB per
file offered out of 1 GB shared, at most 2^60 bytes in a drop.
