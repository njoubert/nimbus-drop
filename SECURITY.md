# Security

Nimbus Drop sends files between Macs on a local network, encrypted and authenticated end to
end. What it is defended against, and what it is not, is written down in
[`docs/security/threat-model.md`](docs/security/threat-model.md); each claim, with the evidence
for it and its limits, in [`docs/security/claims.md`](docs/security/claims.md).

## Reporting a vulnerability

Please report it privately first.

- Use **Report a vulnerability** on this repository's Security tab
  (https://github.com/njoubert/nimbus-drop/security/advisories/new).
- If that is not offered, open an issue that says only that you have a security report, with
  no details, and you will be given a private way to send it.

What helps: the version (the app's About, or `NimbusDrop --print`), what an attacker needs
(on the network, a paired Mac, in the room during a pairing), what they get, and the steps.
A failing test is the best report there is: `Tests/NimbusDropCoreTests/SecurityTests.swift`
and `IndependentReviewTests.swift` show how the existing attacks are written.

This is one person's project. A report is read within a few days. A confirmed vulnerability is
fixed in the next release, with the attack as a test, and credited to whoever found it unless
they would rather not be.

## Supported versions

The latest release only. Protocol 3 (0.3.0 and later) does not talk to anything earlier, and
0.2.2 and earlier have no encryption and no authentication of either end: update every Mac.
The app updates itself from this repository's releases, which are signed with the developer's
Developer ID and notarized by Apple.

## In scope

Anything that lets someone on the network, in the room during a pairing, or at a paired Mac
that means harm: read or alter a drop, pass as a Mac they are not, write outside the folder
the person chose or over something that was there, start anything on another Mac without a
yes from the person at it, crash the app, or keep two Macs from pairing or dropping (beyond
what a flood from many addresses can always do).

## Not in scope

Software already running as the user on either Mac, physical access, and traffic analysis:
see the threat model, which says why.

## What is checked by machine

`./build.sh verify` runs it all: symbolic proofs of the handshake and the pairing (Tamarin),
model checking of the trust store, key expiry, pairing, a drop's rounds and admission (TLA+),
checks that the Swift decision code is the same machine as its model, mutation checks of both
models and tests, and the tests themselves. [`formal/README.md`](formal/README.md) says what
each establishes and what it does not. None of it is an independent audit, and the app has
not had one.
