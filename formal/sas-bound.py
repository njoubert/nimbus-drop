#!/usr/bin/env python3
# Copyright (C) 2026 Niels Joubert
# SPDX-License-Identifier: GPL-3.0-or-later
"""What a six-digit code is worth: the part of the pairing a symbolic prover cannot count.

    python3 formal/sas-bound.py [--digits 3] [--trials 20000] [--budget 20000]

formal/tamarin/NimbusPairing.spthy proves that someone in the middle cannot make the codes
agree by CHOOSING: every value they could steer a code with is either fixed before they see
what they would need (their own commitment) or does not exist yet (the responder's value).
What a proof with perfect hashes cannot say is how often the codes agree by LUCK. This plays
the game, with the real derivation (SHA-256 commitment, HKDF-SHA-256 codes, as in PairCodes
and scripts/vectors.py), against an attacker with a budget of hash evaluations per pairing:

  the protocol      the attacker sits between S and R with keys of its own, so each side has a
                    different handshake hash. It may try as many values as its budget allows
                    whenever it has a free choice. It wins a pairing if the code R shows is the
                    code S expects (S stores the attacker's key) or the reverse.
  no commitment     the same, against a responder that does not check the reveal against the
                    commitment: the attacker sees R's value first and then searches for its own.

Codes are shortened (--digits) so that luck is frequent enough to measure; the claim scales:
with d digits and the protocol as it is, one pairing is won with probability about 2 x 10^-d
whatever the budget (two codes, one blind try at each), so 2 in a million at six digits, per
pairing that two people actually sit down to. Without the commitment check the attacker wins
nearly always once its budget passes 10^d.

Exits non-zero if the measured rates are not those.
"""
import hashlib
import hmac
import math
import os
import sys


def arg(name, default):
    return int(sys.argv[sys.argv.index(name) + 1]) if name in sys.argv else default


DIGITS = arg("--digits", 3)
TRIALS = arg("--trials", 20000)
BUDGET = arg("--budget", 20000)
SPACE = 10 ** DIGITS


def hkdf(key, info, n):
    prk = hmac.new(b"\x00" * 32, key, hashlib.sha256).digest()
    out, block, i = b"", b"", 1
    while len(out) < n:
        block = hmac.new(prk, block + info + bytes([i]), hashlib.sha256).digest()
        out += block
        i += 1
    return out[:n]


def commitment(h, ns):
    return hashlib.sha256(b"nimbus-drop pair commit v1" + h + ns).digest()


def codes(h, ns, nr):
    """(the code the receiver shows, the code the sender shows), shortened to DIGITS."""
    out = hkdf(ns + nr, b"nimbus-drop pair codes v1" + h, 16)
    return int.from_bytes(out[:8], "big") % SPACE, int.from_bytes(out[8:], "big") % SPACE


def attack(check_commitment, budget):
    """One pairing with the attacker in the middle. True if either Mac would store its key."""
    h1, h2 = os.urandom(32), os.urandom(32)  # S's handshake with the attacker; the attacker's with R
    ns = os.urandom(32)                      # S commits; the attacker sees only the commitment
    _ = commitment(h1, ns)

    if check_commitment:
        # Towards R the attacker must commit now, before R's value exists. Whatever it tries
        # with its budget, it is trying against a value it has not seen: any choice is as good.
        ns_fake = os.urandom(32)
        nr = os.urandom(32)                  # R's value, made after the commitment arrived
        # Towards S it must send a value now, before S reveals. It knows R's codes already,
        # and cannot aim at them: S's codes depend on ns, which is inside the commitment.
        nr_fake = os.urandom(32)
        s_receiver, s_sender = codes(h1, ns, nr_fake)
        r_receiver, r_sender = codes(h2, ns_fake, nr)
    else:
        # R does not check the reveal. The attacker answers S first and learns ns and S's
        # codes; it has R's value in hand before it has to say anything binding to R, and
        # searches for a reveal that makes R's codes come out as S's.
        nr_fake = os.urandom(32)
        s_receiver, s_sender = codes(h1, ns, nr_fake)
        nr = os.urandom(32)
        r_receiver = r_sender = None
        for _ in range(budget):
            candidate = os.urandom(32)
            a, b = codes(h2, candidate, nr)
            if a == s_receiver or b == s_sender:
                r_receiver, r_sender = a, b
                break
        if r_receiver is None:
            r_receiver, r_sender = codes(h2, os.urandom(32), nr)
    # S's person types what R shows; S expects its own receiver code. And the reverse.
    return r_receiver == s_receiver or s_sender == r_sender


def same_derivation_as_the_code():
    """The vector `VectorTests` holds the Swift to (from scripts/vectors.py), at six digits."""
    h = bytes.fromhex("9215f3cc01011b03dabe5d4f4ebb601a0594688414f28abe5e5bc28bc6706df2")
    ns, nr = b"\x11" * 32, b"\x22" * 32
    out = hkdf(ns + nr, b"nimbus-drop pair codes v1" + h, 16)
    six = (int.from_bytes(out[:8], "big") % 10 ** 6, int.from_bytes(out[8:], "big") % 10 ** 6)
    return commitment(h, ns).hex() == "964d0d99aa5dab8bcee9d8109aa177dee98b8b3f38aa182b717bcd5bee17fc18" and six == (759656, 893228)


def main():
    if not same_derivation_as_the_code():
        sys.exit("this script no longer derives the codes as PairCodes does")
    expected = 1 - (1 - 1 / SPACE) ** 2
    won = sum(attack(True, BUDGET) for _ in range(TRIALS))
    rate = won / TRIALS
    sigma = math.sqrt(expected * (1 - expected) / TRIALS)
    print(f"{DIGITS} digits, {TRIALS} pairings attacked")
    print(f"  the protocol:    {won} won = {rate:.5f}   (two blind tries in {SPACE}: {expected:.5f}, +/- {4 * sigma:.5f})")
    ok = abs(rate - expected) <= 4 * sigma + 1 / TRIALS

    trials = max(20, TRIALS // 200)
    won = sum(attack(False, BUDGET) for _ in range(trials))
    broken = won / trials
    predicted = 1 - (1 - expected) ** BUDGET
    print(f"  no commitment:   {won} of {trials} won = {broken:.3f}   (a search of {BUDGET}: {predicted:.3f})")
    ok = ok and broken > 0.9 * predicted - 0.05
    print(f"  at six digits, as shipped: {2e-6:.0e} per pairing that two people agree to, whatever the attacker spends")
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
