# What a six-digit code is worth

The claim, the assumptions it rests on, and the attacks counted. An argument written out, not a
machine-checked proof: the symbolic proof (`formal/tamarin/NimbusPairing.spthy`) shows nobody
can make the codes agree by choosing, and cannot count how often they agree by luck. This
counts that. `formal/sas-bound.py` checks the arithmetic (exactly, and by playing the game).

## The claim

In one pairing that two people carry through, someone who sits in the middle of the
connection with keys of their own, hears both codes, says anything on either connection and
makes at most `q` hash evaluations gets a Mac to store a key that is not the other person's
Mac's with probability at most

    2 x 1.00000000000003 x 10^-6  +  q / 2^255  +  q^2 / 2^256

which for any `q` that can be computed is two in a million. Over `n` pairings that people
attempt it is at most `n` times that. In the other mode (identity numbers) there is nothing
to be lucky about: the attacker needs a key whose thirty-digit number equals a given one.

## The protocol, as the code has it

`h` is the handshake hash. `PairCodes`, `PairingMachine`:

    S -> R   c  = SHA-256("nimbus-drop pair commit v1" || h || Ns)      Ns: 32 random bytes
    R -> S   Nr                                                         32 random bytes, drawn after c arrives
    S -> R   Ns                                                         R checks it against c
    out      = HKDF-SHA-256(key = Ns || Nr, info = "nimbus-drop pair codes v1" || h, 16 bytes)
    codes    = (out[0..8] mod 10^6, out[8..16] mod 10^6)                one shown on each Mac

Each person types the code the other Mac shows. A Mac stores the pairing when its own person
typed the right code and the other Mac said its person did.

## Assumptions

1. **Random oracles.** SHA-256 over the commitment's input and HKDF-SHA-256 over the codes'
   input behave as independent random functions. (Standard for this kind of result; it is
   where this argument is weaker than a proof from standard assumptions.)
2. **Randomness.** `Ns` and `Nr` are uniform over 2^256 and drawn once per pairing
   (`Crypto.random`: `SecRandomCopyBytes`). `PairingMachineTests` checks the "once".
3. **The people.** Each types only what the other person's Mac showed, and the attacker
   cannot change what is read out (it may hear it). A person who types a code from anywhere
   else is outside this.
4. **The hash binds the keys.** Two Macs with the same `h` hold each other's real static keys
   (`the_handshake_hash_binds_both_static_keys`, proved in `NimbusHandshake.spthy` with no
   condition). So someone in the middle with their own keys has a different `h` on each side.
5. **One transaction, in order.** Each message once, the nonce only after the commitment, the
   reveal only after the nonce, the same expected code for all three tries
   (`PairingMachine`, held equal to its specification; `Pairing.tla`:
   `EachMessageOnceAndInOrder`, `CodesOnlyAfterTheCommitmentIsOpened`, `ThreeTries`).
6. **One pairing at a time on a Mac** (`PairingGate`; `PairingGate.tla`: `OnePairingAtATime`).

## The argument

The attacker `M` holds `h1` with `S` and `h2` with `R`, `h1 != h2` (4). For `S` to store `M`'s
key, `S`'s person must type the code `S` expects, having read it off `R`'s screen; so the code
`R` shows must equal the code `S` expects. For `R` to store `M`'s key, the code `S` shows must
equal the code `R` expects. Call these the two matches.

Towards `R`, `M` plays the sender: it must send a commitment `c'` before `R` draws `Nr` (5).
Unless `M` finds two inputs with one SHA-256 value (probability at most `q^2 / 2^257`), `c'`
can be opened to at most one `Ns'`, so `Ns'` is fixed before `Nr` exists. `R`'s two codes are
the random function at `(Ns' || Nr, h2)`, a point with 256 fresh bits `M` did not choose: each
is a uniform 64-bit number reduced modulo 10^6, and independent of everything fixed earlier.

Towards `S`, `M` plays the receiver: it must send `Nr'` before `S` reveals `Ns` (5). It holds
`c = H(.. || h1 || Ns)`, which tells it nothing about `Ns` unless it queries the oracle at the
right `Ns` (probability at most `q / 2^256`). So whatever `Nr'` it sends, `S`'s two codes are
the random function at a point containing 256 bits `M` does not know: uniform, as above, and
`M` cannot evaluate them for any candidate `Nr'` before choosing.

`M` may run the two sides in either order, and in either order the second side's codes are
fixed by an honest Mac's fresh value after `M`'s last choice on that side:

- `R` first: `M` knows `R`'s codes, then picks `Nr'` blind to `S`'s. Each match is a guess.
- `S` first: `M` learns `Ns` and `S`'s codes, then must commit to `Ns'` before `Nr`. A guess.

A guess at one code succeeds with at most the probability of the likeliest code. A 64-bit
number modulo 10^6 is not quite uniform: 2^64 is not a multiple of 10^6, and the likeliest
code has probability `ceil(2^64 / 10^6) / 2^64 = 10^-6 x (1 + 2.4 x 10^-14)`
(`sas-bound.py` computes it as an exact fraction). Two matches, so twice that, plus the two
ways of cheating the commitment. That is the claim.

Without the commitment check `M` sees `Nr` first and searches about 10^6 values of `Ns'` for
one that makes `R`'s codes come out as `S`'s: it wins almost always. The simulation shows
both, and the Tamarin mutant `NoCommitCheck` finds the same attack symbolically.

## Attacks counted

| | |
|---|---|
| Hearing both codes | Assumed throughout. The codes are a fingerprint of the connection, not a secret. |
| Grinding (many hash evaluations) | Only against the commitment: `q / 2^256` to learn `Ns` early, `q^2 / 2^257` to open one commitment two ways. Nothing else `M` chooses comes after the value it would need. |
| Modulo bias | 2.4 x 10^-14, counted exactly. |
| Three tries | Against one fixed code, typed by the person from the other screen (3, 5). They are for typing mistakes and give `M` no second guess. |
| Abort and retry | `M` can work out all four codes before the people finish and cut the connection when they do not match, so that a failed attempt looks like a network fault and not like "the codes do not match". It still gets one guess per pairing the two people start: the bound is per attempt, and `n` attempts cost `n` times it. Nothing retries by itself. |
| Parallel sessions | One pairing at a time per Mac (6), so `M` cannot open many and show the person the lucky one. |
| Reflection, role confusion | The two codes are different halves of the output and each Mac shows one and expects the other; a Mac's own code typed back at it is a wrong entry. A Mac does not pair with its own key (`KeyStanding.mine`). `h` covers both openings, both static keys and both ephemerals. |
| A request nobody asked for | `M` needs both people: one to say yes at one Mac, one to type at the other. The prompt says to go on only if someone you can hear is asking; requests nobody asked for are rationed (`PairingGate`). |
| Identity numbers | Thirty digits from 5200 rounds of SHA-512 over the key, compared by the Mac, all thirty. `M` needs a second key with the same number as a given key: about 10^30 keys tried, each costing 5200 hashes. |

## Not covered

- The people being talked into typing something else, or a Mac that is itself compromised.
- A proof without random oracles, or one checked by a machine (CryptoVerif, EasyCrypt). The
  three-move commit, reply, open structure is the one Vaudenay analysed (CRYPTO 2005) and that
  Laur and Nyberg, and Pasini and Vaudenay, built on; this argument follows theirs with the
  truncated KDF in place of their exclusive-or, which is what costs the random-oracle
  assumption. Mapping it onto their theorems line by line has not been done.
- More than two Macs' worth of concurrency beyond (6): the bound is linear in attempts.
