#!/usr/bin/env python3
# Copyright (C) 2026 Niels Joubert
# SPDX-License-Identifier: GPL-3.0-or-later
"""What an ordinary caller cannot do, checked by trying to compile it.

    swift build && python3 scripts/test-capabilities.py

The engine keeps its secrets and its authority behind Swift's access control: key bytes are
`internal` to NimbusCrypto, the types that hold them are `package`, and the things that stand
for something proved (a session, a Known Mac) have no initialiser a caller can reach. That is
only true while nobody widens an access level, and nothing notices when somebody does: the
code still builds. So each line here is a small program that MUST NOT compile, with the
reason the compiler must give, in one of two positions:

  outside   a program that links the engine and is not part of its package: what the engine
            would be to anyone who used it as a library. It sees `public` only.
  inside    a module of the engine's package other than NimbusCrypto (the app is one): it
            sees `package` too, and still must not reach a key's bytes.

And a few that MUST compile, so that a broken build is not mistaken for a locked door.

This is access control, not isolation: everything is one process, and code that set out to
get at a key could (unsafe pointers, reflection, the memory itself). It stops the mistake.
"""
import os
import subprocess
import sys
import tempfile

PACKAGE = "nimbus_drop"

# (position, module to import, code, what the compiler must say; None: it must compile)
CASES = [
    # ---- A program outside the package
    ("outside", "NimbusDropCore", "let k = PublicKey.madeUp(); _ = k.tag; _ = Trust.inMemory().standing(of: k)", None),
    ("outside", "NimbusDropCore", "let k = KeyPair()", "cannot find 'KeyPair' in scope"),
    ("outside", "NimbusDropCore", "_ = DropKeys.self", "cannot find 'DropKeys' in scope"),
    ("outside", "NimbusDropCore", "_ = CipherState.self", "cannot find 'CipherState' in scope"),
    ("outside", "NimbusDropCore", "_ = Noise.self", "cannot find 'Noise' in scope"),
    ("outside", "NimbusDropCore", "_ = TrustCore.self", "cannot find 'TrustCore' in scope"),
    ("outside", "NimbusDropCore", "_ = PairingMachine.self", "cannot find 'PairingMachine' in scope"),
    ("outside", "NimbusDropCore", "_ = Channel.self", "cannot find 'Channel' in scope"),
    ("outside", "NimbusDropCore", "func f(t: Trust) { _ = t.keyPair }", "'keyPair' is inaccessible due to 'package' protection level"),
    ("outside", "NimbusDropCore", "func f(t: Trust) { _ = t.beginReset() }", "'beginReset' is inaccessible due to 'package' protection level"),
    ("outside", "NimbusDropCore", "func f(t: Trust) throws { try t.commit() }", "'commit' is inaccessible due to 'package' protection level"),
    # A session is registered with the trust store by the engine, at the end of a handshake.
    ("outside", "NimbusDropCore", "func f(t: Trust, s: ReceiveSession) { t.track(s, key: s.sender.key) }", "'track' is inaccessible due to 'package' protection level"),
    # A Known Mac is something two people paired: it is made by the trust store and by nothing else.
    ("outside", "NimbusDropCore", "func f(m: KnownMac) { _ = KnownMac(key: m.key, name: \"x\", announced: [], pairedAt: m.pairedAt, method: \"codes\", "
     "endsElapsed: 0, endsWall: m.endsWall, lastSeen: nil, major: 3) }", "missing argument for parameter 'from' in call"),
    # (The initialiser the compiler offers instead is Codable's: a record can be DECODED by
    # anyone. That is why no entry point of the engine takes a record as proof of anything:
    # what a key is to this Mac is asked of the trust store, every time.)
    ("outside", "NimbusDropCore", "func f(m: KnownMac) { _ = m.endsElapsed }", "'endsElapsed' is inaccessible due to 'internal' protection level"),
    # ---- A module of the engine's own package, other than the pure one
    ("inside", "NimbusCrypto", "let k = KeyPair(); _ = k.publicKey.tag", None),
    ("inside", "NimbusCrypto", "let k = KeyPair(); _ = k.raw", "'raw' is inaccessible due to 'internal' protection level"),
    ("inside", "NimbusCrypto", "let k = KeyPair(); _ = k.secret", "'secret' is inaccessible due to 'internal' protection level"),
    ("inside", "NimbusCrypto", "_ = KeyPair(raw: Data())", "argument passed to call that takes no arguments"),
    ("inside", "NimbusCrypto", "_ = CipherState(key: Data())", "'CipherState' initializer is inaccessible due to 'internal' protection level"),
    ("inside", "NimbusCrypto", "_ = Crypto.kdf(Data(), \"label\", 32)", "'kdf' is inaccessible due to 'internal' protection level"),
    ("inside", "NimbusCrypto", "_ = Crypto.hmac(Data(), Data())", "'hmac' is inaccessible due to 'internal' protection level"),
    ("inside", "NimbusCrypto", "_ = Noise.hkdf(Data(), Data(), 2)", "'hkdf' is inaccessible due to 'internal' protection level"),
    ("inside", "NimbusCrypto", "func f(c: TrustCore) { _ = c.file }", "'file' is inaccessible due to 'internal' protection level"),
    ("inside", "NimbusCrypto", "func f(k: DropKeys) { _ = k.attachKey }", "'attachKey' is inaccessible due to 'internal' protection level"),
    ("inside", "NimbusCrypto", "func f(k: DropKeys) { _ = k.master }", "'master' is inaccessible due to 'private' protection level"),
    # A secret can be held and handed on anywhere in the engine; read, and made from bytes, only in the pure module.
    ("inside", "NimbusCrypto", "func f(k: DropKeys) -> Secret { k.resumeKey }", None),
    ("inside", "NimbusCrypto", "func f(k: DropKeys) { _ = k.resumeKey.bytes }", "'bytes' is inaccessible due to 'internal' protection level"),
    ("inside", "NimbusCrypto", "_ = Secret(Data())", "'Secret' initializer is inaccessible due to 'internal' protection level"),
    ("inside", "NimbusCrypto", "_ = DropKeys(master: Data())", "cannot convert value of type 'Data' to expected argument type 'Secret'"),
    ("inside", "NimbusSecurityCore", "func f(c: Channel) { _ = c.master.bytes }", "'bytes' is inaccessible due to 'internal' protection level"),
    ("inside", "NimbusSecurityCore", "func f(c: Channel) -> Data { c.master }", "cannot convert return expression of type 'Secret' to return type 'Data'"),
    ("outside", "NimbusDropCore", "_ = Secret.self", "cannot find 'Secret' in scope"),
]


def main():
    made = subprocess.run(["swift", "build", "--show-bin-path"], capture_output=True, text=True)
    products = made.stdout.strip()
    if made.returncode != 0 or not os.path.exists(os.path.join(products, "NimbusCrypto.swiftmodule")):
        sys.exit("no built modules to check against: run `swift build` first")
    bad = 0
    with tempfile.TemporaryDirectory(prefix="nimbus-capabilities-") as work:
        for n, (position, module, code, must_say) in enumerate(CASES, 1):
            path = os.path.join(work, f"case{n}.swift")
            with open(path, "w") as f:
                f.write(f"import Foundation\nimport {module}\n{code}\n")
            command = ["swiftc", "-typecheck", "-I", products] + (["-package-name", PACKAGE] if position == "inside" else []) + [path]
            done = subprocess.run(command, capture_output=True, text=True)
            said = done.stdout + done.stderr
            errors = [l.split("error: ", 1)[1] for l in said.split("\n") if "error: " in l and ".swift:" in l]
            if must_say is None:
                ok = done.returncode == 0
                note = "compiles, as it must" if ok else "MUST COMPILE and does not: " + "; ".join(errors[:2])
            else:
                ok = done.returncode != 0 and any(must_say in e for e in errors)
                note = "refused, as it must be" if ok else ("COMPILES, and must not" if done.returncode == 0 else "refused for another reason: " + "; ".join(errors[:2]))
            bad += not ok
            print(f"{'ok  ' if ok else 'FAIL'}  {position:7}  {code[:92]}  ->  {note}")
    print(f"\n{len(CASES)} programs, {bad} not as they must be")
    sys.exit(1 if bad else 0)


if __name__ == "__main__":
    main()
