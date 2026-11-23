#!/usr/bin/env python3
# Copyright (C) 2026 Niels Joubert
# SPDX-License-Identifier: GPL-3.0-or-later
"""A second implementation of protocol 3's cryptography, for test vectors.

Written from the specification (docs/plans/secure-drops-plan.html), in another language and
with another library than the app's, so that "it talks to itself" is not mistaken for "it is
correct". It prints JSON; Tests/NimbusDropCoreTests/VectorTests.swift holds a copy and checks
the Swift implementation against it.

    python3 -m venv /tmp/v && /tmp/v/bin/pip install cryptography
    /tmp/v/bin/python scripts/vectors.py

Nothing here is used by the app.
"""
import hashlib
import hmac
import json
import struct

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


def sha256(b): return hashlib.sha256(b).digest()
def hmac256(k, m): return hmac.new(k, m, hashlib.sha256).digest()


def kdf(key, info, n):
    """KDF(key, info, n) of the specification: HKDF-SHA-256, empty salt."""
    return HKDF(algorithm=hashes.SHA256(), length=n, salt=b"", info=info).derive(key)


def noise_hkdf(ck, ikm, outputs):
    """Noise's HKDF: ck is the HMAC key; outputs chained with a counter byte."""
    temp = hmac256(ck, ikm)
    out, last = [], b""
    for i in range(1, outputs + 1):
        last = hmac256(temp, last + bytes([i]))
        out.append(last)
    return out


def nonce(n): return b"\x00" * 4 + struct.pack(">Q", n)


class Key:
    def __init__(self, raw):
        self.priv = X25519PrivateKey.from_private_bytes(raw)
        self.pub = self.priv.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)

    def dh(self, other): return self.priv.exchange(X25519PublicKey.from_public_bytes(other))


class Symmetric:
    """Noise's SymmetricState with the cipher folded in."""

    def __init__(self, prologue):
        name = b"Noise_XX_25519_AESGCM_SHA256"
        self.h = name + b"\x00" * (32 - len(name))
        self.ck = self.h
        self.k = None
        self.n = 0
        self.mix_hash(prologue)

    def mix_hash(self, data): self.h = sha256(self.h + data)

    def mix_key(self, ikm):
        self.ck, self.k = noise_hkdf(self.ck, ikm, 2)
        self.n = 0

    def encrypt_and_hash(self, plain):
        if self.k is None:
            self.mix_hash(plain)
            return plain
        c = AESGCM(self.k).encrypt(nonce(self.n), plain, self.h)
        self.n += 1
        self.mix_hash(c)
        return c

    def decrypt_and_hash(self, data):
        if self.k is None:
            self.mix_hash(data)
            return data
        p = AESGCM(self.k).decrypt(nonce(self.n), data, self.h)
        self.n += 1
        self.mix_hash(data)
        return p


def handshake(prologue, si, ei, sr, er):
    """XX with empty payloads, both sides run and checked against each other."""
    a, b = Symmetric(prologue), Symmetric(prologue)
    # -> e
    m1 = ei.pub
    a.mix_hash(ei.pub); m1 += a.encrypt_and_hash(b"")
    b.mix_hash(m1[:32]); assert b.decrypt_and_hash(m1[32:]) == b""
    # <- e, ee, s, es
    m2 = er.pub
    b.mix_hash(er.pub); b.mix_key(er.dh(ei.pub))
    m2 += b.encrypt_and_hash(sr.pub); b.mix_key(sr.dh(ei.pub)); m2 += b.encrypt_and_hash(b"")
    a.mix_hash(m2[:32]); a.mix_key(ei.dh(m2[:32]))
    rs = a.decrypt_and_hash(m2[32:80]); assert rs == sr.pub
    a.mix_key(ei.dh(rs)); assert a.decrypt_and_hash(m2[80:]) == b""
    # -> s, se
    m3 = a.encrypt_and_hash(si.pub); a.mix_key(si.dh(er.pub)); m3 += a.encrypt_and_hash(b"")
    ri = b.decrypt_and_hash(m3[:48]); assert ri == si.pub
    b.mix_key(er.dh(ri)); assert b.decrypt_and_hash(m3[48:]) == b""
    assert a.h == b.h and a.ck == b.ck
    # Split, with the third output this protocol keeps.
    k1, k2, master = noise_hkdf(a.ck, b"", 3)
    return [m1, m2, m3], a.h, k1, k2, master


def frame(body): 
    n = len(body)
    return struct.pack(">HH", n, (~n) & 0xFFFF) + body


def crockford(b):
    alphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
    bits = "".join(f"{x:08b}" for x in b)
    out = "".join(alphabet[int(bits[i:i + 5], 2)] for i in range(0, len(bits), 5))
    return "-".join(out[i:i + 4] for i in range(0, len(out), 4))


def key_tag(pub): return crockford(sha256(b"nimbus-drop key tag v1" + pub)[:10])


def identity_number(pub):
    h = b"nimbus-drop identity number v1" + pub
    for _ in range(5200):
        h = hashlib.sha512(h + pub).digest()
    return "".join(f"{int.from_bytes(h[i * 5:i * 5 + 5], 'big') % 100000:05d}" for i in range(6))


def six(b): return f"{int.from_bytes(b, 'big') % 1000000:06d}"


def main():
    hx = bytes.fromhex
    si = Key(hx("0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"))
    ei = Key(hx("2122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f40"))
    sr = Key(hx("4142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f60"))
    er = Key(hx("6162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f80"))
    opening = b"NDROP" + bytes([1, 3])
    prologue = b"nimbus-drop/3" + opening + opening
    messages, h, k1, k2, master = handshake(prologue, si, ei, sr, er)

    v = {
        "initiator_static": si.priv.private_bytes_raw().hex(), "initiator_ephemeral": ei.priv.private_bytes_raw().hex(),
        "responder_static": sr.priv.private_bytes_raw().hex(), "responder_ephemeral": er.priv.private_bytes_raw().hex(),
        "initiator_public": si.pub.hex(), "responder_public": sr.pub.hex(),
        "opening": opening.hex(), "prologue": prologue.hex(),
        "handshake_frames": [frame(m).hex() for m in messages],
        "h": h.hex(), "master": master.hex(),
    }

    # The first control message each way: type 1 (offer), no more fragments, total length, body.
    body = b'{"items":["a"],"fileCount":1,"totalBytes":5}'
    plain = bytes([1, 0]) + struct.pack(">I", len(body)) + body
    v["control_body"] = body.hex()
    v["control_frame_initiator"] = frame(AESGCM(k1).encrypt(nonce(0), plain, b"")).hex()
    v["control_frame_responder"] = frame(AESGCM(k2).encrypt(nonce(0), plain, b"")).hex()

    # The drop's keys.
    session = kdf(master, b"nimbus-drop session id v1", 16)
    attach_key = kdf(master, b"nimbus-drop attach v1", 32)
    resume_key = kdf(master, b"nimbus-drop resume v1", 32)
    v["session_id"], v["attach_key"], v["resume_key"] = session.hex(), attach_key.hex(), resume_key.hex()
    stream = lambda conn: kdf(master, b"nimbus-drop stream v1" + struct.pack(">Q", conn), 32)
    v["stream_key_1"], v["stream_key_2"] = stream(1).hex(), stream(2).hex()
    challenge = hx("a0a1a2a3a4a5a6a7a8a9aaabacadaeaf")
    v["challenge"] = challenge.hex()
    v["attach_7"] = (session + struct.pack(">Q", 7) + hmac256(attach_key, session + struct.pack(">Q", 7) + challenge)[:16]).hex()
    later_h = sha256(b"a later handshake")
    v["later_h"] = later_h.hex()
    v["resume_proof"] = hmac256(resume_key, b"resume" + later_h).hex()
    v["resumed_proof"] = hmac256(resume_key, b"resumed" + later_h).hex()

    # One record and the end marker on connection 1: sealed header, then the chunk with the
    # header as associated data; counters 0, 1, 2.
    header = struct.pack(">III", 3, 9, 5)
    k = AESGCM(stream(1))
    v["record"] = (k.encrypt(nonce(0), header, b"") + k.encrypt(nonce(1), b"hello", header)).hex()
    v["end_marker"] = k.encrypt(nonce(2), struct.pack(">III", 0xFFFFFFFF, 0, 0), b"").hex()

    # Pairing.
    ns, nr = hx("11" * 32), hx("22" * 32)
    v["ns"], v["nr"] = ns.hex(), nr.hex()
    v["commit"] = sha256(b"nimbus-drop pair commit v1" + h + ns).hex()
    codes = kdf(ns + nr, b"nimbus-drop pair codes v1" + h, 16)
    v["code_receiver"], v["code_sender"] = six(codes[:8]), six(codes[8:])

    # Identity.
    v["initiator_tag"], v["initiator_number"] = key_tag(si.pub), identity_number(si.pub)
    v["responder_tag"], v["responder_number"] = key_tag(sr.pub), identity_number(sr.pub)
    print(json.dumps(v, indent=1))


if __name__ == "__main__":
    main()
