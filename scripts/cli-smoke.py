#!/usr/bin/env python3
# Copyright (C) 2026 Niels Joubert
# SPDX-License-Identifier: GPL-3.0-or-later
"""The command line, end to end, on one Mac: two identities that are two Macs to each other.

    python3 scripts/cli-smoke.py .build/debug/NimbusDrop

A send between Macs that are not paired is refused and nobody is asked; they pair, each
"person" reading the other's code off its terminal; a folder is offered, accepted on the
terminal and compared byte for byte; a second offer is declined. Exits non-zero on the first
thing that is not as it should be. It makes two identities (cli-smoke-a, cli-smoke-b) under
~/Library/Application Support and removes them afterwards.
"""
import filecmp
import os
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import time

BIN = os.path.abspath(sys.argv[1]) if len(sys.argv) > 1 else ".build/debug/NimbusDrop"
PORT = "47999"
A, B = "cli-smoke-a", "cli-smoke-b"


class Process:
    def __init__(self, args):
        self.p = subprocess.Popen([BIN] + args, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=0)
        self.out = ""
        threading.Thread(target=self._pump, daemon=True).start()

    def _pump(self):
        while True:
            c = self.p.stdout.read(1)
            if not c:
                break
            self.out += c

    def wait(self, pattern, seconds=60):
        end = time.time() + seconds
        while time.time() < end:
            m = re.search(pattern, self.out)
            if m:
                return m
            time.sleep(0.05)
        sys.exit(f"TIMED OUT waiting for {pattern!r}\n--- its output ---\n{self.out}")

    def say(self, line):
        self.p.stdin.write(line + "\n")
        self.p.stdin.flush()


def run(args):
    return subprocess.run([BIN] + args, capture_output=True, text=True, timeout=120)


def forget_identities():
    base = os.path.expanduser("~/Library/Application Support")
    for bundle in os.listdir(base) if os.path.isdir(base) else []:
        if bundle.startswith("com.njoubert.nimbusdrop"):
            for name in (A, B):
                shutil.rmtree(os.path.join(base, bundle, "cli-" + name), ignore_errors=True)


def main():
    forget_identities()
    work = tempfile.mkdtemp(prefix="nd-smoke-")
    src, dst = os.path.join(work, "src", "Photos"), os.path.join(work, "dst")
    os.makedirs(os.path.join(src, "sub"))
    os.makedirs(dst)
    with open(os.path.join(src, "big.bin"), "wb") as f:
        f.write(os.urandom(20_000_000))
    with open(os.path.join(src, "sub", "small.txt"), "w") as f:
        f.write("hello\n")
    receiver = None
    try:
        print(run(["--name", A, "--identity"]).stdout.strip())
        receiver = Process(["--name", B, "--port", PORT, "--no-advertise", "--receive", dst])
        receiver.wait("receiving as")

        print("== not paired: refused, and nobody is asked")
        r = run(["--name", A, "--send", f"127.0.0.1:{PORT}", src])
        assert r.returncode != 0 and "pair first" in r.stdout, r.stdout
        assert "wants to send" not in receiver.out, receiver.out

        print("== pairing: each reads the other's code")
        a = Process(["--name", A, "--pair", f"127.0.0.1:{PORT}"])
        receiver.wait(r"pair\? .*\[y/N\]")
        receiver.say("y")
        code_b = "".join(receiver.wait(r"read this code out[^:]*:\s+(\d{3}) (\d{3})").groups())
        code_a = "".join(a.wait(r"read this code out[^:]*:\s+(\d{3}) (\d{3})").groups())
        assert code_a != code_b
        a.wait("the code they read to you:")
        a.say(code_b)
        receiver.wait("the code they read to you:")
        receiver.say(code_a)
        a.wait("paired with")
        receiver.wait("paired with")

        print("== a drop, accepted on the terminal")
        s = Process(["--name", A, "--send", f"127.0.0.1:{PORT}", src])
        receiver.wait(r"accept “.*” \(.*\) from .* into .*\[y/N\]")
        receiver.say("y")
        print(s.wait(r"done: .*").group(0))
        receiver.wait("saved ")
        cmp = filecmp.dircmp(src, os.path.join(dst, "Photos"))
        assert not (cmp.left_only or cmp.right_only or cmp.diff_files or cmp.funny_files), "the trees differ"
        assert filecmp.cmp(os.path.join(src, "big.bin"), os.path.join(dst, "Photos", "big.bin"), shallow=False)
        assert filecmp.cmp(os.path.join(src, "sub", "small.txt"), os.path.join(dst, "Photos", "sub", "small.txt"), shallow=False)

        print("== a second one, declined")
        s = Process(["--name", A, "--send", f"127.0.0.1:{PORT}", os.path.join(src, "big.bin")])
        receiver.wait(r"wants to send big\.bin")
        time.sleep(0.5)
        receiver.say("n")
        s.wait("declined")
        assert not os.path.exists(os.path.join(dst, "big.bin"))
        print("ok")
    finally:
        if receiver:
            receiver.p.kill()
        shutil.rmtree(work, ignore_errors=True)
        forget_identities()


if __name__ == "__main__":
    main()
