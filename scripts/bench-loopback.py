#!/usr/bin/env python3
# Copyright (C) 2026 Niels Joubert
# SPDX-License-Identifier: GPL-3.0-or-later
"""The data path over loopback, as numbers: for comparing a build with the one before it.

    swift build -c release
    python3 scripts/bench-loopback.py .build/release/NimbusDrop [other-binary …]

Two throwaway identities (bench-a, bench-b) pair on this Mac; b receives unattended from a.
Then, per binary, three times each and the best kept: one large file on 8 connections and on 1,
200 files of 8 MB, 10,000 small files, and the speed test (the engine and the encryption with no
disk at either end). Both ends share this Mac's cores, and the source is in the page cache, so
the figures are for comparing builds on one machine in one sitting and for nothing else.

--quick sends a quarter of the data, once.
"""
import os
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import time

PORT = "47998"
A, B = "bench-a", "bench-b"
QUICK = "--quick" in sys.argv
BINS = [os.path.abspath(a) for a in sys.argv[1:] if not a.startswith("--")]


class Process:
    def __init__(self, binary, args):
        self.p = subprocess.Popen([binary] + args, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=0)
        self.out = ""
        threading.Thread(target=self._pump, daemon=True).start()

    def _pump(self):
        while True:
            c = self.p.stdout.read(1)
            if not c:
                break
            self.out += c

    def wait(self, pattern, seconds=120):
        end = time.time() + seconds
        while time.time() < end:
            m = re.search(pattern, self.out)
            if m:
                return m
            time.sleep(0.02)
        sys.exit(f"TIMED OUT waiting for {pattern!r}\n--- its output ---\n{self.out}")

    def say(self, line):
        self.p.stdin.write(line + "\n")
        self.p.stdin.flush()


def run(binary, args, seconds=600):
    return subprocess.run([binary] + args, capture_output=True, text=True, timeout=seconds)


def forget_identities():
    base = os.path.expanduser("~/Library/Application Support")
    for bundle in os.listdir(base) if os.path.isdir(base) else []:
        if bundle.startswith("com.njoubert.nimbusdrop"):
            for name in (A, B):
                shutil.rmtree(os.path.join(base, bundle, "cli-" + name), ignore_errors=True)


def pair(binary, scratch):
    receiver = Process(binary, ["--name", B, "--port", PORT, "--no-advertise", "--receive", scratch])
    receiver.wait("receiving as")
    a = Process(binary, ["--name", A, "--pair", f"127.0.0.1:{PORT}"])
    receiver.wait(r"pair\? .*\[y/N\]")
    receiver.say("y")
    code_b = "".join(receiver.wait(r"read this code out[^:]*:\s+(\d{3}) (\d{3})").groups())
    code_a = "".join(a.wait(r"read this code out[^:]*:\s+(\d{3}) (\d{3})").groups())
    a.wait("the code they read to you:")
    a.say(code_b)
    receiver.wait("the code they read to you:")
    receiver.say(code_a)
    a.wait("paired with")
    receiver.wait("paired with")
    receiver.p.kill()
    receiver.p.wait()


def make(path, size):
    block = os.urandom(1 << 20)
    with open(path, "wb") as f:
        left = size
        while left > 0:
            f.write(block[: min(left, len(block))])
            left -= len(block)


def main():
    if not BINS:
        sys.exit(__doc__)
    forget_identities()
    work = tempfile.mkdtemp(prefix="nd-bench-")
    src, dst = os.path.join(work, "src"), os.path.join(work, "dst")
    os.makedirs(src)
    os.makedirs(dst)
    scale = 4 if QUICK else 1
    big = os.path.join(src, "big.bin")
    make(big, (4 << 30) // scale)
    medium = os.path.join(src, "medium")
    os.makedirs(medium)
    for i in range(200 // scale):
        make(os.path.join(medium, f"{i:03}.bin"), 8 << 20)
    small = os.path.join(src, "small")
    os.makedirs(small)
    for i in range(10_000 // scale):
        make(os.path.join(small, f"{i:05}.dat"), 4096 + (i * 37) % 10_000)
    cases = [
        ("1 large file, 8 connections", ["--streams", "8"], big),
        ("1 large file, 1 connection ", ["--streams", "1"], big),
        ("files of 8 MB, 8 connections", ["--streams", "8"], medium),
        ("small files, 8 connections ", ["--streams", "8"], small),
    ]
    rounds = 1 if QUICK else 3
    results = {b: {} for b in BINS}
    receiver = None
    try:
        pair(BINS[0], dst)
        tag = re.search(r"[0-9A-Z]{4}(?:-[0-9A-Z]{4}){3}", run(BINS[0], ["--name", A, "--identity"]).stdout).group(0)
        for n in range(rounds):
            for binary in BINS:
                receiver = Process(binary, ["--name", B, "--port", PORT, "--no-advertise", "--unattended-from", tag, "--max-bytes", str(1 << 40), "--receive", dst])
                receiver.wait("receiving as")
                for label, flags, path in cases:
                    r = run(binary, ["--name", A] + flags + ["--send", f"127.0.0.1:{PORT}", path])
                    m = re.search(r"done: .* in ([\d.]+) s = ([\d.]+) ([GM])bps", r.stdout)
                    if not m:
                        sys.exit(f"{label}: no result from {binary}\n{r.stdout}\n--- receiver ---\n{receiver.out}")
                    rate = float(m.group(2)) * (1000 if m.group(3) == "G" else 1)
                    results[binary].setdefault(label, []).append((rate, float(m.group(1))))
                    shutil.rmtree(dst)
                    os.makedirs(dst)
                r = run(binary, ["--name", A, "--seconds", "3", "--speed", f"127.0.0.1:{PORT}"])
                rates = re.findall(r"^(?:to|from) [^\n]*?:\s+([\d.]+) ([GM])bps", r.stdout, re.M)
                if len(rates) == 2:
                    up, down = (float(v) * (1000 if u == "G" else 1) for v, u in rates)
                    results[binary].setdefault("speed test (no disk), up     ", []).append((up, 3))
                    results[binary].setdefault("speed test (no disk), down   ", []).append((down, 3))
                else:
                    print(f"no speed test result from {binary}:\n{r.stdout}")
                receiver.p.kill()
                receiver.p.wait()
                receiver = None
                time.sleep(11)  # the pause between one key's speed tests
        labels = list(results[BINS[0]].keys())
        print(f"\n{'best of ' + str(rounds):30}" + "".join(f"{os.path.basename(os.path.dirname(b)) + '/' + os.path.basename(b):>34}" for b in BINS))
        for label in labels:
            row = f"{label:30}"
            for b in BINS:
                best = max(results[b][label])
                row += f"{best[0]:>20,.0f} Mbps {best[1]:>6.1f} s"
            print(row)
    finally:
        if receiver:
            receiver.p.kill()
        shutil.rmtree(work, ignore_errors=True)
        forget_identities()


if __name__ == "__main__":
    main()
