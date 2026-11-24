#!/usr/bin/env python3
# Copyright (C) 2026 Niels Joubert
# SPDX-License-Identifier: GPL-3.0-or-later
"""The engine's layers, held to what each may touch.

    python3 scripts/check-layers.py

SwiftPM already refuses an import of a module a target does not list. This holds the rest:

  - the list itself (Package.swift must say what the table below says: adding a dependency
    to a layer is a decision, and is made here, in sight);
  - which system frameworks a layer may import (the storage core has no business with the
    network, the transfer core none with AppKit);
  - that NimbusCrypto is pure: no socket, file, clock, lock or thread. It is what the formal
    models in formal/ are about, and a model of code that waits on a socket is a model of
    something else.

Exits non-zero, naming the file and the line, on the first run that finds anything.
"""
import glob
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# module: (modules of ours it may import, system frameworks it may import)
LAYERS = {
    "NimbusBase": ([], ["Foundation", "Darwin"]),
    "NimbusCrypto": (["NimbusBase"], ["Foundation", "CryptoKit"]),
    "NimbusNet": (["NimbusBase"], ["Foundation", "Darwin", "SystemConfiguration"]),
    "NimbusSafeStorageCore": (["NimbusBase"], ["Foundation", "Darwin", "CryptoKit"]),
    "NimbusSecurityCore": (["NimbusBase", "NimbusCrypto", "NimbusNet"], ["Foundation", "Darwin", "CryptoKit", "IOKit"]),
    "NimbusDiscovery": (["NimbusBase", "NimbusCrypto", "NimbusNet", "NimbusSecurityCore"],
                        ["Foundation", "Network", "SystemConfiguration", "dnssd"]),
    "NimbusTransferCore": (["NimbusBase", "NimbusCrypto", "NimbusNet", "NimbusSafeStorageCore", "NimbusSecurityCore"],
                           ["Foundation", "Darwin"]),
    "NimbusDropCore": (["NimbusBase", "NimbusCrypto", "NimbusNet", "NimbusSafeStorageCore", "NimbusSecurityCore", "NimbusDiscovery",
                        "NimbusTransferCore"], ["Foundation", "UniformTypeIdentifiers"]),
}

# What may not appear in the pure module, and why it would not be pure with it.
IMPURE = [
    (r"\bThread\b", "a thread"),
    (r"\bDispatch(Queue|Group|Semaphore)\b", "a queue"),
    (r"\bNS(Recursive)?Lock\b|\bNSCondition\b", "a lock"),
    (r"\bDate\(\)|\bDate\.now\b|timeIntervalSinceNow|mach_continuous_time", "a clock"),
    (r"\bFileManager\b|\bFileHandle\b|(?<!func )(?<![.\w])open\(|contentsOf:", "a file"),
    (r"\bSocket\b|\bsocket\(|\bChannel\b", "a socket"),
    (r"\bUserDefaults\b|\bProcessInfo\b|\bgetenv\b", "the environment"),
    (r"\bDropLog\b", "the log"),
]


def strip_comments(line):
    return re.sub(r"//.*$", "", line)


def main():
    problems = []
    package = open(os.path.join(ROOT, "Package.swift")).read()
    for module, (ours, system) in LAYERS.items():
        # What Package.swift declares for this target.
        m = re.search(r'\.target\(\s*name: "%s"(.*?)\)\s*,\s*\n' % module, package, re.S)
        if not m:
            problems.append(f"Package.swift: no target named {module}")
            continue
        deps = re.search(r"dependencies: \[(.*?)\]", m.group(1), re.S)
        declared = sorted(re.findall(r'"(\w+)"', deps.group(1))) if deps else []
        if declared != sorted(ours):
            problems.append(f"Package.swift: {module} depends on {declared}; the layers say {sorted(ours)}")
        files = sorted(glob.glob(os.path.join(ROOT, "Sources", module, "*.swift")))
        if not files:
            problems.append(f"Sources/{module}: no source files")
        for path in files:
            rel = os.path.relpath(path, ROOT)
            for n, line in enumerate(open(path), 1):
                code = strip_comments(line)
                imp = re.match(r"\s*(?:@\w+\s+)*import\s+(\w+)", code)
                if imp and imp.group(1) not in ours + system:
                    problems.append(f"{rel}:{n}: {module} may not import {imp.group(1)}")
                if module == "NimbusCrypto":
                    for pattern, what in IMPURE:
                        if re.search(pattern, code):
                            problems.append(f"{rel}:{n}: NimbusCrypto is pure and this is {what}: {code.strip()[:90]}")
    # Nothing but tests and the chaos tool may use the proxy, and nothing in the engine draws.
    for path in glob.glob(os.path.join(ROOT, "Sources", "NimbusDrop", "*.swift")):
        for n, line in enumerate(open(path), 1):
            if re.match(r"\s*import\s+NimbusDropChaos\b", line):
                problems.append(f"{os.path.relpath(path, ROOT)}:{n}: the app may not import the chaos proxy")
    for p in problems:
        print(p)
    if problems:
        sys.exit(1)
    print(f"layers: {len(LAYERS)} modules as declared; NimbusCrypto is pure")


if __name__ == "__main__":
    main()
