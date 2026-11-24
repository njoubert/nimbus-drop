#!/usr/bin/env python3
# Copyright (C) 2026 Niels Joubert
# SPDX-License-Identifier: GPL-3.0-or-later
"""The engine's layers, held to what each may touch.

    python3 scripts/check-layers.py            the repository
    python3 scripts/test-check-layers.py       this checker, against trees with one thing wrong

SwiftPM already refuses an import of a module a target does not list. This holds the rest:

  - the list itself (Package.swift must say what the table below says: adding a dependency
    to a layer is a decision, and is made here, in sight), and what follows from it: every
    module a layer reaches THROUGH its dependencies is one the table lets it reach;
  - which system frameworks a layer may import (the storage core has no business with the
    network, the transfer core none with AppKit);
  - that NimbusCrypto is pure: no socket, file, clock, lock, thread, log or mutable global,
    by its own code or by a wrapper in the module under it. It is what the formal models in
    formal/ are about, and a model of code that waits on a socket is a model of something else;
  - that secrets stay where the Core put them: the app does not name the types that hold key
    material, the trust file's plaintext is asked for in one place, and no line that writes
    to the log or to the other Mac names a secret.

WHAT THIS IS NOT. It reads text with patterns. It catches a mistake and it does not prove
purity: code that reached a clock through a closure handed to it, a pointer, or a name this
has not been told about would pass. The compiler's access control (`internal` for what holds
secret bytes) and the module graph are the real boundaries; this is the tripwire beside them.

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
    (r"\bNS(Recursive)?Lock\b|\bNSCondition\b|\bLocked\b|os_unfair_lock", "a lock"),
    (r"\bDate\(\)|\bDate\.now\b|timeIntervalSinceNow|mach_continuous_time|mach_absolute_time|\bContinuousClock\b|\bSuspendingClock\b|CFAbsoluteTimeGetCurrent|clock_gettime|gettimeofday", "a clock"),
    (r"\bFileManager\b|\bFileHandle\b|(?<!func )(?<![.\w])open\(|contentsOf:|\.write\(to:|\bfopen\b|\bopenat\b", "a file"),
    (r"\bSocket\b|\bsocket\(|\bChannel\b|\bNWConnection\b|\bURLSession\b|\bconnect\(", "a socket"),
    (r"\bUserDefaults\b|\bProcessInfo\b|\bgetenv\b", "the environment"),
    (r"\bDropLog\b|\bLogFile\b|\bprint\(|\bNSLog\b|\bos_log\b|\bLogger\b", "the log"),
    (r"\berrnoError\b|\berrno\b", "the last system error"),
    (r"\bstatic var \w+[^{\n]*=|\bnonisolated\(unsafe\)", "a mutable global"),
]

# The exceptions, each with its reason: (file, text the line contains).
PURE_EXCEPTIONS = [
    # The most one stream key may carry. Shortened by tests that exercise running out of key;
    # never written in the app.
    ("DropKeys.swift", "static var streamBytes"),
]

# What holds key material, by name. The app (and the proxy's tool) may not say these: it has
# no business with a key's bytes, and a reviewer should not have to wonder.
SECRET_NAMES = r"\bkeyPair\b|\bKeyPair\b|\bDropKeys\b|\bCipherState\b|\bNoise\b|\.master\b|\bresumeKey\b|\battachKey\b|\bbeginReset\b|\.encoded\(\)|\bTrustCore\b"
APP_MODULES = ["NimbusDrop", "nimbus-chaos"]

# The trust file's plaintext holds this Mac's private key. It is asked for here and nowhere else.
PLAINTEXT_CALL = r"\bcore\.encoded\(\)"
PLAINTEXT_FILES = ["Sources/NimbusSecurityCore/Trust.swift"]

# A line that writes to the log, the terminal or the other Mac may not name a secret.
SAYS = r"\bDropLog\.write\(|(?<![.\w])log\(|\.log\(\"|\bprint\(|\bfputs\(|\bReason\(message:|\bDropError\("
SECRET_IN_TEXT = r"\\\((?:[^()]|\([^()]*\))*\b(master|secret|resumeKey|attachKey|keyPair|\.raw\b(?<!publicKey\.raw)(?<!remote\.raw)(?<!key\.raw))"


def lines(path):
    with open(path) as f:
        return f.read().split("\n")


def strip_comments(line):
    return re.sub(r"//.*$", "", line)


def declared_dependencies(package):
    """{target: [modules of ours it lists]} for every plain target in Package.swift."""
    out = {}
    for m in re.finditer(r'\.target\(\s*name: "(\w+)"(.*?)\)\s*,\s*\n', package, re.S):
        deps = re.search(r"dependencies: \[(.*?)\]", m.group(2), re.S)
        out[m.group(1)] = sorted(re.findall(r'"(\w+)"', deps.group(1))) if deps else []
    return out


def reach(module, graph, seen=None):
    """Every module `module` reaches through what it depends on."""
    seen = set() if seen is None else seen
    for d in graph.get(module, []):
        if d not in seen:
            seen.add(d)
            reach(d, graph, seen)
    return seen


def problems_in(root, layers=None):
    """Everything wrong with the tree at `root`. Empty when nothing is."""
    layers = LAYERS if layers is None else layers
    problems = []
    package = "\n".join(lines(os.path.join(root, "Package.swift")))
    declared = declared_dependencies(package)
    for module, (ours, system) in layers.items():
        if module not in declared:
            problems.append(f"Package.swift: no target named {module}")
            continue
        if declared[module] != sorted(ours):
            problems.append(f"Package.swift: {module} depends on {declared[module]}; the layers say {sorted(ours)}")
        # Through its dependencies a layer must reach nothing the table does not give it.
        beyond = sorted(reach(module, declared) - reach(module, {m: o for m, (o, _) in layers.items()}))
        if beyond:
            problems.append(f"Package.swift: {module} reaches {beyond} through its dependencies; the layers do not allow that")
        files = sorted(glob.glob(os.path.join(root, "Sources", module, "*.swift")))
        if not files:
            problems.append(f"Sources/{module}: no source files")
        for path in files:
            rel = os.path.relpath(path, root)
            for n, line in enumerate(lines(path), 1):
                code = strip_comments(line)
                imp = re.match(r"\s*(?:@\w+\s+)*import\s+(?:(?:struct|class|enum|protocol|func|var|let|typealias)\s+)?(\w+)", code)
                if imp and imp.group(1) not in ours + system:
                    problems.append(f"{rel}:{n}: {module} may not import {imp.group(1)}")
                if module == "NimbusCrypto":
                    for pattern, what in IMPURE:
                        if re.search(pattern, code) and not any(rel.endswith(f) and text in code for f, text in PURE_EXCEPTIONS):
                            problems.append(f"{rel}:{n}: NimbusCrypto is pure and this is {what}: {code.strip()[:90]}")
    # The pure module's own dependencies must be pure in what they offer it: it may not call a
    # wrapper around what it may not call itself. NimbusBase's wrappers are named in IMPURE
    # (DropLog, LogFile, Locked, errnoError); a new one there is a new line there.
    for path in sorted(glob.glob(os.path.join(root, "Sources", "*", "*.swift"))):
        rel = os.path.relpath(path, root)
        module = rel.split(os.sep)[1]
        for n, line in enumerate(lines(path), 1):
            code = strip_comments(line)
            # Nothing but tests and the chaos tool may use the proxy.
            if module == "NimbusDrop" and re.match(r"\s*import\s+NimbusDropChaos\b", code):
                problems.append(f"{rel}:{n}: the app may not import the chaos proxy")
            if module in APP_MODULES and re.search(SECRET_NAMES, code):
                problems.append(f"{rel}:{n}: the app may not name what holds key material: {code.strip()[:90]}")
            if re.search(PLAINTEXT_CALL, code) and rel.replace(os.sep, "/") not in PLAINTEXT_FILES:
                problems.append(f"{rel}:{n}: the trust file's plaintext is asked for here; only {PLAINTEXT_FILES[0]} may")
            if re.search(SAYS, code) and re.search(SECRET_IN_TEXT, code):
                problems.append(f"{rel}:{n}: this line says something and names a secret: {code.strip()[:90]}")
    return problems


def main():
    problems = problems_in(ROOT)
    for p in problems:
        print(p)
    if problems:
        sys.exit(1)
    print(f"layers: {len(LAYERS)} modules as declared, each reaching only what it may; NimbusCrypto is pure; no secret named where it may not be")


if __name__ == "__main__":
    main()
