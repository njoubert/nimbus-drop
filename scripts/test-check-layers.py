#!/usr/bin/env python3
# Copyright (C) 2026 Niels Joubert
# SPDX-License-Identifier: GPL-3.0-or-later
"""scripts/check-layers.py, tested against trees with exactly one thing wrong.

    python3 scripts/test-check-layers.py

A checker that never says no is worth nothing, and one that says no to honest code gets
switched off. Each case builds a small tree (this repository's Package.swift and one file per
module), puts one violation in it, and requires the checker to name it; the last cases are
code that is fine and must pass.
"""
import glob
import importlib.util
import os
import shutil
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
spec = importlib.util.spec_from_file_location("check_layers", os.path.join(HERE, "check-layers.py"))
check = importlib.util.module_from_spec(spec)
spec.loader.exec_module(check)

HEADER = "// Copyright (C) 2026 Niels Joubert\nimport Foundation\n"


class Layers(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.mkdtemp(prefix="nimbus-layers-")
        shutil.copy(os.path.join(os.path.dirname(HERE), "Package.swift"), self.root)
        for module in list(check.LAYERS) + ["NimbusDrop"]:
            self.write(module, "Fine.swift", HEADER + "enum Fine\\(module) {}\n".replace("\\(module)", module))

    def tearDown(self):
        shutil.rmtree(self.root, ignore_errors=True)

    def write(self, module, name, text):
        os.makedirs(os.path.join(self.root, "Sources", module), exist_ok=True)
        open(os.path.join(self.root, "Sources", module, name), "w").write(text)

    def problems(self):
        return check.problems_in(self.root)

    def refuses(self, module, text, saying):
        for old in glob.glob(os.path.join(self.root, "Sources", "*", "Wrong.swift")):
            os.remove(old)
        self.write(module, "Wrong.swift", HEADER + text + "\n")
        found = self.problems()
        self.assertTrue(any(saying in p and f"Sources/{module}/Wrong.swift:3" in p for p in found), f"wanted '{saying}' at line 3, got {found}")
        self.assertEqual(len(found), 1, found)

    def accepts(self, module, text):
        self.write(module, "Right.swift", HEADER + text + "\n")
        self.assertEqual(self.problems(), [])

    def test_the_tree_with_nothing_wrong_passes(self):
        self.assertEqual(self.problems(), [])

    def test_the_real_repository_passes(self):
        self.assertEqual(check.problems_in(check.ROOT), [])

    # ---- the graph

    def test_an_import_of_a_module_above_is_refused(self):
        self.refuses("NimbusCrypto", "import NimbusNet", "NimbusCrypto may not import NimbusNet")
        self.refuses("NimbusSafeStorageCore", "import NimbusSecurityCore", "may not import NimbusSecurityCore")
        self.refuses("NimbusBase", "import NimbusCrypto", "NimbusBase may not import NimbusCrypto")

    def test_the_pure_module_may_not_import_the_runtime_beside_it(self):
        # The log, the lock and the last system error are in a module of their own, and the pure
        # one cannot have them: the compiler would refuse the same import, since Package.swift
        # does not list it.
        self.refuses("NimbusCrypto", "import NimbusRuntime", "NimbusCrypto may not import NimbusRuntime")
        self.refuses("NimbusBase", "import NimbusRuntime", "NimbusBase may not import NimbusRuntime")

    def test_the_module_under_the_pure_one_is_held_to_the_same(self):
        self.refuses("NimbusBase", "let l = NSLock()", "NimbusBase is pure and this is a lock")
        self.refuses("NimbusBase", "public enum Log { nonisolated(unsafe) public static var sink: Int? }", "NimbusBase is pure and this is a mutable global")
        self.refuses("NimbusBase", 'let e = String(cString: strerror(errno))', "NimbusBase is pure and this is the last system error")

    def test_an_import_of_a_framework_the_layer_has_no_business_with_is_refused(self):
        self.refuses("NimbusSafeStorageCore", "import Network", "may not import Network")
        self.refuses("NimbusTransferCore", "import AppKit", "may not import AppKit")
        self.refuses("NimbusCrypto", "import Darwin", "NimbusCrypto may not import Darwin")
        self.refuses("NimbusCrypto", "@preconcurrency import Dispatch", "NimbusCrypto may not import Dispatch")
        self.refuses("NimbusCrypto", "import func Darwin.open", "NimbusCrypto may not import Darwin")

    def test_a_dependency_added_in_package_swift_alone_is_refused(self):
        path = os.path.join(self.root, "Package.swift")
        text = open(path).read()
        old = '.target(name: "NimbusCrypto", dependencies: ["NimbusBase"]),'
        self.assertIn(old, text)
        open(path, "w").write(text.replace(old, '.target(name: "NimbusCrypto", dependencies: ["NimbusBase", "NimbusNet"]),'))
        found = self.problems()
        self.assertTrue(any("NimbusCrypto depends on ['NimbusBase', 'NimbusNet']" in p for p in found), found)

    def test_a_module_reached_only_through_another_is_refused(self):
        # The module under the pure one starts to depend on the network: nothing the pure
        # module lists has changed, and it now reaches a socket.
        path = os.path.join(self.root, "Package.swift")
        text = open(path).read()
        old = '.target(name: "NimbusBase"),'
        self.assertIn(old, text)
        open(path, "w").write(text.replace(old, '.target(name: "NimbusBase", dependencies: ["NimbusNet"]),'))
        found = self.problems()
        self.assertTrue(any("NimbusCrypto reaches ['NimbusNet', 'NimbusRuntime'] through its dependencies" in p for p in found), found)

    def test_the_app_may_not_import_the_proxy(self):
        self.refuses("NimbusDrop", "import NimbusDropChaos", "the app may not import the chaos proxy")

    # ---- purity

    def test_the_pure_module_may_not_read_a_clock(self):
        for text in ["let now = Date()", "let t = Date.now", "let t = mach_continuous_time()", "let c = ContinuousClock()", "let x = d.timeIntervalSinceNow"]:
            self.refuses("NimbusCrypto", text, "this is a clock")

    def test_nor_touch_a_file(self):
        for text in ["let d = try Data(contentsOf: url)", "let fm = FileManager.default", "let fd = open(path, O_RDONLY)", "try data.write(to: url)"]:
            self.refuses("NimbusCrypto", text, "this is a file")

    def test_nor_a_socket_a_thread_or_a_lock(self):
        self.refuses("NimbusCrypto", "let s: Socket? = nil", "this is a socket")
        self.refuses("NimbusCrypto", "let c = socket(AF_INET, SOCK_STREAM, 0)", "this is a socket")
        self.refuses("NimbusCrypto", "Thread.detachNewThread { }", "this is a thread")
        self.refuses("NimbusCrypto", "let q = DispatchQueue.global()", "this is a queue")
        self.refuses("NimbusCrypto", "let l = NSLock()", "this is a lock")

    def test_nor_reach_any_of_those_through_a_wrapper_in_the_module_under_it(self):
        self.refuses("NimbusCrypto", 'DropLog.write("a pure function that logs")', "this is the log")
        self.refuses("NimbusCrypto", "let state = Locked(0)", "this is a lock")
        self.refuses("NimbusCrypto", 'throw errnoError("cannot")', "this is the last system error")
        self.refuses("NimbusCrypto", "let f = LogFile(url)", "this is the log")

    def test_nor_keep_a_mutable_global_or_read_the_environment(self):
        self.refuses("NimbusCrypto", "enum K { static var attempts = 0 }", "this is a mutable global")
        self.refuses("NimbusCrypto", "nonisolated(unsafe) let table = Table()", "this is a mutable global")
        self.refuses("NimbusCrypto", 'let v = ProcessInfo.processInfo.environment["X"]', "this is the environment")

    def test_code_that_is_pure_passes(self):
        self.accepts("NimbusCrypto", "struct M { var opened = false\n    static var all: [Int] { [1, 2] }\n    mutating func open() { opened = true }\n"
                     "    func later(_ d: Date) -> Date { d.addingTimeInterval(1) }\n    func seal(_ box: Data) -> Data { AES.GCM.open(box) } }\n"
                     "// A comment may say Date() and FileManager and Socket.")

    def test_the_same_code_is_fine_in_a_module_that_is_not_pure(self):
        self.accepts("NimbusNet", "let now = Date()\nlet l = NSLock()")

    # ---- secrets

    def test_the_app_may_not_name_what_holds_key_material(self):
        for text in ["let k = model.trust.keyPair", "let p = KeyPair()", "let keys = DropKeys(master: m)", "let m = channel.master", "let c: TrustCore? = nil"]:
            self.refuses("NimbusDrop", text, "the app may not name what holds key material")

    def test_the_trust_files_plaintext_is_asked_for_in_one_place(self):
        self.refuses("NimbusTransferCore", "let bytes = try core.encoded()", "the trust file's plaintext is asked for here")

    def test_a_line_that_says_something_may_not_name_a_secret(self):
        self.refuses("NimbusTransferCore", 'log("the drop\'s master is \\(keys.master.count) bytes")', "says something and names a secret")
        self.refuses("NimbusSecurityCore", 'DropLog.write("resuming with \\(resumeKey)")', "says something and names a secret")
        self.refuses("NimbusSecurityCore", 'throw DropError("bad key \\(pair.raw)")', "says something and names a secret")
        # In the pure module what is to be logged is handed back as an effect, and is still said.
        self.refuses("NimbusSecurityCore", 'return [.log("replaced by \\(k.raw.base64EncodedString())", .warn)]', "says something and names a secret")

    def test_a_line_that_says_a_public_key_or_a_tag_passes(self):
        self.accepts("NimbusSecurityCore", 'func f(key: PublicKey) { DropLog.write("proved \\(key.tag) \\(key.raw.count) and the master plan") }')


if __name__ == "__main__":
    unittest.main(verbosity=1)
