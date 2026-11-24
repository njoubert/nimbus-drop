#!/usr/bin/env python3
# Copyright (C) 2026 Niels Joubert
# SPDX-License-Identifier: GPL-3.0-or-later
"""formal/check.py's own judgement, tested against canned tool output: no prover is run.

    python3 formal/test_check.py

The runner is what turns a prover's output into "the claims hold". If it took a summary with
a lemma missing for a pass, or a mutant that verified for one that was caught, everything it
reports would be worth nothing. Each case here is a way of being wrong that must be refused.
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import check  # noqa: E402

REQUIRED = [{"name": "can_run", "kind": "exists-trace", "expect": "verified"},
            {"name": "is_secret", "kind": "all-traces", "expect": "verified"},
            {"name": "agrees", "kind": "all-traces", "expect": "verified"}]


def tamarin(lines, end=True, extra=""):
    body = "theory T begin\n...\nend\n" + extra + "\n==============================================================================\nsummary of summaries:\n\nanalyzed: T.spthy\n\n  processing time: 1.00s\n  \n"
    body += "".join(f"  {l}\n" for l in lines)
    return body + ("\n==============================================================================\n" if end else "")


GOOD = ["can_run (exists-trace): verified (5 steps)", "is_secret (all-traces): verified (12 steps)", "agrees (all-traces): verified (40 steps)"]


class Tamarin(unittest.TestCase):
    def judge(self, text, code=0, timed_out=False, expectations=None):
        return check.judge_tamarin(text, code, timed_out, REQUIRED, expectations or {})

    def test_a_proof_of_every_required_lemma_passes(self):
        ok, note, results = self.judge(tamarin(GOOD))
        self.assertTrue(ok, note)
        self.assertEqual(results, {"can_run": "verified", "is_secret": "verified", "agrees": "verified"})

    def test_a_lemma_missing_from_the_summary_fails(self):
        ok, note, results = self.judge(tamarin(GOOD[:2]))
        self.assertFalse(ok)
        self.assertIn("agrees: not in the summary", note)
        self.assertEqual(results["agrees"], "not run")

    def test_a_lemma_that_is_not_in_the_register_fails(self):
        ok, note, _ = self.judge(tamarin(GOOD + ["something_new (all-traces): verified (2 steps)"]))
        self.assertFalse(ok)
        self.assertIn("something_new: not in the register", note)

    def test_a_lemma_twice_fails(self):
        ok, note, _ = self.judge(tamarin(GOOD + [GOOD[1]]))
        self.assertFalse(ok)
        self.assertIn("is_secret: in the summary 2 times", note)

    def test_an_incomplete_analysis_fails(self):
        ok, note, results = self.judge(tamarin(GOOD[:2] + ["agrees (all-traces): analysis incomplete (1 steps)"]))
        self.assertFalse(ok)
        self.assertIn("agrees: incomplete (must be verified)", note)
        self.assertEqual(results["agrees"], "incomplete")

    def test_a_falsified_lemma_fails(self):
        ok, note, _ = self.judge(tamarin(GOOD[:1] + ["is_secret (all-traces): falsified - found trace (9 steps)", GOOD[2]]))
        self.assertFalse(ok)
        self.assertIn("is_secret: falsified (must be verified)", note)

    def test_the_wrong_kind_of_lemma_fails(self):
        ok, note, _ = self.judge(tamarin(["can_run (all-traces): verified (5 steps)"] + GOOD[1:]))
        self.assertFalse(ok)
        self.assertIn("can_run: all-traces, and the register says exists-trace", note)

    def test_a_non_zero_exit_fails_whatever_was_printed(self):
        ok, note, results = self.judge(tamarin(GOOD), code=1)
        self.assertFalse(ok)
        self.assertIn("TOOL ERROR", note)
        self.assertEqual(set(results.values()), {"not run"})

    def test_a_timeout_fails(self):
        ok, note, _ = self.judge("", code=None, timed_out=True)
        self.assertFalse(ok)
        self.assertIn("did not finish in time", note)

    def test_a_summary_cut_short_fails(self):
        ok, note, _ = self.judge(tamarin(GOOD, end=False).replace("==============================================================================\nsummary", "summary"))
        self.assertFalse(ok)
        self.assertIn("missing or cut short", note)

    def test_no_summary_at_all_fails(self):
        ok, note, _ = self.judge("maude tool: 'maude'\n checking version: 3.5.1. OK.\n")
        self.assertFalse(ok)
        self.assertIn("missing or cut short", note)

    def test_an_empty_summary_fails(self):
        ok, note, _ = self.judge(tamarin([]))
        self.assertFalse(ok)
        self.assertIn("no lemmas in the summary", note)

    def test_a_theory_that_is_not_well_formed_fails(self):
        ok, note, _ = self.judge(tamarin(GOOD, extra="WARNING: 2 wellformedness check failed!"))
        self.assertFalse(ok)
        self.assertIn("not well-formed", note)

    def test_a_result_that_cannot_be_read_fails(self):
        ok, note, _ = self.judge(tamarin(GOOD[:2] + ["agrees (all-traces): proved, more or less"]))
        self.assertFalse(ok)
        self.assertIn("could not be read", note)

    # A mutant: only the lemma named for it is asked for; the others are left incomplete.
    MUTANT = ["can_run (exists-trace): analysis incomplete (1 steps)", "is_secret (all-traces): falsified - found trace (16 steps)",
              "agrees (all-traces): analysis incomplete (1 steps)"]

    def test_a_mutant_that_falsifies_its_lemma_passes(self):
        ok, note, _ = self.judge(tamarin(self.MUTANT), expectations={"is_secret": "falsified"})
        self.assertTrue(ok, note)
        self.assertIn("fails as it must, on is_secret", note)

    def test_a_mutant_that_survives_fails(self):
        ok, note, _ = self.judge(tamarin(GOOD), expectations={"is_secret": "falsified"})
        self.assertFalse(ok)
        self.assertIn("nothing notices this mutant", note)

    def test_a_mutant_whose_lemma_was_left_incomplete_fails(self):
        ok, note, _ = self.judge(tamarin([l.replace("falsified - found trace", "analysis incomplete") for l in self.MUTANT]), expectations={"is_secret": "falsified"})
        self.assertFalse(ok)
        self.assertIn("is_secret: incomplete (must be falsified)", note)

    def test_a_mutant_that_names_a_lemma_nobody_registered_fails(self):
        ok, note, _ = self.judge(tamarin(self.MUTANT), expectations={"no_such_lemma": "falsified"})
        self.assertFalse(ok)
        self.assertIn("no_such_lemma: asked for, and not in the register", note)

    def test_falsified_counts_only_for_the_mutant_it_was_declared_for(self):
        # The same output, read as a normal run, is a failure.
        ok, _, _ = self.judge(tamarin(self.MUTANT))
        self.assertFalse(ok)


class Register(unittest.TestCase):
    DECLARED = {"T.spthy": [("can_run", "exists-trace"), ("is_secret", "all-traces"), ("agrees", "all-traces")]}

    def full(self):
        return {"T.spthy": [dict(l, claim="c", assumes="a", code=["f"], tests=["t"]) for l in REQUIRED]}

    def test_the_register_and_the_theory_agree(self):
        self.assertEqual(check.check_register(self.full(), self.DECLARED), [])

    def test_a_lemma_deleted_from_the_theory_is_noticed(self):
        problems = check.check_register(self.full(), {"T.spthy": self.DECLARED["T.spthy"][:2]})
        self.assertEqual(problems, ["T.spthy: lemma agrees is required by the register and is not declared"])

    def test_a_lemma_added_to_the_theory_and_not_registered_is_noticed(self):
        problems = check.check_register(self.full(), {"T.spthy": self.DECLARED["T.spthy"] + [("extra", "all-traces")]})
        self.assertEqual(problems, ["T.spthy: lemma extra is declared and is not in the register"])

    def test_a_lemma_declared_twice_is_noticed(self):
        problems = check.check_register(self.full(), {"T.spthy": self.DECLARED["T.spthy"] + [("agrees", "all-traces")]})
        self.assertIn("T.spthy: lemma agrees is declared 2 times", problems)

    def test_a_lemma_turned_from_all_traces_into_exists_trace_is_noticed(self):
        problems = check.check_register(self.full(), {"T.spthy": [("can_run", "exists-trace"), ("is_secret", "exists-trace"), ("agrees", "all-traces")]})
        self.assertEqual(problems, ["T.spthy: lemma is_secret is exists-trace; the register says all-traces"])

    def test_a_theory_nobody_registered_and_a_theory_that_is_gone_are_noticed(self):
        problems = check.check_register(self.full(), {"Other.spthy": []})
        self.assertIn("Other.spthy has no entry in the register", problems)
        self.assertIn("the register lists T.spthy, which is not there", problems)

    def test_a_lemma_without_its_claim_is_noticed(self):
        register = self.full()
        register["T.spthy"][0]["claim"] = ""
        self.assertEqual(check.check_register(register, self.DECLARED), ["T.spthy: lemma can_run has no 'claim' in the register"])

    def test_lemmas_are_read_from_the_theory_and_not_from_its_comments(self):
        path = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".tools", "test-theory.spthy")
        os.makedirs(os.path.dirname(path), exist_ok=True)
        open(path, "w").write('theory T begin\n/* a lemma could hold because nothing happens\nlemma not_this: "F" */\n// lemma nor_this: "F"\n'
                              'lemma can_run: exists-trace\n  "Ex #i. A() @ i"\nlemma is_secret [reuse]:\n  "All #i. A() @ i ==> F"\n'
                              'lemma agrees [heuristic={drop}]:\n  all-traces "T"\nend\n')
        try:
            self.assertEqual(check.declared_lemmas(path), [("can_run", "exists-trace"), ("is_secret", "all-traces"), ("agrees", "all-traces")])
        finally:
            os.remove(path)

    def test_the_real_register_matches_the_real_theories(self):
        theories = {f: check.declared_lemmas(os.path.join(check.TAMARIN, f)) for f in sorted(os.listdir(check.TAMARIN)) if f.endswith(".spthy")}
        self.assertEqual(check.check_register(check.load_register(), theories), [])
        for run in check.TAMARIN_RUNS:
            for lemma in run[3]:
                self.assertIn(lemma, [l["name"] for l in check.load_register()[run[1]]], run[0])


HOLDS_OUT = "Model checking completed. No error has been found.\n1249 states generated, 442 distinct states found, 0 states left on queue.\n"


class TLC(unittest.TestCase):
    def test_a_clean_run_holds(self):
        self.assertEqual(check.judge_tlc(HOLDS_OUT, 0, False, check.HOLDS, []), (True, "442 states"))

    def test_a_clean_printout_with_the_wrong_exit_code_is_a_tool_error(self):
        ok, note = check.judge_tlc(HOLDS_OUT, 12, False, check.HOLDS, [])
        self.assertFalse(ok)
        self.assertIn("TOOL ERROR", note)

    def test_a_violated_invariant_fails_a_model_that_must_hold(self):
        self.assertEqual(check.judge_tlc("Error: Invariant NoWrongBytes is violated.\n", 12, False, check.HOLDS, []), (False, "VIOLATED: NoWrongBytes"))

    def test_a_mutant_that_fails_on_its_property_passes(self):
        ok, note = check.judge_tlc("Error: Invariant NoWrongBytes is violated.\n", 12, False, "NoWrongBytes", [])
        self.assertTrue(ok, note)

    def test_a_mutant_that_fails_on_something_else_fails(self):
        ok, note = check.judge_tlc("Error: Invariant TypeOK is violated.\n", 12, False, "NoWrongBytes", [])
        self.assertFalse(ok)
        self.assertIn("it was to fail on NoWrongBytes", note)

    def test_a_mutant_that_holds_has_survived(self):
        ok, note = check.judge_tlc(HOLDS_OUT, 0, False, "NoWrongBytes", [])
        self.assertFalse(ok)
        self.assertIn("nothing notices this mutant", note)

    def test_properties_assumptions_and_deadlock_are_told_apart_and_matched_to_their_exit_codes(self):
        self.assertTrue(check.judge_tlc("Error: Temporal property ItEnds was violated.\n", 13, False, "ItEnds", ["ItEnds"])[0])
        self.assertTrue(check.judge_tlc("Error: Action property EndsNeverMoveLater is violated.\n", 13, False, "EndsNeverMoveLater", [])[0])
        self.assertTrue(check.judge_tlc("Error: Deadlock reached.\n", 11, False, "deadlock", [])[0])
        named = check.judge_tlc("Error: Assumption line 39, col 1 to line 39, col 9 of module M is false.\n", 10, False, "ImplIsSpec", [], lambda line: "ImplIsSpec" if line == 39 else None)
        self.assertTrue(named[0], named[1])
        self.assertFalse(check.judge_tlc("Error: Deadlock reached.\n", 12, False, "deadlock", [])[0])

    def test_a_parse_error_a_crash_and_a_timeout_are_tool_errors_and_never_a_pass(self):
        for out, code in [("Error: Parsing or semantic analysis failed.\n", 150), ("", 1), ("java.lang.OutOfMemoryError\n", 255), (HOLDS_OUT[:20], 0)]:
            for expected in [check.HOLDS, "NoWrongBytes"]:
                ok, note = check.judge_tlc(out, code, False, expected, [])
                self.assertFalse(ok, (out, code, expected))
                self.assertIn("TOOL ERROR", note)
        self.assertFalse(check.judge_tlc(HOLDS_OUT, None, True, check.HOLDS, [])[0])


if __name__ == "__main__":
    unittest.main(verbosity=1)
