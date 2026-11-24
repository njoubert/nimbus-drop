#!/usr/bin/env python3
# Copyright (C) 2026 Niels Joubert
# SPDX-License-Identifier: GPL-3.0-or-later
"""Runs every formal model, and every mutant of one, and says whether each came out as it must.

    python3 formal/check.py              everything
    python3 formal/check.py tla          the TLA+ models only (seconds to a minute)
    python3 formal/check.py tamarin      the Tamarin models only (minutes)
    python3 formal/check.py register     the lemma register against the theories (no prover)
    python3 formal/check.py Drop         whatever has "Drop" in its name

A model that holds proves little by itself: it may hold because it says nothing. So beside
every model are its mutants, each the model with one guard taken out, and each must FAIL, on
the property named for it. A mutant that passes is reported as loudly as a model that fails.
(`scripts/mutate.py` does the same for the Swift and its tests.)

IT FAILS CLOSED. A run counts as good only when the tool exited as it does for the outcome it
printed, the output is whole, and what it says is exactly what was required:

  - Tamarin: every lemma in formal/tamarin/lemmas.json, once each, with the result written
    there. A lemma missing from the summary, one that is not in the register, one twice, one
    left incomplete, a theory that is not well-formed, a summary cut short, a non-zero exit, a
    timeout: each fails the run. A mutant must falsify the lemma named for it; a mutant that
    verifies it has survived, and that fails too.
  - TLC: the outcome it printed and its exit code must agree (0 nothing found, 10 an
    assumption, 11 deadlock, 12 an invariant, 13 a property; anything else is a tool error).
  - Asking for something that matches nothing is an error, not zero runs that all passed.

Every run's raw output, command, versions, source revision and input hashes are kept under
formal/.results/ (not in git), one folder per invocation, with a summary.json.

Needs: java (TLC), tamarin-prover and maude on the PATH or in Homebrew's usual places. TLC
itself (tla2tools.jar, MIT) is fetched once into formal/.tools/ and checked against a pinned
SHA-256. See formal/README.md. `python3 formal/test_check.py` tests this file's own judgement
against canned tool output, without running a prover.
"""
import datetime
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
TLA = os.path.join(HERE, "tla")
TAMARIN = os.path.join(HERE, "tamarin")
TOOLS = os.path.join(HERE, ".tools")
TLC_URL = "https://github.com/tlaplus/tlaplus/releases/download/v1.8.0/tla2tools.jar"
TLC_SHA256 = "fdffef247f563ef6edbfd44958d2a82db79e7564e07cb673262d896353fa6713"
RESULTS = os.path.join(HERE, ".results")
REGISTER = os.path.join(TAMARIN, "lemmas.json")

HOLDS = "holds"


def find(name, others=()):
    for candidate in [shutil.which(name)] + list(others):
        if candidate and os.path.exists(candidate):
            return candidate
    return None


def tlc_jar():
    jar = os.path.join(TOOLS, "tla2tools.jar")
    if not os.path.exists(jar):
        os.makedirs(TOOLS, exist_ok=True)
        print(f"fetching TLC from {TLC_URL}")
        urllib.request.urlretrieve(TLC_URL, jar + ".part")
        os.rename(jar + ".part", jar)
    digest = hashlib.sha256(open(jar, "rb").read()).hexdigest()
    if digest != TLC_SHA256:
        sys.exit(f"{jar} is not the TLC this was written against (sha256 {digest}); delete it to fetch it again")
    return jar


# ---- TLA+ ------------------------------------------------------------------------------------
# (name, module, constants, invariants, properties, expected, text mutation or None)
# expected: HOLDS, or the name of the invariant / property / assumption that must be violated.

PAIRING_INV = ["TypeOK", "StoresOnlyWhenBothAreTrue", "StoredOnce", "CodesOnlyAfterTheCommitmentIsOpened",
               "EachMessageOnceAndInOrder", "ThreeTries", "NothingCountsBeforeTheCodes"]
SYSTEM_INV = ["TypeOK", "HonestMacsNeverTripTheGuards", "StoredMeansBothPeopleConfirmed", "OneSidedOnlyWhenTimeOrTheLinkRanOut"]
GATE_INV = ["TypeOK", "NotBothTurnedAway", "OnePairingAtATime", "OneOfTheTwo"]
TRUST_INV = ["TypeOK", "AcknowledgedMeansRefusedForGood", "NothingOutlivesTheWithdrawal", "LiveMeansTrustedOrBeingEnded",
             "LiveIsOnTheList", "NoSocketWorkUnderTheLock"]
EXPIRY_INV = ["TypeOK", "TickIsAnEvent", "TheCountCoversTheTimeUp", "TheFileIsLessThanAnHourBehind", "PairedNoLongerThanItsLife",
              "OnlyTheCountRefusesForGood", "PastItsEndIsNeverPaired", "NoSessionPastItsGrace"]
DROP_INV = ["TypeOK", "NoWrongBytes", "PlacedIsWhole", "SentMeansSaved", "NoStreamKeyTwice"]
DROP_PROPS = ["NothingWrittenAfterPlacing", "ItEnds", "ItArrives"]


def drop(**changes):
    c = {"Chunks": "{c1, c2}", "MaxFaults": "3", "MaxConns": "11", "ChecksTag": "TRUE", "KeepsCounter": "TRUE", "MayGiveUp": "FALSE"}
    c.update(changes)
    return c


def trust(**changes):
    c = {"ForGood": "TRUE", "Eviction": "FALSE"}
    c.update(changes)
    return c


def expiry(**changes):
    # Life, Grace and Hour are 90 days, a day and an hour, shrunk; the rest are the bounds of the search.
    c = {"Life": "2", "Grace": "1", "Hour": "2", "MaxUp": "5", "MaxWall": "4", "MaxBoots": "2", "HonestCalendar": "FALSE"}
    c.update(changes)
    return c


TLA_RUNS = [
    # The pairing transaction at one Mac, against an other end that keeps to nothing.
    ("Pairing", "Pairing", {}, PAIRING_INV, ["FinalIsFinal"], HOLDS, None),
    ("Pairing / mutant: the other side's word is enough", "Pairing", {}, PAIRING_INV, [], "StoresOnlyWhenBothAreTrue",
     ("PairingMachine.tla", "IF s.local /\\ s.remote THEN << [s EXCEPT !.phase = \"paired\"]", "IF s.remote THEN << [s EXCEPT !.phase = \"paired\"]")),
    ("Pairing / mutant: a reveal need not open the commitment", "Pairing", {}, PAIRING_INV, [], "CodesOnlyAfterTheCommitmentIsOpened",
     ("PairingMachine.tla", "ELSE IF e = \"revealWrong\" THEN Fail(s, \"didNotKeep\")\n", "")),
    ("Pairing / mutant: 'paired' may be said twice", "Pairing", {}, PAIRING_INV, [], "EachMessageOnceAndInOrder",
     ("PairingMachine.tla", "IF s.remote THEN Fail(s, \"didNotKeep\")\n            ELSE Settle(", "Settle(")),
    ("Pairing / mutant: a fourth entry", "Pairing", {}, PAIRING_INV, [], "ThreeTries",
     ("PairingMachine.tla", "ELSE IF s.tries = 1 THEN", "ELSE IF s.tries = 0 THEN")),
    ("Pairing / mutant: a code typed before the codes are up counts", "Pairing", {}, PAIRING_INV, [], "NothingCountsBeforeTheCodes",
     ("PairingMachine.tla", "    ELSE IF e = \"typedRight\" THEN\n        IF s.phase # \"codes\" \\/ s.local THEN", "    ELSE IF e = \"typedRight\" THEN\n        IF s.local THEN")),

    # The Swift machine is the specification's machine.
    ("PairingRefinement (the Swift code is Step)", "PairingRefinement", {}, ["SpecIsImpl"], [], HOLDS, None),
    ("PairingRefinement / mutant: the specification differs from the code", "PairingRefinement", {}, ["SpecIsImpl"], [], "ImplIsSpec",
     ("PairingMachine.tla", "ELSE IF e = \"timeout\" THEN Fail(s, \"timedOut\")", "ELSE IF e = \"timeout\" THEN Fail(s, \"didNotKeep\")")),

    # Two honest Macs and two people.
    ("PairingSystem (codes)", "PairingSystem", {"ByNumber": "FALSE"}, SYSTEM_INV, ["ItEnds"], HOLDS, None),
    ("PairingSystem (identity numbers)", "PairingSystem", {"ByNumber": "TRUE"}, SYSTEM_INV, ["ItEnds"], HOLDS, None),
    ("PairingSystem / reachable: both Macs store", "PairingSystem", {"ByNumber": "FALSE"}, ["NeverBothStored"], [], "NeverBothStored", None),
    ("PairingSystem / reachable: both Macs store, by number", "PairingSystem", {"ByNumber": "TRUE"}, ["NeverBothStored"], [], "NeverBothStored", None),
    ("PairingSystem / mutant: time never runs out", "PairingSystem", {"ByNumber": "FALSE"}, [], ["ItEnds"], "ItEnds",
     ("PairingSystem.tla", "/\\ \\A a \\in Sides: WF_vars(Deliver(a)) /\\ WF_vars(Timeout(a))", "/\\ \\A a \\in Sides: WF_vars(Deliver(a))")),

    # Two people asking each other at once.
    ("PairingGate", "PairingGate", {"Waits": "TRUE", "PatienceRunsOut": "FALSE"}, GATE_INV, ["EveryRequestIsAnswered"], HOLDS, None),
    ("PairingGate / mutant: a request does not wait for this Mac's own pairing (the code before cac7dd2)", "PairingGate",
     {"Waits": "FALSE", "PatienceRunsOut": "FALSE"}, GATE_INV, [], "NotBothTurnedAway", None),
    ("PairingGate / known limit: the two-second wait runs out first", "PairingGate",
     {"Waits": "TRUE", "PatienceRunsOut": "TRUE"}, GATE_INV, [], "NotBothTurnedAway", None),
    ("PairingGate / mutant: the higher key does not give way", "PairingGate", {"Waits": "TRUE", "PatienceRunsOut": "FALSE"}, GATE_INV, [],
     "NotBothTurnedAway",
     ("PairingGate.tla", "IF samePairing /\\ Lower(y)", "IF samePairing")),
    ("PairingGate / mutant: a request is shown beside this Mac's own pairing (F5)", "PairingGate", {"Waits": "TRUE", "PatienceRunsOut": "FALSE"},
     GATE_INV, [], "OnePairingAtATime",
     ("PairingGate.tla", "          ELSE IF Active(y)\n", "          ELSE IF FALSE\n")),

    # The trust core: the Swift code is the specification's machine.
    ("TrustRefinement (the Swift trust core is Step)", "TrustRefinement", {}, ["SpecIsImpl"], [], HOLDS, None),
    ("TrustRefinement / mutant: the specification registers a session under any key", "TrustRefinement", {}, ["SpecIsImpl"], [], "ImplIsSpec",
     ("TrustCore.tla", "        IF s.known # \"no\" THEN << [s EXCEPT !.tracked = @ \\cup ev.who], << >> >>", "        IF TRUE THEN << [s EXCEPT !.tracked = @ \\cup ev.who], << >> >>")),
    ("TrustRefinement / mutant: the specification counts by the calendar", "TrustRefinement", {}, ["SpecIsImpl"], [], "CountIsCount",
     ("TrustCore.tla", "IF sameBoot THEN Monus(continuous, lastContinuous) ELSE Max(continuous, Monus(wall, lastWall))", "Monus(wall, lastWall)")),
    ("TrustRefinement / mutant: the specification retries a failed write at every tick", "TrustRefinement", {}, ["SpecIsImpl"], [], "SaveDueIsSaveDue",
     ("TrustCore.tla", "changed \\/ (sinceTry >= 30 /\\ (unsaved \\/ sinceSave > 3600))", "changed \\/ sinceSave > 3600 \\/ (unsaved /\\ sinceTry >= 30)")),

    # Withdrawing trust: the lock, the disk and the order, around the core's Step.
    ("TrustWithdraw (a retire notice)", "TrustWithdraw", trust(), TRUST_INV, ["ForGoodOnDiskIsForGood", "NoSilentResurrection"], HOLDS, None),
    ("TrustWithdraw (Forget)", "TrustWithdraw", trust(ForGood="FALSE"), TRUST_INV, ["ForGoodOnDiskIsForGood", "NoSilentResurrection"], HOLDS, None),
    ("TrustWithdraw (tombstones pushed out): trust comes back only by two people pairing", "TrustWithdraw", trust(Eviction="TRUE"),
     ["TypeOK", "NothingOutlivesTheWithdrawal", "LiveMeansTrustedOrBeingEnded", "LiveIsOnTheList", "NoSocketWorkUnderTheLock"],
     ["NoSilentResurrection"], HOLDS, None),
    ("TrustWithdraw / known limit: 'for good' lasts while the tombstone is among the newest 2000", "TrustWithdraw", trust(Eviction="TRUE"),
     TRUST_INV, [], "AcknowledgedMeansRefusedForGood", None),
    ("TrustWithdraw / mutant: a key whose tombstone was pushed out is trusted again", "TrustWithdraw", trust(Eviction="TRUE"), [], ["NoSilentResurrection"],
     "NoSilentResurrection",
     ("TrustCore.tla", "    ELSE IF e = \"evict\" THEN << [s EXCEPT !.tomb = \"none\"], << >> >>", "    ELSE IF e = \"evict\" THEN << [s EXCEPT !.tomb = \"none\", !.known = \"current\"], << >> >>")),
    ("TrustWithdraw / reachable: a session goes live", "TrustWithdraw", trust(), ["NeverLive"], [], "NeverLive", None),
    ("TrustWithdraw / reachable: a retire notice is acknowledged", "TrustWithdraw", trust(), ["NeverAcked"], [], "NeverAcked", None),
    ("TrustWithdraw / mutant: track does not ask again (the code before 2026-11-24)", "TrustWithdraw", trust(),
     TRUST_INV, [], "LiveMeansTrustedOrBeingEnded",
     ("TrustCore.tla", "        IF s.known # \"no\" THEN << [s EXCEPT !.tracked = @ \\cup ev.who], << >> >>", "        IF TRUE THEN << [s EXCEPT !.tracked = @ \\cup ev.who], << >> >>")),
    ("TrustWithdraw / mutant: acknowledged without the write", "TrustWithdraw", trust(), TRUST_INV, [], "AcknowledgedMeansRefusedForGood",
     ("TrustWithdraw.tla", "/\\ w' = IF d = \"ok\" THEN \"committed\" ELSE \"silent\"", "/\\ w' = \"committed\"")),
    ("TrustWithdraw / mutant: sessions ended with the store locked (F7)", "TrustWithdraw", trust(), TRUST_INV, [], "NoSocketWorkUnderTheLock",
     ("TrustWithdraw.tla", "          /\\ lock' = \"none\" /\\ w' = \"ending\"", "          /\\ lock' = \"W\" /\\ w' = \"ending\"")),
    ("TrustWithdraw / mutant: the sessions are not ended", "TrustWithdraw", trust(), TRUST_INV, [], "NothingOutlivesTheWithdrawal",
     ("TrustWithdraw.tla", "IF x \\in toEnd /\\ sess[x] = \"live\" THEN \"ended\" ELSE sess[x]", "sess[x]")),
    ("TrustWithdraw / mutant: a withdrawal does not say which sessions to end", "TrustWithdraw", trust(ForGood="FALSE"), TRUST_INV, [], "LiveMeansTrustedOrBeingEnded",
     ("TrustCore.tla", "WithdrawEffects(s) == << Eff(\"save\", {}), Eff(\"end\", s.tracked),", "WithdrawEffects(s) == << Eff(\"save\", {}), Eff(\"end\", {}),")),
    ("TrustWithdraw / mutant: a retired key may be paired again", "TrustWithdraw", trust(), TRUST_INV, [], "AcknowledgedMeansRefusedForGood",
     ("TrustCore.tla", "    IF s.tomb = \"forGood\" THEN \"retired\"\n", "    IF FALSE THEN \"retired\"\n")),
    ("TrustWithdraw / mutant: a withdrawal that was not written is acknowledged after a restart", "TrustWithdraw", trust(), TRUST_INV, [],
     "AcknowledgedMeansRefusedForGood",
     ("TrustWithdraw.tla", "         /\\ up' = FALSE /\\ lock' = \"none\" /\\ w' = \"dead\"", "         /\\ up' = FALSE /\\ lock' = \"none\" /\\ w' = \"committed\"")),

    # A key's end, against clocks that lie.
    ("Expiry (a calendar that says anything)", "Expiry", expiry(), EXPIRY_INV, ["EndsNeverMoveLater"], HOLDS, None),
    ("Expiry (an honest calendar: nothing is lost)", "Expiry", expiry(HonestCalendar="TRUE", MaxUp="6", MaxWall="6"), EXPIRY_INV + ["NothingIsLost"],
     ["EndsNeverMoveLater"], HOLDS, None),
    ("Expiry / reachable: a key is paired", "Expiry", expiry(), ["NeverPaired"], [], "NeverPaired", None),
    ("Expiry / reachable: a key runs out", "Expiry", expiry(), ["NeverRunsOut"], [], "NeverRunsOut", None),
    ("Expiry / reachable: a pairing ended by the calendar is made again", "Expiry", expiry(), ["NeverPairedAgain"], [], "NeverPairedAgain", None),
    ("Expiry / known limit: an unclean reboot under a lying calendar loses the time since the last write", "Expiry", expiry(), ["NothingIsLost"], [],
     "NothingIsLost", None),
    ("Expiry / mutant: a held calendar stops time", "Expiry", expiry(), EXPIRY_INV, [], "TheCountCoversTheTimeUp",
     ("TrustCore.tla", "IF sameBoot THEN Monus(continuous, lastContinuous) ELSE Max(continuous, Monus(wall, lastWall))", "Monus(wall, lastWall)")),
    ("Expiry / mutant: after a reboot only the calendar counts", "Expiry", expiry(), EXPIRY_INV, [], "TheCountCoversTheTimeUp",
     ("TrustCore.tla", "ELSE Max(continuous, Monus(wall, lastWall))", "ELSE Monus(wall, lastWall)")),
    ("Expiry / mutant: the calendar alone refuses a key for good (F3)", "Expiry", expiry(), EXPIRY_INV, [], "OnlyTheCountRefusesForGood",
     ("Expiry.tla", "EndPasses  == Ahead /\\ Counted >= ends.e\n", "EndPasses  == Ahead /\\ (Counted >= ends.e \\/ wall >= ends.w)\n")),
    ("Expiry / mutant: a key that runs out on the pair-again list is forgotten, not refused (F2)", "Expiry", expiry(), EXPIRY_INV, [],
     "PastItsEndIsNeverPaired",
     ("TrustCore.tla", "              !.tomb = IF RunsOutNow(s) /\\ @ = \"none\" THEN \"expired\" ELSE @]", "              !.tomb = IF s.known = \"current\" /\\ @ = \"none\" THEN \"expired\" ELSE @]")),
    ("Expiry / mutant: pairing again gives the key a new end", "Expiry", expiry(), EXPIRY_INV, ["EndsNeverMoveLater"], "EndsNeverMoveLater",
     ("Expiry.tla", "e == IF Listed(core) THEN Min(life, ends.e) ELSE life", "e == life")),
    ("Expiry / mutant: the count is not written down hourly", "Expiry", expiry(), EXPIRY_INV, [], "TheFileIsLessThanAnHourBehind",
     ("Expiry.tla", "/\\ Counted - mem.lastSave >= Hour", "/\\ FALSE")),
    ("Expiry / mutant: a session has no deadline", "Expiry", expiry(), EXPIRY_INV, [], "NoSessionPastItsGrace",
     ("Expiry.tla", "Late       == core.tracked # {} /\\ Counted > ends.d", "Late       == FALSE")),

    # A drop's rounds under a network that misbehaves.
    ("Drop", "Drop", drop(), DROP_INV, DROP_PROPS, HOLDS, None),
    ("Drop (three chunks, two faults)", "Drop", drop(Chunks="{c1, c2, c3}", MaxFaults="2", MaxConns="8"), DROP_INV, DROP_PROPS, HOLDS, None),
    ("Drop (either end may give up)", "Drop", drop(MayGiveUp="TRUE", MaxFaults="2", MaxConns="8"), DROP_INV,
     ["NothingWrittenAfterPlacing", "ItEnds"], HOLDS, None),
    ("Drop / mutant: a record is written without being opened", "Drop", drop(ChecksTag="FALSE"), DROP_INV, [], "NoWrongBytes", None),
    ("Drop / mutant: the connection counter starts again on a reconnect", "Drop", drop(KeepsCounter="FALSE"), DROP_INV, [], "NoStreamKeyTwice", None),
    ("Drop / mutant: 'complete' is said of a drop that is not whole", "Drop", drop(), DROP_INV, [], "PlacedIsWhole",
     ("Drop.tla", "         /\\ IF have = Chunks\n               THEN placed' = TRUE", "         /\\ IF have # {}\n               THEN placed' = TRUE")),
    ("Drop / mutant: the sender does not come back after losing the conversation", "Drop", drop(), [], ["ItArrives"], "deadlock",
     ("Drop.tla", "Protocol == SPlan \\/ SComplete \\/ Open \\/ SNotice \\/ SDone \\/ SLost \\/ RDone \\/ RLost \\/ Reconnect \\/ Refused",
      "Protocol == SPlan \\/ SComplete \\/ Open \\/ SNotice \\/ SDone \\/ SLost \\/ RDone \\/ RLost \\/ Refused")),
]


# TLC's exit code for each outcome (tlc2.output.EC). Anything else is the tool failing.
TLC_EXIT = {"holds": 0, "assumption": 10, "deadlock": 11, "invariant": 12, "property": 13}


def parse_tlc(out, assumption_name=lambda line: None):
    """What TLC printed: (kind, name, states). kind is one of TLC_EXIT's, or None when the
    output shows neither a clean finish nor a violation it names."""
    states = re.findall(r"([\d,]+) distinct states found", out)
    size = f"{int(states[-1].replace(',', '')):,} states" if states else "no states"
    m = re.search(r"Invariant (\w+) is violated", out)
    if m:
        return "invariant", m.group(1), size
    m = re.search(r"(?:Temporal|Action) property (\w+) (?:was|is) violated", out)
    if m:
        return "property", m.group(1), size
    if "Temporal properties were violated" in out:
        return "property", "a temporal property", size
    if re.search(r"Assumption .* is false", out):
        line = re.search(r"Assumption line (\d+)", out)
        return "assumption", (assumption_name(int(line.group(1))) if line else None) or "an assumption", size
    if "Deadlock reached" in out:
        return "deadlock", "deadlock", size
    if "Model checking completed. No error has been found." in out:
        return "holds", None, size
    return None, None, size


def judge_tlc(out, code, timed_out, expected, properties, assumption_name=lambda line: None):
    """(ok, note) for one TLC run. `expected`: HOLDS, or the name of what must be violated."""
    if timed_out:
        return False, "TOOL ERROR: TLC did not finish in time"
    kind, name, size = parse_tlc(out, assumption_name)
    if kind is None:
        tail = "\n".join(l for l in out.split("\n") if l.strip())[-900:]
        return False, f"TOOL ERROR: TLC did not finish (exit {code}):\n{tail}"
    if code != TLC_EXIT[kind]:
        return False, f"TOOL ERROR: TLC printed '{kind}' and exited {code}, not {TLC_EXIT[kind]}"
    if expected == HOLDS:
        return (kind == "holds"), (size if kind == "holds" else f"VIOLATED: {name}")
    if kind == "holds":
        return False, f"holds, and must not: nothing notices this mutant ({size})"
    if name == expected or (name == "a temporal property" and expected in properties):
        return True, f"fails as it must, on {expected}"
    return False, f"fails on {name}; it was to fail on {expected}"


def run_tlc(java, jar, name, module, constants, invariants, properties, expected, mutation, keep=None):
    work = tempfile.mkdtemp(prefix="nimbus-tlc-")
    command = [java, "-XX:+UseParallelGC", "-cp", jar, "tlc2.TLC", "-workers", "4", "-config", "run.cfg", module + ".tla"]
    out, code, timed_out = "", None, False
    try:
        for f in os.listdir(TLA):
            if f.endswith(".tla"):
                shutil.copy(os.path.join(TLA, f), work)
        if mutation:
            path, old, new = mutation
            text = open(os.path.join(work, path)).read()
            if text.count(old) != 1:
                return False, f"the mutation's text is in {path} {text.count(old)} times, not once"
            open(os.path.join(work, path), "w").write(text.replace(old, new))
        cfg = "SPECIFICATION Spec\n"
        if constants:
            cfg += "CONSTANTS\n" + "".join(f"    {k} = {v}\n" for k, v in constants.items())
        if invariants:
            cfg += "INVARIANTS\n" + "".join(f"    {i}\n" for i in invariants)
        if properties:
            cfg += "PROPERTIES\n" + "".join(f"    {p}\n" for p in properties)
        open(os.path.join(work, "run.cfg"), "w").write(cfg)
        try:
            done = subprocess.run(command, cwd=work, capture_output=True, text=True, timeout=1800)
            out, code = done.stdout + done.stderr, done.returncode
        except subprocess.TimeoutExpired as e:
            out, timed_out = (e.stdout or b"").decode(errors="replace") if isinstance(e.stdout, bytes) else (e.stdout or ""), True
        source = open(os.path.join(work, module + ".tla")).read().split("\n")
    finally:
        shutil.rmtree(work, ignore_errors=True)

    def assumption_name(line):
        named = re.search(r"ASSUME (\w+)", source[line - 1]) if 0 < line <= len(source) else None
        return named.group(1) if named else None

    ok, note = judge_tlc(out, code, timed_out, expected, properties, assumption_name)
    if keep:
        keep(name, "tla", command, out, code, ok, note, {"module": module, "constants": constants, "invariants": invariants,
                                                         "properties": properties, "expected": expected, "mutation": mutation})
    return ok, note


# ---- Tamarin ---------------------------------------------------------------------------------
# (name, file, flags, {lemma: expected}) where expected is "verified" or "falsified".
# With no lemma named, every lemma of the theory must be verified. With lemmas named, only
# those are searched for (a mutant's other lemmas may not terminate: with the commitment check
# gone, the search for an honest pairing ran past 10 GB) and each must come out as named.

TAMARIN_RUNS = [
    ("NimbusHandshake", "NimbusHandshake.spthy", [], {}),
    ("NimbusPairing", "NimbusPairing.spthy", [], {}),
    ("NimbusPairing / mutant: the reveal is not checked against the commitment", "NimbusPairing.spthy", ["-D=NoCommitCheck"],
     {"a_stored_pairing_is_with_the_mac_the_person_meant": "falsified"}),
    ("NimbusPairing / mutant: neither the commitment nor the codes include the handshake hash", "NimbusPairing.spthy", ["-D=NoHashBinding"],
     {"a_stored_pairing_is_with_the_mac_the_person_meant": "falsified"}),
]


def declared_lemmas(path):
    """Every lemma a theory declares, as (name, kind), from its text with the comments taken out."""
    text = re.sub(r"/\*.*?\*/", "", open(path).read(), flags=re.S)
    text = re.sub(r"//[^\n]*", "", text)
    return [(m.group(1), m.group(2) or "all-traces")
            for m in re.finditer(r"^[ \t]*lemma\s+(\w+)\s*(?:\[[^\]]*\])?\s*:\s*(exists-trace|all-traces)?", text, re.M)]


def load_register(path=None):
    register = json.load(open(path or REGISTER))
    return {theory: entry["lemmas"] for theory, entry in register.items() if not theory.startswith("_")}


def check_register(register, theories):
    """The register against the theories as they are written. `theories`: {file name: [(name,
    kind)]} as declared. Returns the problems; none means every lemma written is required and
    every lemma required is written, once, with the kind the register says."""
    problems = []
    for theory in sorted(set(register) | set(theories)):
        if theory not in register:
            problems.append(f"{theory} has no entry in the register")
            continue
        if theory not in theories:
            problems.append(f"the register lists {theory}, which is not there")
            continue
        declared, required = theories[theory], register[theory]
        names = [n for n, _ in declared]
        wanted = [l["name"] for l in required]
        for n in sorted(set(names)):
            if names.count(n) > 1:
                problems.append(f"{theory}: lemma {n} is declared {names.count(n)} times")
        for n in sorted(set(wanted)):
            if wanted.count(n) > 1:
                problems.append(f"{theory}: lemma {n} is registered {wanted.count(n)} times")
        for n in sorted(set(names) - set(wanted)):
            problems.append(f"{theory}: lemma {n} is declared and is not in the register")
        for n in sorted(set(wanted) - set(names)):
            problems.append(f"{theory}: lemma {n} is required by the register and is not declared")
        kinds = dict(declared)
        for l in required:
            if l["name"] in kinds and kinds[l["name"]] != l.get("kind"):
                problems.append(f"{theory}: lemma {l['name']} is {kinds[l['name']]}; the register says {l.get('kind')}")
            if l.get("expect") not in ("verified", "falsified"):
                problems.append(f"{theory}: lemma {l['name']} has no expected result")
            for field in ("claim", "assumes", "code", "tests"):
                if not l.get(field):
                    problems.append(f"{theory}: lemma {l['name']} has no '{field}' in the register")
    return problems


def parse_tamarin(text):
    """What Tamarin's summary says. {"whole": the summary is there and ends as it should,
    "wellformed": bool, "lemmas": [(name, kind, status)], "unread": lines of the summary that
    look like results and could not be read}. status: verified, falsified or incomplete."""
    out = {"whole": False, "wellformed": True, "lemmas": [], "unread": []}
    if "summary of summaries:" not in text:
        return out
    summary = text[text.rindex("summary of summaries:"):]
    lines = summary.split("\n")
    out["whole"] = any(re.fullmatch(r"={20,}", l.strip()) for l in lines)
    if re.search(r"wellformedness check failed", text, re.I):
        out["wellformed"] = False
    for l in lines:
        m = re.match(r"^\s+(\w+) \((all-traces|exists-trace)\): (verified|falsified|analysis incomplete)\b", l)
        if m:
            out["lemmas"].append((m.group(1), m.group(2), "incomplete" if m.group(3) == "analysis incomplete" else m.group(3)))
        elif re.match(r"^\s+\w+ \((all-traces|exists-trace)\)", l):
            out["unread"].append(l.strip())
    return out


def judge_tamarin(text, code, timed_out, required, expectations):
    """(ok, note, results) for one Tamarin run. `required`: the register's lemmas for the
    theory. `expectations`: {} for a normal run, where every required lemma must come out as
    the register says; or {lemma: result} for a mutant, where only those were asked for and
    each must come out as named. results: {lemma: verified | falsified | incomplete | not run}."""
    results = {l["name"]: "not run" for l in required}
    if timed_out:
        return False, "TOOL ERROR: tamarin did not finish in time", results
    if code != 0:
        return False, f"TOOL ERROR: tamarin exited {code}:\n{text[-600:]}", results
    parsed = parse_tamarin(text)
    if not parsed["whole"]:
        return False, "TOOL ERROR: tamarin's summary is missing or cut short:\n" + text[-600:], results
    if not parsed["wellformed"]:
        return False, "the theory is not well-formed", results
    if parsed["unread"]:
        return False, "TOOL ERROR: results that could not be read: " + "; ".join(parsed["unread"]), results
    if not parsed["lemmas"]:
        return False, "TOOL ERROR: no lemmas in the summary", results
    names = [n for n, _, _ in parsed["lemmas"]]
    known = {l["name"]: l for l in required}
    problems = []
    for n in sorted(set(names)):
        if names.count(n) > 1:
            problems.append(f"{n}: in the summary {names.count(n)} times")
        if n not in known:
            problems.append(f"{n}: not in the register")
    for n, kind, status in parsed["lemmas"]:
        if n in known:
            results[n] = status
            if kind != known[n]["kind"]:
                problems.append(f"{n}: {kind}, and the register says {known[n]['kind']}")
    wanted = expectations or {l["name"]: l["expect"] for l in required}
    for n, expect in wanted.items():
        if n not in known:
            problems.append(f"{n}: asked for, and not in the register")
        elif n not in names:
            problems.append(f"{n}: not in the summary")
        elif results[n] != expect:
            if expectations and results[n] == "verified":
                problems.append(f"{n}: verified, and must be {expect}: nothing notices this mutant")
            else:
                problems.append(f"{n}: {results[n]} (must be {expect})")
    if problems:
        return False, "; ".join(problems), results
    falsified = [n for n in wanted if results[n] == "falsified"]
    return True, f"{len(wanted)} lemmas" + (f"; fails as it must, on {', '.join(falsified)}" if falsified else " verified"), results


def run_tamarin(prover, register, name, file, flags, expectations, keep=None):
    prove = [f"--prove={lemma}" for lemma in expectations] or ["--prove"]
    command = [prover] + prove + flags + [os.path.join(TAMARIN, file), "+RTS", "-N4", "-RTS"]
    text, code, timed_out = "", None, False
    try:
        done = subprocess.run(command, capture_output=True, text=True, timeout=7200)
        text, code = done.stdout + done.stderr, done.returncode
    except subprocess.TimeoutExpired:
        timed_out = True
    if file not in register:
        ok, note, results = False, f"{file} has no entry in the register", {}
    else:
        ok, note, results = judge_tamarin(text, code, timed_out, register[file], expectations)
    if keep:
        keep(name, "tamarin", command, text, code, ok, note, {"theory": file, "flags": flags, "expectations": expectations, "lemmas": results})
    return ok, note


# ---- What was run, kept -------------------------------------------------------------------------

def sha256(path):
    return hashlib.sha256(open(path, "rb").read()).hexdigest()


def first_line(command):
    try:
        done = subprocess.run(command, capture_output=True, text=True, timeout=60)
        lines = [l.strip() for l in (done.stdout + done.stderr).split("\n") if l.strip()]
        return next((l for l in lines if re.search(r"\d+\.\d+", l)), lines[0] if lines else "?")
    except (OSError, subprocess.SubprocessError):
        return "?"


class Record:
    """One invocation's evidence: a folder under formal/.results/ with each run's raw output and
    a summary.json saying what was run, with what, on which sources, and how each came out."""

    def __init__(self, versions):
        rev = first_line(["git", "-C", HERE, "rev-parse", "--short", "HEAD"])
        dirty = bool(subprocess.run(["git", "-C", HERE, "status", "--porcelain"], capture_output=True, text=True).stdout.strip())
        stamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        self.folder = os.path.join(RESULTS, f"{stamp}-{rev}{'-dirty' if dirty else ''}")
        os.makedirs(self.folder, exist_ok=True)
        inputs = {os.path.relpath(os.path.join(d, f), HERE): sha256(os.path.join(d, f))
                  for d in (TLA, TAMARIN) for f in sorted(os.listdir(d)) if f.endswith((".tla", ".spthy", ".json"))}
        self.summary = {"when": stamp, "revision": rev, "uncommitted changes": dirty, "command": sys.argv, "tools": versions,
                        "inputs sha256": inputs, "runs": []}

    def keep(self, name, kind, command, output, code, ok, note, detail):
        n = len(self.summary["runs"]) + 1
        raw = f"{n:03d}-{re.sub(r'[^A-Za-z0-9]+', '-', name)[:80].strip('-')}.txt"
        open(os.path.join(self.folder, raw), "w").write(output)
        self.summary["runs"].append({"name": name, "kind": kind, "command": command, "exit": code, "as it must be": ok,
                                     "outcome": note.split("\n")[0], "output": raw, **detail})
        self.write()

    def write(self):
        json.dump(self.summary, open(os.path.join(self.folder, "summary.json"), "w"), indent=1, default=str)


def main():
    words = [a for a in sys.argv[1:] if not a.startswith("-")]
    kinds = {w for w in words if w in ("tla", "tamarin", "register")}
    words = [w for w in words if w not in kinds]

    def wanted(kind, name):
        return (not kinds or kind in kinds) and (not words or any(w.lower() in name.lower() for w in words))

    bad = 0
    ran = 0
    tla = [r for r in TLA_RUNS if wanted("tla", r[0])]
    tam = [r for r in TAMARIN_RUNS if wanted("tamarin", r[0])]

    # The register against the theories: needs no prover, and is checked before any is run.
    register = load_register()
    if wanted("register", "register") or tam:
        theories = {f: declared_lemmas(os.path.join(TAMARIN, f)) for f in sorted(os.listdir(TAMARIN)) if f.endswith(".spthy")}
        problems = check_register(register, theories)
        problems += [f"{r[0]}: asks for {l}, which is not in the register" for r in TAMARIN_RUNS for l in r[3]
                     if l not in [x["name"] for x in register.get(r[1], [])]]
        ran += 1
        bad += bool(problems)
        count = sum(len(v) for v in register.values())
        print(f"{'FAIL' if problems else 'ok  '}  register {count} lemmas in {len(register)} theories"
              + (":\n          " + "\n          ".join(problems) if problems else ", each declared once and each required"), flush=True)

    java = jar = prover = None
    versions = {"python": sys.version.split()[0]}
    if tla:
        # macOS has a /usr/bin/java that is only an invitation to install one: take the first that runs.
        java = next((j for j in [os.environ.get("JAVA"), "/opt/homebrew/opt/openjdk/bin/java", "/usr/local/opt/openjdk/bin/java", shutil.which("java")]
                     if j and os.path.exists(j) and subprocess.run([j, "-version"], capture_output=True).returncode == 0), None)
        if not java:
            sys.exit("no Java to run TLC with: brew install openjdk")
        jar = tlc_jar()
        versions["java"] = first_line([java, "-version"])
        versions["tlc"] = first_line([java, "-cp", jar, "tlc2.TLC", "-h"]) + f" (tla2tools.jar sha256 {TLC_SHA256[:16]}…)"
    if tam:
        prover = find("tamarin-prover", ["/opt/homebrew/bin/tamarin-prover"])
        if not prover:
            sys.exit("no tamarin-prover: brew install tamarin-prover/tap/tamarin-prover")
        versions["tamarin"] = first_line([prover, "--version"])
        versions["maude"] = first_line([find("maude", ["/opt/homebrew/bin/maude"]) or "maude", "--version"])
    if tla or tam:
        print("with    " + "; ".join(f"{k} {v}" for k, v in versions.items()), flush=True)
    record = Record(versions) if (tla or tam) else None

    for run in tla:
        started = time.time()
        ok, note = run_tlc(java, jar, *run, keep=record.keep)
        bad += not ok
        ran += 1
        print(f"{'ok  ' if ok else 'FAIL'}  tla      {run[0]}: {note}  ({time.time() - started:.0f} s)", flush=True)
    for run in tam:
        started = time.time()
        ok, note = run_tamarin(prover, register, *run, keep=record.keep)
        bad += not ok
        ran += 1
        print(f"{'ok  ' if ok else 'FAIL'}  tamarin  {run[0]}: {note}  ({time.time() - started:.0f} s)", flush=True)

    if record:
        record.summary["not as they must be"] = bad
        record.write()
        print(f"\nkept in {os.path.relpath(record.folder, os.getcwd())}")
    if ran == 0 or (words and not (tla or tam)):
        print(f"nothing matches {' '.join(sys.argv[1:])!r}: that is an error, not a pass")
        sys.exit(2)
    print(f"{ran} runs, {bad} not as they must be")
    sys.exit(1 if bad else 0)


if __name__ == "__main__":
    main()
