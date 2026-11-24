#!/usr/bin/env python3
# Copyright (C) 2026 Niels Joubert
# SPDX-License-Identifier: GPL-3.0-or-later
"""Runs every formal model, and every mutant of one, and says whether each came out as it must.

    python3 formal/check.py              everything
    python3 formal/check.py tla          the TLA+ models only (seconds)
    python3 formal/check.py tamarin      the Tamarin models only (minutes)
    python3 formal/check.py Drop         whatever has "Drop" in its name

A model that holds proves little by itself: it may hold because it says nothing. So beside
every model are its mutants, each the model with one guard taken out, and each must FAIL, on
the property named for it. A mutant that passes is reported as loudly as a model that fails.
(`scripts/mutate.py` does the same for the Swift and its tests.)

Needs: java (TLC), tamarin-prover and maude on the PATH or in Homebrew's usual places. TLC
itself (tla2tools.jar, MIT) is fetched once into formal/.tools/ and checked against a pinned
SHA-256. See formal/README.md.
"""
import hashlib
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
             "NoSocketWorkUnderTheLock"]
DROP_INV = ["TypeOK", "NoWrongBytes", "PlacedIsWhole", "SentMeansSaved", "NoStreamKeyTwice"]
DROP_PROPS = ["NothingWrittenAfterPlacing", "ItEnds", "ItArrives"]


def drop(**changes):
    c = {"Chunks": "{c1, c2}", "MaxFaults": "3", "MaxConns": "11", "ChecksTag": "TRUE", "KeepsCounter": "TRUE", "MayGiveUp": "FALSE"}
    c.update(changes)
    return c


def trust(**changes):
    c = {"Sessions": "{s1, s2}", "TrackChecks": "TRUE"}
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

    # Withdrawing trust.
    ("TrustWithdraw", "TrustWithdraw", trust(), TRUST_INV, [], HOLDS, None),
    ("TrustWithdraw (three sessions)", "TrustWithdraw", trust(Sessions="{s1, s2, s3}"), TRUST_INV, [], HOLDS, None),
    ("TrustWithdraw / mutant: track does not ask again (the code before 2026-11-24)", "TrustWithdraw", trust(TrackChecks="FALSE"),
     TRUST_INV, [], "LiveMeansTrustedOrBeingEnded", None),
    ("TrustWithdraw / mutant: acknowledged without the write", "TrustWithdraw", trust(), TRUST_INV, [], "AcknowledgedMeansRefusedForGood",
     ("TrustWithdraw.tla", "\\/ UNCHANGED disk /\\ w' = \"silent\"", "\\/ UNCHANGED disk /\\ w' = \"committed\"")),
    ("TrustWithdraw / mutant: sessions ended with the store locked (F7)", "TrustWithdraw", trust(), TRUST_INV, [], "NoSocketWorkUnderTheLock",
     ("TrustWithdraw.tla", "          /\\ lock' = \"none\" /\\ w' = \"ending\"", "          /\\ lock' = \"W\" /\\ w' = \"ending\"")),
    ("TrustWithdraw / mutant: the sessions are not ended", "TrustWithdraw", trust(), TRUST_INV, [], "NothingOutlivesTheWithdrawal",
     ("TrustWithdraw.tla", "IF s \\in toEnd /\\ sess[s] = \"live\" THEN \"ended\" ELSE sess[s]", "sess[s]")),

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


def run_tlc(java, jar, name, module, constants, invariants, properties, expected, mutation):
    work = tempfile.mkdtemp(prefix="nimbus-tlc-")
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
        out = subprocess.run([java, "-XX:+UseParallelGC", "-cp", jar, "tlc2.TLC", "-workers", "4", "-config", "run.cfg", module + ".tla"],
                             cwd=work, capture_output=True, text=True, timeout=1800).stdout
    finally:
        shutil.rmtree(work, ignore_errors=True)
    states = re.findall(r"([\d,]+) distinct states found", out)
    size = f"{int(states[-1].replace(',', '')):,} states" if states else "no states"
    violated = None
    m = re.search(r"Invariant (\w+) is violated", out)
    if m:
        violated = m.group(1)
    elif re.search(r"(?:Temporal|Action) property (\w+) (?:was|is) violated", out):
        violated = re.search(r"(?:Temporal|Action) property (\w+) (?:was|is) violated", out).group(1)
    elif "Temporal properties were violated" in out:
        violated = "a temporal property"
    elif re.search(r"Assumption .* is false", out):
        line = int(re.search(r"Assumption line (\d+)", out).group(1))
        source = open(os.path.join(TLA, module + ".tla")).read().split("\n")[line - 1]
        named = re.search(r"ASSUME (\w+)", source)
        violated = named.group(1) if named else "an assumption"
    elif "Deadlock reached" in out:
        violated = "deadlock"
    elif "No error has been found" not in out:
        tail = "\n".join(l for l in out.split("\n") if l.strip())[-900:]
        return False, f"TLC did not finish:\n{tail}"
    if expected == HOLDS:
        return (violated is None), (size if violated is None else f"VIOLATED: {violated}")
    if violated is None:
        return False, f"holds, and must not: nothing notices this mutant ({size})"
    if violated == expected or (violated == "a temporal property" and expected in properties):
        return True, f"fails as it must, on {expected}"
    return False, f"fails on {violated}; it was to fail on {expected}"


# ---- Tamarin ---------------------------------------------------------------------------------
# (name, file, flags, {lemma: expected}) where expected is "verified" or "falsified".
# With no lemma named, every lemma of the theory must be verified. With lemmas named, only
# those are searched for (a mutant's other lemmas may not terminate: with the commitment check
# gone, the search for an honest pairing ran past 10 GB) and each must come out as named.

TAMARIN_RUNS = [
    ("NimbusHandshake", "NimbusHandshake.spthy", [], {}),
    # Each guard of the handshake theory taken out (a macro in the file, with the line of the Swift
    # it stands for), and the lemma that must then fail. Not here: -D=NoConnInStreamKey,
    # -D=NoHeaderBinding, -D=NoHashInResume and -D=SameResumeLabel, whose search for a trace was
    # stopped at 12 to 13 GB; nothing is claimed of those four guards (the file says so).
    ("NimbusHandshake / mutant: the initiator does not open the last seal of message 2", "NimbusHandshake.spthy", ["-D=NoMessage2Check"],
     {"a_probe_is_answered_by_the_key_it_reports": "falsified"}),
    ("NimbusHandshake / mutant: the responder does not open the last seal of message 3", "NimbusHandshake.spthy", ["-D=NoMessage3Check"],
     {"the_responder_agrees_with_the_initiator": "falsified"}),
    ("NimbusHandshake / mutant: ee is not mixed into the keys", "NimbusHandshake.spthy", ["-D=NoEE"],
     {"master_is_secret_for_the_initiator": "falsified"}),
    ("NimbusHandshake / mutant: es is not mixed into the keys", "NimbusHandshake.spthy", ["-D=NoES"],
     {"a_probe_is_answered_by_the_key_it_reports": "falsified"}),
    ("NimbusHandshake / mutant: se is not mixed into the keys", "NimbusHandshake.spthy", ["-D=NoSE"],
     {"master_is_secret_for_the_responder": "falsified"}),
    ("NimbusHandshake / mutant: the handshake's seals do not have the hash as associated data", "NimbusHandshake.spthy", ["-D=NoHashInSeals"],
     {"the_responder_agrees_with_the_initiator": "falsified"}),
    ("NimbusHandshake / mutant: the openings are not in the handshake hash", "NimbusHandshake.spthy", ["-D=NoPrologue"],
     {"the_handshake_hash_binds_the_openings": "falsified"}),
    ("NimbusHandshake / mutant: one transport key for both directions", "NimbusHandshake.spthy", ["-D=OneTransportKey"],
     {"the_initiator_hears_only_the_responder": "falsified"}),
    ("NimbusHandshake / mutant: master is taken from the handshake hash", "NimbusHandshake.spthy", ["-D=MasterFromHash"],
     {"master_is_secret_for_the_initiator": "falsified"}),
    ("NimbusHandshake / mutant: what a connection is for is said in the clear", "NimbusHandshake.spthy", ["-D=PurposeInTheClear"],
     {"both_ends_agree_what_a_connection_is_for": "falsified"}),
    ("NimbusHandshake / mutant: the attach key is the session id", "NimbusHandshake.spthy", ["-D=AttachKeyIsSessionID"],
     {"only_the_sender_attaches_a_data_connection": "falsified"}),
    ("NimbusHandshake / mutant: the attach tag is computed without the challenge", "NimbusHandshake.spthy", ["-D=NoChallengeInTag"],
     {"only_the_sender_attaches_a_data_connection": "falsified"}),
    ("NimbusHandshake / mutant: the attach tag is computed without the connection number", "NimbusHandshake.spthy", ["-D=NoConnInTag"],
     {"only_the_sender_attaches_a_data_connection": "falsified"}),
    ("NimbusPairing", "NimbusPairing.spthy", [], {}),
    ("NimbusPairing / mutant: the reveal is not checked against the commitment", "NimbusPairing.spthy", ["-D=NoCommitCheck"],
     {"a_stored_pairing_is_with_the_mac_the_person_meant": "falsified", "the_mac_that_asked_stores_one_exchange": "falsified"}),
    ("NimbusPairing / mutant: neither the commitment nor the codes include the handshake hash", "NimbusPairing.spthy", ["-D=NoHashBinding"],
     {"a_stored_pairing_is_with_the_mac_the_person_meant": "falsified", "the_mac_that_asked_stores_one_exchange": "falsified"}),
]


def run_tamarin(prover, name, file, flags, expectations):
    prove = [f"--prove={lemma}" for lemma in expectations] or ["--prove"]
    out = subprocess.run([prover] + prove + flags + [os.path.join(TAMARIN, file), "+RTS", "-N4", "-RTS"],
                         capture_output=True, text=True, timeout=7200)
    text = out.stdout + out.stderr
    if "summary of summaries" not in text:
        return False, "tamarin did not finish:\n" + text[-900:]
    summary = text[text.index("summary of summaries"):]
    if "wellformedness check failed" in summary:
        return False, "the theory is not well-formed"
    results = re.findall(r"^\s+(\w+) \((?:all-traces|exists-trace)\): (verified|falsified|analysis incomplete)", summary, re.M)
    if not results:
        return False, "no lemmas in the summary"
    if expectations:
        results = [(lemma, got) for lemma, got in results if lemma in expectations]
    wrong = [f"{lemma}: {got} (must be {expectations.get(lemma, 'verified')})" for lemma, got in results
             if got != expectations.get(lemma, "verified")]
    missing = [l for l in expectations if l not in dict(results)]
    if wrong or missing:
        return False, "; ".join(wrong + [f"{l}: not in the theory" for l in missing])
    falsified = [l for l, g in results if g == "falsified"]
    return True, f"{len(results)} lemmas" + (f"; fails as it must, on {', '.join(falsified)}" if falsified else " verified")


def main():
    words = [a for a in sys.argv[1:] if not a.startswith("-")]
    kinds = {w for w in words if w in ("tla", "tamarin")}
    words = [w for w in words if w not in kinds]

    def wanted(kind, name):
        return (not kinds or kind in kinds) and (not words or any(w.lower() in name.lower() for w in words))

    bad = 0
    tla = [r for r in TLA_RUNS if wanted("tla", r[0])]
    if tla:
        # macOS has a /usr/bin/java that is only an invitation to install one: take the first that runs.
        java = next((j for j in [os.environ.get("JAVA"), "/opt/homebrew/opt/openjdk/bin/java", "/usr/local/opt/openjdk/bin/java", shutil.which("java")]
                     if j and os.path.exists(j) and subprocess.run([j, "-version"], capture_output=True).returncode == 0), None)
        if not java:
            sys.exit("no Java to run TLC with: brew install openjdk")
        jar = tlc_jar()
        for run in tla:
            started = time.time()
            ok, note = run_tlc(java, jar, *run)
            bad += not ok
            print(f"{'ok  ' if ok else 'FAIL'}  tla      {run[0]}: {note}  ({time.time() - started:.0f} s)", flush=True)
    tam = [r for r in TAMARIN_RUNS if wanted("tamarin", r[0])]
    if tam:
        prover = find("tamarin-prover", ["/opt/homebrew/bin/tamarin-prover"])
        if not prover:
            sys.exit("no tamarin-prover: brew install tamarin-prover/tap/tamarin-prover")
        for run in tam:
            started = time.time()
            ok, note = run_tamarin(prover, *run)
            bad += not ok
            print(f"{'ok  ' if ok else 'FAIL'}  tamarin  {run[0]}: {note}  ({time.time() - started:.0f} s)", flush=True)
    print(f"\n{len(tla) + len(tam)} runs, {bad} not as they must be")
    sys.exit(1 if bad else 0)


if __name__ == "__main__":
    main()
