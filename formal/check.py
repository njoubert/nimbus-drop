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

# ---- Admission: which connection has a place at the listener, and which gives way (one block) ------------
# Admission.tla is Admission.swift: AdmissionRefinement holds the two equal, both ways, at the two sets of
# limits the Swift was walked at. AdmissionSystem.tla is a listener that asks that machine, one honest
# paired Mac that is watched, and everyone else: any number of connections, from anywhere, as slow as they
# like. Every run is bounded by the limits written here (a pool of three, a rate of four; the listener
# runs at 64, 8, 500 and 200), and is bounded checking, not proof.

ADMISSION_INV = ["TypeOK", "PoolsWithinLimits", "TheRateHolds", "EveryPlaceIsHeldByItsConnection", "AnAddressDecidesOnlyWhoWaits",
                 "ANewcomerWithinTheRateGetsAPlace", "OverTheRateTheNewcomerIsClosed", "TheOldestGivesWay", "ElsewhereCountsForNothing",
                 "NoDropNoPlace", "AKeysPlacesAreItsOwn", "ARetiredKeyGetsNothing", "OneThatGaveWayGetsNothingMore",
                 "GivesWayOnlyAfterAPoolOfNewcomers", "KeptOutByTheRateOnlyOnItsOwnAccount", "APairedMacIsNotTurnedAwayForOthers"]


def admission(**changes):
    """The pools: three places for strangers and two an address; a place for a data connection for each drop
    in progress, of which there are none, one or two; one connection from a key nobody paired and one from
    each of two paired keys; an address that is not on the local network. No rate to speak of. Anyone may
    arrive from the watched Mac's own address."""
    c = {"Addresses": '{"h", "x", "far"}', "Outside": '{"far"}', "Honest": '"h"', "Keys": '{"kh", "kx"}', "HonestKey": '"kh"',
         "Strangers": "3", "StrangersPerAddress": "2", "Arrivals": "1", "ArrivalsPerAddress": "1", "Window": "0", "Gaps": "{1}",
         "UnattachedPerDrop": "1", "UnattachedPerAddress": "1", "Unpaired": "1", "PairedWaiting": "1", "Drops": "{0, 1, 2}",
         "Alone": "FALSE", "Quick": "FALSE", "SetBack": "0"}
    c.update(changes)
    return c


def admission_rate(**changes):
    """The rate: four arrivals in a window of one tick and two from one address; a clock that moves by
    nothing, one tick or two between arrivals; one other address. One place of each kind."""
    return admission(**{**{"Addresses": '{"h", "x"}', "Outside": "{}", "Keys": '{"kh"}', "Strangers": "1", "StrangersPerAddress": "1",
                           "Arrivals": "4", "ArrivalsPerAddress": "2", "Window": "1", "Gaps": "{0, 1, 2}", "Drops": "{0, 1}"}, **changes})


def admission_mutant(what, invariant, old, new, constants=None):
    """The machine with one guard changed (in Admission.tla, which the Swift is held equal to): the system
    must fail on the property named, and that property alone is checked."""
    return (f"AdmissionSystem / mutant: {what}", "AdmissionSystem", constants or admission(), [invariant], [], invariant,
            ("Admission.tla", old, new))


RATED = "IN IF Len(recent) >= Arrivals \\/ From(recent, e[2]) >= ArrivalsPerAddress"
FULL = "ELSE IF Len(pool) > 0 /\\ Len(pool) >= limit THEN 1"
OWN = "THEN CHOOSE i \\in 1..Len(pool): pool[i] = a /\\ \\A j \\in 1..(i - 1): pool[j] # a"

ADMISSION_RUNS = [
    # The Swift machine is the specification's machine, at the two sets of limits it was walked at.
    ("AdmissionRefinement (the Swift code is Step: three places and two an address, two keys)", "AdmissionRefinement",
     {"Walk": '"Pools"'}, ["SpecIsImpl"], [], HOLDS, None),
    ("AdmissionRefinement (the Swift code is Step: three arrivals a window and two an address, a clock that moves)", "AdmissionRefinement",
     {"Walk": '"Rate"'}, ["SpecIsImpl"], [], HOLDS, None),
    ("AdmissionRefinement / mutant: the specification differs from the code (an address at its limit pushes out the oldest of all)",
     "AdmissionRefinement", {"Walk": '"Pools"'}, ["SpecIsImpl"], [], "ImplIsSpec", ("Admission.tla", OWN, "THEN 1")),
    ("AdmissionRefinement / mutant: the specification differs from the code (an arrival counts for a tick longer)",
     "AdmissionRefinement", {"Walk": '"Rate"'}, ["SpecIsImpl"], [], "ImplIsSpec",
     ("Admission.tla", "StillCounts(x) == x.age <= Window", "StillCounts(x) == x.age <= Window + 1")),

    # The listener, the machine, one honest paired Mac and everyone else.
    ("AdmissionSystem (the pools)", "AdmissionSystem", admission(), ADMISSION_INV, [], HOLDS, None),
    ("AdmissionSystem (the pools; nobody else at the watched Mac's address)", "AdmissionSystem", admission(Alone="TRUE"), ADMISSION_INV, [], HOLDS, None),
    ("AdmissionSystem (the rate)", "AdmissionSystem", admission_rate(), ADMISSION_INV + ["NotKeptOutByOthers"], [], HOLDS, None),
    ("AdmissionSystem (the rate; two other addresses, which can fill it between them)", "AdmissionSystem",
     admission_rate(Addresses='{"h", "x", "y"}'), ADMISSION_INV, [], HOLDS, None),
    # The strongest thing that is true of an honest Mac's place among those that have proved nothing: it is
    # lost only when as many were given places after it as the pool holds (or as an address may hold, from
    # its own address). So one that moves on before that is never pushed out; and at exactly that many, it is.
    ("AdmissionSystem (a Mac that moves on before a pool's worth of newcomers is never pushed out)", "AdmissionSystem",
     admission(Quick="TRUE"), ADMISSION_INV + ["TheWatchedMacIsNeverPushedOut"], [], HOLDS, None),
    ("AdmissionSystem / known limit: a pool's worth of newcomers pushes out a Mac that has not yet proved its key", "AdmissionSystem",
     admission(), ["TheWatchedMacIsNeverPushedOut"], [], "TheWatchedMacIsNeverPushedOut", None),
    # What is NOT true, each with the run that shows it. CLAUDE.md: "Not claimed: that a flood from many
    # addresses cannot stop a drop."
    ("AdmissionSystem / known limit: as many addresses as can fill the rate between them keep a Mac out (three, at 200 of the 500 a second)",
     "AdmissionSystem", admission_rate(Addresses='{"h", "x", "y"}'), ["NotKeptOutByOthers"], [], "NotKeptOutByOthers", None),
    ("AdmissionSystem / known limit: keys nobody paired, holding on, keep the next one out (there the newcomer is the one refused)",
     "AdmissionSystem", admission(), ["AKeyNobodyPairedIsNeverTurnedAway"], [], "AKeyNobodyPairedIsNeverTurnedAway", None),
    ("AdmissionSystem / known limit: on a clock that can be set back a Mac within the rate is turned away (the calendar, which the listener read)",
     "AdmissionSystem", admission_rate(SetBack="1"), ["ANewcomerWithinTheRateGetsAPlace"], [], "ANewcomerWithinTheRateGetsAPlace", None),
    # Found by this model, 2026-11-24: the pool of data connections has so many places for each drop in
    # progress, and when a drop ended nobody gave any up.
    ("AdmissionSystem / found: the pool of data connections is over its limit when a drop ends", "AdmissionSystem",
     admission(), ["UnattachedWithinItsLimit"], [], "UnattachedWithinItsLimit", None),
    # The good outcome is reachable: an invariant that says it never happens, which must be violated.
    ("AdmissionSystem / reachable: the watched Mac proves its key and says what it came for", "AdmissionSystem",
     admission(), ["TheWatchedMacNeverSaysWhatItCameFor"], [], "TheWatchedMacNeverSaysWhatItCameFor", None),
    ("AdmissionSystem / reachable: the watched Mac's data connection attaches to its drop", "AdmissionSystem",
     admission(), ["TheWatchedMacNeverAttaches"], [], "TheWatchedMacNeverAttaches", None),

    admission_mutant("a full pool turns the newcomer away (the listener before F1: 64 silent connections kept every paired Mac out)",
                     "ANewcomerWithinTheRateGetsAPlace", RATED, RATED + " \\/ GivesWay(s.strangers, e[2], Strangers, StrangersPerAddress) # 0"),
    admission_mutant("a pool has no size", "PoolsWithinLimits", FULL, "ELSE IF FALSE THEN 1"),
    admission_mutant("one address may hold every place", "PoolsWithinLimits", "IF Count(pool, a) > 0 /\\ Count(pool, a) >= perAddress", "IF FALSE"),
    admission_mutant("a full pool closes its newest, not its oldest", "TheOldestGivesWay", FULL, FULL[:-1] + "Len(pool)"),
    admission_mutant("an address at its limit loses its newest, not its oldest", "TheOldestGivesWay", OWN,
                     "THEN CHOOSE i \\in 1..Len(pool): pool[i] = a /\\ \\A j \\in (i + 1)..Len(pool): pool[j] # a"),
    admission_mutant("an address at its limit pushes out the oldest of all, not its own", "TheOldestGivesWay", OWN, "THEN 1"),
    admission_mutant("an address at its limit pushes out the oldest of all, who then loses its place to fewer newcomers than the pool holds",
                     "GivesWayOnlyAfterAPoolOfNewcomers", OWN, "THEN 1", admission(Strangers="4")),
    admission_mutant("a pool gives up a place one newcomer early", "GivesWayOnlyAfterAPoolOfNewcomers", FULL,
                     "ELSE IF Len(pool) > 0 /\\ Len(pool) + 1 >= limit THEN 1"),
    admission_mutant("a pool gives up a place one newcomer early, and a Mac that was quick enough is pushed out", "TheWatchedMacIsNeverPushedOut", FULL,
                     "ELSE IF Len(pool) > 0 /\\ Len(pool) + 1 >= limit THEN 1", admission(Quick="TRUE")),
    # (With one other address the two cannot arrive more often between them than the rate allows, and the
    # rate for all decides nothing: a run at those limits passed with it removed. So: two others.)
    admission_mutant("arrivals are not rationed", "TheRateHolds", RATED, "IN IF From(recent, e[2]) >= ArrivalsPerAddress",
                     admission_rate(Addresses='{"h", "x", "y"}')),
    admission_mutant("arrivals from one address are not rationed", "OverTheRateTheNewcomerIsClosed", RATED, "IN IF Len(recent) >= Arrivals",
                     admission_rate()),
    admission_mutant("one address's arrivals count against every address", "KeptOutByTheRateOnlyOnItsOwnAccount", RATED,
                     "IN IF Len(recent) >= ArrivalsPerAddress", admission_rate()),
    admission_mutant("one address's arrivals count against every address, and a Mac that has not arrived in the window is kept out", "NotKeptOutByOthers",
                     RATED, "IN IF Len(recent) >= ArrivalsPerAddress", admission_rate()),
    admission_mutant("an arrival counts for a tick longer", "ANewcomerWithinTheRateGetsAPlace", "StillCounts(x) == x.age <= Window",
                     "StillCounts(x) == x.age <= Window + 1", admission_rate()),
    admission_mutant("an arrival is forgotten a tick early", "TheRateHolds", "StillCounts(x) == x.age <= Window", "StillCounts(x) == x.age < Window",
                     admission_rate()),
    admission_mutant("a connection from elsewhere is given a place", "ElsewhereCountsForNothing", 'IF e[3] # "local" THEN Close(s, "elsewhere")',
                     'IF FALSE THEN Close(s, "elsewhere")'),
    admission_mutant("a data connection gets a place with no drop in progress", "NoDropNoPlace", 'IN IF e[3] = 0 THEN Close(t, "noDrop")',
                     'IN IF FALSE THEN Close(t, "noDrop")'),
    admission_mutant("a connection that proved a key keeps its place among the strangers (and could be the one that gives way)",
                     "EveryPlaceIsHeldByItsConnection",
                     'ELSE LET t == [s EXCEPT !.strangers = Remove(@, who[2])]\n             IN IF e[3] \\in {"mine", "retired"}',
                     'ELSE LET t == s\n             IN IF e[3] \\in {"mine", "retired"}'),
    admission_mutant("keys nobody paired are not counted", "PoolsWithinLimits", "IF s.unpaired < Unpaired THEN", "IF TRUE THEN"),
    admission_mutant("a paired key that has asked for nothing is not counted", "PoolsWithinLimits", "IF s.waiting[e[3]] < PairedWaiting THEN", "IF TRUE THEN"),
    admission_mutant("paired keys share one count", "AKeysPlacesAreItsOwn", "IF s.waiting[e[3]] < PairedWaiting THEN",
                     "IF Cardinality({k \\in Keys: s.waiting[k] > 0}) < PairedWaiting THEN"),
    admission_mutant("paired keys share one count, and the watched Mac is turned away for what another key has waiting", "APairedMacIsNotTurnedAwayForOthers",
                     "IF s.waiting[e[3]] < PairedWaiting THEN", "IF Cardinality({k \\in Keys: s.waiting[k] > 0}) < PairedWaiting THEN"),
    admission_mutant("where a key comes from decides whether it is counted (an address deciding more than who waits)", "AnAddressDecidesOnlyWhoWaits",
                     "IF s.unpaired < Unpaired THEN", "IF s.unpaired < Unpaired /\\ Count(t.strangers, s.strangers[who[2]]) = 0 THEN"),
    admission_mutant("a key nobody paired stops being counted when it asks to pair", "EveryPlaceIsHeldByItsConnection",
                     'IF who[1] = "waiting" THEN Noted([s EXCEPT !.waiting[who[2]] = @ - 1])\n        ELSE Noted(s)\n    ELSE \\* closed',
                     'IF who[1] = "waiting" THEN Noted([s EXCEPT !.waiting[who[2]] = @ - 1])\n        ELSE IF who[1] = "unpaired" THEN '
                     'Noted([s EXCEPT !.unpaired = @ - 1])\n        ELSE Noted(s)\n    ELSE \\* closed'),
    admission_mutant("a paired key is counted after it has said what it came for", "EveryPlaceIsHeldByItsConnection",
                     'ELSE IF e[1] = "purpose" THEN\n        IF who[1] = "waiting" THEN', 'ELSE IF e[1] = "purpose" THEN\n        IF FALSE THEN'),
    admission_mutant("a stranger that has gone still holds its place (a count that is never given back)", "EveryPlaceIsHeldByItsConnection",
                     'given back\n        IF who[1] = "stranger" THEN', 'given back\n        IF FALSE THEN'),
    admission_mutant("a key nobody paired is still counted when its connection has gone", "EveryPlaceIsHeldByItsConnection",
                     'ELSE IF who[1] = "unpaired" THEN Noted(', 'ELSE IF FALSE THEN Noted('),
    admission_mutant("an attached data connection goes on holding its place", "EveryPlaceIsHeldByItsConnection",
                     'ELSE IF e[1] = "attached" THEN\n        IF who[1] = "unattached" THEN', 'ELSE IF e[1] = "attached" THEN\n        IF FALSE THEN'),
    admission_mutant("a connection that gave way is told it has a place", "OneThatGaveWayGetsNothingMore",
                     'IF who[1] # "stranger" THEN Close(s, "gone")\n        ELSE LET t == [s EXCEPT !.strangers = Remove(@, who[2])]\n             IN IF e[3] = 0',
                     'IF who[1] # "stranger" THEN << s, << "moved", 0 >> >>\n        ELSE LET t == [s EXCEPT !.strangers = Remove(@, who[2])]\n'
                     '             IN IF e[3] = 0'),
    admission_mutant("a retired key is given a place", "ARetiredKeyGetsNothing", 'IN IF e[3] \\in {"mine", "retired"} THEN Close(t, e[3])',
                     'IN IF e[3] = "mine" THEN Close(t, e[3])\n                ELSE IF e[3] = "retired" THEN '
                     '<< [t EXCEPT !.unpaired = @ + 1], << "moved", 0 >> >>'),
]

TLA_RUNS += ADMISSION_RUNS
# ---- end of Admission ---------------------------------------------------------------------------------------



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
    ("NimbusPairing", "NimbusPairing.spthy", [], {}),
    ("NimbusPairing / mutant: the reveal is not checked against the commitment", "NimbusPairing.spthy", ["-D=NoCommitCheck"],
     {"a_stored_pairing_is_with_the_mac_the_person_meant": "falsified"}),
    ("NimbusPairing / mutant: neither the commitment nor the codes include the handshake hash", "NimbusPairing.spthy", ["-D=NoHashBinding"],
     {"a_stored_pairing_is_with_the_mac_the_person_meant": "falsified"}),
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
