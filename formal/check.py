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
def gate(**changes):
    c = {"Waits": "TRUE", "PatienceRunsOut": "FALSE", "StartsBesideARequest": "FALSE"}
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
    ("PairingGate", "PairingGate", gate(), GATE_INV, ["EveryRequestIsAnswered", "NeverShownBesideAPairingUnderWay"], HOLDS, None),
    ("PairingGate / reachable: a pairing goes ahead at both ends", "PairingGate", gate(), ["NeverGoesAhead"], [], "NeverGoesAhead", None),
    ("PairingGate (a person starts a pairing with a request on screen): the gate still holds one", "PairingGate", gate(StartsBesideARequest="TRUE"),
     ["TypeOK", "OnePairingAtATime"], ["EveryRequestIsAnswered", "NeverShownBesideAPairingUnderWay"], HOLDS, None),
    ("PairingGate / reachable: a person starts a pairing with a request on screen", "PairingGate", gate(StartsBesideARequest="TRUE"),
     ["NeverStartsWithARequestOnScreen"], [], "NeverStartsWithARequestOnScreen", None),
    ("PairingGate / known limit: a yes to a request, given in the instant this Mac's own pairing with that Mac is being turned away", "PairingGate",
     gate(StartsBesideARequest="TRUE"), ["NotBothTurnedAway"], [], "NotBothTurnedAway", None),
    ("PairingGate / mutant: a request does not wait for this Mac's own pairing (the code before cac7dd2)", "PairingGate",
     gate(Waits="FALSE"), GATE_INV, [], "NotBothTurnedAway", None),
    ("PairingGate / known limit: the two-second wait runs out first", "PairingGate",
     gate(PatienceRunsOut="TRUE"), ["NotBothTurnedAway"], [], "NotBothTurnedAway", None),
    ("PairingGate / mutant: the higher key does not give way", "PairingGate", gate(), GATE_INV, [],
     "NotBothTurnedAway",
     ("PairingGate.tla", "IF samePairing /\\ Lower(y)", "IF samePairing")),
    ("PairingGate / mutant: a request is shown beside this Mac's own pairing (F5)", "PairingGate", gate(),
     [], ["NeverShownBesideAPairingUnderWay"], "NeverShownBesideAPairingUnderWay",
     ("PairingGate.tla", "          ELSE IF Active(y)\n", "          ELSE IF FALSE\n")),
    ("PairingGate / mutant: a yes takes the gate without asking whether it is free", "PairingGate", gate(StartsBesideARequest="TRUE"),
     ["OnePairingAtATime"], [], "OnePairingAtATime",
     ("PairingGate.tla", "          /\\ IF Mine(y)\n", "          /\\ IF FALSE\n")),

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
                 "GivesWayOnlyAfterAPoolOfNewcomers", "KeptOutByTheRateOnlyOnItsOwnAccount", "APairedMacIsNotTurnedAwayForOthers",
                 "UnattachedWithinItsLimit", "WhenADropEndsItsPlacesEndWithIt", "AKeyNobodyPairedGetsAPlaceWhileAnyoneCanGiveWay",
                 "TheOldestKeyThatHasAskedForNothingGivesWay", "OneThatHasAskedKeepsItsPlace"]


def admission(**changes):
    """The pools: three places for strangers and two an address; a place for a data connection for each drop
    in progress, of which there are none, one or two; one connection from a key nobody paired and one from
    each of two paired keys; an address that is not on the local network. No rate to speak of. Anyone may
    arrive from the watched Mac's own address. The watched Mac is paired."""
    c = {"Addresses": '{"h", "x", "far"}', "Outside": '{"far"}', "Honest": '"h"', "Keys": '{"kh", "kx"}', "HonestKey": '"kh"',
         "Strangers": "3", "StrangersPerAddress": "2", "Arrivals": "1", "ArrivalsPerAddress": "1", "Window": "0", "Gaps": "{1}",
         "UnattachedPerDrop": "1", "UnattachedPerAddress": "1", "Unpaired": "1", "UnpairedPerAddress": "1", "PairedWaiting": "1",
         "Drops": "{0, 1, 2}", "Alone": "FALSE", "Quick": "FALSE", "SetBack": "0", "Paired": "TRUE", "OthersAsk": "TRUE"}
    c.update(changes)
    return c


def admission_rate(**changes):
    """The rate: four arrivals in a window of one tick and two from one address; a clock that moves by
    nothing, one tick or two between arrivals; one other address. One place of each kind."""
    return admission(**{**{"Addresses": '{"h", "x"}', "Outside": "{}", "Keys": '{"kh"}', "Strangers": "1", "StrangersPerAddress": "1",
                           "Arrivals": "4", "ArrivalsPerAddress": "2", "Window": "1", "Gaps": "{0, 1, 2}", "Drops": "{0, 1}"}, **changes})


def admission_keys(**changes):
    """The keys nobody paired: three places and two an address, any of them having asked or not; two places
    for strangers on the way in; one other address, and anyone may arrive from the watched Mac's own. The
    watched Mac is one nobody has paired: it proves its key and asks to pair. No drops, no rate to speak of."""
    return admission(**{**{"Addresses": '{"h", "x"}', "Outside": "{}", "Keys": '{"kh"}', "Strangers": "2", "StrangersPerAddress": "2",
                           "Unpaired": "3", "UnpairedPerAddress": "2", "Drops": "{0}", "Paired": "FALSE"}, **changes})


def admission_mutant(what, invariant, old, new, constants=None):
    """The machine with one guard changed (in Admission.tla, which the Swift is held equal to): the system
    must fail on the property named, and that property alone is checked."""
    return (f"AdmissionSystem / mutant: {what}", "AdmissionSystem", constants or admission(), [invariant], [], invariant,
            ("Admission.tla", old, new))


RATED = "IN IF Len(recent) >= Arrivals \\/ From(recent, e[2]) >= ArrivalsPerAddress"
FULL = "ELSE IF Len(pool) > 0 /\\ Len(pool) >= limit THEN 1"
OWN = "THEN CHOOSE i \\in 1..Len(pool): pool[i] = a /\\ \\A j \\in 1..(i - 1): pool[j] # a"
ANYKEY = "THEN IF Silent(pool) # {} THEN Oldest(Silent(pool)) ELSE -1"
OWNKEY = "THEN IF Held(pool, a) \\cap Silent(pool) # {} THEN Oldest(Held(pool, a) \\cap Silent(pool)) ELSE -1"
STILL = "StillCounts(x) == x.age >= 0 /\\ x.age <= Window"

ADMISSION_RUNS = [
    # The Swift machine is the specification's machine, at the two sets of limits it was walked at.
    ("AdmissionRefinement (the Swift code is Step: three places for strangers and two an address, data connections for up to two drops)",
     "AdmissionRefinement", {"Walk": '"Pools"'}, ["SpecIsImpl"], [], HOLDS, None),
    ("AdmissionRefinement (the Swift code is Step: three arrivals a window and two an address, a clock that moves forward and back)",
     "AdmissionRefinement", {"Walk": '"Rate"'}, ["SpecIsImpl"], [], HOLDS, None),
    ("AdmissionRefinement (the Swift code is Step: three places for keys nobody paired and two an address, some having asked)",
     "AdmissionRefinement", {"Walk": '"Keys"'}, ["SpecIsImpl"], [], HOLDS, None),
    ("AdmissionRefinement (the Swift code is Step: two paired keys, each counted by itself)",
     "AdmissionRefinement", {"Walk": '"Waiting"'}, ["SpecIsImpl"], [], HOLDS, None),
    ("AdmissionRefinement / mutant: the specification differs from the code (a request that has been read gives way to a stranger's key)",
     "AdmissionRefinement", {"Walk": '"Keys"'}, ["SpecIsImpl"], [], "ImplIsSpec",
     ("Admission.tla", ANYKEY, "THEN 1")),
    ("AdmissionRefinement / mutant: the specification differs from the code (paired keys share one count)",
     "AdmissionRefinement", {"Walk": '"Waiting"'}, ["SpecIsImpl"], [], "ImplIsSpec",
     ("Admission.tla", "IF s.waiting[e[3]] < PairedWaiting THEN", "IF Cardinality({k \\in Keys: s.waiting[k] > 0}) < PairedWaiting THEN")),
    ("AdmissionRefinement / mutant: the specification differs from the code (an address at its limit pushes out the oldest of all)",
     "AdmissionRefinement", {"Walk": '"Pools"'}, ["SpecIsImpl"], [], "ImplIsSpec", ("Admission.tla", OWN, "THEN 1")),
    ("AdmissionRefinement / mutant: the specification differs from the code (an arrival counts for a tick longer)",
     "AdmissionRefinement", {"Walk": '"Rate"'}, ["SpecIsImpl"], [], "ImplIsSpec",
     ("Admission.tla", STILL, STILL + " + 1")),

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
    # A key nobody paired is a key anyone can make. Until 2026-11-24 a full pool of them turned the newcomer
    # away, and this block had that as a known limit ("keys nobody paired, holding on, keep the next one out");
    # an independent review called it what it was, F1 in the pool F1's fix had not reached. Now the oldest
    # that has asked for nothing gives way, and an address has its share. What is left of the limit, and
    # still fails as it must: connections whose requests to pair have been READ keep their places (one may be
    # in front of a person for minutes), and when they hold every place a newcomer could take, it is turned
    # away. How many of those can last is the pairing queue's to say (one on screen, four behind), not this
    # machine's.
    ("AdmissionSystem (keys nobody paired; the watched Mac is one of them, and asks to pair)", "AdmissionSystem",
     admission_keys(), ADMISSION_INV, [], HOLDS, None),
    ("AdmissionSystem (keys nobody paired that say nothing, however many, never keep a Mac from asking to pair)", "AdmissionSystem",
     admission_keys(OthersAsk="FALSE"), ADMISSION_INV + ["TheWatchedMacIsNotTurnedAway"], [], HOLDS, None),
    ("AdmissionSystem (a Mac nobody paired that asks before a pool's worth of newer keys is never pushed out)", "AdmissionSystem",
     admission_keys(Quick="TRUE"), ADMISSION_INV + ["TheWatchedMacIsNeverPushedOut"], [], HOLDS, None),
    ("AdmissionSystem / known limit: a pool's worth of newer keys pushes out one that has not yet asked", "AdmissionSystem",
     admission_keys(), ["TheWatchedMacIsNeverPushedOut"], [], "TheWatchedMacIsNeverPushedOut", None),
    ("AdmissionSystem / known limit: requests to pair that have been read hold their places, and with every place so held the next key is turned away",
     "AdmissionSystem", admission_keys(), ["AKeyNobodyPairedIsNeverTurnedAway"], [], "AKeyNobodyPairedIsNeverTurnedAway", None),
    ("AdmissionSystem / reachable: a Mac nobody has paired proves its key and asks to pair", "AdmissionSystem",
     admission_keys(), ["TheWatchedMacNeverAsksToPair"], [], "TheWatchedMacNeverAsksToPair", None),
    # Found on the way, 2026-11-24: the listener timed arrivals by the calendar. On a clock that can be set
    # back, a Mac within the rate is turned away, for as long as the clock was set back by; held still, for
    # good. No rule inside the machine prevents that, so this run fails now as it did then: what was put
    # right is the clock the listener reads, which cannot be set (ReviewTests, mutate.py). What the machine
    # itself promises of any clock is the run after it.
    ("AdmissionSystem / known limit: on a clock that can be set back a Mac within the rate is turned away (the calendar, which the listener read)",
     "AdmissionSystem", admission_rate(SetBack="1"), ["ANewcomerWithinTheRateGetsAPlace"], [], "ANewcomerWithinTheRateGetsAPlace", None),
    ("AdmissionSystem (the rate, on a clock that is set back: nothing is counted from later than now, and nothing is lost count of)",
     "AdmissionSystem", admission_rate(SetBack="2", Arrivals="2", ArrivalsPerAddress="1"),
     ["TypeOK", "PoolsWithinLimits", "EveryPlaceIsHeldByItsConnection", "NothingIsCountedFromLaterThanNow", "AnAddressDecidesOnlyWhoWaits"], [], HOLDS, None),
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
    admission_mutant("an arrival counts for a tick longer", "ANewcomerWithinTheRateGetsAPlace", STILL, STILL + " + 1",
                     admission_rate()),
    admission_mutant("an arrival is forgotten a tick early", "TheRateHolds", STILL, STILL.replace("<=", "<"), admission_rate()),
    admission_mutant("an arrival from later than now goes on counting (set back an hour, the clock kept everyone out for the hour)",
                     "NothingIsCountedFromLaterThanNow", STILL, "StillCounts(x) == x.age <= Window", admission_rate(SetBack="2")),
    # Found by this model, 2026-11-24, and the first of these is the listener as it was: the pool of data
    # connections has so many places for each drop in progress, and when a drop ended nobody gave any up.
    admission_mutant("when a drop ends the places it gave are kept (the listener until 2026-11-24)", "UnattachedWithinItsLimit",
                     "IN IF over > 0 THEN << [s EXCEPT !.unattached", "IN IF FALSE THEN << [s EXCEPT !.unattached"),
    admission_mutant("when a drop ends every data connection gives way, whatever is still in progress", "WhenADropEndsItsPlacesEndWithIt",
                     "LET over == Len(s.unattached) - UnattachedPerDrop * e[2]", "LET over == Len(s.unattached)"),
    admission_mutant("when a drop ends the newest give way, not the ones that have waited longest", "EveryPlaceIsHeldByItsConnection",
                     "!.unattached = SubSeq(@, over + 1, Len(@))]", "!.unattached = SubSeq(@, 1, Len(@) - over)]"),
    admission_mutant("when a drop ends, a Mac whose own drop goes on is pushed out with fewer after it than the pool still holds",
                     "GivesWayOnlyAfterAPoolOfNewcomers", "LET over == Len(s.unattached) - UnattachedPerDrop * e[2]",
                     "LET over == Len(s.unattached) - UnattachedPerDrop * e[2] + 1", admission(UnattachedPerDrop="2")),
    admission_mutant("a connection from elsewhere is given a place", "ElsewhereCountsForNothing", 'IF e[3] # "local" THEN Close(s, "elsewhere")',
                     'IF FALSE THEN Close(s, "elsewhere")'),
    admission_mutant("a data connection gets a place with no drop in progress", "NoDropNoPlace", 'IN IF e[3] = 0 THEN Close(t, "noDrop")',
                     'IN IF FALSE THEN Close(t, "noDrop")'),
    admission_mutant("a connection that proved a key keeps its place among the strangers (and could be the one that gives way)",
                     "EveryPlaceIsHeldByItsConnection",
                     'ELSE LET t == [s EXCEPT !.strangers = Remove(@, who[2])]\n             IN IF e[3] \\in {"mine", "retired"}',
                     'ELSE LET t == s\n             IN IF e[3] \\in {"mine", "retired"}'),
    admission_mutant("keys nobody paired that say nothing keep the next one out (the listener until 2026-11-24)",
                     "AKeyNobodyPairedGetsAPlaceWhileAnyoneCanGiveWay", ANYKEY, "THEN -1", admission_keys()),
    admission_mutant("keys nobody paired that say nothing keep a Mac from asking to pair (the listener until 2026-11-24)",
                     "TheWatchedMacIsNotTurnedAway", ANYKEY, "THEN -1", admission_keys(OthersAsk="FALSE")),
    admission_mutant("keys nobody paired are not counted", "PoolsWithinLimits", "ELSE IF Len(pool) > 0 /\\ Len(pool) >= limit\n", "ELSE IF FALSE\n",
                     admission_keys()),
    admission_mutant("one address may hold every place among the keys nobody paired", "PoolsWithinLimits",
                     "IF Held(pool, a) # {} /\\ Cardinality(Held(pool, a)) >= perAddress", "IF FALSE", admission_keys()),
    admission_mutant("a request to pair that has been read gives way to a stranger's key", "OneThatHasAskedKeepsItsPlace", ANYKEY, "THEN 1",
                     admission_keys()),
    admission_mutant("at its share an address pushes out the oldest key of all that has asked for nothing, not its own",
                     "TheOldestKeyThatHasAskedForNothingGivesWay", OWNKEY, ANYKEY, admission_keys()),
    admission_mutant("among the keys nobody paired the newest that has asked for nothing gives way, not the oldest",
                     "TheOldestKeyThatHasAskedForNothingGivesWay", "Oldest(S)     == CHOOSE i \\in S: \\A j \\in S: i <= j",
                     "Oldest(S)     == CHOOSE i \\in S: \\A j \\in S: i >= j", admission_keys()),
    admission_mutant("the pool of keys nobody paired gives up a place one newcomer early, and a Mac that was quick enough is pushed out",
                     "TheWatchedMacIsNeverPushedOut", "ELSE IF Len(pool) > 0 /\\ Len(pool) >= limit\n", "ELSE IF Len(pool) > 0 /\\ Len(pool) + 1 >= limit\n",
                     admission_keys(Quick="TRUE")),
    admission_mutant("that a key nobody paired has asked is not noted (it can still be told to give way)", "EveryPlaceIsHeldByItsConnection",
                     "!.unpaired[who[2]].asked = TRUE", "!.unpaired[who[2]].asked = FALSE", admission_keys()),
    admission_mutant("a paired key that has asked for nothing is not counted", "PoolsWithinLimits", "IF s.waiting[e[3]] < PairedWaiting THEN", "IF TRUE THEN"),
    admission_mutant("paired keys share one count", "AKeysPlacesAreItsOwn", "IF s.waiting[e[3]] < PairedWaiting THEN",
                     "IF Cardinality({k \\in Keys: s.waiting[k] > 0}) < PairedWaiting THEN"),
    admission_mutant("paired keys share one count, and the watched Mac is turned away for what another key has waiting", "APairedMacIsNotTurnedAwayForOthers",
                     "IF s.waiting[e[3]] < PairedWaiting THEN", "IF Cardinality({k \\in Keys: s.waiting[k] > 0}) < PairedWaiting THEN"),
    admission_mutant("where a paired key comes from decides whether it is counted (an address deciding more than who waits)",
                     "AnAddressDecidesOnlyWhoWaits", "IF s.waiting[e[3]] < PairedWaiting THEN",
                     "IF s.waiting[e[3]] < PairedWaiting /\\ Count(t.strangers, s.strangers[who[2]]) = 0 THEN"),
    admission_mutant("a key nobody paired stops being counted when it asks to pair", "EveryPlaceIsHeldByItsConnection",
                     'Noted([s EXCEPT !.unpaired[who[2]].asked = TRUE])', 'Noted([s EXCEPT !.unpaired = Remove(@, who[2])])'),
    admission_mutant("a paired key is counted after it has said what it came for", "EveryPlaceIsHeldByItsConnection",
                     'ELSE IF e[1] = "purpose" THEN\n        IF who[1] = "waiting" THEN', 'ELSE IF e[1] = "purpose" THEN\n        IF FALSE THEN'),
    admission_mutant("a stranger that has gone still holds its place (a count that is never given back)", "EveryPlaceIsHeldByItsConnection",
                     'given back\n        IF who[1] = "stranger" THEN', 'given back\n        IF FALSE THEN'),
    admission_mutant("a key nobody paired is still counted when its connection has gone", "EveryPlaceIsHeldByItsConnection",
                     'ELSE IF who[1] = "unpaired" THEN Noted([s EXCEPT !.unpaired = Remove(@, who[2])])', 'ELSE IF FALSE THEN Noted(s)'),
    admission_mutant("an attached data connection goes on holding its place", "EveryPlaceIsHeldByItsConnection",
                     'ELSE IF e[1] = "attached" THEN\n        IF who[1] = "unattached" THEN', 'ELSE IF e[1] = "attached" THEN\n        IF FALSE THEN'),
    admission_mutant("a connection that gave way is told it has a place", "OneThatGaveWayGetsNothingMore",
                     'IF who[1] # "stranger" THEN Close(s, "gone")\n        ELSE LET t == [s EXCEPT !.strangers = Remove(@, who[2])]\n             IN IF e[3] = 0',
                     'IF who[1] # "stranger" THEN << s, << "moved", 0 >> >>\n        ELSE LET t == [s EXCEPT !.strangers = Remove(@, who[2])]\n'
                     '             IN IF e[3] = 0'),
    admission_mutant("a retired key is given a place", "ARetiredKeyGetsNothing", 'IN IF e[3] \\in {"mine", "retired"} THEN Close(t, e[3])',
                     'IN IF e[3] = "mine" THEN Close(t, e[3])\n                ELSE IF e[3] = "retired" THEN '
                     '<< [t EXCEPT !.unpaired = Append(@, [from |-> s.strangers[who[2]], asked |-> FALSE])], << "moved", 0 >> >>'),
]

TLA_RUNS += ADMISSION_RUNS
# ---- end of Admission ---------------------------------------------------------------------------------------



# ---- A drop's conversation ---------------------------------------------------------------------
# RoundMachine.tla is Sources/NimbusCrypto/RoundMachine.swift (RoundRefinement holds the two
# equal). Rounds.tla is each of its two machines against an other end that keeps to nothing;
# Drop.tla is the two of them and a network that misbehaves. Every guard of the machines has a
# mutant here: the specification with that guard taken out, and the property that must notice.

ROUNDS_SENDER = ["TypeOK", "EndsOnce", "AWithdrawalSaysNothing", "NothingIsSaidAfterAnEnd", "OfferedOnce", "ManifestOnlyToAYes",
                 "ChunksOnlyForAPlan", "CompleteOnlyAsAnAnswer", "DeclinedOnlyAsTheAnswerToTheOffer", "FruitlessReconnectsEndIt",
                 "OnlyReconnectsCount", "ReconnectOnlyUnderWay", "UnderWayALossIsGotBack", "OnlyAReconnectIsGivenUp",
                 "SUnderWaySilenceIsNotTheEnd", "AnAttemptThatGotNowhereChangesNothing", "STheirWordEndsIt", "TheLinksFaultIsNotSaid",
                 "NothingIsSaidBeforeTheOffer"]
ROUNDS_RECEIVER = ["TypeOK", "EndsOnce", "AWithdrawalSaysNothing", "NothingBeforeTheYes", "NobodyToAskMeansNo", "AskedOnce",
                   "OnlyWhatWasOffered", "NothingArrivesBeforeTheFolder", "PlacedOnlyWhenWhole", "OneJudgementARound",
                   "CompleteOnlyWhenInPlace", "IdleRoundsEndIt", "OnlyIdleRoundsCount", "HeldOnlyUnderWay", "UnderWayALossIsHeld",
                   "BackOnlyToAHeldDrop", "NobodyGivesUpWhoWasNotWaiting", "DeclinedOnlyOnceSaid", "DeclinedMeansNo",
                   "TheQuestionGoesWhenTheDropDoes", "TheSendersGivingUpIsNotAnswered", "RUnderWaySilenceIsNotTheEnd",
                   "RTheirWordEndsIt", "AFinishedDropSaysOnlyCompleteAgain"]

DROP_INV = ["TypeOK", "NoWrongBytes", "PlacedIsWhole", "SentMeansSaved", "NoStreamKeyTwice", "NothingBeforeTheYes", "OnlyWhatWasOffered",
            "DeclinedWroteNothing", "NothingWrittenOnceJudged"]
DROP_PROPS = ["NothingWrittenAfterPlacing", "ItEnds", "ItArrives"]


def drop(**changes):
    """Drop.tla's constants: as the code is, the person says yes, the sender is honest, nobody gives up, and the
    conversation is cut only once the drop is under way and fewer times than the sender has patience."""
    c = {"Chunks": "{c1, c2}", "MaxFaults": "3", "MaxCuts": "2", "MaxConns": "11", "Patience": "3", "IdleRounds": "5", "Says": '{"yes"}',
         "Lies": "FALSE", "ChecksTag": "TRUE", "KeepsCounter": "TRUE", "KeepsOutLate": "TRUE", "CutsEarly": "FALSE", "MayGiveUp": "FALSE"}
    c.update(changes)
    return c


def rounds(end, mutant=None, fails=HOLDS, old=None, new=None):
    """One end of the conversation against anything; with `mutant`, RoundMachine.tla with `old` made `new`."""
    title = f"Rounds (the {'sending' if end == 'sender' else 'receiving'} end)" + (f" / mutant: {mutant}" if mutant else "")
    return (title, "Rounds", {"End": f'"{end}"', "Patience": "3" if end == "sender" else "5"},
            ROUNDS_SENDER if end == "sender" else ROUNDS_RECEIVER, ["FinalIsFinal"] if fails == HOLDS else [], fails,
            ("RoundMachine.tla", old, new) if mutant else None)


ROUND_RUNS = [
    # The Swift machines are the specification's machines.
    ("RoundRefinement (the Swift code is the two Steps)", "RoundRefinement", {}, ["SpecIsImpl"], [], HOLDS, None),
    ("RoundRefinement / mutant: the specification's sender differs from the code", "RoundRefinement", {}, ["SpecIsImpl"], [], "ImplIsSpec",
     ("RoundMachine.tla", "IF s.phase = \"reconnecting\" THEN SFail(s, \"couldNotGetBack\")", "IF s.phase = \"reconnecting\" THEN SFail(s, \"lost\")")),
    ("RoundRefinement / mutant: the specification's receiver differs from the code", "RoundRefinement", {}, ["SpecIsImpl"], [], "ImplIsSpec",
     ("RoundMachine.tla", "ELSE IF s.phase \\in {\"settling\", \"awaitSender\", \"placing\"} THEN Nothing(s)",
      "ELSE IF s.phase \\in {\"awaitSender\", \"placing\"} THEN Nothing(s)")),
    ("RoundRefinement / mutant: the specification begins where the code does not", "RoundRefinement", {}, ["SpecIsImpl"], [], "SameBeginnings",
     ("RoundMachine.tla", "ReceiverStart(patience) == [phase |-> \"idle\", idle |-> 0, patience |-> patience]",
      "ReceiverStart(patience) == [phase |-> \"deciding\", idle |-> 0, patience |-> patience]")),

    ("RoundRefinement / mutant: the specification lets data into a drop that is being put in place", "RoundRefinement", {}, ["SpecIsImpl"], [],
     "QueryIsQuery",
     ("RoundMachine.tla", "TakesData(s) == s.phase \\in {\"planning\", \"reading\", \"settling\", \"awaitSender\"}",
      "TakesData(s) == s.phase \\in {\"planning\", \"reading\", \"settling\", \"awaitSender\", \"placing\"}")),

    # The sending end, against a receiver and a network that keep to nothing.
    rounds("sender"),
    rounds("sender", "an end is not the end", "EndsOnce",
           "    IF Final(s) THEN << s, << >> >>\n    ELSE IF e = \"cancelled\" THEN << [s EXCEPT !.phase = \"cancelled\"], SWord(s)",
           "    IF e = \"cancelled\" THEN << [s EXCEPT !.phase = \"cancelled\"], SWord(s)"),
    rounds("sender", "withdrawing trust says a farewell (F7)", "AWithdrawalSaysNothing",
           "ELSE IF e = \"withdrawn\" THEN << [s EXCEPT !.phase = \"failed\"], << \"fail withdrawn\" >> >>",
           "ELSE IF e = \"withdrawn\" THEN SFail(s, \"withdrawn\")"),
    rounds("sender", "the offer goes again", "OfferedOnce",
           "IF s.phase = \"idle\" THEN << [s EXCEPT !.phase = \"awaitAnswer\"], << \"send offer\" >> >>",
           "IF s.phase \\in {\"idle\", \"awaitVerdict\"} THEN << [s EXCEPT !.phase = \"awaitAnswer\"], << \"send offer\" >> >>"),
    rounds("sender", "the manifest goes before the other person has answered", "ManifestOnlyToAYes",
           "ELSE IF s.phase = \"awaitAnswer\" /\\ e = \"accept\" THEN", "ELSE IF s.phase \\in {\"idle\", \"awaitAnswer\"} /\\ e = \"accept\" THEN"),
    rounds("sender", "a plan is taken before the manifest it answers", "ChunksOnlyForAPlan",
           "ELSE IF s.phase \\in {\"awaitPlan\", \"awaitVerdict\"} /\\ IsPlan(e) THEN STake(s, e, FALSE)",
           "ELSE IF s.phase \\in {\"awaitAnswer\", \"awaitPlan\", \"awaitVerdict\"} /\\ IsPlan(e) THEN STake(s, e, FALSE)"),
    rounds("sender", "'complete' is believed before anything was sent", "CompleteOnlyAsAnAnswer",
           "ELSE IF s.phase = \"awaitVerdict\" /\\ e = \"complete\" THEN", "ELSE IF s.phase \\in {\"awaitPlan\", \"awaitVerdict\"} /\\ e = \"complete\" THEN"),
    rounds("sender", "'complete' is believed in the middle of a round", "CompleteOnlyAsAnAnswer",
           "ELSE IF s.phase = \"awaitVerdict\" /\\ e = \"complete\" THEN", "ELSE IF s.phase \\in {\"sending\", \"awaitVerdict\"} /\\ e = \"complete\" THEN"),
    rounds("sender", "'done' is said of a round that never was", "CompleteOnlyAsAnAnswer",
           "IF s.phase = \"sending\" THEN << [s EXCEPT !.phase = \"awaitVerdict\"], << \"send done\" >> >>",
           "IF s.phase \\in {\"awaitPlan\", \"sending\"} THEN << [s EXCEPT !.phase = \"awaitVerdict\"], << \"send done\" >> >>"),
    rounds("sender", "a decline is taken after the drop began", "DeclinedOnlyAsTheAnswerToTheOffer",
           "ELSE IF s.phase = \"awaitAnswer\" /\\ e = \"decline\" THEN", "ELSE IF s.phase \\in {\"awaitAnswer\", \"awaitVerdict\"} /\\ e = \"decline\" THEN"),
    rounds("sender", "reconnects that find nothing new go on for ever", "FruitlessReconnectsEndIt",
           "IN IF f < s.patience", "IN IF TRUE"),
    rounds("sender", "a round that ends short counts as a fruitless reconnect", "OnlyReconnectsCount",
           "ELSE IF back THEN s.fruitless + 1 ELSE s.fruitless", "ELSE s.fruitless + 1"),
    rounds("sender", "a conversation lost before the drop is under way is reconnected", "ReconnectOnlyUnderWay",
           "IF s.phase \\in {\"sending\", \"awaitVerdict\"} THEN << [s EXCEPT !.phase = \"reconnecting\"], << \"reconnect\" >> >>",
           "IF s.phase \\in {\"awaitPlan\", \"sending\", \"awaitVerdict\"} THEN << [s EXCEPT !.phase = \"reconnecting\"], << \"reconnect\" >> >>"),
    rounds("sender", "a conversation lost in the middle of a round ends the drop", "UnderWayALossIsGotBack",
           "IF s.phase \\in {\"sending\", \"awaitVerdict\"} THEN << [s EXCEPT !.phase = \"reconnecting\"], << \"reconnect\" >> >>",
           "IF s.phase = \"awaitVerdict\" THEN << [s EXCEPT !.phase = \"reconnecting\"], << \"reconnect\" >> >>"),
    rounds("sender", "time running out ends a drop that is not waiting", "OnlyAReconnectIsGivenUp",
           "        IF s.phase = \"reconnecting\" THEN SFail(s, \"couldNotGetBack\")\n        ELSE << s, << >> >>", "        SFail(s, \"couldNotGetBack\")"),
    rounds("sender", "silence under way ends the drop", "SUnderWaySilenceIsNotTheEnd",
           "IF s.phase \\in {\"sending\", \"awaitVerdict\"} THEN << s, << \"hangUp\" >> >>", "IF FALSE THEN << s, << \"hangUp\" >> >>"),
    rounds("sender", "what is not an answer to a reconnect ends the drop", "AnAttemptThatGotNowhereChangesNothing",
           "        ELSE IF s.phase = \"reconnecting\" THEN << s, << >> >>\n        ELSE SFail(s, \"unexpected\")", "        ELSE SFail(s, \"unexpected\")"),
    rounds("sender", "the receiver's reason for stopping is not the end", "STheirWordEndsIt",
           "        IF e = \"error\" THEN SFail(s, \"theirs\")\n        ELSE IF s.phase = \"awaitAnswer\" /\\ e = \"accept\"",
           "        IF s.phase = \"awaitAnswer\" /\\ e = \"accept\""),
    rounds("sender", "a plan that cannot be read is taken", "ChunksOnlyForAPlan",
           "    IF e = \"planMalformed\" THEN SFail(s, \"malformed\")\n    ELSE LET f ==", "    LET f =="),
    rounds("sender", "the link's fault is said on the link", "TheLinksFaultIsNotSaid",
           "ELSE << [s EXCEPT !.phase = \"failed\"], << \"fail lost\" >> >>", "ELSE SFail(s, \"lost\")"),
    rounds("sender", "an error that is nobody's message is said", "TheLinksFaultIsNotSaid",
           "ELSE IF e = \"stoppedSilently\" THEN << [s EXCEPT !.phase = \"failed\"], << \"fail here\" >> >>",
           "ELSE IF e = \"stoppedSilently\" THEN SFail(s, \"here\")"),
    rounds("sender", "a word is said before there is anybody to say it to", "NothingIsSaidBeforeTheOffer",
           "SWord(s) == IF s.phase = \"idle\" THEN << >> ELSE << \"send error\" >>", "SWord(s) == << \"send error\" >>"),

    # The receiving end, against a sender, a person and a network that keep to nothing.
    rounds("receiver"),
    rounds("receiver", "an end is not the end", "EndsOnce", "    ELSE IF Final(s) THEN Nothing(s)\n", ""),
    rounds("receiver", "withdrawing trust says a farewell", "AWithdrawalSaysNothing",
           "<< \"fail withdrawn\" >> \\o Unask(s) >>", "<< \"send error\", \"fail withdrawn\" >> \\o Unask(s) >>"),
    rounds("receiver", "a yes to a question that was never asked is taken", "NothingBeforeTheYes",
           "IF s.phase = \"deciding\" THEN << [s EXCEPT !.phase = \"awaitManifest\"], << \"send accept\" >> >> ELSE Nothing(s)",
           "IF s.phase \\in {\"idle\", \"deciding\"} THEN << [s EXCEPT !.phase = \"awaitManifest\"], << \"send accept\" >> >> ELSE Nothing(s)"),
    rounds("receiver", "a yes after the pairing ended is taken (F6)", "NothingBeforeTheYes",
           "THEN << [s EXCEPT !.phase = \"failed\"], << \"send decline pairingRanOut\", \"send error\", \"fail pairingRanOut\" >> >>",
           "THEN << [s EXCEPT !.phase = \"awaitManifest\"], << \"send accept\" >> >>"),
    rounds("receiver", "a manifest is taken while the person is still deciding", "NothingBeforeTheYes",
           "        IF s.phase = \"deciding\" THEN\n", "        IF s.phase = \"deciding\" /\\ e = \"manifest\" THEN << [s EXCEPT !.phase = \"preparing\"], << \"prepare\" >> >>\n        ELSE IF s.phase = \"deciding\" THEN\n"),
    rounds("receiver", "nobody to ask, and the question is shown", "NobodyToAskMeansNo",
           "IF s.phase = \"idle\" THEN << [s EXCEPT !.phase = \"declining\"], << \"send decline notReceiving\" >> >> ELSE Nothing(s)",
           "IF s.phase = \"idle\" THEN << [s EXCEPT !.phase = \"deciding\"], << \"ask\" >> >> ELSE Nothing(s)"),
    rounds("receiver", "the question is asked again", "AskedOnce",
           "IF s.phase = \"idle\" THEN << [s EXCEPT !.phase = \"deciding\"], << \"ask\" >> >> ELSE Nothing(s)",
           "IF s.phase \\in {\"idle\", \"awaitManifest\"} THEN << [s EXCEPT !.phase = \"deciding\"], << \"ask\" >> >> ELSE Nothing(s)"),
    rounds("receiver", "a manifest that is not what was offered is taken", "OnlyWhatWasOffered",
           "ELSE IF s.phase = \"awaitManifest\" /\\ e = \"manifest\" THEN", "ELSE IF s.phase = \"awaitManifest\" /\\ e \\in {\"manifest\", \"manifestOther\"} THEN"),
    rounds("receiver", "a manifest that did not pass validate is taken", "OnlyWhatWasOffered",
           "ELSE IF s.phase = \"awaitManifest\" /\\ e = \"manifest\" THEN", "ELSE IF s.phase = \"awaitManifest\" /\\ e \\in {\"manifest\", \"manifestInvalid\"} THEN"),
    rounds("receiver", "a manifest that cannot be read is taken", "OnlyWhatWasOffered",
           "ELSE IF s.phase = \"awaitManifest\" /\\ e = \"manifest\" THEN", "ELSE IF s.phase = \"awaitManifest\" /\\ e \\in {\"manifest\", \"manifestMalformed\"} THEN"),
    rounds("receiver", "'prepared' is believed of a folder nobody asked for", "NothingArrivesBeforeTheFolder",
           "IF s.phase = \"preparing\" THEN << [s EXCEPT !.phase = \"planning\"], << \"send plan\" >> >> ELSE Nothing(s)",
           "IF s.phase \\in {\"awaitManifest\", \"preparing\"} THEN << [s EXCEPT !.phase = \"planning\"], << \"send plan\" >> >> ELSE Nothing(s)"),
    rounds("receiver", "the rounds begin on a plan that was never to be said", "HeldOnlyUnderWay",
           "ELSE IF s.phase = \"planning\" THEN << [s EXCEPT !.phase = \"reading\"], << >> >>",
           "ELSE IF s.phase \\in {\"awaitManifest\", \"planning\"} THEN << [s EXCEPT !.phase = \"reading\"], << >> >>"),
    rounds("receiver", "'done' is taken before the rounds began", "NothingArrivesBeforeTheFolder",
           "ELSE IF s.phase = \"reading\" /\\ e = \"done\" THEN", "ELSE IF s.phase \\in {\"awaitManifest\", \"reading\"} /\\ e = \"done\" THEN"),
    rounds("receiver", "a second 'done' while the first is being judged", "OneJudgementARound",
           "ELSE IF s.phase = \"reading\" /\\ e = \"done\" THEN", "ELSE IF s.phase \\in {\"reading\", \"settling\"} /\\ e = \"done\" THEN"),
    rounds("receiver", "the drop is put in place when it is not whole", "PlacedOnlyWhenWhole",
           "ELSE IF e = \"whole\" THEN << [s EXCEPT !.phase = \"placing\"], << \"place\" >> >>",
           "ELSE IF e \\in {\"whole\", \"more\"} THEN << [s EXCEPT !.phase = \"placing\"], << \"place\" >> >>"),
    rounds("receiver", "a judgement nobody asked for is believed", "PlacedOnlyWhenWhole",
           "IF s.phase # \"settling\" THEN Nothing(s)", "IF s.phase \\notin {\"reading\", \"settling\"} THEN Nothing(s)"),
    rounds("receiver", "'complete' is said before the drop is in place", "CompleteOnlyWhenInPlace",
           "IF s.phase = \"placing\" THEN << [s EXCEPT !.phase = \"completed\"], << \"send complete\", \"end completed\" >> >>",
           "IF s.phase \\in {\"settling\", \"placing\"} THEN << [s EXCEPT !.phase = \"completed\"], << \"send complete\", \"end completed\" >> >>"),
    rounds("receiver", "a drop that failed tells a sender that comes back it is complete", "NothingBeforeTheYes",
           "IF s.phase = \"completed\" /\\ e = \"senderBack\" THEN << s, << \"send complete\" >> >>",
           "IF Final(s) /\\ e = \"senderBack\" THEN << s, << \"send complete\" >> >>"),
    rounds("receiver", "rounds that bring nothing go on for ever", "IdleRoundsEndIt",
           "ELSE IF s.idle + 1 < s.patience THEN", "ELSE IF TRUE THEN"),
    rounds("receiver", "a round that brought something still counts as idle", "OnlyIdleRoundsCount",
           "ELSE IF e = \"more\" THEN << [s EXCEPT !.idle = 0, !.phase = \"reading\"], << \"send plan\" >> >>",
           "ELSE IF e = \"more\" THEN << [s EXCEPT !.phase = \"reading\"], << \"send plan\" >> >>"),
    rounds("receiver", "a drop whose first plan never went out is held for the sender", "HeldOnlyUnderWay",
           "ELSE IF s.phase = \"reading\" THEN << [s EXCEPT !.phase = \"awaitSender\"], << \"hold\" >> >>",
           "ELSE IF s.phase \\in {\"planning\", \"reading\"} THEN << [s EXCEPT !.phase = \"awaitSender\"], << \"hold\" >> >>"),
    rounds("receiver", "a conversation lost in the middle of a round ends the drop", "UnderWayALossIsHeld",
           "ELSE IF s.phase = \"reading\" THEN << [s EXCEPT !.phase = \"awaitSender\"], << \"hold\" >> >>",
           "ELSE IF FALSE THEN << [s EXCEPT !.phase = \"awaitSender\"], << \"hold\" >> >>"),
    rounds("receiver", "a sender is answered as back by a drop that is not held for it", "BackOnlyToAHeldDrop",
           "IF s.phase = \"awaitSender\" THEN << [s EXCEPT !.phase = \"reading\"], << \"send plan\" >> >> ELSE Nothing(s)",
           "IF s.phase \\in {\"reading\", \"awaitSender\"} THEN << [s EXCEPT !.phase = \"reading\"], << \"send plan\" >> >> ELSE Nothing(s)"),
    rounds("receiver", "a sender that is there is given up on", "NobodyGivesUpWhoWasNotWaiting",
           "IF s.phase = \"awaitSender\" THEN RFail(s, \"didNotComeBack\") ELSE Nothing(s)",
           "IF s.phase \\in {\"reading\", \"awaitSender\"} THEN RFail(s, \"didNotComeBack\") ELSE Nothing(s)"),
    rounds("receiver", "a decline is the end before it is said", "DeclinedOnlyOnceSaid",
           "IF s.phase = \"deciding\" THEN << [s EXCEPT !.phase = \"declining\"], << \"send decline declined\" >> >> ELSE Nothing(s)",
           "IF s.phase = \"deciding\" THEN << [s EXCEPT !.phase = \"declined\"], << \"send decline declined\", \"end declined\" >> >> ELSE Nothing(s)"),
    rounds("receiver", "a no is taken after the yes", "DeclinedMeansNo",
           "IF s.phase = \"deciding\" THEN << [s EXCEPT !.phase = \"declining\"], << \"send decline declined\" >> >> ELSE Nothing(s)",
           "IF s.phase \\in {\"deciding\", \"reading\"} THEN << [s EXCEPT !.phase = \"declining\"], << \"send decline declined\" >> >> ELSE Nothing(s)"),
    rounds("receiver", "the question stays on screen when the drop ends", "TheQuestionGoesWhenTheDropDoes",
           "Unask(s) == IF s.phase = \"deciding\" THEN << \"unask\" >> ELSE << >>", "Unask(s) == << >>"),
    rounds("receiver", "a question that is not up is taken away", "TheQuestionGoesWhenTheDropDoes",
           "Unask(s) == IF s.phase = \"deciding\" THEN << \"unask\" >> ELSE << >>", "Unask(s) == << \"unask\" >>"),
    rounds("receiver", "a sender that gives up while the person decides is answered", "TheSendersGivingUpIsNotAnswered",
           "            ELSE << [s EXCEPT !.phase = \"failed\"], << \"fail wentAway\", \"unask\" >> >>\n",
           "            ELSE << [s EXCEPT !.phase = \"failed\"], << \"send error\", \"fail wentAway\", \"unask\" >> >>\n"),
    rounds("receiver", "silence under way ends the drop", "RUnderWaySilenceIsNotTheEnd",
           "IF s.phase \\in {\"reading\", \"settling\", \"awaitSender\"} THEN << s, << \"hangUp\" >> >>", "IF FALSE THEN << s, << \"hangUp\" >> >>"),
    rounds("receiver", "the sender's reason for stopping is not the end", "RTheirWordEndsIt",
           "ELSE IF s.phase = \"reading\" /\\ e = \"error\" THEN RFail(s, \"theirs\")", "ELSE IF s.phase = \"reading\" /\\ e = \"error\" THEN Nothing(s)"),
    rounds("receiver", "a 'done' that cannot be read is taken", "RTheirWordEndsIt",
           "ELSE IF s.phase = \"reading\" /\\ e = \"done\" THEN", "ELSE IF s.phase = \"reading\" /\\ e \\in {\"done\", \"doneMalformed\"} THEN"),
    rounds("receiver", "a finished drop answers anything at all", "AFinishedDropSaysOnlyCompleteAgain",
           "IF s.phase = \"completed\" /\\ e = \"senderBack\" THEN << s, << \"send complete\" >> >>",
           "IF s.phase = \"completed\" /\\ e \\in {\"senderBack\", \"lost\"} THEN << s, << \"send complete\" >> >>"),

    # A drop: the two machines, the person, and a network that misbehaves.
    ("Drop", "Drop", drop(), DROP_INV, DROP_PROPS, HOLDS, None),
    ("Drop (three chunks, two faults)", "Drop", drop(Chunks="{c1, c2, c3}", MaxFaults="2", MaxConns="8"), DROP_INV, DROP_PROPS, HOLDS, None),
    ("Drop (cut at any time; either end may give up; the person may say no; the sender may lie)", "Drop",
     drop(CutsEarly="TRUE", MayGiveUp="TRUE", Says='{"yes", "no"}', Lies="TRUE", MaxFaults="2", MaxConns="8"), DROP_INV,
     ["NothingWrittenAfterPlacing", "ItEnds"], HOLDS, None),
    ("Drop / reachable: it arrives", "Drop", drop(MaxFaults="1", MaxCuts="1", MaxConns="4"), ["NeverArrives"], [], "NeverArrives", None),
    ("Drop / reachable: a no is a no", "Drop", drop(Says='{"no"}', MaxFaults="1", MaxCuts="1", MaxConns="4"), ["NeverDeclined"], [], "NeverDeclined", None),
    ("Drop / known limit: cut before the sender has heard what the receiver holds, the drop ends", "Drop",
     drop(CutsEarly="TRUE", MaxFaults="1", MaxCuts="1", MaxConns="4"), [], ["ItArrives"], "ItArrives", None),
    ("Drop / known limit: as many fruitless reconnects as the sender has patience", "Drop",
     drop(Patience="1", MaxFaults="1", MaxCuts="1", MaxConns="4"), [], ["ItArrives"], "ItArrives", None),
    ("Drop / known limit: as many idle rounds as the receiver has patience", "Drop",
     drop(IdleRounds="1", MaxFaults="1", MaxCuts="0", MaxConns="4"), [], ["ItArrives"], "ItArrives", None),
    ("Drop / mutant: a record is written without being opened", "Drop", drop(ChecksTag="FALSE"), DROP_INV, [], "NoWrongBytes", None),
    ("Drop / mutant: the connection counter starts again on a reconnect", "Drop", drop(KeepsCounter="FALSE"), DROP_INV, [], "NoStreamKeyTwice", None),
    ("Drop / mutant: a data connection is let into a drop that has been judged (the code before 2026-11-24)", "Drop", drop(KeepsOutLate="FALSE"),
     DROP_INV, [], "NothingWrittenOnceJudged", None),
    ("Drop / mutant: the ledger is said to be whole when it is not", "Drop", drop(), DROP_INV, [], "PlacedIsWhole",
     ("Drop.tla", "RDo(IF have = Chunks THEN \"whole\"", "RDo(IF have # {} THEN \"whole\"")),
    ("Drop / mutant: the machine puts in place a drop that was not judged whole", "Drop", drop(), DROP_INV, [], "PlacedIsWhole",
     ("RoundMachine.tla", "ELSE IF e = \"whole\" THEN << [s EXCEPT !.phase = \"placing\"], << \"place\" >> >>",
      "ELSE IF e \\in {\"whole\", \"more\"} THEN << [s EXCEPT !.phase = \"placing\"], << \"place\" >> >>")),
    ("Drop / mutant: 'complete' is said before the drop is in place", "Drop", drop(), DROP_INV, [], "SentMeansSaved",
     ("RoundMachine.tla", "ELSE IF e = \"whole\" THEN << [s EXCEPT !.phase = \"placing\"], << \"place\" >> >>",
      "ELSE IF e = \"whole\" THEN << [s EXCEPT !.phase = \"placing\"], << \"send complete\", \"place\" >> >>")),
    ("Drop / mutant: the receiver accepts without waiting for the person", "Drop", drop(), DROP_INV, [], "NothingBeforeTheYes",
     ("RoundMachine.tla", "IF s.phase = \"idle\" THEN << [s EXCEPT !.phase = \"deciding\"], << \"ask\" >> >> ELSE Nothing(s)",
      "IF s.phase = \"idle\" THEN << [s EXCEPT !.phase = \"awaitManifest\"], << \"ask\", \"send accept\" >> >> ELSE Nothing(s)")),
    ("Drop / mutant: a manifest that is not what was offered is taken", "Drop", drop(Lies="TRUE"), DROP_INV, [], "OnlyWhatWasOffered",
     ("RoundMachine.tla", "ELSE IF s.phase = \"awaitManifest\" /\\ e = \"manifest\" THEN",
      "ELSE IF s.phase = \"awaitManifest\" /\\ e \\in {\"manifest\", \"manifestOther\"} THEN")),
    ("Drop / mutant: the sender does not come back after losing the conversation", "Drop", drop(), [], ["ItArrives"], "deadlock",
     ("Drop.tla", "            \\/ Reconnect \\/ Refused \\/ Abandoned", "            \\/ Refused \\/ Abandoned")),
    ("Drop / mutant: the sending machine gives up a drop whose conversation is lost in the middle of a round", "Drop", drop(), [], ["ItArrives"], "ItArrives",
     ("RoundMachine.tla", "IF s.phase \\in {\"sending\", \"awaitVerdict\"} THEN << [s EXCEPT !.phase = \"reconnecting\"], << \"reconnect\" >> >>",
      "IF s.phase = \"awaitVerdict\" THEN << [s EXCEPT !.phase = \"reconnecting\"], << \"reconnect\" >> >>")),
    ("Drop / mutant: the receiving machine does not hold a drop whose conversation is lost", "Drop", drop(), [], ["ItArrives"], "ItArrives",
     ("RoundMachine.tla", "ELSE IF s.phase = \"reading\" THEN << [s EXCEPT !.phase = \"awaitSender\"], << \"hold\" >> >>",
      "ELSE IF FALSE THEN << [s EXCEPT !.phase = \"awaitSender\"], << \"hold\" >> >>")),
    ("Drop / mutant: a finished drop does not say 'complete' again to a sender that comes back", "Drop", drop(), [], ["ItArrives"], "deadlock",
     ("RoundMachine.tla", "IF s.phase = \"completed\" /\\ e = \"senderBack\" THEN << s, << \"send complete\" >> >>",
      "IF s.phase = \"completed\" /\\ e = \"senderBack\" THEN << s, << >> >>")),
]

TLA_RUNS += ROUND_RUNS


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
