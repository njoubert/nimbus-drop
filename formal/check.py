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
]

TLA_RUNS += ROUND_RUNS


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
