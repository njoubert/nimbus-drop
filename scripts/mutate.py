import subprocess,sys
M=[
 ("the commitment is not checked","Sources/NimbusDropCore/Pairing.swift","guard Crypto.same(PairCodes.commitment(h: c.h, ns: ns), commit) else {","guard true || Crypto.same(PairCodes.commitment(h: c.h, ns: ns), commit) else {","PairingTests/testAMacThatDoesNotKeepToThePairingIsDropped"),
 ("the codes ignore the handshake hash","Sources/NimbusDropCore/Pairing.swift",'let out = Crypto.kdf(ns + nr, Data("nimbus-drop pair codes v1".utf8) + h, 16)','let out = Crypto.kdf(ns + nr, Data("nimbus-drop pair codes v1".utf8), 16)',"PairingTests/testTheCodesComeFromWhatBothEndsSaw"),
 ("a typed code is not compared","Sources/NimbusDropCore/Pairing.swift","let right = Crypto.same(Data(digits.utf8), Data(expected.utf8))","let right = true || Crypto.same(Data(digits.utf8), Data(expected.utf8))","PairingTests/testSomeoneInTheMiddleWhoHearsBothCodesStillFails"),
 ("the other side's word is enough to pair","Sources/NimbusDropCore/Pairing.swift","let ready = localRight && remoteRight && !_state.isFinal","let ready = remoteRight && !_state.isFinal","PairingTests/testTheOtherSideSayingItMatchedPairsNobody"),
 ("the expected key is not checked","Sources/NimbusDropCore/Channel.swift","if let expect, expect != theirs { throw DropError.wrongKey(expectName) }","if let expect, expect != theirs, false { throw DropError.wrongKey(expectName) }","ProtocolTests/testAnImpostorAtThePairedMacsAddressLearnsNothing"),
 ("the attach tag is not checked","Sources/NimbusDropCore/Receiver.swift","guard let keys, !_isFinalOrCancelled, Crypto.same(tag, keys.attachTag(conn: conn, challenge: challenge)),","guard let keys, !_isFinalOrCancelled,","ProtocolTests/testNobodyButTheSenderCanAttachADataConnection"),
 ("a connection number may be used twice","Sources/NimbusDropCore/Receiver.swift","claimed.count < 1 << 20, claimed.insert(conn).inserted else { return false }","claimed.count < 1 << 20 else { return false }","ProtocolTests/testNobodyButTheSenderCanAttachADataConnection"),
 ("the attach ignores the challenge","Sources/NimbusDropCore/Channel.swift","Crypto.hmac(attachKey, sessionID + Crypto.be64(conn) + challenge).prefix(16)","Crypto.hmac(attachKey, sessionID + Crypto.be64(conn)).prefix(16)","ProtocolTests/testNobodyButTheSenderCanAttachADataConnection"),
 ("the resume proof is not checked","Sources/NimbusDropCore/Receiver.swift","""              Crypto.same(proof, DropKeys.resumeProof(keys.resumeKey, "resume", h: channel.h)),
""","","ProtocolTests/testOnlyTheSameDropsSenderCanResumeIt"),
 ("any paired key may resume any drop","Sources/NimbusDropCore/Receiver.swift","session.peerKey == key, session.resume(on: channel, proof: resume.proof)","session.resume(on: channel, proof: resume.proof)","ProtocolTests/testOnlyTheSameDropsSenderCanResumeIt"),
 ("the prologue leaves the openings out","Sources/NimbusDropCore/Channel.swift",'Data("nimbus-drop/\\(protocolVersion)".utf8) + initiator + responder','Data("nimbus-drop/\\(protocolVersion)".utf8)',"ProtocolTests/testAnOpeningAlteredOnTheWayBreaksTheHandshake"),
 ("an unpaired Mac may send an offer","Sources/NimbusDropCore/Receiver.swift","guard case .paired(let mac) = standing, hello.paired else { socket.shutdown(); return }","let mac = (try? trust.store(pairing: key, announced: name, method: \"x\", remaining: 9)) ?? { fatalError() }()","ProtocolTests/testAStrangerWhoClaimsToBePairedIsNotBelieved"),
 ("a retired key is let in","Sources/NimbusDropCore/Trust.swift","        } else if refuseForGood {","        } else if false {","ProtocolTests/testResetTellsThePairedMacsAndTheOldKeyIsRefusedFromThenOn"),
 ("withdrawing trust leaves sessions alone","Sources/NimbusDropCore/Trust.swift",'        endSessions(of: key, because: "\\(name) is no longer trusted (\\(reason))")\n','',"ProtocolTests/testRetiringAKeyEndsItsDropBeforeAnythingIsPutInPlace"),
 ("a held calendar stops time","Sources/NimbusDropCore/Trust.swift","let delta = boot == file.lastBoot ? c - file.lastContinuous : max(c, wall.timeIntervalSince(file.lastWall))","let delta = wall.timeIntervalSince(file.lastWall)","TrustTests/testACalendarHeldStillDoesNotKeepAKeyAlive"),
 ("unpaired connections are not counted","Sources/NimbusDropCore/Receiver.swift","guard unpaired < Tuning.unpaired else { return false }","guard unpaired < 100000 else { return false }","ProtocolTests/testCompletingAHandshakeWithAFreshKeyEarnsNothing"),
 ("a forgotten Mac goes on calling the other paired","Sources/NimbusDropCore/Sender.swift","            trust.notePairingGone(channel.remote)\n","","ProtocolTests/testAMacThatWasForgottenStopsCallingItPaired"),
 ("a non-canonical key is taken","Sources/NimbusDropCore/Crypto.swift","guard b[31] & 0x80 == 0 else { return nil }","","TrustTests/testAKeyHasOneEncoding"),
 ("a record's length need only fit the buffer",'Sources/NimbusDropCore/Receiver.swift','length == manifest.chunkLength(file: file, chunk: chunk) else { throw StreamFault.damaged }','length <= manifest.chunkSize else { throw StreamFault.damaged }','ReviewTests/testFuzzRecordsFromAPairedSenderThatMeansHarm'),
 ('the end marker need not be exactly the end marker','Sources/NimbusDropCore/Receiver.swift','guard header.chunk == 0, header.length == 0 else { throw StreamFault.damaged }','','ReviewTests/testTheEndOfADataConnectionIsExactlyTheEndMarker'),
 ("a finished drop's answer goes to any paired key that names it",'Sources/NimbusDropCore/Receiver.swift','if let done = lock.withLock({ completed[resume.session] }), done.key == key,\n               Crypto.same(resume.proof, DropKeys.resumeProof(done.resumeKey, "resume", h: channel.h)) {','if let done = lock.withLock({ completed[resume.session] }) {','ReviewTests/testAFinishedDropsAnswerIsOnlyForItsSenderAndGoesWhenTrustDoes'),
 ("withdrawing trust leaves a finished drop's resume key behind",'Sources/NimbusDropCore/Receiver.swift','completed = completed.filter { $0.value.key != key }','','ReviewTests/testAFinishedDropsAnswerIsOnlyForItsSenderAndGoesWhenTrustDoes'),
 ('the receiver takes an offer from a Mac that says it is not paired','Sources/NimbusDropCore/Receiver.swift','guard case .paired(let mac) = standing, hello.paired else { socket.shutdown(); return }','guard case .paired(let mac) = standing else { socket.shutdown(); return }','ReviewTests/testAnOfferFromAMacThatSaysItIsNotPairedIsNotShown'),
 ('the sender shows its key to a responder that is not paired','Sources/NimbusDropCore/Sender.swift','case .renew, .unknown: throw DropError.notPaired("This Mac is not paired with \\(name)")','case .renew, .unknown: break','ReviewTests/testASenderDoesNotShowItsKeyToAMacItIsNotPairedWith'),
 ('data connections that have not attached are not counted','Sources/NimbusDropCore/Receiver.swift','guard unattached < Tuning.unattachedPerDrop * sessions.count else { return false }','guard sessions.count > 0 else { return false }','ReviewTests/testDataConnectionsThatHaveProvedNothingAreCounted'),
 ('strangers are not counted','Sources/NimbusDropCore/Receiver.swift','guard arrivals.count < Tuning.arrivalsPerSecond, strangers < Tuning.strangers else { return false }','guard arrivals.count < Tuning.arrivalsPerSecond else { return false }','ReviewTests/testConnectionsThatHaveProvedNoKeyAreCounted'),
 ('arrivals are not rationed','Sources/NimbusDropCore/Receiver.swift','guard arrivals.count < Tuning.arrivalsPerSecond, strangers < Tuning.strangers else { return false }','guard strangers < Tuning.strangers else { return false }','ReviewTests/testArrivalsAreRationed'),
 ('a drop may have any number of data connections','Sources/NimbusDropCore/Receiver.swift','guard active.count < Tuning.streamsPerDrop else {','guard active.count < 1_000_000 else {','ReviewTests/testNoMoreDataConnectionsThanADropMayHave'),
 ('the codes never run out of time','Sources/NimbusDropCore/Pairing.swift','if Date() > deadline, !lock.withLock({ localRight && remoteRight }) {','if false, Date() > deadline {','ReviewTests/testTheCodesRunOutOfTime'),
 ('a request to pair from a key that may not pair is shown','Sources/NimbusDropCore/Receiver.swift','guard standing.mayPair else {','guard standing.mayPair || true else {','ReviewTests/testARequestToPairFromAKeyThatHasRunOutIsNotShown'),
 ('a key that runs out on the pair-again list is forgotten, not refused (F2)','Sources/NimbusDropCore/Trust.swift','if !file.tombstones.contains(where: { $0.key == r.key }) { file.tombstones.append(Tombstone(key: r.key, name: r.name, at: wall, reason: "expired")) }','','ReviewTests/testAKeyThatRunsOutOnThePairAgainListStaysRefused'),
 ('the calendar alone refuses a paired key for good (F3)','Sources/NimbusDropCore/Trust.swift','for k in file.known where elapsed >= k.endsElapsed && !file.tombstones.contains(where: { $0.key == k.key }) {','for k in file.known where !current(k.endsElapsed, k.endsWall) && !file.tombstones.contains(where: { $0.key == k.key }) {','TrustTests/testACalendarSetForwardEndsThePairingEarlyAndNotTheKey'),
 ("the calendar alone refuses every key when this Mac's own is replaced (F3)",'Sources/NimbusDropCore/Trust.swift','for k in file.known where !file.tombstones.contains(where: { $0.key == k.key }) && file.elapsed >= k.endsElapsed {','for k in file.known where !file.tombstones.contains(where: { $0.key == k.key }) && !current(k.endsElapsed, k.endsWall) {','ReviewTests/testACalendarSetForwardOnceCostsARenewalAndNoMore'),
 ("a request is shown beside this Mac's own pairing (F5)",'Sources/NimbusDropCore/Receiver.swift','        if trust.gate.active != nil { return busy("\\(identity.name) is in the middle of another pairing", log: "this Mac is in the middle of a pairing of its own") }\n','','ReviewTests/testNoRequestIsShownWhileThisMacIsItselfPairing'),
 ('an offer outlives the pairing it was made under (F6)','Sources/NimbusDropCore/Trust.swift','.filter { $0.state == .waitingForAccept }','.filter { _ in false }','ReviewTests/testAnOfferStillWaitingWhenItsKeyEndsIsWithdrawn'),
 ('a yes is not checked against the pairing (F6)','Sources/NimbusDropCore/Receiver.swift','guard listener.trust.standing(of: control.remote).isPaired else {','guard true else {','ReviewTests/testAYesToAnOfferWhoseKeyHasSinceEndedStartsNothing'),
 ('withdrawing trust waits to say goodbye (F7)','Sources/NimbusDropCore/Sender.swift','        quiet.connection = true\n','','ReviewTests/testAPairedMacCannotLockTheTrustStoreByRetiringItselfMidDrop'),
 ('sessions are ended with the trust store locked (F7)','Sources/NimbusDropCore/Trust.swift','            lock.unlock()\n            for r in run { r() }\n','            for r in run { r() }\n            lock.unlock()\n','ReviewTests/testEndingASessionDoesNotHoldTheTrustStore'),
 ('a handshake message may carry a payload','Sources/NimbusDropCore/Channel.swift','        // A handshake message carries the handshake and nothing else: a payload ends it.\n        guard try noise.read(try read(socket, limit: 1024)).isEmpty else { throw DropError.damagedMessage }','        _ = try noise.read(try read(socket, limit: 1024))','ReviewTests/testAHandshakeMessageWithAPayloadEndsTheConnection'),
 ('a file may have more chunks than can be numbered','Sources/NimbusDropCore/Manifest.swift','guard e.size / Int64(chunkSize) < Int64(UInt32.max) else {','guard true else {','SecurityTests/testHostileNumbersAreRefusedNotCrashedOn'),
 ('the receiver does not hold a stream key to its bytes','Sources/NimbusDropCore/Receiver.swift','            guard carried <= DropKeys.streamBytes else { throw StreamFault.damaged }\n','','ReviewTests/testAStreamKeyIsHeldToItsBytesByTheReceiverToo'),
 ('a pairing this Mac began goes on after trust in the key is withdrawn','Sources/NimbusDropCore/Receiver.swift','        if let mine = trust.gate.active, mine.peerKey == key, !pairings.contains(where: { $0 === mine }) { pairings.append(mine) }\n','','ReviewTests/testWithdrawingTrustStopsAPairingThisMacBeganWithThatKey'),
 ('a refused identity is named as it calls itself','Sources/NimbusDropCore/Receiver.swift','                if case .expired(let mac) = standing { known = mac.name }\n','','ReviewTests/testARequestToPairFromAKeyThatHasRunOutIsNotShown'),
 ("a reconnect proves this Mac's new key, not the one the drop began with",'Sources/NimbusDropCore/Sender.swift','keys: lock.withLock { mine } ?? trust.keyPair, expect: peer','keys: trust.keyPair, expect: peer','ChaosTests/testADropFinishesOnTheKeyItStartedWith'),
 ('a withdrawal that could not be written is not tried again','Sources/NimbusDropCore/Trust.swift','|| (unsavedChange && file.elapsed - lastTry >= 30) { save() }','{ save() }','TrustTests/testAWithdrawalThatCouldNotBeWrittenIsTriedAgainUntilItHolds'),
 # Not here: removing the all-zero check in KeyPair.agree. CryptoKit refuses that agreement
 # before the check is reached, so no test can tell (the review of 2026-11-23).
]
only=sys.argv[1:] 
bad=0
for name,path,old,new,test in M:
    if only and not any(o in name for o in only): continue
    src=open(path).read()
    if src.count(old)!=1: print("SKIP (pattern count %d): %s"%(src.count(old),name)); bad+=1; continue
    open(path,'w').write(src.replace(old,new))
    try:
        r=subprocess.run(["swift","test","--filter",test],capture_output=True,text=True,timeout=400)
        out=r.stdout+r.stderr
        if "error:" in out and ("Executed 1 test, with" in out) and "with 0 failures" not in out.split("Executed 1 test,")[1][:40]:
            print("caught   :",name)
        elif "error:" in out and "Executed" not in out:
            print("NO BUILD :",name, [l for l in out.splitlines() if 'error' in l][:2]); bad+=1
        else:
            print("MISSED   :",name,"->",test); bad+=1
    finally:
        open(path,'w').write(src)
print("problems:",bad)
