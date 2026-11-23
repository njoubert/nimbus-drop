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
 ("a non-canonical key is taken","Sources/NimbusDropCore/Crypto.swift","guard b[31] & 0x80 == 0 else { return nil }","","TrustTests/testAKeyHasOneEncoding"),
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
