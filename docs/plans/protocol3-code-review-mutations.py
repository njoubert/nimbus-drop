"""Extra mutation checks for the Phase 5 review. Run from the worktree root.
Each guard is broken in turn and the five attack/drop test classes are run; a guard whose
removal nothing notices is a test gap."""
import subprocess, sys, re
R = "Sources/NimbusDropCore/Receiver.swift"
S = "Sources/NimbusDropCore/Sender.swift"
C = "Sources/NimbusDropCore/Crypto.swift"
P = "Sources/NimbusDropCore/Pairing.swift"
M = [
 ("a record's length need only fit the buffer, not match the manifest", R,
  "length == manifest.chunkLength(file: file, chunk: chunk) else { throw StreamFault.damaged }",
  "length <= manifest.chunkSize else { throw StreamFault.damaged }"),
 ("the end marker need not be exactly the end marker", R,
  "guard header.chunk == 0, header.length == 0 else { throw StreamFault.damaged }", ""),
 ("a finished drop's answer (its file names) goes to any paired key that names the session", R,
  """if let done = lock.withLock({ completed[resume.session] }), done.key == key,
               Crypto.same(resume.proof, DropKeys.resumeProof(done.resumeKey, "resume", h: channel.h)) {""",
  "if let done = lock.withLock({ completed[resume.session] }) {"),
 ("withdrawing trust leaves a finished drop's resume key behind", R,
  "completed = completed.filter { $0.value.key != key }", ""),
 ("the receiver takes an offer though the sender says it is not paired", R,
  "guard case .paired(let mac) = standing, hello.paired else { socket.shutdown(); return }",
  "guard case .paired(let mac) = standing else { socket.shutdown(); return }"),
 ("the sender offers though the receiver says it is not paired", S,
  "guard theirs.paired else {", "guard theirs.paired || true else {"),
 ("the sender shows its key to a responder that is not paired (no expected key)", S,
  'case .renew, .unknown: throw DropError.notPaired("This Mac is not paired with \\(name)")',
  "case .renew, .unknown: break"),
 ("data connections that have not attached are not counted", R,
  "guard unattached < Tuning.unattachedPerDrop * sessions.count else { return false }",
  "guard sessions.count > 0 else { return false }"),
 ("strangers are not counted", R,
  "guard arrivals.count < Tuning.arrivalsPerSecond, strangers < Tuning.strangers else { return false }",
  "guard arrivals.count < Tuning.arrivalsPerSecond else { return false }"),
 ("arrivals are not rationed", R,
  "guard arrivals.count < Tuning.arrivalsPerSecond, strangers < Tuning.strangers else { return false }",
  "guard strangers < Tuning.strangers else { return false }"),
 ("an all-zero key agreement is taken", C,
  "guard bytes.contains(where: { $0 != 0 }) else { throw DropError.notAuthentic }", ""),
 ("a key at or above the field prime is taken", C,
  "if b[31] == 0x7f, b[1..<31].allSatisfy({ $0 == 0xff }), b[0] >= 0xed { return nil }", ""),
 ("the codes never run out of time", P,
  "if Date() > deadline, !lock.withLock({ localRight && remoteRight }) {",
  "if false, Date() > deadline {"),
 ("a request is shown though requests are paused", R,
  "if quiet > 0 { return busy(", "if quiet > 1e9 { return busy("),
 ("a queued data connection beyond 64 per drop is taken", R,
  "guard active.count < Tuning.streamsPerDrop else {", "guard active.count < 1_000_000 else {"),
 ("a pairing request from a key that may not pair is shown", R,
  "guard standing.mayPair else {", "guard standing.mayPair || true else {"),
]
only = sys.argv[1:]
for name, path, old, new in M:
    if only and not any(o in name for o in only): continue
    src = open(path).read()
    if src.count(old) != 1:
        print("SKIP (pattern count %d): %s" % (src.count(old), name)); continue
    open(path, "w").write(src.replace(old, new))
    try:
        r = subprocess.run(["swift", "test", "--filter", "ProtocolTests|SecurityTests|PairingTests|TrustTests|DropTests"],
                           capture_output=True, text=True, timeout=900)
        out = r.stdout + r.stderr
        failed = sorted(set(re.findall(r"error: -\[NimbusDropCoreTests\.(\w+ \w+)\]", out)))
        if "Executed" not in out:
            print("NO BUILD :", name, [l for l in out.splitlines() if "error" in l][:2])
        elif failed:
            print("caught   :", name, "->", ", ".join(failed)[:300])
        else:
            print("MISSED   :", name)
    except subprocess.TimeoutExpired:
        print("TIMEOUT  :", name)
    finally:
        open(path, "w").write(src)
    sys.stdout.flush()
