// Copyright (C) 2026 Niels Joubert
// SPDX-License-Identifier: GPL-3.0-or-later
import Foundation
import NimbusDropChaos

// nimbus-chaos — the test proxy from the command line, to put between two real Macs.
//
//   nimbus-chaos --to HOST[:PORT] [--listen PORT] [--seed N] [SETTING…] [--at WHEN SETTING…]…
//
// Point the sender at this proxy instead of the receiver:
//   nimbus-chaos --to macbookairm4.local --listen 47900 rate=20M --at 5s rate=500K --at 400MB kill=data
//   NimbusDrop --send 127.0.0.1:47900 ~/Pictures/Christmas
//
// WHEN is seconds from the start ("5s") or bytes carried toward the receiver ("400MB").
// SETTING is one of:
//   rate=20M | rate=off     the link's capacity in bytes per second (K, M, G)
//   loss=0.02               chance a 1460-byte segment is lost (imitated as a timeout each)
//   corrupt=50M | corrupt=off   flip one bit about every that many bytes of the data connections
//   blackhole=on|off        carry nothing, close nothing
//   refuse=on|off           close new connections as they arrive
//   kill=all|data|control|one   close connections under the traffic, now

func fail(_ message: String) -> Never {
    fputs(message + "\n", stderr)
    exit(2)
}

func size(_ text: String) -> Int64? {
    var t = text.uppercased()
    if t.hasSuffix("B") { t.removeLast() }
    var scale: Int64 = 1
    if let last = t.last, let s = ["K": Int64(1000), "M": 1_000_000, "G": 1_000_000_000][String(last)] { scale = s; t.removeLast() }
    return Double(t).map { Int64($0 * Double(scale)) }
}

func apply(_ setting: String, to proxy: ChaosProxy) {
    let parts = setting.split(separator: "=", maxSplits: 1).map(String.init)
    guard parts.count == 2 else { fail("not a setting: \(setting)") }
    let (key, value) = (parts[0], parts[1])
    print("  \(setting)")
    switch key {
    case "rate": let v = value == "off" ? nil : size(value).map { Int($0) }; proxy.set { $0.bytesPerSecond = v }
    case "loss": guard let p = Double(value) else { fail("loss wants a number") }; proxy.set { $0.loss = p }
    case "corrupt": let v = value == "off" ? nil : size(value).map { Int($0) }; proxy.set { $0.corruptEvery = v }
    case "blackhole": proxy.set { $0.blackhole = value == "on" }
    case "refuse": proxy.set { $0.refuseNew = value == "on" }
    case "kill":
        switch value {
        case "all": proxy.kill(.all)
        case "data": proxy.kill(.data)
        case "control": proxy.kill(.control)
        case "one": proxy.killOneData()
        default: fail("kill wants all, data, control or one")
        }
    default: fail("unknown setting: \(key)")
    }
}

var args = Array(CommandLine.arguments.dropFirst())
var target: String?
var listenPort: UInt16 = 47900
var seed: UInt64 = 1
var now: [String] = []
var events: [(when: String, settings: [String])] = []
while !args.isEmpty {
    let a = args.removeFirst()
    switch a {
    case "--to": target = args.isEmpty ? nil : args.removeFirst()
    case "--listen": listenPort = UInt16(args.isEmpty ? "" : args.removeFirst()) ?? listenPort
    case "--seed": seed = UInt64(args.isEmpty ? "" : args.removeFirst()) ?? seed
    case "--at":
        guard !args.isEmpty else { fail("--at wants a time or a byte count") }
        events.append((args.removeFirst(), []))
    case "-h", "--help": fail("usage: nimbus-chaos --to HOST[:PORT] [--listen PORT] [--seed N] [SETTING…] [--at WHEN SETTING…]…")
    default:
        if events.isEmpty { now.append(a) } else { events[events.count - 1].settings.append(a) }
    }
}
guard let target else { fail("usage: nimbus-chaos --to HOST[:PORT] [--listen PORT] [SETTING…] [--at WHEN SETTING…]…") }
let hostPort = target.split(separator: ":").map(String.init)
let proxy: ChaosProxy
do {
    proxy = try ChaosProxy(targetHost: hostPort[0], targetPort: hostPort.count > 1 ? UInt16(hostPort[1]) ?? 47823 : 47823,
                           listenPort: listenPort, seed: seed)
} catch { fail("\(error)") }
setvbuf(stdout, nil, _IOLBF, 0)
print("nimbus-chaos: port \(proxy.port) → \(target)")
for s in now { apply(s, to: proxy) }
for e in events {
    let settings = e.settings
    let run: @Sendable (ChaosProxy) -> Void = { p in
        print("at \(e.when):")
        for s in settings { apply(s, to: p) }
    }
    if e.when.hasSuffix("s"), let seconds = Double(e.when.dropLast()) {
        proxy.after(seconds: seconds, run)
    } else if let bytes = size(e.when) {
        proxy.whenForwarded(bytes: bytes, run)
    } else { fail("--at wants seconds (5s) or bytes (400MB), not \(e.when)") }
}
proxy.start()

var last = proxy.stats
while true {
    Thread.sleep(forTimeInterval: 1)
    let s = proxy.stats
    if s.bytesToTarget != last.bytesToTarget || s.connections != last.connections || s.connectionsKilled != last.connectionsKilled {
        let mbps = Double(s.bytesToTarget - last.bytesToTarget) * 8 / 1e6
        print(String(format: "%7.1f Mbps  %d open  %.1f MB carried  %d bits flipped  %d segments lost  %d killed  %d refused",
                     mbps, proxy.openConnections, Double(s.bytesToTarget) / 1e6, s.bitsFlipped, s.segmentsLost, s.connectionsKilled, s.connectionsRefused))
    }
    last = s
}
