// Copyright (C) 2026 Niels Joubert
// SPDX-License-Identifier: GPL-3.0-or-later
import AppKit
import Combine
import NimbusDropCore
import SwiftUI

/// What the app is doing, live: this Mac's place on the network, who it can see, every drop
/// with each of its connections, and under that every line of the debug log as it is written.
/// A diagnostic, in the manner of Nimbus Leviton Bar's Internals panel; nothing here changes
/// anything.
///
/// The lines come from `Diagnostics`, which has been filling since launch, so what led up to a
/// failure is already here when the panel is opened. The same lines are in the log file.
struct InternalsView: View {
    @ObservedObject var model: AppModel
    @State private var events: [Diagnostics.Event] = []
    @State private var shownVersion = -1
    @State private var status = ""
    @State private var filter: Diagnostics.Kind?
    @State private var paused = false
    /// The least important level shown.
    @State private var floor = LogLevel.debug
    @State private var search = ""
    private let tick = Timer.publish(every: 0.5, on: .main, in: .common).autoconnect()

    private static let clock: DateFormatter = {
        let f = DateFormatter()
        f.dateFormat = "HH:mm:ss.SSS"
        return f
    }()
    private static let day: DateFormatter = {
        let f = DateFormatter()
        f.dateFormat = "MMM d  HH:mm:ss.SSS"
        return f
    }()

    /// The time, with the date in front for a line from another day.
    private static func when(_ date: Date) -> String {
        Calendar.current.isDateInToday(date) ? clock.string(from: date) : day.string(from: date)
    }

    private var shown: [Diagnostics.Event] {
        events.filter { e in
            e.level >= floor && (filter == nil || e.kind == filter)
                && (search.isEmpty || e.text.localizedCaseInsensitiveContains(search) || (e.tag ?? "").localizedCaseInsensitiveContains(search))
        }
    }

    var body: some View {
        VSplitView {
            ScrollView {
                Text(status)
                    .font(.system(size: 11, design: .monospaced))
                    .textSelection(.enabled)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(10)
            }
            .frame(minHeight: 110, idealHeight: 200)

            VStack(spacing: 0) {
                HStack(spacing: 8) {
                    Picker("Show", selection: $filter) {
                        Text("All").tag(Diagnostics.Kind?.none)
                        Text("Drops").tag(Diagnostics.Kind?.some(.drop))
                        Text("Network").tag(Diagnostics.Kind?.some(.discovery))
                        Text("App").tag(Diagnostics.Kind?.some(.app))
                    }
                    .pickerStyle(.segmented).labelsHidden().fixedSize()
                    Picker("Level", selection: $floor) {
                        Text("Debug and up").tag(LogLevel.debug)
                        Text("Info and up").tag(LogLevel.info)
                        Text("Warnings and errors").tag(LogLevel.warn)
                        Text("Errors only").tag(LogLevel.error)
                    }
                    .labelsHidden().fixedSize()
                    .help("The log file always holds every level; this chooses what is listed here.")
                    TextField("Filter", text: $search).textFieldStyle(.roundedBorder).frame(maxWidth: 180)
                    Spacer()
                    Button(paused ? "Resume" : "Pause") { paused.toggle(); if !paused { reload(force: true) } }
                    Button("Copy") { copy() }.help("Copies what is listed, with the status above it: safe to paste into a bug report.")
                    Button("Clear") { Diagnostics.shared.clear(); reload(force: true) }
                        .help("Empties this list. The log file keeps everything.")
                    Button("Show Log File") { AppDelegate.shared?.showLog() }
                }
                .controlSize(.small)
                .padding(.horizontal, 10).padding(.vertical, 6)
                Divider()
                ScrollViewReader { proxy in
                    ScrollView {
                        LazyVStack(alignment: .leading, spacing: 0) {
                            ForEach(shown) { e in row(e).id(e.id) }
                        }
                        .padding(.vertical, 4)
                    }
                    .onChange(of: shown.last?.id) { _, last in
                        if let last, !paused { proxy.scrollTo(last, anchor: .bottom) }
                    }
                }
            }
            .frame(minHeight: 160, idealHeight: 340)
        }
        .frame(minWidth: 640, idealWidth: 820, minHeight: 380, idealHeight: 580)
        .onAppear { reload(force: true) }
        .onReceive(tick) { _ in
            status = model.internalsStatus()
            if !paused { reload(force: false) }
        }
    }

    /// A line is coloured by the level it was written with, and by nothing else.
    private func row(_ e: Diagnostics.Event) -> some View {
        HStack(alignment: .firstTextBaseline, spacing: 8) {
            Text(Self.when(e.at)).foregroundStyle(.secondary)
            Text(e.level.label).foregroundStyle(colour(e.level)).frame(width: 40, alignment: .leading)
            Text(e.kind.rawValue).foregroundStyle(.secondary).frame(width: 36, alignment: .leading)
            Text(e.tag ?? "").foregroundStyle(.secondary).frame(width: 84, alignment: .leading)
            Text(e.text).foregroundStyle(e.level == .info ? AnyShapeStyle(.primary) : AnyShapeStyle(colour(e.level)))
                .textSelection(.enabled).fixedSize(horizontal: false, vertical: true)
            Spacer(minLength: 0)
        }
        .font(.system(size: 11, design: .monospaced))
        .padding(.horizontal, 10).padding(.vertical, 1.5)
    }

    private func colour(_ level: LogLevel) -> Color {
        switch level {
        case .debug: return Color.secondary.opacity(0.75)
        case .info: return .secondary
        case .warn: return Palette.warning
        case .error: return Palette.failure
        }
    }

    private func reload(force: Bool) {
        let v = Diagnostics.shared.version
        guard force || v != shownVersion else { return }
        shownVersion = v
        events = Diagnostics.shared.all
    }

    private func copy() {
        let lines = shown.map { "\(Self.when($0.at)) \($0.level.label) \($0.kind.rawValue.padding(toLength: 4, withPad: " ", startingAt: 0)) \($0.tag.map { "[\($0)] " } ?? "")\($0.text)" }
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(model.internalsStatus() + "\n\n" + lines.joined(separator: "\n") + "\n", forType: .string)
    }
}

@MainActor
final class InternalsPanelController {
    private let panel: NSPanel

    init(model: AppModel) {
        panel = NSPanel(contentRect: NSRect(x: 0, y: 0, width: 820, height: 580),
                        styleMask: [.titled, .closable, .resizable, .utilityWindow], backing: .buffered, defer: false)
        panel.title = "Internals — Nimbus Drop"
        // Floating on purpose: the point is watching the lines arrive while a drop runs behind it.
        panel.isFloatingPanel = true
        panel.hidesOnDeactivate = false
        panel.isReleasedWhenClosed = false
        panel.contentViewController = NSHostingController(rootView: InternalsView(model: model))
        panel.setFrameAutosaveName("NimbusDropInternals")
        if panel.frame.origin == .zero { panel.center() }
    }

    func show() {
        NSApp.activate(ignoringOtherApps: true)
        panel.makeKeyAndOrderFront(nil)
    }

    /// The panel with a staged drop and its lines, as a PNG, for `--dump-internals`.
    static func dump(to path: String) -> Bool {
        _ = NSApplication.shared
        let d = Diagnostics.shared
        for (level, line): (LogLevel, String) in [
            (.info, "—— Nimbus Drop v0.2.1 (31) · protocol 2.2 started from /Applications/Nimbus Drop.app; macOS Version 27.0.1"),
            (.info, "receiving as macbookpro on port 47823; addresses 192.168.1.107 (en9)"),
            (.info, "discovery: found macbookairm4 at 192.168.1.143:47823 (Nimbus Drop 0.2.1, protocol 2.2)"),
            (.info, "sending /Volumes/Photos/Christmas 2026 to macbookairm4"),
            (.info, "[3972FA send] “Christmas 2026” to macbookairm4 at 192.168.1.143:47823: 1204 files, 31200000000 bytes, 8 connections"),
            (.info, "[3972FA send] waitingForAccept"),
            (.info, "[3972FA send] round 1: the receiver has 0 of 31200000000 bytes; 7440 chunks to send"),
            (.debug, "[3972FA send] opened 8 data connections to 192.168.1.143:47823"),
            (.info, "[3972FA send] transferring"),
            (.warn, "[3972FA send] a data connection failed after 31 chunks: Connection lost: Broken pipe"),
            (.warn, "[3972FA send] a data connection failed after 33 chunks: Connection lost: Broken pipe"),
            (.debug, "discovery: macbookairm4 is at 192.168.1.122:47823"),
            (.warn, "[3972FA send] lost the control connection: Connection lost: Broken pipe"),
            (.warn, "[3972FA send] reconnecting  (6236681569 of 31200000000 bytes, 240 of 1204 files; rounds 1, connections lost 8, damaged chunks 0, reconnects 0 in 0 attempts, chunks 1487 of which retransmitted 0)"),
            (.info, "[3972FA send] trying to reach macbookairm4 again for up to 60 s"),
            (.warn, "[3972FA send] reconnect attempt 1 to 192.168.1.143:47823: Cannot connect to 192.168.1.143: Operation timed out"),
            (.debug, "[3972FA send] macbookairm4 is now at 192.168.1.122:47823"),
            (.info, "[3972FA send] reconnected on attempt 2; the receiver answered plan"),
            (.info, "[3972FA send] round 2: the receiver has 6210991569 of 31200000000 bytes; 5959 chunks to send"),
            (.debug, "[3972FA send] opened 8 data connections to 192.168.1.122:47823"),
            (.info, "[3972FA send] transferring"),
        ] { d.record(level, line) }
        let model = AppModel(demoPeers: [Peer(id: "1", name: "macbookairm4", address: "192.168.1.122", port: 47823)], manual: [], rows: [])
        model.demoInternals = """
        This Mac     macbookpro · 192.168.1.107 (en9) · Nimbus Drop 0.2.1 · protocol 2.2
        Receiving    on, port 47823 · open at login: enabled
        Discovery    browsing · 1 destination
                     macbookairm4      192.168.1.122:47823   Nimbus Drop 0.2.1 · protocol 2.2

        Drops        1 moving
        3972FA send  “Christmas 2026” → macbookairm4 (192.168.1.122)   transferring for 1:12
                     9.84 GB of 31.2 GB (32 %) · 921 Mbps · 1,204 files, 310 done
                     round 2 · 2,351 chunks sent, 9 retransmitted · 8 connections dropped · reconnected once in 2 attempts
                     connections  #9  192.168.1.122:47823   108 chunks   453 MB   active now
                                  #10 192.168.1.122:47823   107 chunks   449 MB   active now
                                  #11 192.168.1.122:47823   108 chunks   453 MB   active now
                                  #12 192.168.1.122:47823   106 chunks   445 MB   idle 0.4 s
        """
        let host = NSHostingView(rootView: InternalsView(model: model).background(Color(nsColor: .windowBackgroundColor)))
        let window = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 900, height: 600), styleMask: [.titled], backing: .buffered, defer: false)
        window.appearance = NSAppearance(named: .darkAqua)
        window.contentView = host
        window.setContentSize(NSSize(width: 900, height: 600))
        host.layoutSubtreeIfNeeded()
        RunLoop.main.run(until: Date().addingTimeInterval(1.2))
        host.layoutSubtreeIfNeeded()
        guard let rep = host.bitmapImageRepForCachingDisplay(in: host.bounds) else { return false }
        host.cacheDisplay(in: host.bounds, to: rep)
        do { try rep.representation(using: .png, properties: [:])?.write(to: URL(fileURLWithPath: path)) } catch { return false }
        print("wrote \(path)")
        return true
    }
}
