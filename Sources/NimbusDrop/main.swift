// Copyright (C) 2026 Niels Joubert
// SPDX-License-Identifier: GPL-3.0-or-later
import AppKit
import NimbusDropCore
import NimbusUpdater

// Nimbus Drop — send files and folders to another Mac on the local network. See README.md.
//
// Flags (all optional; build.sh uses most of them):
//   --enable-login-item     register this bundle as a Login Item and exit
//   --disable-login-item    unregister it and exit
//   --login-item-status     print the Login Item's state and exit
//   --render-icon PATH [--size PX]   write the app icon as a PNG and exit
//   --render-iconset DIR    write an .iconset (for iconutil) and exit
//   --render-dmg-background DIR [--signed]   write the disk image's background PNGs and exit
//   --dump-bar PATH         render the status item's states to PATH (a strip), exit
//   --dump-window PATH      render the window with made-up Macs and drops to PATH (+ -light, -empty), exit
//   --crowd N               with --dump-window: N made-up destinations, at the default size and a wide one
//   --dump-kinds PATH       render the "which kinds of file?" sheet to PATH, exit
//   --dump-settings PATH    render the Settings window to PATH, exit
//   --dump-history PATH     render the History window with a made-up history to PATH, exit
//   --dump-internals PATH   render the Internals panel with a staged drop to PATH, exit
//   --dump-offer PATH       render the "do you want this drop?" panel to PATH, exit
//   --dump-pairing PATH     render every stage of the pairing panel to PATH-<stage>.png, exit
//   --show-window           open the window at launch (the app otherwise starts in the menu bar only)
//
// The engine without the app:
//   --receive [DIR]         take drops from paired Macs into DIR (default: the current folder), asking
//                           on the terminal for each; answers requests to pair the same way.
//                           --once exits after the first, --no-advertise stays off Bonjour,
//                           --any-network takes drops from beyond the local subnet too
//   --unattended-from TAG   with --receive (before it): accept without asking, but only from the one
//                           paired key named, one drop at a time; --max-bytes N caps each (100 GB)
//   --pair TARGET           pair with TARGET by two spoken codes; --verify TARGET by identity numbers
//   --identity              this identity's key tag, identity number and end date; exit
//   --known                 the Macs this identity is paired with; --forget TAG removes one
//   --reset-identity        tell the paired Macs this key is retired, and make a new one
//   --speed TARGET          measure the link to a paired Mac, both ways, no disk ([--seconds N] [--streams N] before it)
//   --service show|hide|status   “Nimbus Drop To…” in the Services menu (the binary inside the app)
//   --uninstall [--yes]     list everything this copy has left on this Mac; with --yes, remove it and the app
//   --key-lifetime 90d      how long keys last: 1h, 1d, 1w, 30d or 90d
//   --send TARGET PATH…     send to TARGET: a Mac's name as --peers shows it, HOST or HOST:PORT
//   --peers                 the Macs found on the network in three seconds; exit
//   --watch-peers           the same, live, with everything Bonjour reports (Ctrl-C to stop)
//   --name NAME             the name to go by (and a separate identity) for --receive / --send
//   --port N                the port to listen on / connect to (default 47823)
//   --streams N             parallel connections for --send
//   --only jpg,cr3          with --send (before it): only these kinds of file
//   --verbose               print the debug log's lines while --send / --receive run (before them)
//   --print                 this Mac's name, addresses and settings; exit
//   --check-update          what the updater sees on GitHub; exit
//   --preflight APP.app     the release checks build.sh release runs; exit

func usage() -> Never {
    print("""
    usage: NimbusDrop [--receive [DIR] [--once] [--no-advertise] | --send TARGET PATH… | --peers | --print]
                      [--name NAME] [--port N] [--streams N] [--show-window]
                      [--enable-login-item | --disable-login-item | --login-item-status]
                      [--render-icon PATH [--size PX]] [--render-iconset DIR]
                      [--render-dmg-background DIR [--signed]] [--dump-bar PATH] [--dump-window PATH]
                      [--check-update | --preflight APP.app]
    """)
    exit(2)
}

var dumpBarPath: String?
var dumpWindowPath: String?
var dumpCrowd = 0
var showWindowAtLaunch = false
var renderIconPath: String?
var renderIconSize = 1024
var renderIconsetDir: String?
var renderDMGBackgroundDir: String?
var dmgSigned = false
var receiveDir: String?
var receiveOnce = false
var sendArgs: [String]?
var cli: CLI.Command?

var args = Array(CommandLine.arguments.dropFirst())
func takeValue(_ flag: String) -> String {
    guard !args.isEmpty else { fputs("\(flag) needs a value\n", stderr); usage() }
    return args.removeFirst()
}
while !args.isEmpty {
    let a = args.removeFirst()
    switch a {
    case "--enable-login-item":
        do { try LoginItem.setEnabled(true); print("login item: \(LoginItem.statusDescription)") }
        catch { fputs("could not register the login item: \(error)\n", stderr); exit(1) }
        UserDefaults.standard.set(true, forKey: LoginItem.registeredDefaultsKey)
        UserDefaults.standard.synchronize()
        exit(0)
    case "--disable-login-item":
        do { try LoginItem.setEnabled(false); print("login item: \(LoginItem.statusDescription)") }
        catch { fputs("could not unregister the login item: \(error)\n", stderr); exit(1) }
        exit(0)
    case "--login-item-status":
        print(LoginItem.statusDescription)
        exit(0)
    case "--render-icon": renderIconPath = takeValue(a)
    case "--size": renderIconSize = Int(takeValue(a)) ?? 1024
    case "--render-iconset": renderIconsetDir = takeValue(a)
    case "--render-dmg-background": renderDMGBackgroundDir = takeValue(a)
    case "--signed": dmgSigned = true
    case "--dump-bar": dumpBarPath = takeValue(a)
    case "--dump-window": dumpWindowPath = takeValue(a)
    case "--dump-kinds": let v = takeValue(a); exit(MainActor.assumeIsolated { MainWindowController.dumpKinds(to: v) ? 0 : 1 })
    case "--dump-settings": let v = takeValue(a); exit(MainActor.assumeIsolated { SettingsWindowController.dump(to: v) ? 0 : 1 })
    case "--dump-history": let v = takeValue(a); exit(MainActor.assumeIsolated { HistoryWindowController.dump(to: v) ? 0 : 1 })
    case "--dump-internals": let v = takeValue(a); exit(MainActor.assumeIsolated { InternalsPanelController.dump(to: v) ? 0 : 1 })
    case "--dump-pairing": let v = takeValue(a); exit(MainActor.assumeIsolated { PairingPanel.dump(to: v) ? 0 : 1 })
    case "--dump-offer": let v = takeValue(a); exit(MainActor.assumeIsolated { OfferPanel.dump(to: v) ? 0 : 1 })
    case "--crowd": dumpCrowd = Int(takeValue(a)) ?? 0
    case "--show-window": showWindowAtLaunch = true
    case "--receive":
        receiveDir = "."
        if let next = args.first, !next.hasPrefix("-") { receiveDir = args.removeFirst() }
    case "--once": receiveOnce = true
    case "--no-advertise": MainActor.assumeIsolated { CLI.advertise = false }
    case "--any-network": MainActor.assumeIsolated { CLI.anyNetwork = true }
    case "--send":
        // Everything up to the next flag: the target, then what to send.
        var rest: [String] = []
        while let next = args.first, !next.hasPrefix("--") { rest.append(args.removeFirst()) }
        guard rest.count >= 2 else { fputs("--send needs a target and at least one path\n", stderr); usage() }
        sendArgs = rest
    case "--peers": cli = .peers
    case "--speed": cli = .speed(target: takeValue(a))
    case "--seconds": let v = Double(takeValue(a)); MainActor.assumeIsolated { if let v { CLI.speedSeconds = v } }
    case "--uninstall":
        let yes = args.first == "--yes"
        exit(MainActor.assumeIsolated { Uninstaller.commandLine(confirmed: yes) })
    case "--service":
        let v = takeValue(a)
        MainActor.assumeIsolated {
            guard ServiceMenu.key != nil else { fputs("--service needs the app's bundle: run the binary inside the app\n", stderr); exit(1) }
            if v == "show" || v == "hide" { ServiceMenu.setShown(v == "show"); Thread.sleep(forTimeInterval: 0.5) }
            print("“\(ServiceMenu.key ?? "")” is \(ServiceMenu.isShown ? "shown" : "hidden") in the Services menu")
        }
        exit(0)
    case "--pair": cli = .pair(target: takeValue(a), byNumber: false)
    case "--verify": cli = .pair(target: takeValue(a), byNumber: true)
    case "--identity": cli = .identity
    case "--known": cli = .known
    case "--forget": cli = .forget(tag: takeValue(a))
    case "--reset-identity": cli = .resetIdentity
    case "--key-lifetime": cli = .keyLifetime(takeValue(a))
    case "--unattended-from": let v = takeValue(a); MainActor.assumeIsolated { CLI.unattendedFrom = v }
    case "--max-bytes": let v = Int64(takeValue(a)); MainActor.assumeIsolated { if let v { CLI.maxBytes = v } }
    case "--watch-peers": cli = .watchPeers
    case "--name": let v = takeValue(a); MainActor.assumeIsolated { CLI.name = v }
    case "--port": let v = UInt16(takeValue(a)); MainActor.assumeIsolated { CLI.port = v }
    case "--only": let v = takeValue(a).split(separator: ",").map { String($0).replacingOccurrences(of: ".", with: "") }; MainActor.assumeIsolated { CLI.only = v }
    case "--streams": let v = Int(takeValue(a)); MainActor.assumeIsolated { CLI.streams = v }
    case "--print": cli = .print
    case "--verbose": DropLog.sink = { level, line in FileHandle.standardError.write(Data(("  \(level.label) \(line)\n").utf8)) }
    case "--check-update": cli = .checkUpdate
    case "--preflight": cli = .preflight(app: takeValue(a))
    case "-h", "--help": usage()
    default:
        if !a.hasPrefix("-psn") { fputs("ignoring unknown argument \(a)\n", stderr) }
    }
}
if let dir = receiveDir { cli = .receive(dir: dir, once: receiveOnce) }
if let s = sendArgs { cli = .send(target: s[0], paths: Array(s.dropFirst())) }

if let dir = renderIconsetDir {
    do { try AppIcon.writeIconset(to: dir); print("wrote \(dir)") } catch { fputs("iconset: \(error)\n", stderr); exit(1) }
    exit(0)
}
if let dir = renderDMGBackgroundDir {
    do { try DMGBackground.write(to: dir, signed: dmgSigned); print("wrote \(dir)") } catch { fputs("dmg background: \(error)\n", stderr); exit(1) }
    exit(0)
}
if let path = renderIconPath {
    guard let data = AppIcon.pngData(px: renderIconSize) else { fputs("icon render failed\n", stderr); exit(1) }
    do { try data.write(to: URL(fileURLWithPath: path)); print("wrote \(path) (\(renderIconSize)×\(renderIconSize))") }
    catch { fputs("icon: \(error)\n", stderr); exit(1) }
    exit(0)
}
if let path = dumpBarPath { exit(MainActor.assumeIsolated { StatusBarController.dumpBar(to: path) ? 0 : 1 }) }
if let path = dumpWindowPath { exit(MainActor.assumeIsolated { MainWindowController.dump(to: path, crowd: dumpCrowd) ? 0 : 1 }) }
if let cli { exit(MainActor.assumeIsolated { CLI.run(cli) }) }

@MainActor
final class AppDelegate: NSObject, NSApplicationDelegate {
    nonisolated(unsafe) static var shared: AppDelegate?
    var model: AppModel!
    var statusBar: StatusBarController!
    var updater: Updater?
    var window: MainWindowController?
    var menu: MainMenu!
    var settings: SettingsWindowController?
    var history: HistoryWindowController?
    var log: LogFile?
    var internals: InternalsPanelController?

    static var logURL: URL {
        let name = Bundle.main.infoDictionary?["CFBundleName"] as? String ?? "Nimbus Drop"
        return FileManager.default.homeDirectoryForCurrentUser
            .appendingPathComponent("Library/Logs/\(name)/nimbus-drop.log")
    }

    /// What the app is doing, live: status, connections, and the log as it is written.
    @objc func showInternals() {
        if internals == nil { internals = InternalsPanelController(model: model) }
        internals?.show()
    }

    /// The log file, selected in Finder (it opens in Console with a double-click).
    @objc func showLog() {
        log?.flush()
        NSWorkspace.shared.activateFileViewerSelecting([AppDelegate.logURL])
    }

    func applicationDidFinishLaunching(_ notification: Notification) {
        AppDelegate.shared = self
        NSApp.setActivationPolicy(.accessory)
        // The debug log: ~/Library/Logs/<the app's name>/nimbus-drop.log, so the development
        // copy keeps its own. Everything the engine and the app note goes there.
        let log = LogFile(url: AppDelegate.logURL)
        self.log = log
        // The same lines go to the Internals panel's buffer, which starts with what the file
        // already holds: the panel shows earlier runs too, not only this one.
        Diagnostics.shared.seed(from: AppDelegate.logURL)
        DropLog.sink = { level, line in
            log.append("\(level.label) \(line)")
            Diagnostics.shared.record(level, line)
        }
        DropLog.write("—— \(StatusBarController.versionString()) started from \(Bundle.main.bundlePath); macOS \(ProcessInfo.processInfo.operatingSystemVersionString)")

        // One copy only, the newest: two copies on one Mac would both announce it and split the
        // incoming drops between them. The development bundle counts as a copy too.
        if Bundle.main.bundleIdentifier != nil {
            let others = Updates.bundleIDs.flatMap { NSRunningApplication.runningApplications(withBundleIdentifier: $0) }
                .filter { $0.processIdentifier != getpid() }
            for o in others {
                NSLog("another copy is running (pid \(o.processIdentifier)); asking it to quit")
                o.terminate()
            }
        }

        model = AppModel()
        if let version = Updates.runningVersion {
            updater = Updater(config: Updates.config(currentVersion: version))
        }
        menu = MainMenu(model: model, updater: updater)
        statusBar = StatusBarController(model: model)
        model.installUpdate = { [weak self] in self?.menu.installUpdate() }
        updater?.onChange = { [weak self] in self?.menu.updaterChanged() }
        updater?.start()
        model.start()

        // "Nimbus Drop To…" in Finder's Services menu (declared in the Info.plist build.sh
        // writes). The port name is the bundle's name, which is also what the menu item says,
        // so the development copy's service is its own and is told apart.
        if let name = Bundle.main.infoDictionary?["CFBundleName"] as? String {
            NSApp.servicesProvider = self
            NSRegisterServicesProvider(self, name)
            NSUpdateDynamicServices()
        }

        // `build.sh install` registers with --enable-login-item; a drag-install from the disk
        // image has nobody to do that, so the first launch from an Applications folder registers
        // instead: Open at login is on by default for a fresh install. Once only: turning it off
        // later (Settings, System Settings) sticks across updates. Not from anywhere else (the
        // disk image itself, Downloads): a Login Item pointing at a path that then goes away is a
        // ghost entry. Such a copy registers on its first launch after it is moved into place.
        let path = Bundle.main.bundlePath
        let installed = path.hasPrefix("/Applications/") || path.hasPrefix(NSHomeDirectory() + "/Applications/")
        if installed, !UserDefaults.standard.bool(forKey: LoginItem.registeredDefaultsKey) {
            UserDefaults.standard.set(true, forKey: LoginItem.registeredDefaultsKey)
            try? LoginItem.setEnabled(true)
        }
        // The switch in Settings was read before this ran; show what is true now.
        model.openAtLogin = LoginItem.isEnabled
        // Opened by hand (not at login): show the window, as any app would.
        if showWindowAtLaunch || !launchedAtLogin {
            showWindow()
            // The icon is given its place in the menu bar a moment after launch.
            DispatchQueue.main.asyncAfter(deadline: .now() + 0.4) { [weak self] in
                MainActor.assumeIsolated { self?.window?.settle(under: self?.statusBar?.anchor) }
            }
        }
    }

    /// Whether launchd started this copy as a Login Item rather than a person opening it.
    private var launchedAtLogin: Bool {
        guard let event = NSAppleEventManager.shared().currentAppleEvent else { return false }
        return event.eventID == kAEOpenApplication
            && event.paramDescriptor(forKeyword: keyAEPropData)?.enumCodeValue == keyAELaunchedAsLogInItem
    }

    @objc func showWindow() {
        if window == nil { window = MainWindowController(model: model) }
        window?.show(under: statusBar?.anchor)
    }

    /// The Settings window (⌘,), made on first use and kept.
    @objc func showSettings() {
        if settings == nil { settings = SettingsWindowController(model: model, updater: updater) }
        model.openAtLogin = LoginItem.isEnabled   // it can be changed in System Settings too
        settings?.show()
    }

    /// Every drop that has ended; the main window keeps one for only a minute.
    @objc func showHistory() {
        if history == nil { history = HistoryWindowController(model: model) }
        history?.show()
    }

    /// The menu bar item: open the window, or close it when it is already in front.
    func toggleWindow() {
        if let window, window.isFront { window.close() } else { showWindow() }
    }

    @objc func addByAddress() {
        showWindow()
        model.askingForAddress = true
    }

    /// The Services menu: files and folders selected in Finder (or anywhere else that offers
    /// them). They are held in the window until a destination is clicked.
    @objc func dropService(_ pboard: NSPasteboard, userData: String, error: AutoreleasingUnsafeMutablePointer<NSString>) {
        let urls = (pboard.readObjects(forClasses: [NSURL.self], options: [.urlReadingFileURLsOnly: true]) as? [URL]) ?? []
        guard !urls.isEmpty else {
            error.pointee = "Nimbus Drop can only send files and folders."
            return
        }
        showWindow()
        model.pendingURLs = urls
    }

    /// Clicking the Dock icon, or opening the app again while it runs.
    func applicationShouldHandleReopen(_ sender: NSApplication, hasVisibleWindows flag: Bool) -> Bool {
        showWindow()
        return true
    }

    /// Files dropped on the Dock icon: open the window so a Mac can be picked for them.
    func application(_ application: NSApplication, open urls: [URL]) {
        showWindow()
        model.pendingURLs = urls.filter(\.isFileURL)
    }

    func applicationShouldTerminate(_ sender: NSApplication) -> NSApplication.TerminateReply {
        guard model.hasActiveTransfers else { return .terminateNow }
        let alert = NSAlert()
        alert.messageText = "A drop is still under way"
        alert.informativeText = "Quitting stops it. What has arrived is kept, and sending the same items again continues from there."
        alert.addButton(withTitle: "Quit")
        alert.addButton(withTitle: "Keep Going")
        NSApp.activate(ignoringOtherApps: true)
        return alert.runModal() == .alertFirstButtonReturn ? .terminateNow : .terminateCancel
    }

    func applicationWillTerminate(_ notification: Notification) {
        model?.stop()
        DropLog.write("—— quit")
        log?.flush()
    }
}

MainActor.assumeIsolated {
    let app = NSApplication.shared
    let delegate = AppDelegate()
    app.delegate = delegate
    app.run()
}
