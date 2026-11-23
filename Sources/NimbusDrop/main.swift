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
//   --dump-offer PATH       render the "do you want this drop?" panel to PATH, exit
//   --show-window           open the window at launch (the app otherwise starts in the menu bar only)
//
// The engine without the app:
//   --receive [DIR]         take every drop into DIR (default: the current folder) without asking;
//                           --once exits after the first, --no-advertise stays off Bonjour
//   --send TARGET PATH…     send to TARGET: a Mac's name as --peers shows it, HOST or HOST:PORT
//   --peers                 the Macs found on the network in three seconds; exit
//   --watch-peers           the same, live, with everything Bonjour reports (Ctrl-C to stop)
//   --name NAME             the name to go by (and a separate identity) for --receive / --send
//   --port N                the port to listen on / connect to (default 47823)
//   --streams N             parallel connections for --send
//   --only jpg,cr3          with --send (before it): only these kinds of file
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
    case "--dump-offer": let v = takeValue(a); exit(MainActor.assumeIsolated { OfferPanel.dump(to: v) ? 0 : 1 })
    case "--crowd": dumpCrowd = Int(takeValue(a)) ?? 0
    case "--show-window": showWindowAtLaunch = true
    case "--receive":
        receiveDir = "."
        if let next = args.first, !next.hasPrefix("-") { receiveDir = args.removeFirst() }
    case "--once": receiveOnce = true
    case "--no-advertise": MainActor.assumeIsolated { CLI.advertise = false }
    case "--send":
        // Everything up to the next flag: the target, then what to send.
        var rest: [String] = []
        while let next = args.first, !next.hasPrefix("--") { rest.append(args.removeFirst()) }
        guard rest.count >= 2 else { fputs("--send needs a target and at least one path\n", stderr); usage() }
        sendArgs = rest
    case "--peers": cli = .peers
    case "--watch-peers": cli = .watchPeers
    case "--name": let v = takeValue(a); MainActor.assumeIsolated { CLI.name = v }
    case "--port": let v = UInt16(takeValue(a)); MainActor.assumeIsolated { CLI.port = v }
    case "--only": let v = takeValue(a).split(separator: ",").map { String($0).replacingOccurrences(of: ".", with: "") }; MainActor.assumeIsolated { CLI.only = v }
    case "--streams": let v = Int(takeValue(a)); MainActor.assumeIsolated { CLI.streams = v }
    case "--print": cli = .print
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

    func applicationDidFinishLaunching(_ notification: Notification) {
        AppDelegate.shared = self
        NSApp.setActivationPolicy(.accessory)

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
        // image has nobody to do that, so the first launch from /Applications registers instead.
        // Once only: turning it off later (menu, System Settings) sticks across updates.
        let installed = Bundle.main.bundlePath.hasPrefix("/Applications/")
        if installed, !UserDefaults.standard.bool(forKey: LoginItem.registeredDefaultsKey) {
            UserDefaults.standard.set(true, forKey: LoginItem.registeredDefaultsKey)
            try? LoginItem.setEnabled(true)
        }
        // Opened by hand (not at login): show the window, as any app would.
        if showWindowAtLaunch || !launchedAtLogin { showWindow() }
    }

    /// Whether launchd started this copy as a Login Item rather than a person opening it.
    private var launchedAtLogin: Bool {
        guard let event = NSAppleEventManager.shared().currentAppleEvent else { return false }
        return event.eventID == kAEOpenApplication
            && event.paramDescriptor(forKeyword: keyAEPropData)?.enumCodeValue == keyAELaunchedAsLogInItem
    }

    @objc func showWindow() {
        if window == nil { window = MainWindowController(model: model) }
        window?.show()
    }

    /// The Settings window (⌘,), made on first use and kept.
    @objc func showSettings() {
        if settings == nil { settings = SettingsWindowController(model: model, updater: updater) }
        settings?.show()
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

    func applicationWillTerminate(_ notification: Notification) { model?.stop() }
}

MainActor.assumeIsolated {
    let app = NSApplication.shared
    let delegate = AppDelegate()
    app.delegate = delegate
    app.run()
}
