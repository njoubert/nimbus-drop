#!/usr/bin/env bash
# Build, run and install Nimbus Drop — send files and folders to another Mac on the LAN.
#
#   ./build.sh              debug build → .build/debug/NimbusDrop
#   ./build.sh test         whole drops over loopback, the manifest, the resume ledger (swift test)
#   ./build.sh verify [word…]  everything that is checked by a machine: the layers, the formal models
#                           and their mutants (formal/check.py: TLC and Tamarin), the short-code
#                           simulation, and swift test. Words narrow the models ("tla", "Drop").
#   ./build.sh verify quick    the part of that which takes about a minute: no Tamarin, and of the
#                           tests only the pure core's.
#   ./build.sh run [args]   debug build as dist/debug/Nimbus Drop Dev.app, (re)launch it detached.
#                           Add --fg to run in the foreground instead (logs here, Ctrl-C quits).
#                           Its identifier is com.njoubert.nimbusdrop.dev: its own settings,
#                           permissions and Login Items entry. Launching it quits the installed copy.
#   ./build.sh stop         quit every running NimbusDrop (dev or installed)
#   ./build.sh app          release build → dist/Nimbus Drop.app (ad-hoc signed, icon baked in)
#   ./build.sh dmg          release build → dist/NimbusDrop-<version>.dmg, the drag-to-Applications
#                           disk image (background drawn by Sources/NimbusDrop/DMGBackground.swift)
#   ./build.sh install      release build → /Applications/Nimbus Drop.app (replacing any older
#                           copy), register it as a Login Item, launch
#   ./build.sh uninstall    unregister the Login Item, quit, delete the app and the saved preferences
#   ./build.sh status       running? installed? Login Item registered?
#   ./build.sh icon         re-render docs/icon.png from Sources/NimbusDrop/AppIcon.swift
#   ./build.sh clean        remove build products
#
# Signing: release bundles (app / dmg / install) are ad-hoc signed unless a Developer ID is
# configured, in which case they are signed with it, hardened-runtime, timestamped, and the
# disk image is notarized and stapled. Configure it in a git-ignored ./.signing file (or the
# environment):
#   SIGN_IDENTITY="Developer ID Application: Niels Joubert (TEAMID)"
#   NOTARY_PROFILE=<profile>       # the name given to: xcrun notarytool store-credentials <profile> ...
# Debug builds (run) stay ad-hoc.
set -euo pipefail
cd "$(dirname "$0")"

NAME=NimbusDrop  # executable / target / process name
APP_NAME="Nimbus Drop"  # what the user sees: the .app, the volume, Login Items
BUNDLE_ID=com.njoubert.nimbusdrop
# The development bundle's own identity. Under the release's identifier a dev copy took over the
# installed copy's Login Items record, and launchd then refused the installed binary at login
# (Launch Constraint Violation, 2026-10-11).
DEV_BUNDLE_ID=$BUNDLE_ID.dev
DEV_APP_NAME="$APP_NAME Dev"
VERSION=0.3.1
INSTALL_DIR=/Applications
INSTALLED="$INSTALL_DIR/$APP_NAME.app"
DEV_APP="dist/debug/$DEV_APP_NAME.app"
REL_APP="dist/$APP_NAME.app"
DMG="dist/$NAME-$VERSION.dmg"
ZIP="dist/$NAME-$VERSION.zip"     # what the auto-updater downloads; a release needs both

# Developer ID signing / notarization, off unless configured (see the header).
SIGN_IDENTITY="${SIGN_IDENTITY:-}"
NOTARY_PROFILE="${NOTARY_PROFILE:-}"
if [ -f .signing ]; then
  # shellcheck source=/dev/null
  . ./.signing
fi

# --- helpers -----------------------------------------------------------------------------

dim=$'\033[2m'; green=$'\033[32m'; yellow=$'\033[33m'; reset=$'\033[0m'
say()  { printf '%s%s%s\n' "$green" "$*" "$reset"; }
note() { printf '%s%s%s\n' "$dim" "$*" "$reset"; }
warn() { printf '%s%s%s\n' "$yellow" "$*" "$reset" >&2; }

# Assemble a .app around a built binary: Info.plist, icon, ad-hoc signature.
#   make_bundle <config: debug|release> <out.app> <bundle id> <name>
make_bundle() {
  local config=$1 app=$2 bundle_id=$3 name=$4 bin=".build/$1/$NAME"
  rm -rf "$app"
  mkdir -p "$app/Contents/MacOS" "$app/Contents/Resources"
  cp "$bin" "$app/Contents/MacOS/$NAME"
  cp LICENSE "$app/Contents/Resources/LICENSE"

  # The icon is drawn in code; render it to an .iconset and let iconutil pack it.
  local iconset="dist/$config-AppIcon.iconset"
  "$bin" --render-iconset "$iconset" >/dev/null
  iconutil -c icns "$iconset" -o "$app/Contents/Resources/AppIcon.icns"
  rm -rf "$iconset"

  cat > "$app/Contents/Info.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>CFBundleName</key><string>$name</string>
  <key>CFBundleDisplayName</key><string>$name</string>
  <key>CFBundleIdentifier</key><string>$bundle_id</string>
  <key>CFBundleExecutable</key><string>$NAME</string>
  <key>CFBundleIconFile</key><string>AppIcon</string>
  <key>CFBundlePackageType</key><string>APPL</string>
  <key>CFBundleShortVersionString</key><string>$VERSION</string>
  <key>CFBundleVersion</key><string>$(git rev-list --count HEAD 2>/dev/null || echo 1)</string>
  <key>LSMinimumSystemVersion</key><string>15.0</string>
  <key>LSUIElement</key><true/>
  <key>NSHighResolutionCapable</key><true/>
  <key>NSPrincipalClass</key><string>NSApplication</string>
  <key>NSServices</key>
  <array><dict>
    <key>NSMenuItem</key><dict><key>default</key><string>$name To…</string></dict>
    <key>NSMessage</key><string>dropService</string>
    <key>NSPortName</key><string>$name</string>
    <key>NSSendFileTypes</key><array><string>public.item</string></array>
    <key>NSRequiredContext</key><dict/>
  </dict></array>
  <key>NSLocalNetworkUsageDescription</key>
  <string>Nimbus Drop finds other Macs running Nimbus Drop on your local network, and sends files to them and receives files from them over it.</string>
  <key>NSBonjourServices</key>
  <array><string>_nimbusdrop._tcp</string></array>
  <key>NSDownloadsFolderUsageDescription</key>
  <string>Nimbus Drop saves the files other Macs send you into the folder you choose, and reads the files you choose to send.</string>
  <key>NSDesktopFolderUsageDescription</key>
  <string>Nimbus Drop saves the files other Macs send you into the folder you choose, and reads the files you choose to send.</string>
  <key>NSDocumentsFolderUsageDescription</key>
  <string>Nimbus Drop saves the files other Macs send you into the folder you choose, and reads the files you choose to send.</string>
  <key>NSRemovableVolumesUsageDescription</key>
  <string>Nimbus Drop saves the files other Macs send you into the folder you choose, and reads the files you choose to send.</string>
  <key>NSNetworkVolumesUsageDescription</key>
  <string>Nimbus Drop saves the files other Macs send you into the folder you choose, and reads the files you choose to send.</string>
</dict></plist>
PLIST
  plutil -convert xml1 -o /dev/null "$app/Contents/Info.plist"   # validate (plutil -lint misparses here)

  if [ "$config" = release ] && [ -n "$SIGN_IDENTITY" ]; then
    # Hardened runtime + secure timestamp are what notarization requires.
    codesign --force --sign "$SIGN_IDENTITY" --options runtime --timestamp \
      --identifier "$bundle_id" "$app"
    codesign --verify --strict --deep "$app"
    note "bundled $app  (signed: $SIGN_IDENTITY)"
  else
    if ! codesign --force --sign - --identifier "$bundle_id" "$app" >/dev/null 2>&1; then
      warn "codesign failed (continuing unsigned)"
    fi
    note "bundled $app  (ad-hoc signed)"
  fi
}

# Send something to Apple's notary service and staple the ticket to it.
#   notarize <path to .zip/.dmg to submit> <path to staple (the .app or the .dmg)>
notarize() {
  local submit=$1 staple=$2
  say "notarizing $(basename "$submit") — this waits on Apple, usually a few minutes"
  if ! xcrun notarytool submit "$submit" --keychain-profile "$NOTARY_PROFILE" --wait; then
    warn "notarization failed; for the reason run:"
    warn "  xcrun notarytool log <submission id> --keychain-profile $NOTARY_PROFILE"
    return 1
  fi
  xcrun stapler staple -q "$staple"
  note "stapled $staple"
}

# Notarize the release app itself (so a copy dragged out of the DMG verifies offline too),
# then the DMG is signed, notarized and stapled in make_dmg.
notarize_app() {
  local app=$1 zip="dist/$NAME-notarize.zip"
  [ -n "$NOTARY_PROFILE" ] || { warn "no NOTARY_PROFILE: app signed but not notarized"; return 0; }
  rm -f "$zip"
  ditto -c -k --keepParent "$app" "$zip"
  notarize "$zip" "$app"
  rm -f "$zip"
}

# The auto-updater's asset: the stapled app, zipped with ditto (which keeps symlinks and
# extended attributes, so the signature and the notarization ticket survive). Must run after
# notarize_app, or the download is the pre-staple copy.
#   make_zip <app> <out.zip>
make_zip() {
  local app=$1 out=$2
  rm -f "$out"
  ditto -c -k --keepParent "$app" "$out"
  note "packed $out ($(du -h "$out" | cut -f1))"
}

# Wrap dist/Nimbus Drop.app in the usual drag-to-Applications disk image: the app, an
# Applications alias, and a background picture that says what to do and what to expect.
# Finder keeps icon positions / background / window size in the volume's .DS_Store, and the
# only supported way to write that is to ask Finder — hence the AppleScript (the first run
# prompts for permission to control Finder).
#   make_dmg <app> <out.dmg>
make_dmg() {
  local app=$1 out=$2 bin="$1/Contents/MacOS/$NAME"
  local staging="dist/dmg-staging" rw="dist/$NAME-rw.dmg" vol="/Volumes/$APP_NAME"

  rm -rf "$staging" "$rw"
  mkdir -p "$staging/.background"
  ditto "$app" "$staging/$APP_NAME.app"
  ln -s /Applications "$staging/Applications"
  cp LICENSE "$staging/.LICENSE"    # hidden: present, but not a third icon to drag
  local bgflags=()
  [ -n "$SIGN_IDENTITY" ] && bgflags+=(--signed)   # drops the "unsigned build" footer
  "$bin" --render-dmg-background "$staging/.background" "${bgflags[@]+"${bgflags[@]}"}" >/dev/null
  # One TIFF holding the 1× and 2× renders, so Finder picks the sharp one on Retina.
  tiffutil -cathidpicheck "$staging/.background/background.png" "$staging/.background/background@2x.png" \
    -out "$staging/.background/background.tiff" >/dev/null 2>&1
  rm "$staging/.background/background.png" "$staging/.background/background@2x.png"

  # A stale mount from an earlier run would make this one land on "/Volumes/$NAME 1".
  if [ -d "$vol" ]; then hdiutil detach "$vol" -quiet -force || true; fi
  hdiutil create -volname "$APP_NAME" -srcfolder "$staging" -ov -format UDRW -fs HFS+ -quiet "$rw"
  local dev
  dev=$(hdiutil attach -readwrite -noverify -noautoopen "$rw" | awk '/^\/dev\// {print $1; exit}')
  [ -d "$vol" ] || { warn "mount failed"; hdiutil detach "$dev" -quiet || true; return 1; }

  # Geometry matches DMGBackground.swift: 640×440 window, icon centres at (170,210) / (470,210).
  osascript >/dev/null <<APPLESCRIPT
tell application "Finder"
  tell disk "$APP_NAME"
    open
    set current view of container window to icon view
    set toolbar visible of container window to false
    set statusbar visible of container window to false
    set pathbar visible of container window to false
    -- Finder remembers the (hidden) sidebar's width and adds it back on reopen unless zeroed.
    set sidebar width of container window to 0
    -- bounds include the 28 pt title bar.
    set the bounds of container window to {200, 120, 840, 588}
    set opts to the icon view options of container window
    set arrangement of opts to not arranged
    set icon size of opts to 128
    set text size of opts to 12
    set label position of opts to bottom
    set background picture of opts to file ".background:background.tiff"
    set position of item "$APP_NAME.app" of container window to {170, 210}
    set position of item "Applications" of container window to {470, 210}
    close
    open
    set sidebar width of container window to 0
    set the bounds of container window to {200, 120, 840, 588}
    update without registering applications
    delay 1
    close
  end tell
end tell
APPLESCRIPT
  sync
  rm -rf "$vol/.fseventsd"
  chmod -Rf go-w "$vol" || true
  hdiutil detach "$dev" -quiet
  rm -f "$out"
  hdiutil convert "$rw" -format UDZO -imagekey zlib-level=9 -quiet -o "$out"
  rm -rf "$rw" "$staging"
  if [ -n "$SIGN_IDENTITY" ]; then
    codesign --force --sign "$SIGN_IDENTITY" --timestamp "$out"
    if [ -n "$NOTARY_PROFILE" ]; then
      notarize "$out" "$out"
      spctl -a -t open --context context:primary-signature -v "$out" 2>&1 | sed 's/^/  /' || true
    fi
  else
    codesign --force --sign - "$out" >/dev/null 2>&1 || true
  fi
  note "packed $out ($(du -h "$out" | cut -f1))"
}

# Quit every running copy, installed and development, and wait for them to go away. The quit
# Apple event first (it needs no Automation permission), a signal if nobody answers.
stop_all() {
  if pgrep -x "$NAME" >/dev/null; then
    local id sent=0
    for id in "$BUNDLE_ID" "$DEV_BUNDLE_ID"; do
      osascript -e "if application id \"$id\" is running then tell application id \"$id\" to quit" >/dev/null 2>&1 && sent=1
    done
    [ $sent = 1 ] || pkill -x "$NAME" || true
    for _ in $(seq 1 50); do pgrep -x "$NAME" >/dev/null || break; sleep 0.1; done
    pgrep -x "$NAME" >/dev/null && { warn "still running, killing"; pkill -9 -x "$NAME" || true; sleep 0.3; }
    say "stopped $NAME"
  else
    note "$NAME is not running"
  fi
}

# --- commands ----------------------------------------------------------------------------

cmd="${1:-build}"
[ $# -gt 0 ] && shift

case "$cmd" in
  build)
    swift build
    say "ok → .build/debug/$NAME"
    ;;

  test)
    swift test
    ;;

  verify)
    # "quick": what takes seconds. The layers, the runner's own tests, the register, the TLA+
    # models, and the tests of the pure core (which hold the generated relations to the code).
    quick=0
    if [ "${1:-}" = "quick" ]; then quick=1; shift; fi
    python3 scripts/check-layers.py
    python3 scripts/test-check-layers.py 2>&1 | tail -3
    python3 formal/test_check.py 2>&1 | tail -3
    python3 formal/sas-bound.py
    if [ $quick = 1 ]; then
      python3 formal/check.py register tla "$@"
      swift test --filter NimbusCryptoTests
      say "verified (quick): the layers, the register, the TLA+ models and their mutants, the pure core's tests. Not run: Tamarin, the engine's tests."
    else
      python3 formal/check.py "$@"
      # The tests include those that hold formal/tla/*Impl.tla to what the code does.
      swift test
      say "verified: the layers, the models and their mutants, the tests"
    fi
    ;;
  run)
    fg=0; args=()
    for a in "$@"; do [ "$a" = "--fg" ] && fg=1 || args+=("$a"); done
    swift build
    make_bundle debug "$DEV_APP" "$DEV_BUNDLE_ID" "$DEV_APP_NAME"
    stop_all
    if [ $fg = 1 ]; then
      exec "$DEV_APP/Contents/MacOS/$NAME" "${args[@]+"${args[@]}"}"
    fi
    open -n "$DEV_APP" --args "${args[@]+"${args[@]}"}"
    say "launched $DEV_APP   (./build.sh stop to quit, ./build.sh run --fg for logs)"
    ;;

  stop)
    stop_all
    if [ -e "$INSTALLED" ]; then note "the installed copy can be restarted with: open -a $NAME"; fi
    ;;

  app)
    swift build -c release
    make_bundle release "$REL_APP" "$BUNDLE_ID" "$APP_NAME"
    [ -n "$SIGN_IDENTITY" ] && notarize_app "$REL_APP"
    say "built $REL_APP"
    ;;

  dmg)
    swift build -c release
    make_bundle release "$REL_APP" "$BUNDLE_ID" "$APP_NAME"
    [ -n "$SIGN_IDENTITY" ] && notarize_app "$REL_APP"
    make_zip "$REL_APP" "$ZIP"
    make_dmg "$REL_APP" "$DMG"
    say "built $DMG"
    note "Test it: open $DMG"
    ;;

  # Everything a release needs, in the order the notes say: build both artefacts, tag, publish.
  # Refuses to publish from a dirty tree or a commit that is not the version's tag.
  release)
    notes=${1:-}
    if [ -z "$notes" ] || [ ! -f "$notes" ]; then
      warn "usage: ./build.sh release NOTES.md   (the GitHub release body)"
      exit 2
    fi
    if [ -n "$(git status --porcelain)" ]; then
      warn "working tree is dirty; commit first"
      exit 1
    fi
    tag="v$VERSION"
    if git rev-parse "$tag" >/dev/null 2>&1; then
      if [ "$(git rev-parse "$tag^{commit}")" != "$(git rev-parse HEAD)" ]; then
        warn "$tag exists but is not HEAD"
        exit 1
      fi
    else
      git tag -a "$tag" -m "$APP_NAME $VERSION"
      note "tagged $tag"
    fi
    "$0" dmg
    # The requirements auto-update depends on, checked while it can still be undone: identity,
    # signature, version, and whether the copies people already have would accept this build.
    swift build >/dev/null
    ".build/debug/$NAME" --preflight "$REL_APP"
    git push origin main
    git push origin "$tag"
    if command -v gh >/dev/null 2>&1; then
      gh release create "$tag" "$DMG" "$ZIP" --title "$APP_NAME $VERSION" --notes-file "$notes"
      say "published $tag"
    else
      warn "gh is not installed; publish by hand:"
      note "gh release create $tag $DMG $ZIP --title \"$APP_NAME $VERSION\" --notes-file $notes"
    fi
    note "the updater needs $(basename "$ZIP") on the release — a DMG-only release is invisible to it"
    ;;

  install)
    swift build -c release
    make_bundle release "$REL_APP" "$BUNDLE_ID" "$APP_NAME"
    [ -n "$SIGN_IDENTITY" ] && notarize_app "$REL_APP"
    stop_all
    if [ -e "$INSTALLED" ]; then
      note "replacing $INSTALLED"
      rm -rf "$INSTALLED"
    fi
    ditto "$REL_APP" "$INSTALLED"
    # SMAppService registers the bundle that calls it, so the installed copy registers itself
    # (it prints the state and exits); then launch it.
    "$INSTALLED/Contents/MacOS/$NAME" --enable-login-item || warn "could not register the Login Item"
    open "$INSTALLED"
    say "installed $INSTALLED"
    note "It is running now and opens at login. Toggle that in the menu or in System Settings › General › Login Items."
    ;;

  uninstall)
    # The same list as the app's own uninstaller (Settings › Uninstall; Leftovers in the core),
    # done from outside so that it also works on a copy too old to know `--uninstall`. The
    # paired Macs are not told from here: the app's Settings does that.
    rm -rf "$HOME/Library/Caches/$BUNDLE_ID" "$HOME/Library/Application Support/$BUNDLE_ID" \
      "$HOME/Library/Application Support/$BUNDLE_ID.cli" "$HOME/Library/Logs/$APP_NAME" \
      "$HOME/Library/HTTPStorages/$BUNDLE_ID" "$HOME/Library/HTTPStorages/$BUNDLE_ID.binarycookies" \
      "$HOME/Library/Cookies/$BUNDLE_ID.binarycookies" "$HOME/Library/WebKit/$BUNDLE_ID" \
      "$HOME/Library/Saved Application State/$BUNDLE_ID.savedState"
    defaults delete NimbusDrop >/dev/null 2>&1 || true
    /usr/libexec/PlistBuddy -c "Delete :NSServicesStatus:'$BUNDLE_ID - $APP_NAME To… - dropService'" \
      "$HOME/Library/Preferences/pbs.plist" >/dev/null 2>&1 || true
    rm -rf "$INSTALL_DIR/.$NAME-old.app" "$INSTALL_DIR/.$NAME-update.app"
    if [ -e "$INSTALLED" ]; then
      stop_all
      # Unregister from the installed bundle before it disappears, or Login Items keeps a ghost.
      "$INSTALLED/Contents/MacOS/$NAME" --disable-login-item || warn "could not unregister the Login Item"
      rm -rf "$INSTALLED"
      say "removed $INSTALLED"
    else
      stop_all
      note "$INSTALLED is not installed"
    fi
    if defaults delete "$BUNDLE_ID" >/dev/null 2>&1; then note "removed preferences"; fi
    tccutil reset All "$BUNDLE_ID" >/dev/null 2>&1 || true
    /System/Library/CoreServices/pbs -update >/dev/null 2>&1 || true
    ;;

  status)
    if pgrep -x "$NAME" >/dev/null; then
      say "running: $(pgrep -x "$NAME" | xargs ps -o pid=,command= -p | head -3)"
    else
      note "not running"
    fi
    if [ -e "$INSTALLED" ]; then
      say "installed: $INSTALLED (v$(defaults read "$INSTALLED/Contents/Info" CFBundleShortVersionString 2>/dev/null || echo '?'))"
      sig=$(codesign -dv --verbose=2 "$INSTALLED" 2>&1 || true)   # Authority= lines need verbose=2
      auth=$(printf '%s\n' "$sig" | grep -m1 '^Authority=' | cut -d= -f2- || true)
      gate=$(spctl -a -t exec -v "$INSTALLED" 2>&1 || true)   # "source=Notarized Developer ID" when stapled/notarized
      note "signed by: ${auth:-ad-hoc (no identity)}  ·  Gatekeeper: ${gate#*: }"
      note "login item: $("$INSTALLED/Contents/MacOS/$NAME" --login-item-status)"
      if [ -w "$INSTALL_DIR" ]; then
        note "updates: $INSTALL_DIR is writable, so the app can replace itself"
      else
        warn "updates: $INSTALL_DIR is not writable by you — the app will only link to the release page"
      fi
      for stray in "$INSTALL_DIR/.$NAME-old.app" "$INSTALL_DIR/.$NAME-update.app"; do
        [ -e "$stray" ] && warn "left over from an update: $stray"
      done
    else
      note "not installed in $INSTALL_DIR"
    fi
    ;;

  icon)
    swift build >/dev/null
    .build/debug/$NAME --render-icon docs/icon.png --size 512
    ;;

  clean)
    rm -rf .build dist
    ;;

  *)
    sed -n '2,/^set -euo/p' "$0" | grep '^#' | sed 's/^# \{0,1\}//' >&2
    exit 2
    ;;
esac
