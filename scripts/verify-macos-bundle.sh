#!/usr/bin/env bash
# Verify the app the user would actually install: Tauri removes the
# intermediate .app after generating its DMG. Never inspect that path.
set -euo pipefail

dmg_dir="src-tauri/target/release/bundle/dmg"
dmg=$(find "$dmg_dir" -maxdepth 1 -type f -name '*.dmg' -print -quit)
if [[ -z "$dmg" || ! -s "$dmg" ]]; then
  echo "Missing or empty unsigned DMG in $dmg_dir" >&2
  exit 1
fi

mount_dir=$(mktemp -d "${TMPDIR:-/tmp}/security-agent-dmg.XXXXXX")
mounted=0
cleanup() {
  if [[ "$mounted" == "1" ]]; then
    hdiutil detach "$mount_dir" -quiet || true
  fi
  rmdir "$mount_dir" 2>/dev/null || true
}
trap cleanup EXIT

hdiutil attach -readonly -nobrowse -mountpoint "$mount_dir" "$dmg"
mounted=1

app=$(find "$mount_dir" -maxdepth 1 -type d -name '*.app' -print -quit)
if [[ -z "$app" || ! -f "$app/Contents/Info.plist" ]]; then
  echo "DMG does not contain a macOS application with an Info.plist" >&2
  exit 1
fi

bundle_id=$(/usr/libexec/PlistBuddy -c 'Print :CFBundleIdentifier' "$app/Contents/Info.plist")
if [[ "$bundle_id" != "com.gavindu.securityagent.desktop" ]]; then
  echo "Unexpected bundle identifier: $bundle_id" >&2
  exit 1
fi

executable=$(/usr/libexec/PlistBuddy -c 'Print :CFBundleExecutable' "$app/Contents/Info.plist")
binary="$app/Contents/MacOS/$executable"
test -x "$binary" || { echo "Missing bundle executable: $executable" >&2; exit 1; }
lipo -verify_arch arm64 "$binary" || { echo "Bundle lacks Apple Silicon arm64 executable" >&2; exit 1; }

icon=$(find "$app/Contents/Resources" -type f -name '*.icns' -print -quit)
test -n "$icon" || { echo "Missing bundled .icns icon" >&2; exit 1; }

echo "Verified installed application inside DMG: bundle=$bundle_id, executable=$executable, arch=arm64"
