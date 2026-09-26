#!/bin/bash
set -euo pipefail
src="$(cd "$(dirname "$0")/.." && pwd)"
: "${AES128_APP:?Set AES128_APP to the signed AES128 VPN.app bundle}"
: "${AES128_OUTPUT:?Set AES128_OUTPUT to the installer output directory}"
identity="${AES128_INSTALLER_IDENTITY:-}"
app="$(cd "$(dirname "$AES128_APP")" && pwd)/$(basename "$AES128_APP")"
out="$AES128_OUTPUT/AES128-VPN-macOS-Apple-Silicon-1.0.3.pkg"
stage=$(mktemp -d "${TMPDIR:-/tmp}/aes128-pkg.XXXXXX")
trap 'rm -rf "$stage"' EXIT
mkdir -p "$stage/root/Applications" "$stage/root/Library/LaunchDaemons" "$stage/scripts" "$AES128_OUTPUT"
codesign --verify --deep --strict "$app"
ditto --noextattr --noqtn "$app" "$stage/root/Applications/AES128 VPN.app"
install -m 644 "$src/packaging/macos/com.aes128.vpn.helper.plist" "$stage/root/Library/LaunchDaemons/"
cp "$src/packaging/macos/scripts/preinstall" "$src/packaging/macos/scripts/postinstall" "$stage/scripts/"
(cd "$app/Contents/MacOS" && shasum -a 256 aes128-helper xray sing-box) > "$stage/scripts/helper.sha256"
pkgbuild --analyze --root "$stage/root" "$stage/components.plist"
/usr/libexec/PlistBuddy -c 'Set :0:BundleIsRelocatable false' "$stage/components.plist"
/usr/libexec/PlistBuddy -c 'Set :0:BundleHasStrictIdentifier true' "$stage/components.plist"
/usr/libexec/PlistBuddy -c 'Set :0:BundleOverwriteAction upgrade' "$stage/components.plist"
pkgbuild --root "$stage/root" --component-plist "$stage/components.plist" \
  --identifier com.aes128.vpn.pkg --version 1.0.3 --install-location / \
  --ownership recommended --scripts "$stage/scripts" "$stage/AES128-component.pkg"
build_args=(--distribution "$src/packaging/macos/Distribution.xml" --resources "$src/packaging/macos/resources" --package-path "$stage")
if [[ -n "$identity" ]]; then build_args+=(--sign "$identity" --timestamp); fi
productbuild "${build_args[@]}" "$out"
(cd "$AES128_OUTPUT" && shasum -a 256 "$(basename "$out")" > "$(basename "$out").sha256")
echo "Built $out"
