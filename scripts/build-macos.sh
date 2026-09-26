#!/bin/bash
set -euo pipefail
src="$(cd "$(dirname "$0")/.." && pwd)"
: "${AES128_CORES:?Set AES128_CORES to verified Darwin arm64 cores directory}"
: "${AES128_OUTPUT:?Set AES128_OUTPUT to output directory}"
identity="${AES128_SIGN_IDENTITY:--}"
app="$AES128_OUTPUT/AES128 VPN.app"
mkdir -p "$app/Contents/MacOS" "$app/Contents/Resources" "$app/Contents/Library/LaunchDaemons"
"$src/scripts/generate-macos-icons.sh"
(cd "$src/aes128/frontend" && npm ci --ignore-scripts && npm run build)
cp "$AES128_CORES/xray" "$AES128_CORES/sing-box" "$app/Contents/MacOS/"
for binary in xray sing-box; do
 /usr/bin/codesign --force --options runtime --timestamp=none --sign "$identity" "$app/Contents/MacOS/$binary"
done
xray_hash="$(shasum -a 256 "$app/Contents/MacOS/xray" | cut -d ' ' -f1)"
singbox_hash="$(shasum -a 256 "$app/Contents/MacOS/sing-box" | cut -d ' ' -f1)"
(cd "$src/backend" && CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 go build -trimpath -ldflags="-s -w -X main.xraySHA256=$xray_hash -X main.singBoxSHA256=$singbox_hash" -o "$app/Contents/MacOS/aes128-helper" .)
(cd "$src/aes128" && CGO_ENABLED=1 GOOS=darwin GOARCH=arm64 MACOSX_DEPLOYMENT_TARGET=13.0 go build -tags production -trimpath -ldflags='-s -w -extldflags=-mmacosx-version-min=13.0' -o "$app/Contents/MacOS/aes128" .)

cp "$src/aes128/build/darwin/Info.plist" "$app/Contents/Info.plist"
cp "$src/aes128/build/darwin/icons.icns" "$app/Contents/Resources/"
mkdir -p "$app/Contents/Resources/Licenses"
cp "$src/licenses/"* "$app/Contents/Resources/Licenses/"
cp "$src/aes128/frontend/src/assets/fonts/IBM-Plex-Mono-OFL.txt" "$app/Contents/Resources/Licenses/"
cp "$src/aes128/build/darwin/com.aes128.vpn.helper.plist" "$app/Contents/Library/LaunchDaemons/"
chmod 755 "$app/Contents/MacOS/"*
for binary in aes128-helper aes128; do
 /usr/bin/codesign --force --options runtime --timestamp=none --sign "$identity" "$app/Contents/MacOS/$binary"
done
/usr/bin/codesign --force --options runtime --timestamp=none --sign "$identity" "$app"
/usr/bin/codesign --verify --deep --strict "$app"
echo "Built $app"
