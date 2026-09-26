#!/bin/bash
set -euo pipefail
src="$(cd "$(dirname "$0")/.." && pwd)"
input="$src/aes128/build/darwin/appicon.png"
swift "$src/scripts/render-macos-icon.swift" "$src/aes128/build/appicon.png" "$input"
output="$src/aes128/build/darwin/icons.icns"
stage=$(mktemp -d "${TMPDIR:-/tmp}/aes128-icons.XXXXXX")
trap 'rm -rf "$stage"' EXIT
mkdir -p "$stage/AES128.iconset"
for size in 16 32 128 256 512; do
    sips -z "$size" "$size" "$input" --out "$stage/AES128.iconset/icon_${size}x${size}.png" >/dev/null
    retina=$((size * 2))
    sips -z "$retina" "$retina" "$input" --out "$stage/AES128.iconset/icon_${size}x${size}@2x.png" >/dev/null
done
iconutil -c icns "$stage/AES128.iconset" -o "$output"
echo "Generated AES128 macOS icon: $output"
