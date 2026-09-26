# AES128 VPN for macOS

macOS client for [aes.cx](https://aes.cx), built with Go, Wails and a JavaScript frontend. Targets Apple Silicon and macOS 13 or later.

[Инструкция на русском](README_MACOS_RU.md)

## Status

Version 1.0.3, with source review fixes. This repository publishes the macOS source and packaging tools. It is a development build, not a notarized public installer. Intel and universal builds are not supported by the build scripts.

Supports VLESS XHTTP, XTLS Vision, custom VLESS links and domain-based split tunneling. A privileged helper manages Xray, sing-box, routes and DNS; the GUI runs as the signed-in user. Session data is encrypted with a key stored in macOS Keychain.

Kill switch and Hysteria2 are unavailable. On connection failure, the helper restores the ordinary network. Live IPv6 leak testing, physical sleep/wake, Wi-Fi changes, reboot, Tor and Reality require further validation. Automated tests do not certify these scenarios.

## Build

Requirements: Apple Silicon Mac, macOS 13+, Xcode Command Line Tools, Go 1.26.8 or newer, Node.js 22.12 or newer, and Python 3.

```sh
python3 scripts/fetch-macos-cores.py ./cores
export AES128_CORES="$PWD/cores"
export AES128_OUTPUT="$PWD/build-macos"
export AES128_SIGN_IDENTITY='Apple Development: YOUR IDENTITY'
./scripts/build-macos.sh
```

Use an Apple signing identity for testing helper registration and Keychain access. Without `AES128_SIGN_IDENTITY`, the script uses an ad-hoc signature suitable for build inspection; installation and helper authorization are not certified in that mode. Distribution through Gatekeeper requires appropriate Developer ID signing and notarization, which these scripts do not perform automatically.

Build an installer from the resulting app:

```sh
AES128_APP="$AES128_OUTPUT/AES128 VPN.app" ./scripts/build-macos-installer.sh
```

Set `AES128_INSTALLER_IDENTITY` to your Developer ID Installer identity to sign the package. Otherwise the installer is unsigned. Do not commit signing certificates, credentials, downloaded cores or generated packages.

## Verification

Build frontend assets before running GUI module tests, because Go embeds them.

```sh
(cd aes128/frontend && npm ci --ignore-scripts && npm run build)
(cd backend && go test -race ./... && go vet ./...)
(cd aes128 && MACOSX_DEPLOYMENT_TARGET=13.0 go test -race -ldflags=-extldflags=-mmacosx-version-min=13.0 ./... && go vet ./...)
(cd proto/vpnpb && go test ./... && go vet ./...)
python3 packaging/macos/tests/test_scripts.py
```

For configuration validation with the pinned cores, set `AES128_CORE_DIR` to an absolute path when running backend tests. Installer tests stub privileged system commands. Live API, Keychain and tunnel tests are opt-in; see the Russian guide before enabling them.

## Layout

| Directory | Purpose |
| --- | --- |
| `aes128/` | Desktop application, storage and frontend |
| `backend/` | macOS privileged helper and network configuration |
| `proto/` | gRPC protocol and generated bindings |
| `scripts/` | Core download, app build and installer packaging |
| `packaging/macos/` | Installer resources, lifecycle scripts and tests |
| `licenses/` | Third-party core licenses |

## External components and licensing

Pinned downloads and checksums are recorded in `CORE_PROVENANCE.json`. The downloader verifies archive SHA-256 values before extracting executables.

- [Xray 26.2.6 source](https://github.com/XTLS/Xray-core/tree/v26.2.6): MPL-2.0; license in `licenses/`.
- [sing-box 1.11.15 source](https://github.com/SagerNet/sing-box/tree/v1.11.15): GPL-3.0; license in `licenses/`.
- IBM Plex Mono: OFL-1.1; license alongside the font assets.
- Go and npm dependencies retain their respective licenses.

No license for the original AES128 application code has been selected. Public visibility alone does not grant an open-source license. Third-party license texts apply to their respective components.
