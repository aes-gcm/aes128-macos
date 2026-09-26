# AES128 VPN for macOS

A macOS client for [aes.cx](https://aes.cx). Built for Apple Silicon and macOS 13 or later.

**[Download for macOS](https://github.com/aes-gcm/aes128-macos/releases/download/v1.0.4/AES128-VPN-macOS-Apple-Silicon-1.0.4.pkg)** · [Release notes](https://github.com/aes-gcm/aes128-macos/releases/tag/v1.0.4) · [Website](https://aes.cx)

## Install

1. Download the `.pkg` installer and quit any running copy of AES128 VPN.
2. Open the installer and authorize installation. It installs the app and its VPN service.
3. Open AES128 VPN from Applications, sign in and connect.

Version **1.0.4 beta**. The app uses an Apple Development signature; the installer is unsigned and has not been notarized. macOS may block it. Only if you trust this release, use **System Settings → Privacy & Security → Open Anyway** after attempting to open it. Do not disable Gatekeeper globally. Intel Macs are not supported.

**По-русски:** скачайте `.pkg`, закройте старую версию и запустите установщик. Для установки службы потребуется пароль администратора. Это бета-версия без нотарификации Apple; если macOS блокирует файл, разрешить его можно в «Системные настройки → Конфиденциальность и безопасность → Всё равно открыть».

## Features

- VLESS XHTTP, XTLS Vision and custom VLESS links.
- Domain-based split tunneling.
- Session encryption with a key stored in macOS Keychain.
- Privileged helper with peer authentication, verified core binaries and DNS recovery.

Kill switch and Hysteria2 are not supported. On connection failure, the ordinary network is restored. IPv6 leak protection, sleep/wake, Wi-Fi changes, reboot, Tor and Reality need further live validation.

## Build from source

Requires Go 1.26.8+, Node.js 22.12+, Python 3 and Xcode Command Line Tools.

```sh
python3 scripts/fetch-macos-cores.py ./cores
export AES128_CORES="$PWD/cores"
export AES128_OUTPUT="$PWD/build-macos"
export AES128_SIGN_IDENTITY='Apple Development: YOUR IDENTITY'
./scripts/build-macos.sh
AES128_APP="$AES128_OUTPUT/AES128 VPN.app" ./scripts/build-macos-installer.sh
```

Without a signing identity, the app receives an ad-hoc signature for build inspection. Set `AES128_INSTALLER_IDENTITY` to sign the installer with a Developer ID Installer identity. Notarization is a separate distribution step.

| Directory | Contents |
| --- | --- |
| `aes128` | Desktop app and frontend |
| `backend` | macOS VPN helper |
| `proto` | gRPC protocol |
| `scripts` | Download, build and packaging tools |
| `packaging` | macOS installer resources |
| `licenses` | Third-party licenses |

## Third-party components

[Xray 26.2.6](https://github.com/XTLS/Xray-core/tree/v26.2.6) uses MPL-2.0; [sing-box 1.11.15](https://github.com/SagerNet/sing-box/tree/v1.11.15) uses GPL-3.0. Their licenses are included in the app and `licenses/`; upstream source archives accompany the release. Download checksums are pinned in `CORE_PROVENANCE.json`. IBM Plex Mono uses OFL-1.1, included with the font assets. Other dependencies retain their respective licenses.

A license for the original AES128 application code has not been specified.
