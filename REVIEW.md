# Source review — 2026-09-26

Changes made before initial publication:

- Removed internal handoff documents, unused platform templates, Windows-specific files and explanatory source comments. Preserved compiler directives, cgo declarations, generated type annotations and third-party licenses.
- Aligned the application version with package version 1.0.3 and replaced the Windows update URL with this repository's releases page.
- Fixed DNS recovery retries while the helper is idle. Added a regression test for recovery after a transient failure.
- Recheck the active console user on every RPC, including existing connections. Added authorization tests for user switching, the login window, missing peer identity and failed console lookup.
- Removed the hard-coded QA server and require explicit disposable test credentials and endpoints.
- Updated Go to 1.26.8, gRPC to 1.83.2 and affected transitive dependencies, including go-git, go-billy and golang.org/x/crypto.
- Added macOS CI and exclusions for generated assets, downloaded cores, credentials and local state.

Go vulnerability checks found no affected application/helper symbols, and no affected GUI imports after the updates. A module-level advisory remains for the unused, deprecated `golang.org/x/crypto/openpgp` package (GO-2026-5932); the client does not import that package.

## Scope

Local checks cover race-enabled Go tests, `go vet`, frontend compilation and npm audit, pinned-core configuration validation, installer lifecycle tests, source secret scanning and app/package compilation. Installer tests mock privileged operating-system commands; building a package does not install it.

The Go vulnerability scan covers the application/helper module graphs. It does not audit the separately downloaded Xray and sing-box executable internals. Checksums verify the pinned downloads; they do not establish the absence of upstream vulnerabilities.

Live VPN traffic, production API accounts, installed-helper upgrades, Keychain prompts, IPv6 leaks, physical sleep/wake, Wi-Fi changes and reboot were not retested during this source review. Read the platform limitations in README before installing a development build.

The public repository contains source only. No Developer ID signed/notarized installer is published by this review.
