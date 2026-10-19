# Candidate packaging

Run `sh go-client/scripts/build.sh` from any directory to produce the Windows
amd64 and macOS amd64/arm64 service payloads, plus the Windows GUI-subsystem
installer helper. Outputs are isolated under `artifacts/go-client/0.2.0`.
`GO`, `VERSION`, `TARGETS` and `OUTPUT_ROOT` can select the toolchain and output.
No install or service registration occurs during this build.

On a Windows packaging host, build
`installer/Sf.EndpointAI.Go.Setup/Sf.EndpointAI.Go.Setup.wixproj`, supplying the
existing private `ProductionInputDir` with `client-credentials.json` and
`Set-ProductionClientControl.ps1`. This project reuses the original MSI product
upgrade identity, service identity and transactional action sequence. The Go
helper implements all seven original actions and preserves the legacy
`rollback.json` schema in the protected InstallerState directory. Credentials
are never written to its logs. DPAPI protection of persisted client secrets is
provided by the service, as in the existing architecture.

On a Mac packaging host, use the existing PKG entrypoint with
`CLIENT_IMPLEMENTATION=go VERSION=0.2.0 ARCH=arm64` (or `ARCH=x86_64`), providing
`CLIENT_CREDENTIALS_FILE` privately. Signing variables remain
`APP_SIGN_IDENTITY` and `INSTALLER_SIGN_IDENTITY`; use the existing notarization
script afterward. These operations require actual signing identities and must
be performed in the approved release environment.

Both package paths retain the old data paths, launcher/service names,
upgrade/quiesce/recovery flows and uninstall entrypoints. The existing .NET
build remains the default. Candidate packaging must not be mistaken for native
installation acceptance: Windows and both Mac architectures still require
upgrade, rollback, reboot, uninstall, signing, IOA and 4-hour validation.

Before rollback from 0.2.0 to 0.1.22, stop the candidate service and use the
existing recovery procedure with the retained old package. MSI MajorUpgrade
blocks ordinary downgrade installs; do not force a downgrade while running.
