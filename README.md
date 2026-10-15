# InputLeap Modernized

> **Unofficial fork.** This repository is not an official release of the Input Leap project and is not endorsed by its maintainers.

InputLeap Modernized is an experimental Windows-focused fork of [Input Leap](https://github.com/input-leap/input-leap). It combines a Rust/Tauri desktop interface with the existing C++/Qt Input Leap runtime. The C++ runtime remains responsible for production input and clipboard sharing; the Rust runtime is not yet its replacement.

Current fork version: `3.7.3-modernized`
Tauri application version: `0.1.3`

## Current status

The migration is intentionally hybrid:

```text
Rust/Tauri UI
  ├─ status, topology, configuration and lifecycle controls
  └─ starts/monitors the existing runtime
       └─ input-leaps on Windows
```

The C++/Qt runtime is still required for production keyboard, mouse and clipboard sharing. The Rust crates and agent contain protocol and platform migration work, but they do not yet replace every C++ runtime responsibility. Removing `src/`, CMake, Qt or the C++ executables now would break the working application.

## Supported scope

The planned product and release acceptance target is:

- Windows 10/11 x64;
- Windows ↔ Windows operation over the local network;
- the existing C++/Qt runtime supervised by the Tauri interface.

Linux build scripts and inherited cross-platform source remain in the repository, but Linux is not part of the planned product release or its acceptance criteria. macOS and Wayland are likewise outside the release scope. No platform support or security property should be inferred solely from the presence of source code; each release capability requires validation on the packaged build.

## Main functionality

- keyboard and mouse sharing through the existing C++/Qt runtime;
- clipboard text, files, folders and images;
- encrypted runtime transport with certificate-based peer trust;
- topology and runtime status in the Tauri interface;
- runtime start/stop controls;
- fail-closed clipboard image conversion and hidden transfer staging;
- a single notification-area icon when the Tauri interface supervises the C++ runtime.

## Repository layout

| Path | Purpose |
| --- | --- |
| `rust/apps/input-leap` | Tauri desktop interface and static frontend |
| `rust/bins` | experimental Rust executables and platform agents |
| `rust/crates` | Rust protocol, transport and shared-domain crates |
| `src` | current C++/Qt compatibility runtime |
| `linux` | inherited Linux build and packaging helpers (not a release target) |
| `docs/architecture/rust-rewrite` | active migration contracts and threat model |
| `dist` | source packaging definitions; generated installers are not versioned |

Historical gate logs, machine-specific handoff notes, phase scripts, screenshots and generated installers are intentionally excluded from source control.

## Build and test

### Rust workspace

The main Rust workspace uses the pinned toolchain in `rust/rust-toolchain.toml`:

```bash
cargo fmt --manifest-path rust/Cargo.toml --all --check
cargo clippy --locked --manifest-path rust/Cargo.toml --workspace --all-targets -- -D warnings
cargo test --locked --manifest-path rust/Cargo.toml --workspace
cargo deny --manifest-path rust/Cargo.toml check
```

### Tauri application

Install the Tauri system prerequisites for the target platform, then run:

```bash
cargo fmt --manifest-path rust/apps/input-leap/src-tauri/Cargo.toml --check
cargo test --locked --manifest-path rust/apps/input-leap/src-tauri/Cargo.toml
cargo deny --manifest-path rust/apps/input-leap/src-tauri/Cargo.toml check licenses
cargo run --locked --manifest-path rust/apps/input-leap/src-tauri/Cargo.toml
```

The Tauri interface expects the compatible C++ executables to be installed or discoverable in one of the runtime locations implemented in `src-tauri/src/main.rs`.

### C++ compatibility runtime

The runtime currently requires CMake, C++ build tools, Qt and OpenSSL. See [`docs/building.md`](docs/building.md) for upstream build prerequisites. Platform helpers are also available:

```text
Windows: clean_build.ps1
Linux:   linux/build_popos_deb.sh
```

`clean_build.ps1` still supports the legacy Inno Setup package because it is the current fallback installer for the C++ runtime. Generated `.exe` installers must remain outside Git.

## Security and private material

Do not commit or publish:

- private keys, combined certificate/private-key PEM files or trust stores;
- real hostnames, user names, IP addresses or machine-specific paths;
- runtime logs, screenshots, packet captures or transfer staging data;
- generated installers, DLL bundles or build directories.

Production operation must keep transport cryptography enabled. Do not use crypto-disable flags as a workaround. Certificate trust, device pairing and application authorization are distinct controls; do not describe a peer as securely paired unless the relevant control channel and data operation enforce that authorization. Review the active contracts in [`docs/architecture/rust-rewrite`](docs/architecture/rust-rewrite) before changing transport, trust, update or process-lifecycle behavior.

## Distribution status

This checkout is maintained for private use while the Windows installer, security controls, clean-machine validation and license packaging are completed. Do not distribute binaries until a fresh dependency inventory, all applicable license texts/notices, corresponding-source compliance, relinkability where required, and generated installer contents have been reviewed.

Security and license checks must be evaluated against the Windows release dependency graph. Linux-only dependencies are not part of this release target, but remain documented in the source dependency inventory. Do not suppress an applicable Windows advisory without a documented review and mitigation.

The repository intentionally does not contain a prebuilt Windows installer. Build outputs should be generated from a reviewed source revision and accompanied by a software bill of materials and the applicable third-party notices before distribution.

## Handoff to Codex — 2026-08-04

The current public source handoff is intentionally paused. Do not infer that CI is green or that a release is ready.

### Repository and branch

- Public repository: `https://github.com/tisterlingcorp-dev/inputleap-modernized`
- Default branch: `master`
- Local working branch: `public-sanitized`, tracking `modernized/master`
- Last published commit: `569eb7e6` (`fix: provide non-Windows update helpers`)
- Working tree was clean after that push.

### Changes made during publication

The sanitized public snapshot was recreated without private history, `.git`, caches, `.pyc`, DLLs or generated installers. The following minimal build fixes were then published because public CI exposed missing or incompatible source content:

1. `49e9cfdf` — include required CMake modules;
2. `cdb5577d` — restore public dependency gitlinks `ext/gtest` and `ext/gulrak-filesystem`;
3. `9ce5f386` — include `src/lib/server/Config.h`;
4. `569eb7e6` — provide non-Windows implementations for update helpers used by Linux compilation.

The last fix was based on a CodeQL build failure reporting undefined `StagingDirectoryLock` and `removeFileWithoutReparseRace` on Linux. It was not locally compiled because the available `out/build/debug-tests` directory had no `build.ninja`; it must be verified by a clean CI build.

### CI state at handoff

The runs for `569eb7e6` were started but had not finished when work was paused:

- Build tests: queued;
- Quality: pending;
- CodeQL: in progress.

Previous CodeQL runs failed during C++ compilation, not because of a CodeQL finding. The first error was the missing non-Windows update helpers described above. Inspect the logs for the new commit before changing source again. Fix only the first reproducible error and rerun all gates.

### Required next steps

1. Confirm the public branch and working tree:

   ```bash
   git status --short --branch
   git ls-remote modernized refs/heads/master
   ```

2. Check the three workflows for the current HEAD. A timeout or cancellation is not a pass:

   ```bash
   gh run list --repo tisterlingcorp-dev/inputleap-modernized --limit 10 \
     --json databaseId,workflowName,status,conclusion,headSha
   ```

3. If a workflow fails, read only its failed log first:

   ```bash
   gh run view <RUN_ID> --repo tisterlingcorp-dev/inputleap-modernized --log-failed
   ```

4. Before any release or binary publication, independently verify: clean source tree, no secrets or opaque binaries, submodules resolve publicly, Build tests/Quality/CodeQL pass, `cargo deny` advisories are explicitly reviewed, and third-party notices/legal packaging are complete.

5. Do not publish a release, installer, update manifest, signing key, or auto-update channel from this handoff alone.

### Known blockers and cautions

- `cargo deny --manifest-path rust/apps/input-leap/src-tauri/Cargo.toml check advisories` previously reported unmaintained GTK3 and Unicode transitive crates; advisories were not suppressed.
- Bonjour/mDNSResponder redistribution and generated installer contents still require legal/dependency review.
- macOS and Wayland remain permanently out of scope.
- Production runtime validation requires TLS/mTLS and must not use `--disable-crypto`.
- Do not commit private runtime logs, credentials, machine-specific paths, build directories or generated binaries.

## License

The C++ code and derivative project source are licensed under **GPL-2.0-only with the Input Leap OpenSSL linking exception** in [`LICENSE`](LICENSE). The Rust packages declare `GPL-2.0-only`; the additional OpenSSL permission in the repository license remains applicable where relevant.

Dependencies and incorporated components remain under their respective licenses. See [`THIRD_PARTY_NOTICES.md`](THIRD_PARTY_NOTICES.md).

The Input Leap name and visual identity identify the upstream project. This fork must be described as unofficial and must not imply upstream endorsement.
