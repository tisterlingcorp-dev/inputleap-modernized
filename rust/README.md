# Input Leap Rust workspace

This directory contains the Rust migration libraries, including the Windows pilot
control contract and supervisor policy. See [Windows delivery](../docs/architecture/rust-rewrite/windows-rust-delivery.md)
for the approved Rust-only target and remaining acceptance work.

The C++ application remains the operational runtime. Existing Rust TLS/protocol/
transfer primitives and Windows input backend are partial; no production parity
or complete Windows worker/service is claimed. Tauri, agent and server are separate
Cargo workspaces and must be tested explicitly.

Current workspace membership is intentionally limited to crates under `crates/*`.
Crates inherit the `GPL-2.0-only` base identifier; the repository `LICENSE`
remains authoritative for the additional OpenSSL permission.

## Windows pilot gate

From the repository root, run `./scripts/windows/gate_rust_pilot.ps1` in PowerShell.
It validates locked metadata, formatting, Clippy, tests, Release builds and
dependency policy for the root, agent, server and Tauri manifests. The matching
`Rust Windows pilot` workflow does not publish or install anything. The optional
`-SkipDependencyAudit` is local-only and never emits the full release-gate marker.

## Local gates

Install the pinned supply-chain tools inside this workspace, not globally:

```text
cd rust
cargo install --root .tools cargo-deny --version 0.20.2 --locked
cargo install --root .tools cargo-audit --version 0.22.2 --locked
```

Then run all R1 gates from `rust/`:

```text
# Windows
python scripts/gate.py

# Linux/macOS
python3 scripts/gate.py
```

The runner checks Cargo metadata, formatting, Clippy with warnings denied,
workspace tests, dependency policy, exact pinned tool versions, and RustSec
advisories. Missing or wrong-version local tools are a hard failure.

The advisory checks intentionally use the current RustSec databases and may
fetch updates over HTTPS. Their result is time-dependent rather than
byte-reproducible; an unavailable or failed update makes the gate fail closed.
