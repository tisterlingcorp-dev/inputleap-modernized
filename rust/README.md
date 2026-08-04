# Input Leap Rust workspace (R1)

This directory contains the minimal Rust workspace foundation introduced in R1.

The existing C++ application remains the Input Leap runtime. This tranche does not replace that runtime, provide a Rust runtime, add Tauri integration, or claim feature/protocol parity with the C++ implementation.

Current workspace membership is intentionally limited to crates under `crates/*`.
Crates inherit the `GPL-2.0-only` base identifier; the repository `LICENSE`
remains authoritative for the additional OpenSSL permission.

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
