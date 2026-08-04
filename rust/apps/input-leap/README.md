# InputLeap Tauri application

This directory contains the modern desktop interface for the InputLeap Modernized fork.

## Runtime boundary

The application is not yet a standalone replacement for Input Leap. It provides diagnostic topology, authenticated daemon status, authenticated runtime reload and sanitized logs, while the production input-sharing process is still the C++ compatibility runtime:

- Windows: `input-leaps.exe`, supervised by `input-leapd.exe` outside the Tauri process;
- Linux X11: `input-leapc`;
- experimental status provider: `rust/bins/input-leap-agent` or `INPUT_LEAP_AGENT_PATH`.

The application must not claim keyboard/mouse parity from a successful UI launch alone. Real sharing still requires the C++ runtime and a physical two-machine validation.

## Commands exposed to the frontend

The first authenticated control cut exposes narrowly scoped commands for:

- diagnostic network topology and sanitized logs;
- authoritative runtime status through authenticated local daemon IPC;
- runtime reload bound to the daemon's durably applied generation.

Start and stop are intentionally absent from the Tauri bridge. Generic shell, process-control, filesystem and network access are not exposed to the frontend.

## Local checks

From the repository root:

```bash
cargo fmt --manifest-path rust/apps/input-leap/src-tauri/Cargo.toml --check
cargo test --locked --manifest-path rust/apps/input-leap/src-tauri/Cargo.toml
cargo deny --manifest-path rust/apps/input-leap/src-tauri/Cargo.toml check licenses
```

Run the interface with:

```bash
cargo run --locked --manifest-path rust/apps/input-leap/src-tauri/Cargo.toml
```

Platform-specific Tauri prerequisites must be installed first. Do not commit generated files under `target/`.

## License

The package declares `GPL-2.0-only` and follows the repository `LICENSE`, including the Input Leap OpenSSL linking permission where applicable. Dependency licenses are recorded in `Cargo.lock`, checked by `cargo-deny`, and summarized in the repository `THIRD_PARTY_NOTICES.md`.
