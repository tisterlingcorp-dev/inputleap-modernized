# InputLeap Tauri application

This directory contains the modern desktop interface for the InputLeap Modernized fork.

## Runtime boundary

The application is not yet a standalone replacement for Input Leap. The Tauri shell manages and displays the production C++ runtime; it does not replace the input-sharing engine:

- Windows: `input-leaps.exe`, supervised by `input-leapd.exe` outside the Tauri process;
- Linux X11: `input-leapc`;
- experimental status provider: `rust/bins/input-leap-agent` or `INPUT_LEAP_AGENT_PATH`.

The Tauri UI and runtime are separate processes. A successful UI launch, running daemon, or TCP connection alone does not prove keyboard/mouse, clipboard, or file-transfer parity. Those capabilities still require the C++ runtime and physical two-machine validation.

## Commands exposed to the frontend

The Tauri bridge currently exposes narrowly scoped commands for:

- diagnostic network topology and sanitized logs;
- authoritative runtime status through authenticated local daemon IPC;
- authenticated runtime start, stop, and reload through daemon IPC;
- topology updates bound to the daemon's durably applied generation;
- a Windows-only, allowlisted launcher for the bundled Qt device/transfer center (the executable must be the trusted sibling `input-leap.exe`).

Peer discovery, human-confirmed pairing/revocation, and file/clipboard transfer controls still run in the Qt device/transfer center opened by that command; they are not native Tauri screens. Do not treat discovery as authorization or claim full feature parity until those flows are validated end-to-end. Generic shell, arbitrary process control, unrestricted filesystem access, and arbitrary network access are not exposed to the frontend.

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
