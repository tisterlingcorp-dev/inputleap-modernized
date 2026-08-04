#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
REPO_ROOT=$(cd -- "$SCRIPT_DIR/../.." && pwd)
RUST_ROOT="$REPO_ROOT/rust"
export CARGO_HOME="$RUST_ROOT/.tools/linux/cargo"
export RUSTUP_HOME="$RUST_ROOT/.tools/linux/rustup"
export PATH="$RUSTUP_HOME/toolchains/1.97.0-x86_64-unknown-linux-gnu/bin:$CARGO_HOME/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

run() {
    printf '+'
    printf ' %q' "$@"
    printf '\n'
    "$@"
}

cd "$RUST_ROOT"
run rustc --version
run cargo --version
printf '+ cargo metadata --locked --format-version 1 --no-deps >/dev/null\n'
cargo metadata --locked --format-version 1 --no-deps >/dev/null
printf 'RUST_R2_LINUX_METADATA_PASS\n'
run cargo fmt --check
printf 'RUST_R2_LINUX_FMT_PASS\n'
run cargo clippy --locked --workspace --all-targets -- -D warnings
printf 'RUST_R2_LINUX_CLIPPY_PASS\n'
run cargo test --locked --workspace
printf 'RUST_R2_LINUX_TEST_PASS\n'

shopt -s nullglob
deny_candidates=()
for candidate in "$RUST_ROOT/.tools/linux/install-target/release/deps"/cargo_deny-*; do
    if [[ -x "$candidate" && "$candidate" != *.d ]]; then
        deny_candidates+=("$candidate")
    fi
done
if [[ ${#deny_candidates[@]} -ne 1 ]]; then
    printf 'RUST_R2_LINUX_GATE_FAIL cargo_deny_candidates=%s\n' "${#deny_candidates[@]}" >&2
    exit 1
fi
run "${deny_candidates[0]}" --version
run "${deny_candidates[0]}" --locked check
printf 'RUST_R2_LINUX_DENY_PASS\n'
printf 'RUST_R2_LINUX_GATE_PASS audit=WINDOWS_ONLY\n'
