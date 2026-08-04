#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "${SCRIPT_DIR}"

echo "Fetching updates from origin..."
git fetch origin --prune

current_branch="$(git branch --show-current)"
if [[ -z "${current_branch}" ]]; then
    echo "Cannot update: not currently on a branch." >&2
    exit 1
fi

upstream="$(git rev-parse --abbrev-ref --symbolic-full-name '@{u}' 2>/dev/null || true)"
if [[ -z "${upstream}" ]]; then
    upstream="origin/${current_branch}"
fi

echo "Updating ${current_branch} from ${upstream}..."
git merge --ff-only "${upstream}"

echo "Configuring local build..."
cmake --preset release

echo "Building local executables..."
cmake --build --preset release --parallel

echo "Running Release tests..."
QT_QPA_PLATFORM=offscreen ctest --preset release

echo "Build complete:"
ls -lh out/build/release/bin/input-leap out/build/release/bin/input-leapc out/build/release/bin/input-leaps

echo
echo "Version:"
(out/build/release/bin/input-leapc --version 2>&1 | sed -n '1,2p') || true

echo
echo "Run the new local GUI with:"
echo "  ./run-inputleap-modernized.sh"
