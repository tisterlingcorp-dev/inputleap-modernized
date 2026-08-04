#!/usr/bin/env bash
#
# Build and optionally install an InputLeap .deb package on Pop!_OS/Ubuntu.
#
# Usage:
#   ./linux/build_popos_deb.sh
#   ./linux/build_popos_deb.sh --install

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
INSTALL_PACKAGE=0

for arg in "$@"; do
    case "$arg" in
        --install)
            INSTALL_PACKAGE=1
            ;;
        -h|--help)
            sed -n '1,12p' "$0"
            exit 0
            ;;
        *)
            echo "Unknown option: $arg" >&2
            exit 2
            ;;
    esac
done

if ! command -v apt-get >/dev/null 2>&1; then
    echo "This installer is intended for Pop!_OS/Ubuntu systems with apt." >&2
    exit 1
fi

if [ ! -f /etc/os-release ]; then
    echo "Could not detect the Linux distribution." >&2
    exit 1
fi

. /etc/os-release
case "${ID:-}" in
    pop|ubuntu|linuxmint|debian)
        ;;
    *)
        echo "Warning: detected '${PRETTY_NAME:-unknown}'. Continuing because it may still be Debian/Ubuntu compatible."
        ;;
esac

echo "Installing build dependencies..."
sudo apt-get update
sudo apt-get install -y \
    build-essential \
    cmake \
    debhelper \
    devscripts \
    dpkg-dev \
    fakeroot \
    git \
    libavahi-compat-libdnssd-dev \
    libssl-dev \
    libx11-dev \
    libxext-dev \
    libxi-dev \
    libxinerama-dev \
    libxrandr-dev \
    libxtst-dev \
    ninja-build \
    pkg-config \
    qt6-base-dev \
    qt6-tools-dev \
    qt6-tools-dev-tools \
    xvfb

cd "$REPO_DIR"

echo "Initializing submodules..."
git submodule update --init --recursive

echo "Preparing Debian packaging metadata..."
rm -rf debian
cp -a dist/debian debian

export DEB_BUILD_OPTIONS="${DEB_BUILD_OPTIONS:-nocheck}"

echo "Building InputLeap .deb package..."
dpkg-buildpackage -us -uc -b

PACKAGE_PATH="$(find "$REPO_DIR/.." -maxdepth 1 -type f -name 'input-leap_*.deb' -print | sort | tail -n 1)"

if [ -z "$PACKAGE_PATH" ]; then
    echo "Build finished, but no input-leap .deb package was found next to the repository." >&2
    exit 1
fi

echo "Package created:"
echo "  $PACKAGE_PATH"

if [ "$INSTALL_PACKAGE" -eq 1 ]; then
    echo "Installing package..."
    sudo apt-get install -y "$PACKAGE_PATH"
    echo "InputLeap installed. Start it from the app menu or run: input-leap"
else
    echo "To install it now, run:"
    echo "  sudo apt-get install '$PACKAGE_PATH'"
fi
