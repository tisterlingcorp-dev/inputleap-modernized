#!/usr/bin/env python3
"""Run fail-closed local quality gates for the R1 Rust workspace."""

from __future__ import annotations

import json
import os
import shutil
import stat
import subprocess
import sys
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TOOLS_BIN = ROOT / ".tools" / "bin"
EXECUTABLE_SUFFIX = ".exe" if os.name == "nt" else ""
EXPECTED_TOOLCHAIN_CHANNEL = "1.97.0"
EXPECTED_VERSIONS = {
    "rustc": "rustc 1.97.0 (2d8144b78 2026-07-07)",
    "cargo": "cargo 1.97.0 (c980f4866 2026-06-30)",
    "cargo-deny": "cargo-deny 0.20.2",
    "cargo-audit": "cargo-audit 0.22.2",
}


def display(command: list[str]) -> None:
    """Print a command before execution."""
    print("+", subprocess.list2cmdline(command), flush=True)


def path_tool(name: str) -> Path:
    """Return a required PATH tool; rustup symlink names must be preserved."""
    found = shutil.which(name)
    if found is None:
        raise SystemExit(f"missing PATH tool: {name}")
    path = Path(found)
    if not path.exists():
        raise SystemExit(f"PATH tool does not exist: {path}")
    return path.absolute()


def is_unsafe_link(path: Path) -> bool:
    """Detect symlinks and Windows reparse points such as junctions."""
    if path.is_symlink():
        return True
    if os.name == "nt":
        attributes = getattr(path.lstat(), "st_file_attributes", 0)
        return bool(attributes & stat.FILE_ATTRIBUTE_REPARSE_POINT)
    return False


def local_tool(name: str) -> Path:
    """Return a required project-local Cargo tool or fail closed."""
    for directory in (ROOT / ".tools", TOOLS_BIN):
        if not directory.is_dir():
            raise SystemExit(f"missing project-local tool directory: {directory}")
        if is_unsafe_link(directory):
            raise SystemExit(f"refusing linked project-local tool directory: {directory}")
    path = TOOLS_BIN / f"{name}{EXECUTABLE_SUFFIX}"
    if not path.is_file():
        raise SystemExit(
            f"missing project-local tool: {path}\n"
            "install the pinned tools from rust/README.md"
        )
    if is_unsafe_link(path):
        raise SystemExit(f"refusing symlinked project-local tool: {path}")
    return path.resolve(strict=True)


def verify_exact_version(name: str, executable: Path) -> None:
    """Require the exact pinned version string for one executable."""
    command = [str(executable), "--version"]
    display(command)
    result = subprocess.run(
        command,
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    actual = result.stdout.strip()
    expected = EXPECTED_VERSIONS[name]
    if actual != expected:
        raise SystemExit(
            f"unexpected {name} version: expected {expected!r}, got {actual!r}"
        )
    print(f"verified {actual}", flush=True)


def verify_toolchain_configuration() -> tuple[Path, Path]:
    """Validate the checked-in toolchain policy and active Rust executables."""
    with (ROOT / "rust-toolchain.toml").open("rb") as stream:
        config = tomllib.load(stream).get("toolchain", {})

    if config.get("channel") != EXPECTED_TOOLCHAIN_CHANNEL:
        raise SystemExit("rust-toolchain.toml channel does not match the R1 pin")
    components = set(config.get("components", []))
    if not {"clippy", "rustfmt"}.issubset(components):
        raise SystemExit("rust-toolchain.toml must include clippy and rustfmt")

    override = os.environ.get("RUSTUP_TOOLCHAIN")
    if override and not (
        override == EXPECTED_TOOLCHAIN_CHANNEL
        or override.startswith(f"{EXPECTED_TOOLCHAIN_CHANNEL}-")
    ):
        raise SystemExit(f"refusing RUSTUP_TOOLCHAIN override: {override}")

    rustc = path_tool("rustc")
    cargo = path_tool("cargo")
    verify_exact_version("rustc", rustc)
    verify_exact_version("cargo", cargo)
    return rustc, cargo


def verify_lockfile(root: Path = ROOT) -> None:
    """Require a checked-in regular lockfile before Cargo graph resolution."""
    lockfile = root / "Cargo.lock"
    if not lockfile.is_file() or lockfile.is_symlink():
        raise SystemExit(f"missing or unsafe Cargo.lock: {lockfile}")


def verify_workspace_members(cargo: Path) -> None:
    """Require lock consistency and inherited lint/license policy for every member."""
    command = [
        str(cargo),
        "metadata",
        "--locked",
        "--format-version",
        "1",
        "--no-deps",
    ]
    display(command)
    result = subprocess.run(
        command,
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    metadata = json.loads(result.stdout)
    members = set(metadata["workspace_members"])
    packages = {package["id"]: package for package in metadata["packages"]}

    for member in sorted(members):
        package = packages.get(member)
        if package is None:
            raise SystemExit(f"workspace member missing from metadata: {member}")
        manifest_path = Path(package["manifest_path"]).resolve(strict=True)
        if not manifest_path.is_relative_to(ROOT.resolve()):
            raise SystemExit(f"workspace member escapes rust/: {manifest_path}")
        with manifest_path.open("rb") as stream:
            manifest = tomllib.load(stream)
        if manifest.get("lints", {}).get("workspace") is not True:
            raise SystemExit(f"workspace lints not inherited: {manifest_path}")
        license_policy = manifest.get("package", {}).get("license", {})
        if not isinstance(license_policy, dict) or license_policy.get("workspace") is not True:
            raise SystemExit(f"workspace license not inherited: {manifest_path}")

    print(f"verified workspace policy for {len(members)} member(s)", flush=True)


def run(command: list[str]) -> None:
    """Run one gate from the workspace root and stop on failure."""
    display(command)
    subprocess.run(command, cwd=ROOT, check=True)


def main() -> int:
    """Execute formatting, lint, test, license and current-advisory gates."""
    _, cargo = verify_toolchain_configuration()
    verify_lockfile()
    cargo_deny = local_tool("cargo-deny")
    cargo_audit = local_tool("cargo-audit")
    verify_exact_version("cargo-deny", cargo_deny)
    verify_exact_version("cargo-audit", cargo_audit)
    verify_workspace_members(cargo)

    commands = [
        [str(cargo), "fmt", "--check"],
        [
            str(cargo),
            "clippy",
            "--locked",
            "--workspace",
            "--all-targets",
            "--",
            "-D",
            "warnings",
        ],
        [str(cargo), "test", "--locked", "--workspace"],
        [str(cargo_deny), "--locked", "check"],
        [str(cargo_audit), "audit", "--file", "Cargo.lock"],
    ]

    for command in commands:
        run(command)

    print("R1_GATE_PASS", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
