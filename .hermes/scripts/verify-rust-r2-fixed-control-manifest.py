from __future__ import annotations

import hashlib
import json
import os
import stat
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
MANIFEST = (
    REPO_ROOT
    / "rust"
    / "crates"
    / "inputleap-protocol-legacy"
    / "tests"
    / "fixtures"
    / "manifest-r2.3-fixed-control.json"
)
EXPECTED_FIXTURES = {
    "remote-qinf-payload",
    "remote-ciak-payload",
    "remote-crop-payload",
    "remote-cout-payload",
}
REPARSE_POINT = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)


def fail(message: str) -> None:
    print(f"R2_3_FIXED_CONTROL_MANIFEST_FAIL {message}", file=sys.stderr)
    raise SystemExit(1)


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(64 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def require_regular_file(path: Path, label: str) -> None:
    try:
        metadata = path.lstat()
    except OSError as error:
        fail(f"{label}_stat path={path} error={error}")
    if not stat.S_ISREG(metadata.st_mode):
        fail(f"{label}_not_regular path={path}")
    if getattr(metadata, "st_file_attributes", 0) & REPARSE_POINT:
        fail(f"{label}_reparse_point path={path}")


def main() -> int:
    require_regular_file(MANIFEST, "manifest")
    try:
        manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        fail(f"manifest_parse error={error}")

    if manifest.get("schema") != 1 or manifest.get("tranche") != "R2.3":
        fail("schema_or_tranche")
    if manifest.get("interopScope") != (
        "payload bytes only; receiver-state matrices are Rust policy tests derived by static "
        "inspection of the cited C++ dispatches; no C++ state machine transitions are executed"
    ):
        fail("interop_scope")
    if manifest.get("statefulCoverage") != (
        "none; no C++ state machine transitions are executed"
    ):
        fail("stateful_coverage")
    if manifest.get("contextSemantics") != {
        "direction": "wire sender-to-receiver",
        "state": "receiver state",
    }:
        fail("context_semantics")

    source_relative = manifest.get("sourceManifest")
    if not isinstance(source_relative, str):
        fail("source_manifest_path")
    source_manifest = (MANIFEST.parent / source_relative).resolve()
    if not source_manifest.is_relative_to(REPO_ROOT):
        fail("source_manifest_outside_repo")
    require_regular_file(source_manifest, "source_manifest")
    if sha256(source_manifest) != manifest.get("sourceManifestSha256"):
        fail("source_manifest_hash")

    fixtures = manifest.get("fixtures")
    if not isinstance(fixtures, list) or len(fixtures) != len(EXPECTED_FIXTURES):
        fail("fixture_count")
    names = {entry.get("name") for entry in fixtures if isinstance(entry, dict)}
    if names != EXPECTED_FIXTURES:
        fail("fixture_names")

    for entry in fixtures:
        relative = entry.get("path")
        if not isinstance(relative, str):
            fail("fixture_path_type")
        relative_path = Path(relative)
        if relative_path.is_absolute() or len(relative_path.parts) != 1 or relative_path.name != relative:
            fail(f"fixture_path_unsafe path={relative}")
        fixture = MANIFEST.parent / relative_path
        require_regular_file(fixture, "fixture")
        if fixture.stat().st_size != entry.get("size") or entry.get("size") != 4:
            fail(f"fixture_size path={relative}")
        if sha256(fixture) != entry.get("sha256"):
            fail(f"fixture_hash path={relative}")

    print(
        "R2_3_FIXED_CONTROL_MANIFEST_PASS "
        f"fixtures={len(fixtures)} r0_sha256={manifest['sourceManifestSha256']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
