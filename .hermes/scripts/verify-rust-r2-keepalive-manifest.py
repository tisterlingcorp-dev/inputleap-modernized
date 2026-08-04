from __future__ import annotations

import hashlib
import json
import os
import stat
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
FIXTURE_DIR = (
    REPO_ROOT / "rust" / "crates" / "inputleap-protocol-legacy" / "tests" / "fixtures"
)
MANIFEST = FIXTURE_DIR / "manifest-r2.5-keepalive.json"
R0_RELATIVE = Path("docs/architecture/rust-rewrite/r0-source-manifest.json")
EXPECTED_R0_SHA256 = "0ad0796e14367bf461e3df3022c1e71a6d303a6b4561a26ee1b2c506eb6fbabf"
EXPECTED_SCOPES = {
    "interopScope": "payload bytes and PacketStreamFilter outer framing",
    "rustStatefulCoverage": "none",
    "cppStatefulCoverage": "real ServerProxy and ClientProxy1_6 dispatch via public event APIs",
    "timerExpirationCoverage": "none (blocked pending virtual clock)",
}
EXPECTED_CONTEXTS = {
    "decodeContexts": [
        "server-to-client/client-handshake",
        "server-to-client/active",
        "client-to-server/active",
    ],
    "encodeObservedContexts": [
        "server-to-client/active",
        "client-to-server/server-awaiting-info",
        "client-to-server/active",
    ],
    "encodeUnknownContexts": ["server-to-client/client-handshake"],
}
EXPECTED_STATEFUL_CASES = [
    "client-handshake: CALV output",
    "client-active: CALV then CNOP output",
    "server-handshake: close and CLIENT_PROXY_DISCONNECTED",
    "server-active: no protocol send and two structural heartbeat alarm resets",
]
EXPECTED_FILES = {
    "remote-calv-payload.bin": "73b6a222e74a48bcaea5d5a367bd9ecb28b0ac6a983ed27e885da39fe20d9e18",
    "../../../../../src/test/rust-r2/KeepAliveInterop.cpp": "e26557762570fffc4638db2686f4a577cb4a66e726b66fcff3b3e58a887274e6",
    "../../../../../src/test/rust-r2/KeepAliveStatefulInterop.cpp": "2b1a2a53d1cd5b2712c1d549195fb9385d99874d4759024282383bf79db375b1",
}


def fail(message: str) -> None:
    raise ValueError(message)


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def lexical(path: Path) -> Path:
    return Path(os.path.abspath(path))


def require_regular_no_reparse(path: Path, label: str) -> Path:
    repo = lexical(REPO_ROOT)
    candidate = lexical(path)
    try:
        relative = candidate.relative_to(repo)
    except ValueError as error:
        raise ValueError(f"{label} escapes repository: {candidate}") from error
    current = repo
    for part in relative.parts:
        current = current / part
        try:
            metadata = current.lstat()
        except FileNotFoundError as error:
            raise ValueError(f"{label} is missing: {current}") from error
        if stat.S_ISLNK(metadata.st_mode):
            fail(f"{label} contains symlink: {current}")
        attributes = getattr(metadata, "st_file_attributes", 0)
        reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
        if attributes & reparse_flag:
            fail(f"{label} contains reparse point: {current}")
    if not candidate.is_file():
        fail(f"{label} is not a regular file: {candidate}")
    return candidate


def main() -> int:
    require_regular_no_reparse(MANIFEST, "manifest")
    with MANIFEST.open("r", encoding="utf-8") as handle:
        data = json.load(handle)

    if data.get("schema") != 1 or data.get("tranche") != "R2.5":
        fail("unexpected manifest schema or tranche")
    for key, expected in EXPECTED_SCOPES.items():
        if data.get(key) != expected:
            fail(f"unexpected {key}: {data.get(key)!r}")
    if data.get("contextSemantics") != {
        "direction": "wire sender-to-receiver",
        "state": "receiver state",
    }:
        fail("unexpected contextSemantics")

    source_text = data.get("sourceManifest")
    if source_text != "../../../../../docs/architecture/rust-rewrite/r0-source-manifest.json":
        fail("unexpected sourceManifest path")
    source_manifest = lexical(FIXTURE_DIR / source_text)
    if source_manifest != lexical(REPO_ROOT / R0_RELATIVE):
        fail("sourceManifest does not resolve to repository R0 manifest")
    require_regular_no_reparse(source_manifest, "source manifest")
    if data.get("sourceManifestSha256") != EXPECTED_R0_SHA256:
        fail("manifest R0 hash field is stale")
    if sha256(source_manifest) != EXPECTED_R0_SHA256:
        fail("current R0 manifest hash differs from frozen R2.5 anchor")

    fixture = data.get("fixture")
    if not isinstance(fixture, dict):
        fail("fixture must be an object")
    if fixture.get("message") != "CALV" or fixture.get("cppSymbol") != "kMsgCKeepAlive":
        fail("unexpected CALV identity")
    if fixture.get("file") != "remote-calv-payload.bin":
        fail("fixture path must be the frozen basename")
    if fixture.get("size") != 4 or fixture.get("terminal") is not False:
        fail("unexpected CALV size or terminal metadata")
    for key, expected in EXPECTED_CONTEXTS.items():
        if fixture.get(key) != expected:
            fail(f"unexpected fixture.{key}: {fixture.get(key)!r}")
    asymmetries = fixture.get("asymmetries")
    if not isinstance(asymmetries, list) or len(asymmetries) != 1:
        fail("encode-only ServerAwaitingInfo asymmetry must be explicit")
    source_refs = fixture.get("sourceRefs")
    if not isinstance(source_refs, list) or len(source_refs) < 6:
        fail("CALV sourceRefs are incomplete")

    outer = data.get("outerFrame")
    if outer != {
        "producer": "PacketStreamFilter::write",
        "size": 8,
        "hex": "0000000443414c56",
    }:
        fail("unexpected outerFrame metadata")
    if data.get("statefulCases") != EXPECTED_STATEFUL_CASES:
        fail("unexpected statefulCases")
    if data.get("limitationSourceRefs") != [
        "src/lib/base/EventQueue.h:114-118",
        "src/lib/base/EventQueue.cpp:111-137",
        "src/test/global/TestEventQueue.cpp:34-39",
    ]:
        fail("timer limitation source references are incomplete")

    unknowns = data.get("unknowns")
    if not isinstance(unknowns, list) or len(unknowns) != 3:
        fail("manifest must preserve all three CALV limitations")
    if "UNKNOWN" not in unknowns[0] or "not authorized" not in unknowns[0]:
        fail("handshake encode unknown must remain fail-closed")
    if "virtual clock" not in unknowns[1] or "does not execute" not in unknowns[2]:
        fail("timer/Rust stateful limitations must remain explicit")

    harnesses = data.get("harnesses")
    if not isinstance(harnesses, list) or len(harnesses) != 2:
        fail("manifest must contain exactly two harnesses")
    manifest_hashes = {fixture["file"]: fixture.get("sha256")}
    for entry in harnesses:
        if not isinstance(entry, dict) or not isinstance(entry.get("coverage"), str):
            fail("invalid harness entry")
        manifest_hashes[entry.get("file")] = entry.get("sha256")
    if manifest_hashes != EXPECTED_FILES:
        fail("manifest file/hash set mismatch")

    for relative, expected_hash in EXPECTED_FILES.items():
        path = require_regular_no_reparse(FIXTURE_DIR / relative, f"frozen file {relative}")
        if relative == "remote-calv-payload.bin" and path.stat().st_size != 4:
            fail("CALV fixture is not exactly four bytes")
        if sha256(path) != expected_hash:
            fail(f"hash mismatch for {relative}")

    print(
        "R2_5_KEEPALIVE_MANIFEST_PASS "
        f"files={len(EXPECTED_FILES)} r0_sha256={EXPECTED_R0_SHA256} "
        "cpp_stateful=FOUR_CASES timer_expiration=NOT_COVERED_VIRTUAL_CLOCK_REQUIRED"
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, json.JSONDecodeError) as error:
        print(f"verify-rust-r2-keepalive-manifest: {error}", file=sys.stderr)
        raise SystemExit(1) from error
