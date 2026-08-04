from __future__ import annotations

import hashlib
import json
import os
import stat
import sys
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[2]
FIXTURE_DIR = (
    REPO_ROOT / "rust" / "crates" / "inputleap-protocol-legacy" / "tests" / "fixtures"
)
MANIFEST = FIXTURE_DIR / "manifest-r2.6-incompatible-version.json"
R0_RELATIVE = Path("docs/architecture/rust-rewrite/r0-source-manifest.json")
EXPECTED_R0_SHA256 = "167a70874bb4a136b7b65b12ff5f78b25bedbde6cfc35f06fe0188ecfd6c1cef"
EXPECTED_CONTEXT = "server-to-client/client-handshake"
EXPECTED_REJECTED_CONTEXTS = [
    "server-to-client/server-awaiting-hello-back",
    "server-to-client/server-awaiting-info",
    "server-to-client/active",
    "client-to-server/client-handshake",
    "client-to-server/server-awaiting-hello-back",
    "client-to-server/server-awaiting-info",
    "client-to-server/active",
]
EXPECTED_SOURCE_REFS = [
    "src/lib/inputleap/protocol_types.cpp:52",
    "src/lib/inputleap/ProtocolUtil.cpp:215-269",
    "src/lib/inputleap/PacketStreamFilter.cpp:87-99",
    "src/lib/server/ClientProxyUnknown.cpp:145-220",
    "src/lib/client/ServerProxy.cpp:150-219",
]
EXPECTED_HAZARD_REFS = [
    "src/lib/client/ServerProxy.cpp:189-195",
    "src/lib/inputleap/ProtocolUtil.h:74-84",
    "src/lib/inputleap/ProtocolUtil.cpp:215-269",
]
EXPECTED_FILES = {
    "remote-eicv-1-6-payload.bin": "9391b1e4703549b5c2d4da4e1603da72e1009c72ffc5419341d3c7bb6eb8cc90",
    "../../../../../src/test/rust-r2/IncompatibleVersionInterop.cpp": "e338d348c24f980c1420b72d67a83922c3735f53830c46823a927cd0eaf33a56",
    "../../../../../src/test/rust-r2/IncompatibleVersionStatefulInterop.cpp": "b749a2a3d57706ff990356f9dd1c83f34a88fe9eb0a872752cf3d6e89f39f36b",
}
EXPECTED_TOP_LEVEL_KEYS = {
    "schema",
    "name",
    "tranche",
    "sourceRevision",
    "sourceManifest",
    "sourceManifestSha256",
    "interopScope",
    "rustStatefulCoverage",
    "cppStatefulCoverage",
    "terminalityScope",
    "numericOracle",
    "contextSemantics",
    "fixture",
    "outerFrame",
    "consumerHazard",
    "harnesses",
    "statefulCases",
    "limitations",
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


def reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            fail(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def load_manifest() -> dict[str, Any]:
    manifest = require_regular_no_reparse(MANIFEST, "manifest")
    raw = manifest.read_bytes()
    if len(raw) > 65536:
        fail("manifest exceeds 64 KiB")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as error:
        raise ValueError("manifest is not strict UTF-8") from error
    data = json.loads(text, object_pairs_hook=reject_duplicate_keys)
    if not isinstance(data, dict):
        fail("manifest root must be an object")
    return data


def main() -> int:
    data = load_manifest()
    if set(data) != EXPECTED_TOP_LEVEL_KEYS:
        fail("manifest top-level key set mismatch")
    if data["schema"] != 1 or data["tranche"] != "R2.6":
        fail("unexpected manifest schema or tranche")
    if data["name"] != "inputleap-r2.6-incompatible-version-differential-fixture":
        fail("unexpected manifest name")
    if data["sourceRevision"] != "ffad9334acfba9b9bb2ea8ba3645cb0c05c94f11":
        fail("unexpected source revision")
    if data["interopScope"] != "payload bytes and PacketStreamFilter outer framing":
        fail("interop scope must remain byte/framing limited")
    if data["rustStatefulCoverage"] != "none":
        fail("Rust stateful coverage must remain none")
    if data["cppStatefulCoverage"] != (
        "real ServerProxy client-handshake dispatch via public STREAM_INPUT_READY event API"
    ):
        fail("unexpected C++ stateful coverage")
    if data["terminalityScope"] != (
        "Rust parser metadata plus separately observed C++ CLIENT_CONNECTION_FAILED effect"
    ):
        fail("terminal metadata/effect separation is stale")
    if data["numericOracle"] != (
        "ProtocolUtil writer bytes only; ServerProxy logged major/minor values are excluded"
    ):
        fail("numeric oracle limitation is missing")
    if data["contextSemantics"] != {
        "direction": "wire sender-to-receiver",
        "state": "receiver state",
    }:
        fail("unexpected context semantics")

    source_text = data["sourceManifest"]
    if source_text != "../../../../../docs/architecture/rust-rewrite/r0-source-manifest.json":
        fail("unexpected sourceManifest path")
    source_manifest = lexical(FIXTURE_DIR / source_text)
    if source_manifest != lexical(REPO_ROOT / R0_RELATIVE):
        fail("sourceManifest does not resolve to repository R0 manifest")
    require_regular_no_reparse(source_manifest, "source manifest")
    if data["sourceManifestSha256"] != EXPECTED_R0_SHA256:
        fail("manifest R0 hash field is stale")
    if sha256(source_manifest) != EXPECTED_R0_SHA256:
        fail("current R0 manifest differs from the R2.6 anchor")

    fixture = data["fixture"]
    if not isinstance(fixture, dict) or set(fixture) != {
        "message",
        "format",
        "file",
        "size",
        "sha256",
        "cppSymbol",
        "fieldTypes",
        "decodeContexts",
        "decodeStructuralValues",
        "encodeObservedContexts",
        "encodeObservedValues",
        "rejectedContexts",
        "boundary",
        "terminal",
        "sourceRefs",
    }:
        fail("fixture key set mismatch")
    expected_fixture = {
        "message": "EICV",
        "format": "EICV%2i%2i",
        "file": "remote-eicv-1-6-payload.bin",
        "size": 8,
        "sha256": EXPECTED_FILES["remote-eicv-1-6-payload.bin"],
        "cppSymbol": "kMsgEIncompatible",
        "fieldTypes": ["major:i16", "minor:i16"],
        "decodeContexts": [EXPECTED_CONTEXT],
        "decodeStructuralValues": "all i16 bit patterns",
        "encodeObservedContexts": [EXPECTED_CONTEXT],
        "encodeObservedValues": [[1, 6]],
        "rejectedContexts": EXPECTED_REJECTED_CONTEXTS,
        "boundary": 8,
        "terminal": True,
        "sourceRefs": EXPECTED_SOURCE_REFS,
    }
    if fixture != expected_fixture:
        fail("fixture contract mismatch")

    fixture_path = require_regular_no_reparse(
        FIXTURE_DIR / fixture["file"], "EICV fixture"
    )
    if fixture_path.stat().st_size != 8:
        fail("EICV fixture is not exactly eight bytes")
    if fixture_path.read_bytes() != bytes.fromhex("4549435600010006"):
        fail("EICV fixture bytes are not canonical writer output")
    if sha256(fixture_path) != fixture["sha256"]:
        fail("EICV fixture hash mismatch")

    if data["outerFrame"] != {
        "producer": "PacketStreamFilter::write",
        "size": 12,
        "hex": "000000084549435600010006",
    }:
        fail("outer frame metadata mismatch")
    if data["consumerHazard"] != {
        "description": (
            "ServerProxy passes int32_t pointers for %2i while ProtocolUtil::vreadf writes "
            "through uint16_t pointers"
        ),
        "policy": "never assert or compare C++ consumer major/minor values",
        "sourceRefs": EXPECTED_HAZARD_REFS,
    }:
        fail("C++ numeric consumer hazard is missing or stale")

    harnesses = data["harnesses"]
    if not isinstance(harnesses, list) or len(harnesses) != 2:
        fail("manifest must contain exactly two C++ harnesses")
    manifest_hashes = {fixture["file"]: fixture["sha256"]}
    for entry in harnesses:
        if not isinstance(entry, dict) or set(entry) != {"file", "sha256", "coverage"}:
            fail("invalid harness entry")
        if not isinstance(entry["coverage"], str) or not entry["coverage"]:
            fail("harness coverage must be a non-empty string")
        manifest_hashes[entry["file"]] = entry["sha256"]
    if manifest_hashes != EXPECTED_FILES:
        fail("manifest file/hash set mismatch")

    for relative, expected_hash in EXPECTED_FILES.items():
        path = require_regular_no_reparse(FIXTURE_DIR / relative, f"frozen file {relative}")
        if sha256(path) != expected_hash:
            fail(f"hash mismatch for {relative}")

    if data["statefulCases"] != [
        "client-handshake: public STREAM_INPUT_READY dispatch emits CLIENT_CONNECTION_FAILED and stops before trailing QINF"
    ]:
        fail("unexpected stateful case set")
    if data["limitations"] != [
        "Rust is a codec only and does not execute disconnect or state transitions",
        "C++ consumer numeric fields are not evidence because of the int32_t/uint16_t pointer-width mismatch",
    ]:
        fail("manifest limitations must remain explicit")

    print(
        "R2_6_INCOMPATIBLE_VERSION_MANIFEST_PASS "
        f"files={len(EXPECTED_FILES)} r0_sha256={EXPECTED_R0_SHA256} "
        "cpp_terminal_effect=CLIENT_CONNECTION_FAILED numeric_fields=NOT_ORACLED"
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, json.JSONDecodeError) as error:
        print(f"verify-rust-r2-incompatible-version-manifest: {error}", file=sys.stderr)
        raise SystemExit(1) from error
