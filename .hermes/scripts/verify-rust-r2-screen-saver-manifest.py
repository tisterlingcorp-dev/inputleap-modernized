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
MANIFEST = FIXTURE_DIR / "manifest-r2.7-screen-saver.json"
R0_RELATIVE = Path("docs/architecture/rust-rewrite/r0-source-manifest.json")
EXPECTED_R0_SHA256 = "dfcb36366f2a6b8d19e541a50847d2ddf6b82dacf21fc3b8744becfe5ef95fc6"
EXPECTED_CONTEXT = "server-to-client/active"
EXPECTED_REJECTED_CONTEXTS = [
    "server-to-client/client-handshake",
    "server-to-client/server-awaiting-hello-back",
    "server-to-client/server-awaiting-info",
    "client-to-server/client-handshake",
    "client-to-server/server-awaiting-hello-back",
    "client-to-server/server-awaiting-info",
    "client-to-server/active",
]
EXPECTED_SOURCE_REFS = [
    "src/lib/inputleap/protocol_types.cpp:30",
    "src/lib/inputleap/ProtocolUtil.cpp:33-192,215-269",
    "src/lib/inputleap/PacketStreamFilter.cpp:87-99",
    "src/lib/server/Server.cpp:143-148,299-302,1500-1551",
    "src/lib/server/ClientProxy1_6.cpp:390-393",
    "src/lib/server/IClientConnection.h:54",
    "src/lib/server/ClientConnectionLoggingWrapper.cpp:127-131",
    "src/lib/server/ClientConnectionByStream.cpp:100-103",
    "src/lib/client/ServerProxy.cpp:222-280,773-783",
    "src/lib/client/Client.cpp:326-330",
    "src/lib/inputleap/Screen.cpp:170-179",
]
EXPECTED_FILES = {
    "remote-csec-off-payload.bin": "9b5811bf99a4951ab8e6139915a3de4a0831258195a31d96ecfaaf7332151d5b",
    "remote-csec-on-payload.bin": "24f9c720cce25864f82aeb9bd32c6873e8bda0782090a8880551e3daf502b311",
    "../../../../../src/test/rust-r2/ScreenSaverInterop.cpp": "aee1f30042c3c3d9e4f15b05c349c18ce9ed4197eac53fcf3d1eaa6d46948ecd",
    "../../../../../src/test/rust-r2/ScreenSaverStatefulInterop.cpp": "970e9e8016cfefa62439675903c2eec25c7cf0bc5dbff72274ed0a320db3f2c8",
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
    "valueSemantics",
    "contextSemantics",
    "fixtures",
    "contract",
    "outerFrames",
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
    if data["schema"] != 1 or data["tranche"] != "R2.7":
        fail("unexpected manifest schema or tranche")
    if data["name"] != "inputleap-r2.7-screen-saver-differential-fixtures":
        fail("unexpected manifest name")
    if data["sourceRevision"] != "ffad9334acfba9b9bb2ea8ba3645cb0c05c94f11":
        fail("unexpected source revision")
    if data["interopScope"] != "payload bytes and PacketStreamFilter outer framing":
        fail("interop scope must remain byte/framing limited")
    if data["rustStatefulCoverage"] != "none":
        fail("Rust stateful coverage must remain none")
    if data["cppStatefulCoverage"] != (
        "real ServerProxy active dispatch via public STREAM_INPUT_READY event API into a recording Client override"
    ):
        fail("unexpected C++ stateful coverage")
    if data["valueSemantics"] != (
        "decode preserves raw u8; C++ consumes zero as false and every nonzero value as true; "
        "productive bool writer emits only 0 and 1"
    ):
        fail("screen-saver value semantics are stale")
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
        fail("current R0 manifest differs from the R2.7 anchor")

    expected_fixtures = [
        {
            "state": "off",
            "file": "remote-csec-off-payload.bin",
            "raw": 0,
            "size": 5,
            "sha256": EXPECTED_FILES["remote-csec-off-payload.bin"],
        },
        {
            "state": "on",
            "file": "remote-csec-on-payload.bin",
            "raw": 1,
            "size": 5,
            "sha256": EXPECTED_FILES["remote-csec-on-payload.bin"],
        },
    ]
    if data["fixtures"] != expected_fixtures:
        fail("fixture set mismatch")
    for entry, expected_bytes in zip(expected_fixtures, [b"CSEC\x00", b"CSEC\x01"]):
        path = require_regular_no_reparse(FIXTURE_DIR / entry["file"], entry["state"] + " fixture")
        if path.stat().st_size != 5 or path.read_bytes() != expected_bytes:
            fail(f"{entry['state']} fixture bytes are not canonical writer output")
        if sha256(path) != entry["sha256"]:
            fail(f"{entry['state']} fixture hash mismatch")

    expected_contract = {
        "message": "CSEC",
        "format": "CSEC%1i",
        "cppSymbol": "kMsgCScreenSaver",
        "fieldTypes": ["raw:u8"],
        "decodeContexts": [EXPECTED_CONTEXT],
        "decodeStructuralValues": "all u8 bit patterns",
        "encodeObservedContexts": [EXPECTED_CONTEXT],
        "encodeObservedValues": [0, 1],
        "rejectedContexts": EXPECTED_REJECTED_CONTEXTS,
        "boundary": 5,
        "terminal": False,
        "sourceRefs": EXPECTED_SOURCE_REFS,
    }
    if data["contract"] != expected_contract:
        fail("CSEC contract mismatch")
    if data["outerFrames"] != [
        {"state": "off", "producer": "PacketStreamFilter::write", "size": 9,
         "hex": "000000054353454300"},
        {"state": "on", "producer": "PacketStreamFilter::write", "size": 9,
         "hex": "000000054353454301"},
    ]:
        fail("outer frame metadata mismatch")

    harnesses = data["harnesses"]
    if not isinstance(harnesses, list) or len(harnesses) != 2:
        fail("manifest must contain exactly two C++ harnesses")
    manifest_hashes = {entry["file"]: entry["sha256"] for entry in expected_fixtures}
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
        "client-active: public STREAM_INPUT_READY dispatch maps raw 0,1,255 to false,true,true",
        "client-active: nonterminal CSEC processing continues to trailing CROP",
        "client-active: accepted CSEC does not close or emit CLIENT_CONNECTION_FAILED or CLIENT_DISCONNECTED",
    ]:
        fail("unexpected stateful case set")
    if data["limitations"] != [
        "Rust is a codec only and does not execute screen-saver or protocol-state effects",
        "The C++ stateful harness observes the virtual Client API boundary; operating-system screen-saver activation is outside this protocol gate",
    ]:
        fail("manifest limitations must remain explicit")

    print(
        "R2_7_SCREEN_SAVER_MANIFEST_PASS "
        f"files={len(EXPECTED_FILES)} r0_sha256={EXPECTED_R0_SHA256} "
        "cpp_values=FALSE_TRUE_TRUE trailing_CROP=PROCESSED rust_stateful=NONE"
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, json.JSONDecodeError) as error:
        print(f"verify-rust-r2-screen-saver-manifest: {error}", file=sys.stderr)
        raise SystemExit(1) from error
