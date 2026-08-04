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
MANIFEST = FIXTURE_DIR / "manifest-r2.8-mouse-button.json"
R0_RELATIVE = Path("docs/architecture/rust-rewrite/r0-source-manifest.json")
EXPECTED_R0_SHA256 = "91c0e8ed46f8c164338fbc415f50a4a37a9e24a4940fe2908494ad4fc1256068"
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
    "src/lib/inputleap/protocol_types.cpp:40-41",
    "src/lib/inputleap/mouse_types.h:23-44",
    "src/lib/inputleap/ProtocolUtil.cpp:33-192,194-254,256-310",
    "src/lib/inputleap/PacketStreamFilter.cpp:87-99",
    "src/lib/server/Server.cpp:130-133,1231-1260,1615-1652",
    "src/lib/server/ClientProxy1_6.cpp:354-361",
    "src/lib/server/IClientConnection.h:46-49",
    "src/lib/server/ClientConnectionLoggingWrapper.cpp:91-101",
    "src/lib/server/ClientConnectionByStream.cpp:70-77",
    "src/lib/client/ServerProxy.cpp:222-250,665-697",
    "src/lib/client/Client.cpp:299-308",
    "src/lib/inputleap/Screen.cpp:208-217",
]
EXPECTED_FILES = {
    "remote-dmdn-button1-payload.bin": "7347d35fc518118f3d663e1318dc11fc0fd3f8feb2b1ee4a1662c84b93642b3c",
    "remote-dmup-button1-payload.bin": "014786569d7cdd0342ca1eea6174a461d0bc15e22b6d4922bdb911ef57a8a44b",
    "../../../../../src/test/rust-r2/MouseButtonInterop.cpp": "f5042bef5af9e1a2969641320ab3442c5fb9d57595cf423f3b8df0ad603026d4",
    "../../../../../src/test/rust-r2/MouseButtonStatefulInterop.cpp": "f8dbaa2605a0ce5d3e22d89aeee5576048ea9b8bcb3af06e67ba7d4d0a003813",
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


def exact_json(actual: Any, expected: Any) -> bool:
    if type(actual) is not type(expected):
        return False
    if isinstance(expected, dict):
        return set(actual) == set(expected) and all(
            exact_json(actual[key], expected[key]) for key in expected
        )
    if isinstance(expected, list):
        return len(actual) == len(expected) and all(
            exact_json(actual_value, expected_value)
            for actual_value, expected_value in zip(actual, expected)
        )
    return actual == expected


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
    if type(data["schema"]) is not int or data["schema"] != 1 or data["tranche"] != "R2.8":
        fail("unexpected manifest schema or tranche")
    if data["name"] != "inputleap-r2.8-mouse-button-differential-fixtures":
        fail("unexpected manifest name")
    if data["sourceRevision"] != "ffad9334acfba9b9bb2ea8ba3645cb0c05c94f11":
        fail("unexpected source revision")
    if data["interopScope"] != "payload bytes and PacketStreamFilter outer framing":
        fail("interop scope must remain byte/framing limited")
    if data["rustStatefulCoverage"] != "none":
        fail("Rust stateful coverage must remain none")
    if data["cppStatefulCoverage"] != (
        "real ServerProxy active dispatch via public STREAM_INPUT_READY event API into "
        "RecordingClient mouseDown/mouseUp overrides; typed DSOP activation and truncated "
        "DMDN/DMUP fail-closed cases avoid varargs and uninitialized callback behavior"
    ):
        fail("unexpected C++ stateful coverage")
    if data["valueSemantics"] != (
        "ButtonID is u8; the C++ reader reads int8_t and casts to ButtonID, preserving all "
        "one-byte bit patterns; the writer API accepts ButtonID without range validation"
    ):
        fail("mouse-button value semantics are stale")
    if not exact_json(
        data["contextSemantics"],
        {"direction": "wire sender-to-receiver", "state": "receiver state"},
    ):
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
        fail("current R0 manifest differs from the R2.8 anchor")

    expected_fixtures = [
        {
            "kind": "down",
            "file": "remote-dmdn-button1-payload.bin",
            "button": 1,
            "size": 5,
            "sha256": EXPECTED_FILES["remote-dmdn-button1-payload.bin"],
        },
        {
            "kind": "up",
            "file": "remote-dmup-button1-payload.bin",
            "button": 1,
            "size": 5,
            "sha256": EXPECTED_FILES["remote-dmup-button1-payload.bin"],
        },
    ]
    if not exact_json(data["fixtures"], expected_fixtures):
        fail("fixture set mismatch")
    expected_payloads = [b"DMDN\x01", b"DMUP\x01"]
    for entry, expected_bytes in zip(expected_fixtures, expected_payloads):
        path = require_regular_no_reparse(
            FIXTURE_DIR / entry["file"], entry["kind"] + " fixture"
        )
        if path.stat().st_size != 5 or path.read_bytes() != expected_bytes:
            fail(f"{entry['kind']} fixture bytes are not canonical writer output")
        if sha256(path) != entry["sha256"]:
            fail(f"{entry['kind']} fixture hash mismatch")

    expected_contract = {
        "messages": ["DMDN", "DMUP"],
        "formats": ["DMDN%1i", "DMUP%1i"],
        "cppSymbols": ["kMsgDMouseDown", "kMsgDMouseUp"],
        "fieldTypes": ["button:u8"],
        "decodeContexts": [EXPECTED_CONTEXT],
        "decodeStructuralValues": "all u8 bit patterns",
        "encodeObservedContexts": [EXPECTED_CONTEXT],
        "encodeWriterDomain": "all ButtonID/u8 bit patterns",
        "rejectedContexts": EXPECTED_REJECTED_CONTEXTS,
        "boundary": 5,
        "terminal": False,
        "sourceRefs": EXPECTED_SOURCE_REFS,
    }
    if not exact_json(data["contract"], expected_contract):
        fail("DMDN/DMUP contract mismatch")

    expected_outer_frames = [
        {
            "kind": "down",
            "producer": "PacketStreamFilter::write",
            "size": 9,
            "hex": "00000005444d444e01",
        },
        {
            "kind": "up",
            "producer": "PacketStreamFilter::write",
            "size": 9,
            "hex": "00000005444d555001",
        },
    ]
    if not exact_json(data["outerFrames"], expected_outer_frames):
        fail("outer frame metadata mismatch")
    for entry, payload in zip(expected_outer_frames, expected_payloads):
        if bytes.fromhex(entry["hex"]) != len(payload).to_bytes(4, "big") + payload:
            fail(f"{entry['kind']} outer frame is not the canonical framed payload")

    expected_harnesses = [
        {
            "file": "../../../../../src/test/rust-r2/MouseButtonInterop.cpp",
            "sha256": EXPECTED_FILES[
                "../../../../../src/test/rust-r2/MouseButtonInterop.cpp"
            ],
            "coverage": (
                "ProtocolUtil writer payload bytes and PacketStreamFilter outer frames for "
                "DMDN/DMUP and all decimal u8 values; decode is raw byte equality only"
            ),
        },
        {
            "file": "../../../../../src/test/rust-r2/MouseButtonStatefulInterop.cpp",
            "sha256": EXPECTED_FILES[
                "../../../../../src/test/rust-r2/MouseButtonStatefulInterop.cpp"
            ],
            "coverage": (
                "real ServerProxy public-event dispatch uses typed DSOP activation, preserves "
                "ordered DMDN/DMUP callbacks for 1 and 255, emits five CNOP replies, continues "
                "to trailing CROP, and rejects four-byte DMDN/DMUP with EBAD plus connection "
                "failure and no callback or OS input"
            ),
        },
    ]
    if not exact_json(data["harnesses"], expected_harnesses):
        fail("harness set mismatch")
    manifest_hashes = {
        entry["file"]: entry["sha256"] for entry in expected_fixtures + expected_harnesses
    }
    if manifest_hashes != EXPECTED_FILES:
        fail("manifest file/hash set mismatch")
    for relative, expected_hash in EXPECTED_FILES.items():
        path = require_regular_no_reparse(FIXTURE_DIR / relative, f"frozen file {relative}")
        if sha256(path) != expected_hash:
            fail(f"hash mismatch for {relative}")

    if not exact_json(
        data["statefulCases"],
        [
            "client-active: ordered public STREAM_INPUT_READY callbacks are DMDN 1, DMUP 1, DMDN 255, DMUP 255",
            "client-active: each normal message including trailing CROP emits one CNOP reply",
            "client-active: nonterminal mouse-button processing continues to trailing CROP",
            "client-active: accepted messages do not close or emit CLIENT_CONNECTION_FAILED or CLIENT_DISCONNECTED",
            "client-active: four-byte DMDN and DMUP emit EBAD, fail the connection, and produce no mouse callback",
        ],
    ):
        fail("unexpected stateful case set")
    if not exact_json(
        data["limitations"],
        [
            "Rust is a codec only and does not execute mouse or protocol-state effects",
            "RecordingClient prevents operating-system input; platform injection behavior, validity of undefined button IDs, and physical pointer effects are outside this protocol gate",
        ],
    ):
        fail("manifest limitations must remain explicit")

    print(
        "R2_8_MOUSE_BUTTON_MANIFEST_PASS "
        f"files={len(EXPECTED_FILES)} r0_sha256={EXPECTED_R0_SHA256} "
        "callbacks=DMDN_1_DMUP_1_DMDN_255_DMUP_255 trailing_CROP=PROCESSED "
        "replies=FIVE_CNOP truncated_DMDN_DMUP=EBAD_DISCONNECT_NO_CALLBACK "
        "rust_stateful=NONE"
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, json.JSONDecodeError) as error:
        print(f"verify-rust-r2-mouse-button-manifest: {error}", file=sys.stderr)
        raise SystemExit(1) from error
