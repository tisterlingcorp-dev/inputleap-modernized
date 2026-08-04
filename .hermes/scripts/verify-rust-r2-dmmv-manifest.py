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
MANIFEST = FIXTURE_DIR / "manifest-r2.9-dmmv.json"
R0_RELATIVE = Path("docs/architecture/rust-rewrite/r0-source-manifest.json")
EXPECTED_R0_SHA256 = "824c23e273a510830e9fb2e5f0be9ea968b837dc575ca36661dbfb4be8c521ef"
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
    "src/lib/inputleap/protocol_types.cpp:42",
    "src/lib/inputleap/ProtocolUtil.h:41-89,100-107",
    "src/lib/inputleap/ProtocolUtil.cpp:33-192,194-254,256-310,454-497",
    "src/lib/io/StreamFilter.cpp:24-31,90-99",
    "src/lib/inputleap/PacketStreamFilter.cpp:87-99,129-147,151-177",
    "src/lib/server/Server.cpp:476,1041,1655-1669,1970",
    "src/lib/server/ClientProxy1_6.cpp:364-367",
    "src/lib/server/ClientConnectionByStream.cpp:80-83",
    "src/lib/client/ServerProxy.cpp:224-226,700-713",
    "src/lib/client/Client.cpp:311-314",
    "src/lib/inputleap/Screen.cpp:220-223",
]
EXPECTED_FILES = {
    "remote-dmmv-min-max-frame.bin": "4a91f0ce941b70135bdef44375ffe3d428f9dfc87d00a14d34d72baaaa306f96",
    "../../../../../src/test/rust-r2/DmmvInterop.cpp": "832d5ed9f00761159b7effc83db00d506e21f4ba25762591c51aebcda04e1fbc",
    "../../../../../src/test/rust-r2/DmmvStatefulInterop.cpp": "3ac0b3c075bdc7878b53981a483480278369866676ce5dc7058a58e8072f3e3b",
    "../../examples/dmmv_interop.rs": "bda34de062f45bab8f3c6a4482b90b177bfb33ffe29a3be2a2a157f49c30bd01",
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
    "scopeExclusions",
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


def verify_scope_exclusion() -> None:
    for relative in [
        "rust/crates/inputleap-protocol-legacy/src/lib.rs",
        "rust/crates/inputleap-protocol-legacy/tests/remote_protocol.rs",
    ]:
        path = require_regular_no_reparse(REPO_ROOT / relative, f"scope source {relative}")
        text = path.read_text(encoding="utf-8")
        if "DKDN" in text or "KeyDown" in text:
            fail(f"R2.9 scope contains future DKDN work: {relative}")


def main() -> int:
    data = load_manifest()
    if set(data) != EXPECTED_TOP_LEVEL_KEYS:
        fail("manifest top-level key set mismatch")
    if type(data["schema"]) is not int or data["schema"] != 1 or data["tranche"] != "R2.9":
        fail("unexpected manifest schema or tranche")
    if data["name"] != "inputleap-r2.9-dmmv-differential-fixtures":
        fail("unexpected manifest name")
    if data["sourceRevision"] != "ffad9334acfba9b9bb2ea8ba3645cb0c05c94f11":
        fail("unexpected source revision")
    if data["interopScope"] != "DMMV payload bytes through PacketStreamFilter outer framing":
        fail("interop scope must remain byte/framing limited")
    if data["rustStatefulCoverage"] != "none":
        fail("Rust stateful coverage must remain none")
    if data["cppStatefulCoverage"] != (
        "real ServerProxy active dispatch via public STREAM_INPUT_READY event API into "
        "RecordingClient mouseMove override; truncated DMMV fails closed before any callback"
    ):
        fail("unexpected C++ stateful coverage")
    if data["valueSemantics"] != (
        "DMMV carries two signed i16 coordinates; C++ ProtocolUtil and Rust preserve all "
        "16-bit patterns byte-identically"
    ):
        fail("DMMV value semantics are stale")
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
        fail("current R0 manifest differs from the R2.9 anchor")

    expected_fixtures = [
        {
            "kind": "min-max-frame",
            "file": "remote-dmmv-min-max-frame.bin",
            "x": -32768,
            "y": 32767,
            "size": 12,
            "sha256": EXPECTED_FILES["remote-dmmv-min-max-frame.bin"],
        }
    ]
    if not exact_json(data["fixtures"], expected_fixtures):
        fail("fixture set mismatch")
    fixture = require_regular_no_reparse(
        FIXTURE_DIR / expected_fixtures[0]["file"], "DMMV fixture"
    )
    expected_frame = bytes.fromhex("00000008444d4d5680007fff")
    if fixture.read_bytes() != expected_frame or sha256(fixture) != expected_fixtures[0]["sha256"]:
        fail("DMMV fixture is not canonical C++ writer/framing output")

    expected_contract = {
        "messages": ["DMMV"],
        "formats": ["DMMV%2i%2i"],
        "cppSymbols": ["kMsgDMouseMove"],
        "fieldTypes": ["x:i16", "y:i16"],
        "decodeContexts": [EXPECTED_CONTEXT],
        "decodeStructuralValues": "all signed i16 coordinate pairs",
        "encodeObservedContexts": [EXPECTED_CONTEXT],
        "encodeWriterDomain": "all signed i16 coordinate pairs",
        "rejectedContexts": EXPECTED_REJECTED_CONTEXTS,
        "boundary": 8,
        "terminal": False,
        "sourceRefs": EXPECTED_SOURCE_REFS,
    }
    if not exact_json(data["contract"], expected_contract):
        fail("DMMV contract mismatch")

    expected_outer_frames = [
        {
            "kind": "min-max-frame",
            "producer": "PacketStreamFilter::write",
            "size": 12,
            "hex": "00000008444d4d5680007fff",
        }
    ]
    if not exact_json(data["outerFrames"], expected_outer_frames):
        fail("outer frame metadata mismatch")
    if bytes.fromhex(expected_outer_frames[0]["hex"]) != expected_frame:
        fail("outer frame metadata is not canonical")

    expected_harnesses = [
        {
            "file": "../../../../../src/test/rust-r2/DmmvInterop.cpp",
            "sha256": EXPECTED_FILES["../../../../../src/test/rust-r2/DmmvInterop.cpp"],
            "coverage": (
                "C++ ProtocolUtil payload and PacketStreamFilter frame generation; bidirectional "
                "C++/Rust decode and encode at signed i16 boundaries"
            ),
        },
        {
            "file": "../../../../../src/test/rust-r2/DmmvStatefulInterop.cpp",
            "sha256": EXPECTED_FILES[
                "../../../../../src/test/rust-r2/DmmvStatefulInterop.cpp"
            ],
            "coverage": (
                "real ServerProxy public-event dispatch records MIN/MAX then -1/0, processes "
                "trailing CROP, emits three CNOP replies, and rejects four-byte DMMV with "
                "EBAD plus connection failure and no callback"
            ),
        },
        {
            "file": "../../examples/dmmv_interop.rs",
            "sha256": EXPECTED_FILES["../../examples/dmmv_interop.rs"],
            "coverage": "Rust frame decode/encode bridge with exclusive output publication",
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
            "client-active: ordered callbacks are DMMV -32768/32767 then DMMV -1/0",
            "client-active: DSOP activation, both DMMV messages, and trailing CROP emit three CNOP replies",
            "client-active: nonterminal DMMV processing continues to trailing CROP",
            "client-active: four-byte DMMV emits EBAD, fails the connection, and produces no mouse callback",
        ],
    ):
        fail("unexpected stateful case set")
    if not exact_json(
        data["scopeExclusions"],
        [
            "DKDN is excluded from R2.9 and reserved for a separately gated future tranche",
            "IPC 24801 is outside this DMMV vertical slice",
        ],
    ):
        fail("scope exclusions are incomplete")
    if not exact_json(
        data["limitations"],
        [
            "Rust is a codec only and does not execute mouse or protocol-state effects",
            "RecordingClient prevents operating-system input; platform injection and physical pointer effects are outside this protocol gate",
        ],
    ):
        fail("manifest limitations must remain explicit")

    verify_scope_exclusion()
    print(
        "R2_9_DMMV_MANIFEST_PASS "
        f"files={len(EXPECTED_FILES)} r0_sha256={EXPECTED_R0_SHA256} "
        "callbacks=MIN_MAX_THEN_NEGATIVE_ZERO trailing_CROP=PROCESSED "
        "replies=THREE_CNOP truncated_DMMV=EBAD_DISCONNECT_NO_CALLBACK "
        "dkdn=EXCLUDED rust_stateful=NONE"
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, json.JSONDecodeError) as error:
        print(f"verify-rust-r2-dmmv-manifest: {error}", file=sys.stderr)
        raise SystemExit(1) from error
