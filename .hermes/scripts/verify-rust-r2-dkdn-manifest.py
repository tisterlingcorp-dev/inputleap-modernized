#!/usr/bin/env python3
"""Fail-closed verifier for the frozen R2.10 DKDN differential contract."""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import sys
from pathlib import Path
from typing import Any

REPO = Path(__file__).resolve().parents[2]
FIXTURES = REPO / "rust/crates/inputleap-protocol-legacy/tests/fixtures"
MANIFEST = FIXTURES / "manifest-r2.10-dkdn.json"
EXPECTED_FRAME = bytes.fromhex("0000000a444b444e12348001ffff")
EXPECTED_CONTEXTS = {
    "server-to-client/client-handshake",
    "server-to-client/server-awaiting-hello-back",
    "server-to-client/server-awaiting-info",
    "client-to-server/client-handshake",
    "client-to-server/server-awaiting-hello-back",
    "client-to-server/server-awaiting-info",
    "client-to-server/active",
}


def fail(message: str) -> None:
    raise ValueError(message)


def reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            fail(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def assert_plain_file(path: Path, root: Path) -> Path:
    root_absolute = Path(os.path.abspath(root))
    candidate = Path(os.path.abspath(path))
    try:
        relative = candidate.relative_to(root_absolute)
    except ValueError as error:
        fail(f"path escapes repository: {path}: {error}")

    current = root_absolute
    for component in relative.parts:
        current /= component
        info = current.lstat()
        if stat.S_ISLNK(info.st_mode):
            fail(f"symlink forbidden: {current}")
        attributes = getattr(info, "st_file_attributes", 0)
        if attributes & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0):
            fail(f"reparse point forbidden: {current}")

    resolved_root = root_absolute.resolve(strict=True)
    resolved = candidate.resolve(strict=True)
    try:
        resolved.relative_to(resolved_root)
    except ValueError as error:
        fail(f"resolved path escapes repository: {path}: {error}")
    if not resolved.is_file():
        fail(f"not a regular file: {resolved}")
    return resolved


def manifest_relative(value: str) -> Path:
    relative = Path(value)
    if not value or "\\" in value or relative.is_absolute():
        fail(f"invalid manifest-relative path: {value!r}")
    saw_named_component = False
    for component in relative.parts:
        if component == "..":
            if saw_named_component:
                fail(f"non-leading parent traversal forbidden: {value!r}")
        elif component not in ("", "."):
            saw_named_component = True
    return assert_plain_file(MANIFEST.parent / relative, REPO)


def verify_source_ref(reference: str) -> None:
    match = re.fullmatch(r"([^:]+):(\d+(?:-\d+)?(?:,\d+(?:-\d+)?)*)", reference)
    if not match:
        fail(f"invalid sourceRef: {reference}")
    path = assert_plain_file(REPO / match.group(1), REPO)
    line_count = len(path.read_text(encoding="utf-8", errors="strict").splitlines())
    for region in match.group(2).split(","):
        if "-" in region:
            first, last = (int(value) for value in region.split("-", 1))
        else:
            first = last = int(region)
        if first < 1 or last < first or last > line_count:
            fail(f"sourceRef outside file: {reference} lines={line_count}")


def require(condition: bool, message: str) -> None:
    if not condition:
        fail(message)


def verify() -> None:
    assert_plain_file(MANIFEST, REPO)
    data = json.loads(MANIFEST.read_text(encoding="utf-8"), object_pairs_hook=reject_duplicates)
    require(data["schema"] == 1 and data["tranche"] == "R2.10", "schema/tranche mismatch")
    require(data["rustStatefulCoverage"] == "none", "Rust stateful overclaim")
    require("RecordingClient keyDown override" in data["cppStatefulCoverage"], "missing safe C++ double")
    require(
        "every partial DKDN payload length 4 through 9" in data["cppStatefulCoverage"],
        "missing complete partial-length coverage claim",
    )
    require(
        "CLIENT_DISCONNECTED and transport close are not claimed" in data["cppStatefulCoverage"],
        "missing honest disconnect limitation",
    )

    source_manifest = manifest_relative(data["sourceManifest"])
    require(sha256(source_manifest) == data["sourceManifestSha256"], "R0 source manifest hash mismatch")
    source_data = json.loads(source_manifest.read_text(encoding="utf-8"), object_pairs_hook=reject_duplicates)
    require(
        source_data["schema"] == 1
        and source_data["pathCount"] == 78
        and len(source_data["files"]) == 78,
        "R0 identity mismatch",
    )

    fixtures = data["fixtures"]
    require(len(fixtures) == 1, "exactly one DKDN fixture required")
    fixture = fixtures[0]
    require(
        (fixture["keyId"], fixture["modifierMask"], fixture["button"], fixture["size"])
        == (0x1234, 0x8001, 0xFFFF, 14),
        "fixture metadata mismatch",
    )
    fixture_path = manifest_relative(fixture["file"])
    require(fixture_path.read_bytes() == EXPECTED_FRAME, "fixture bytes mismatch")
    require(sha256(fixture_path) == fixture["sha256"], "fixture hash mismatch")

    contract = data["contract"]
    require(contract["messages"] == ["DKDN"], "message scope mismatch")
    require(contract["formats"] == ["DKDN%2i%2i%2i"], "format mismatch")
    require(contract["cppSymbols"] == ["kMsgDKeyDown"], "C++ symbol mismatch")
    require(
        contract["fieldTypes"] == ["keyId:u16", "modifierMask:u16", "button:u16"],
        "field type mismatch",
    )
    require(contract["decodeContexts"] == ["server-to-client/active"], "decode context mismatch")
    require(contract["encodeObservedContexts"] == ["server-to-client/active"], "encode context mismatch")
    require(set(contract["rejectedContexts"]) == EXPECTED_CONTEXTS, "seven rejected contexts mismatch")
    require(contract["boundary"] == 10 and contract["terminal"] is False, "boundary/terminal mismatch")
    for reference in contract["sourceRefs"]:
        verify_source_ref(reference)

    frames = data["outerFrames"]
    require(
        len(frames) == 1
        and frames[0]["size"] == 14
        and frames[0]["hex"] == EXPECTED_FRAME.hex()
        and frames[0]["producer"] == "PacketStreamFilter::write",
        "outer frame metadata mismatch",
    )

    harnesses = data["harnesses"]
    require(len(harnesses) == 3, "three harnesses required")
    for harness in harnesses:
        path = manifest_relative(harness["file"])
        require(sha256(path) == harness["sha256"], f"harness hash mismatch: {path}")
    require(
        any(
            "every partial DKDN payload length 4 through 9" in case
            and "no key callback" in case
            and "does not raise CLIENT_DISCONNECTED" in case
            for case in data["statefulCases"]
        ),
        "missing complete and honest truncation stateful case",
    )
    require(any("DKUP and DKRP" in item for item in data["scopeExclusions"]), "sibling scope exclusion missing")
    require(any("Rust is a codec only" in item for item in data["limitations"]), "Rust limitation missing")
    require(any("operating-system input" in item for item in data["limitations"]), "OS-input exclusion missing")

    rust_lib = (REPO / "rust/crates/inputleap-protocol-legacy/src/lib.rs").read_text(encoding="utf-8")
    rust_tests = (REPO / "rust/crates/inputleap-protocol-legacy/tests/remote_protocol.rs").read_text(encoding="utf-8")
    server_proxy = (REPO / "src/lib/client/ServerProxy.cpp").read_text(encoding="utf-8")
    stateful_harness = (REPO / "src/test/rust-r2/DkdnStatefulInterop.cpp").read_text(encoding="utf-8")
    attributes = (REPO / ".gitattributes").read_text(encoding="utf-8")
    require('b"DKDN"' in rust_lib and "RemoteMessage::KeyDown" in rust_lib, "Rust DKDN codec absent")
    require("dkdn_context_matrix_is_only_server_to_client_active" in rust_tests, "context test absent")
    require("every_short_dkdn_payload_is_malformed_without_boundary" in rust_tests, "truncation test absent")
    require('throw XBadClient("truncated key down message")' in server_proxy, "C++ truncation hardening absent")
    require(
        "for (std::size_t length = 4; length < 10; ++length)" in stateful_harness,
        "stateful partial-length loop absent",
    )
    require(
        "events.saw(EventType::CLIENT_DISCONNECTED)" in stateful_harness,
        "CLIENT_DISCONNECTED exclusion absent",
    )
    require("rust/**/*.bin -text" in attributes, "binary fixture attribute absent")

    print(
        "R2_10_DKDN_MANIFEST_PASS files=4 r0_sha256="
        f"{data['sourceManifestSha256']} payload=10 frame=14 contexts=1of8 "
        "truncated_lengths=4_to_9_EBAD_CONNECTION_FAILED_NO_CALLBACK "
        "client_disconnected_event=NOT_CLAIMED rust_stateful=NONE os_input=NOT_INVOKED"
    )


def main() -> int:
    try:
        verify()
        return 0
    except (KeyError, TypeError, ValueError, OSError, json.JSONDecodeError) as error:
        print(f"R2_10_DKDN_MANIFEST_FAIL: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
