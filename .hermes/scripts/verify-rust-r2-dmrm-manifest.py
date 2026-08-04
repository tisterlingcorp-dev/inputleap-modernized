#!/usr/bin/env python3
"""Fail-closed verifier for the frozen R2.13 DMRM differential contract."""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import subprocess
import sys
from pathlib import Path
from typing import Any

REPO = Path(__file__).resolve().parents[2]
FIXTURES = REPO / "rust/crates/inputleap-protocol-legacy/tests/fixtures"
MANIFEST = FIXTURES / "manifest-r2.13-dmrm.json"
EXPECTED_FRAME = bytes.fromhex("00000008444d524d80007fff")
EXPECTED_CONTEXTS = {
    "server-to-client/client-handshake",
    "server-to-client/server-awaiting-hello-back",
    "server-to-client/server-awaiting-info",
    "client-to-server/client-handshake",
    "client-to-server/server-awaiting-hello-back",
    "client-to-server/server-awaiting-info",
    "client-to-server/active",
}
EXPECTED_HASHES = {
    "remote-dmrm-min-max-frame.bin": "1a3a28f89f5780ae3832395b45b6a0345132932ed6b65b0756bda8eab2710264",
    "../../../../../src/test/rust-r2/DmrmInterop.cpp": "2dda7631f92d739e42659070a1e76ba140f0c6c494f0f9a20f3a5582ebe50299",
    "../../../../../src/test/rust-r2/DmrmStatefulInterop.cpp": "271a13caea5b2a64413ab085300b09fe7c28e813aae8fd0ef577a242836c2b83",
    "../../examples/dmrm_interop.rs": "744bc674b3e6447770191faf52cac4dda4ad8bf1a6e22b9c2f06082907f2a19c",
}
DMRM_BATCH_RUNNERS = (
    REPO / ".hermes/scripts/rust-r2-dmrm-interop.bat",
    REPO / ".hermes/scripts/rust-r2-dmrm-stateful.bat",
)
EXPECTED_TOP_LEVEL = {
    "schema", "name", "tranche", "sourceRevision", "sourceManifest",
    "sourceManifestSha256", "interopScope", "rustStatefulCoverage",
    "cppStatefulCoverage", "valueSemantics", "contextSemantics", "fixtures",
    "contract", "outerFrames", "harnesses", "statefulCases",
    "scopeExclusions", "limitations",
}


def fail(message: str) -> None:
    raise ValueError(message)


def require(condition: bool, message: str) -> None:
    if not condition:
        fail(message)


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


def plain_file(path: Path) -> Path:
    root = Path(os.path.abspath(REPO))
    candidate = Path(path)
    if not candidate.is_absolute():
        candidate = root / candidate
    try:
        relative = candidate.relative_to(root)
    except ValueError as error:
        fail(f"path escapes repository: {path}: {error}")
    current = root
    for component in relative.parts:
        current /= component
        try:
            info = current.lstat()
        except FileNotFoundError:
            fail(f"missing path component: {current}")
        if stat.S_ISLNK(info.st_mode):
            fail(f"symlink forbidden: {current}")
        attributes = getattr(info, "st_file_attributes", 0)
        if attributes & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400):
            fail(f"reparse point forbidden: {current}")
    resolved = candidate.resolve(strict=True)
    resolved.relative_to(root.resolve(strict=True))
    require(resolved.is_file(), f"not a regular file: {resolved}")
    return resolved


def manifest_file(value: str) -> Path:
    relative = Path(value)
    require(bool(value) and "\\" not in value and not relative.is_absolute(),
            f"invalid manifest path: {value!r}")
    saw_name = False
    for component in relative.parts:
        if component == "..":
            require(not saw_name, f"non-leading parent traversal: {value!r}")
        elif component not in ("", "."):
            saw_name = True
    return plain_file(MANIFEST.parent / relative)


def verify_source_ref(reference: str) -> None:
    match = re.fullmatch(r"([^:]+):(\d+(?:-\d+)?(?:,\d+(?:-\d+)?)*)", reference)
    require(match is not None, f"invalid sourceRef: {reference}")
    path = plain_file(REPO / match.group(1))
    line_count = len(path.read_text(encoding="utf-8", errors="strict").splitlines())
    for region in match.group(2).split(","):
        if "-" in region:
            first, last = (int(value) for value in region.split("-", 1))
        else:
            first = last = int(region)
        require(1 <= first <= last <= line_count,
                f"sourceRef outside file: {reference}, lines={line_count}")


def verify_batch_runners() -> None:
    for path in DMRM_BATCH_RUNNERS:
        text = plain_file(path).read_text(encoding="utf-8", errors="strict")
        require(re.search(r"(?im)^\s*if\s+errorlevel\s+1\b", text) is None,
                f"batch runner misses negative exit status: {path}")
        require('if not "!ERRORLEVEL!"=="0" goto :failed' in text,
                f"batch runner lacks exact-zero exit check: {path}")


def verify() -> None:
    plain_file(MANIFEST)
    verify_batch_runners()
    raw = MANIFEST.read_bytes()
    require(len(raw) <= 65536, "manifest exceeds 64 KiB")
    data = json.loads(raw.decode("utf-8"), object_pairs_hook=reject_duplicates)
    require(set(data) == EXPECTED_TOP_LEVEL, "manifest top-level keys mismatch")
    require(data["schema"] == 1 and data["tranche"] == "R2.13", "schema/tranche mismatch")
    require(data["name"] == "inputleap-r2.13-dmrm-differential-fixtures", "name mismatch")
    head = subprocess.run(
        ["git", "rev-parse", "HEAD"], cwd=REPO, check=True,
        capture_output=True, text=True,
    ).stdout.strip()
    require(data["sourceRevision"] == head,
            f"sourceRevision does not match HEAD: manifest={data['sourceRevision']} HEAD={head}")
    require(data["rustStatefulCoverage"] == "none", "Rust stateful overclaim")
    require("every partial DMRM payload length 4 through 7" in data["cppStatefulCoverage"],
            "complete truncation coverage missing")
    require("does not claim CLIENT_DISCONNECTED or transport close" in data["cppStatefulCoverage"],
            "disconnect limitation missing")

    source_manifest = manifest_file(data["sourceManifest"])
    require(sha256(source_manifest) == data["sourceManifestSha256"],
            "R0 source manifest hash mismatch")
    source_data = json.loads(source_manifest.read_text(encoding="utf-8"),
                             object_pairs_hook=reject_duplicates)
    require(source_data["schema"] == 1
            and source_data["pathCount"] == len(source_data["files"]),
            "R0 identity mismatch")

    require(len(data["fixtures"]) == 1, "exactly one fixture required")
    fixture = data["fixtures"][0]
    require((fixture["dx"], fixture["dy"], fixture["size"])
            == (-32768, 32767, 12), "fixture metadata mismatch")
    fixture_path = manifest_file(fixture["file"])
    require(fixture_path.read_bytes() == EXPECTED_FRAME, "fixture bytes mismatch")
    require(sha256(fixture_path) == fixture["sha256"] == EXPECTED_HASHES[fixture["file"]],
            "fixture hash mismatch")

    contract = data["contract"]
    require(contract["messages"] == ["DMRM"], "message scope mismatch")
    require(contract["formats"] == ["DMRM%2i%2i"], "format mismatch")
    require(contract["cppSymbols"] == ["kMsgDMouseRelMove"], "C++ symbol mismatch")
    require(contract["fieldTypes"] == ["dx:i16", "dy:i16"], "field types mismatch")
    require(contract["decodeContexts"] == ["server-to-client/active"], "decode context mismatch")
    require(contract["encodeObservedContexts"] == ["server-to-client/active"], "encode context mismatch")
    require(set(contract["rejectedContexts"]) == EXPECTED_CONTEXTS,
            "seven rejected contexts mismatch")
    require(contract["boundary"] == 8 and contract["terminal"] is False,
            "boundary/terminal mismatch")
    for reference in contract["sourceRefs"]:
        verify_source_ref(reference)

    frames = data["outerFrames"]
    require(len(frames) == 1 and frames[0]["size"] == 12
            and frames[0]["hex"] == EXPECTED_FRAME.hex()
            and frames[0]["producer"] == "PacketStreamFilter::write",
            "outer frame mismatch")

    require(len(data["harnesses"]) == 3, "three harnesses required")
    found_hashes: dict[str, str] = {fixture["file"]: fixture["sha256"]}
    for harness in data["harnesses"]:
        path = manifest_file(harness["file"])
        require(sha256(path) == harness["sha256"], f"harness hash mismatch: {path}")
        found_hashes[harness["file"]] = harness["sha256"]
    require(found_hashes == EXPECTED_HASHES, "frozen file/hash set mismatch")

    require(any("length 4 through 7" in case and "no mouse callback" in case
                and "does not raise CLIENT_DISCONNECTED" in case
                for case in data["statefulCases"]), "stateful truncation case missing")
    require(any("DMWM remains outside R2.13" in item for item in data["scopeExclusions"]),
            "sibling scope exclusion missing")
    require(any("Rust is a codec only" in item for item in data["limitations"]),
            "Rust limitation missing")
    require(any("operating-system input" in item for item in data["limitations"]),
            "OS input exclusion missing")

    rust_lib = plain_file(REPO / "rust/crates/inputleap-protocol-legacy/src/lib.rs").read_text(encoding="utf-8")
    rust_tests = plain_file(REPO / "rust/crates/inputleap-protocol-legacy/tests/remote_protocol.rs").read_text(encoding="utf-8")
    server_proxy = plain_file(REPO / "src/lib/client/ServerProxy.cpp").read_text(encoding="utf-8")
    stateful = plain_file(REPO / "src/test/rust-r2/DmrmStatefulInterop.cpp").read_text(encoding="utf-8")
    attributes = plain_file(REPO / ".gitattributes").read_text(encoding="utf-8")
    require('b"DMRM"' in rust_lib and "RemoteMessage::MouseRelativeMove" in rust_lib,
            "Rust DMRM codec absent")
    require("dmrm_context_matrix_and_short_output_fail_closed" in rust_tests,
            "context/output test absent")
    require("every_short_dmrm_payload_is_malformed_without_boundary" in rust_tests,
            "Rust truncation test absent")
    require('throw XBadClient("truncated relative mouse move message")' in server_proxy,
            "C++ truncation hardening absent")
    require("for (std::size_t length = 4; length < 8; ++length)" in stateful,
            "stateful partial-length loop absent")
    require("events.saw(EventType::CLIENT_DISCONNECTED)" in stateful,
            "CLIENT_DISCONNECTED exclusion absent")
    require("rust/**/*.bin -text" in attributes, "binary fixture attribute absent")

    print(
        "R2_13_DMRM_MANIFEST_PASS files=4 payload=8 frame=12 contexts=1of8 "
        "truncated_lengths=4_to_7_EBAD_CONNECTION_FAILED_NO_CALLBACK "
        "client_disconnected_event=NOT_CLAIMED rust_stateful=NONE os_input=NOT_INVOKED"
    )


def main() -> int:
    try:
        verify()
        return 0
    except (KeyError, TypeError, ValueError, OSError, UnicodeError, json.JSONDecodeError) as error:
        print(f"R2_13_DMRM_MANIFEST_FAIL: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
