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
MANIFEST = FIXTURE_DIR / "manifest-r2.4-terminal-control.json"
R0_RELATIVE = Path("docs/architecture/rust-rewrite/r0-source-manifest.json")
EXPECTED_R0_SHA256 = "5fa4a674551f72f378d9bb3939dd8668af84cca06eae55577b502b16efe94a73"
EXPECTED_SCOPES = {
    "interopScope": "payload bytes only",
    "statefulCoverage": "none",
    "terminalityScope": "Rust caller policy metadata only",
}
EXPECTED_CONTEXT_SEMANTICS = {
    "direction": "wire sender-to-receiver",
    "state": "receiver state",
}
EXPECTED = {
    "CBYE": {
        "file": "remote-cbye-payload.bin",
        "sha256": "030ed1eac90aa12abee471287cf6a8d91e3cf3ec04918966b01f763b5d641140",
        "cppSymbol": "kMsgCClose",
        "decodeContexts": ["server-to-client/client-handshake", "server-to-client/active"],
        "encodeObservedContexts": [],
        "encodePolicy": "fail-closed: ClientProxy::close(msg) ignores msg and flushes without serializing CBYE",
    },
    "EBSY": {
        "file": "remote-ebsy-payload.bin",
        "sha256": "cc3554239224d26f93199cf6d7a5122995eaccb08535ccd690471a9203cd1ed8",
        "cppSymbol": "kMsgEBusy",
        "decodeContexts": ["server-to-client/client-handshake"],
        "encodeObservedContexts": [],
        "encodePolicy": "fail-closed: ClientProxy::close(msg) ignores msg and flushes without serializing EBSY",
    },
    "EUNK": {
        "file": "remote-eunk-payload.bin",
        "sha256": "209e1ac361f0099bcf0b53cf046a1e2842806a4efd58797a2039267cbe826c5e",
        "cppSymbol": "kMsgEUnknown",
        "decodeContexts": ["server-to-client/client-handshake"],
        "encodeObservedContexts": [],
        "encodePolicy": "fail-closed: ClientProxy::close(msg) ignores msg and flushes without serializing EUNK",
    },
    "EBAD": {
        "file": "remote-ebad-payload.bin",
        "sha256": "d9c97391b509a1b7277048208960565bcc2fd02f80da79270142033d87830d68",
        "cppSymbol": "kMsgEBad",
        "decodeContexts": ["server-to-client/client-handshake", "server-to-client/active"],
        "encodeObservedContexts": ["server-to-client/client-handshake"],
        "encodePolicy": "client-to-server receiver state is UNKNOWN and remains fail-closed; active decode does not authorize active encode",
    },
}


def fail(message: str) -> None:
    raise ValueError(message)


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def inside_repo(path: Path) -> bool:
    lexical_repo = Path(os.path.abspath(REPO_ROOT))
    lexical_path = Path(os.path.abspath(path))
    try:
        lexical_path.relative_to(lexical_repo)
    except ValueError:
        return False
    return True


def require_regular_no_reparse(path: Path, label: str) -> None:
    lexical_repo = Path(os.path.abspath(REPO_ROOT))
    lexical_path = Path(os.path.abspath(path))
    if not inside_repo(lexical_path):
        fail(f"{label} escapes repository: {path}")
    current = lexical_repo
    relative = lexical_path.relative_to(current)
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
    if not lexical_path.is_file():
        fail(f"{label} is not a regular file: {lexical_path}")


def main() -> int:
    require_regular_no_reparse(MANIFEST, "manifest")
    with MANIFEST.open("r", encoding="utf-8") as handle:
        data = json.load(handle)

    if data.get("schema") != 1 or data.get("tranche") != "R2.4":
        fail("unexpected manifest schema or tranche")
    for key, expected in EXPECTED_SCOPES.items():
        if data.get(key) != expected:
            fail(f"unexpected {key}: {data.get(key)!r}")
    if data.get("contextSemantics") != EXPECTED_CONTEXT_SEMANTICS:
        fail("unexpected contextSemantics")
    unknowns = data.get("unknowns")
    if not isinstance(unknowns, list) or len(unknowns) != 2:
        fail("manifest must preserve the two explicit unknown/stateful limitations")
    if "UNKNOWN" not in unknowns[0] or "not authorized" not in unknowns[0]:
        fail("EBAD client-to-server UNKNOWN must remain explicit and fail-closed")
    if "No C++ disconnect" not in unknowns[1]:
        fail("stateful terminal execution limitation must remain explicit")

    source_manifest_text = data.get("sourceManifest")
    if source_manifest_text != "../../../../../docs/architecture/rust-rewrite/r0-source-manifest.json":
        fail("unexpected sourceManifest path")
    source_manifest = Path(os.path.abspath(FIXTURE_DIR / source_manifest_text))
    expected_source_manifest = Path(os.path.abspath(REPO_ROOT / R0_RELATIVE))
    if source_manifest != expected_source_manifest:
        fail("sourceManifest does not resolve to the repository R0 manifest")
    require_regular_no_reparse(source_manifest, "source manifest")
    if data.get("sourceManifestSha256") != EXPECTED_R0_SHA256:
        fail("manifest R0 hash field is stale")
    if sha256(source_manifest) != EXPECTED_R0_SHA256:
        fail("current R0 manifest hash differs from the frozen R2.4 anchor")

    entries = data.get("fixtures")
    if not isinstance(entries, list) or len(entries) != len(EXPECTED):
        fail("manifest must contain exactly four terminal-control fixtures")
    seen_messages: set[str] = set()
    seen_files: set[str] = set()
    for entry in entries:
        if not isinstance(entry, dict):
            fail("fixture entry must be an object")
        message = entry.get("message")
        if message not in EXPECTED or message in seen_messages:
            fail(f"unexpected or duplicate message: {message!r}")
        expected = EXPECTED[message]
        filename = entry.get("file")
        if filename != Path(str(filename)).name or filename in seen_files:
            fail(f"fixture filename must be a unique basename: {filename!r}")
        for key, expected_value in expected.items():
            if entry.get(key) != expected_value:
                fail(f"unexpected {message}.{key}: {entry.get(key)!r}")
        if entry.get("size") != 4 or entry.get("terminal") is not True:
            fail(f"unexpected size/terminal metadata for {message}")
        source_refs = entry.get("sourceRefs")
        if not isinstance(source_refs, list) or not source_refs or not all(
            isinstance(value, str) and value for value in source_refs
        ):
            fail(f"missing sourceRefs for {message}")
        fixture = FIXTURE_DIR / filename
        require_regular_no_reparse(fixture, f"fixture {message}")
        if fixture.stat().st_size != 4:
            fail(f"fixture {message} is not exactly four bytes")
        if sha256(fixture) != expected["sha256"]:
            fail(f"fixture {message} hash mismatch")
        seen_messages.add(message)
        seen_files.add(filename)

    if seen_messages != set(EXPECTED):
        fail("fixture message set mismatch")
    print(
        "R2_4_TERMINAL_CONTROL_MANIFEST_PASS "
        f"fixtures={len(seen_messages)} r0_sha256={EXPECTED_R0_SHA256} "
        "terminal_policy_metadata=PASS_NOT_STATEFUL_TERMINAL_EXECUTION"
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, json.JSONDecodeError) as error:
        print(f"verify-rust-r2-terminal-control-manifest: {error}", file=sys.stderr)
        raise SystemExit(1) from error
