#!/usr/bin/env python3
"""Generate or verify the deterministic Rust R0 source manifest."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_OUTPUT = ROOT / "docs/architecture/rust-rewrite/r0-source-manifest.json"
R0_BASE_REVISION = "ffad9334acfba9b9bb2ea8ba3645cb0c05c94f11"
R0_BRANCH_AT_FREEZE = "fix/tls-rejected-socket-cleanup"

REQUIRED_FILES = {
    ".gitignore",
    "CMakeLists.txt",
    "cmake/ProjectOptions.cmake",
    ".hermes/scripts/generate-rust-r0-source-manifest.py",
    ".hermes/scripts/rust-r0-unittests.bat",
    "docs/architecture/rust-rewrite/contract-inventory.md",
    "docs/architecture/rust-rewrite/threat-model.md",
    "src/gui/CMakeLists.txt",
    "src/gui/src/FileTransferService.cpp",
    "src/gui/src/FileTransferService.h",
    "src/gui/src/Ipc.cpp",
    "src/gui/src/Ipc.h",
    "src/gui/src/IpcClient.cpp",
    "src/gui/src/IpcClient.h",
    "src/gui/src/IpcReader.cpp",
    "src/gui/src/IpcReader.h",
    "src/gui/src/PairingProtocolCodec.cpp",
    "src/gui/src/PairingProtocolCodec.h",
    "src/gui/src/PairingService.cpp",
    "src/gui/src/PairingService.h",
    "src/gui/test/PairingServiceTests.cpp",
    "src/gui/test/fixtures/pairing-srp6a-hkdf-v1.json",
    "src/lib/client/Client.cpp",
    "src/lib/client/Client.h",
    "src/lib/client/ServerProxy.cpp",
    "src/lib/client/ServerProxy.h",
    "src/lib/inputleap/ClipboardChunk.cpp",
    "src/lib/inputleap/ClipboardChunk.h",
    "src/lib/inputleap/win32/DaemonApp.cpp",
    "src/lib/inputleap/win32/DaemonApp.h",
    "src/lib/inputleap/FileChunk.cpp",
    "src/lib/inputleap/FileChunk.h",
    "src/lib/inputleap/PacketStreamFilter.cpp",
    "src/lib/inputleap/PacketStreamFilter.h",
    "src/lib/inputleap/Screen.cpp",
    "src/lib/io/StreamFilter.cpp",
    "src/lib/inputleap/ProtocolUtil.cpp",
    "src/lib/inputleap/ProtocolUtil.h",
    "src/lib/inputleap/protocol_types.cpp",
    "src/lib/inputleap/protocol_types.h",
    "src/lib/ipc/Ipc.cpp",
    "src/lib/ipc/Ipc.h",
    "src/lib/ipc/IpcClientProxy.cpp",
    "src/lib/ipc/IpcConnectionStateStore.cpp",
    "src/lib/ipc/IpcConnectionStateStore.h",
    "src/lib/ipc/IpcFrameReader.cpp",
    "src/lib/ipc/IpcFrameReader.h",
    "src/lib/ipc/IpcMessage.cpp",
    "src/lib/ipc/IpcMessage.h",
    "src/lib/ipc/IpcServerProxy.cpp",
    "src/lib/server/ClientConnectionByStream.cpp",
    "src/lib/server/ClientConnectionByStream.h",
    "src/lib/server/ClientProxy.cpp",
    "src/lib/server/ClientProxy.h",
    "src/lib/server/ClientProxy1_6.cpp",
    "src/lib/server/ClientProxy1_6.h",
    "src/lib/server/ClientProxyUnknown.cpp",
    "src/lib/server/ClientProxyUnknown.h",
    "src/lib/server/Server.cpp",
    "src/test/helpers/ProtocolFixtureEmitter.cpp",
    "src/test/helpers/ProtocolFixtureEmitter.h",
    "src/test/helpers/VerifyProtocolFixtureEmitter.cmake.in",
    "src/test/integtests/ipc/IpcTests.cpp",
    "src/test/unittests/CMakeLists.txt",
    "src/test/unittests/inputleap/ProtocolFixtureEmitterTests.cpp",
    "src/test/unittests/inputleap/ProtocolUtilTests.cpp",
    "src/test/unittests/ipc/IpcConnectionStateStoreTests.cpp",
    "src/test/unittests/ipc/IpcFrameReaderTests.cpp",
}

REQUIRED_DIRECTORIES = {
    "src/test/fixtures/rust-r0-wire",
}


def collect_paths() -> list[str]:
    paths = set(REQUIRED_FILES)
    for relative_directory in REQUIRED_DIRECTORIES:
        directory = ROOT / relative_directory
        if not directory.is_dir() or directory.is_symlink():
            raise RuntimeError(f"required fixture directory is unavailable: {relative_directory}")
        children = [child for child in directory.iterdir() if child.is_file()]
        if not children:
            raise RuntimeError(f"required fixture directory is empty: {relative_directory}")
        for child in children:
            paths.add(child.relative_to(ROOT).as_posix())
    return sorted(paths)


def canonical_content(relative_path: str, data: bytes) -> tuple[bytes, str]:
    if relative_path.endswith(".bin"):
        return data, "raw"
    without_crlf = data.replace(b"\r\n", b"")
    if b"\r" in without_crlf:
        raise RuntimeError(f"text source contains a lone CR: {relative_path}")
    return data.replace(b"\r\n", b"\n"), "canonical-lf"


def build_manifest() -> dict[str, object]:
    entries: list[dict[str, object]] = []
    content_digest = hashlib.sha256()
    for relative_path in collect_paths():
        path = ROOT / relative_path
        if path.is_symlink() or not path.is_file():
            raise RuntimeError(f"required source is not a regular file: {relative_path}")
        data, hash_mode = canonical_content(relative_path, path.read_bytes())
        digest = hashlib.sha256(data).hexdigest()
        entry = {
            "path": relative_path,
            "size": len(data),
            "hashMode": hash_mode,
            "sha256": digest,
        }
        entries.append(entry)
        content_digest.update(relative_path.encode("utf-8"))
        content_digest.update(b"\0")
        content_digest.update(str(len(data)).encode("ascii"))
        content_digest.update(b"\0")
        content_digest.update(hash_mode.encode("ascii"))
        content_digest.update(b"\0")
        content_digest.update(digest.encode("ascii"))
        content_digest.update(b"\n")

    return {
        "schema": 1,
        "name": "inputleap-rust-r0-source-manifest",
        "scope": "R0 C++ wire/IPC/pairing oracles, fixtures, tests, contracts, and build wiring",
        "textHashNormalization": "CRLF-to-LF; lone CR rejected; .bin hashed raw",
        "baseRevision": R0_BASE_REVISION,
        "snapshotKind": "dirty-working-tree-content-manifest",
        "branchAtFreeze": R0_BRANCH_AT_FREEZE,
        "pathCount": len(entries),
        "contentDigest": content_digest.hexdigest(),
        "files": entries,
    }


def encoded_manifest() -> bytes:
    return (json.dumps(build_manifest(), ensure_ascii=False, indent=2) + "\n").encode("utf-8")


def write_atomically(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(prefix=path.name + ".", dir=path.parent)
    temporary_path = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary_path, path)
    finally:
        if temporary_path.exists():
            temporary_path.unlink()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true", help="verify without modifying the manifest")
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    arguments = parser.parse_args()

    output = arguments.output.resolve()
    data = encoded_manifest()
    if arguments.check:
        if not output.is_file() or output.read_bytes() != data:
            print(f"R0_SOURCE_MANIFEST_MISMATCH path={output}")
            return 1
        print(f"R0_SOURCE_MANIFEST_PASS pathCount={build_manifest()['pathCount']}")
        return 0

    write_atomically(output, data)
    manifest = json.loads(data)
    print(
        "R0_SOURCE_MANIFEST_WRITTEN "
        f"pathCount={manifest['pathCount']} contentDigest={manifest['contentDigest']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
