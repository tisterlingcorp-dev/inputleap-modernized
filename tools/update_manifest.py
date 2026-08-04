#!/usr/bin/env python
"""Create and use the InputLeap release-manifest Ed25519 key.

The private seed is protected with Windows DPAPI and never written to the
repository in plaintext. Only the current Windows user can decrypt it.
"""

from __future__ import annotations

import argparse
import base64
import ctypes
from ctypes import wintypes
from datetime import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import sys
from typing import Final
from urllib.parse import urlsplit

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

KEY_ID: Final = "inputleap-modernized-release-2026-01"
PRODUCTION_PUBLIC_KEY_HEX: Final = "3bdcc40b918377b0e4468acac69df830b8f9f8e9f7701604202082d61cb7aca6"
PRODUCTION_PUBLIC_KEYS: Final = {
    KEY_ID: PRODUCTION_PUBLIC_KEY_HEX,
    "inputleap-modernized-release-2026-02": "a0796391ac0378562fa81f24b35ed4bafbcd2b32e28b1018b6295ebc6776036e",
    "inputleap-modernized-release-2026-03": "f5a9f310b136d579b57d7a4c5540952f7012af94491e5925aa31126c423c2bd0",
}
ENTROPY: Final = b"InputLeap secure update signing key v1"
DEFAULT_KEY_PATH: Final = Path.home() / ".inputleap-release" / "update-signing-key.dpapi"
MAX_PACKAGE_BYTES: Final = 8 * 1024 * 1024 * 1024


class DataBlob(ctypes.Structure):
    _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_ubyte))]


def wipe_bytearray(data: bytearray) -> None:
    for index in range(len(data)):
        data[index] = 0


def _blob(data: bytes | bytearray) -> tuple[DataBlob, ctypes.Array[ctypes.c_ubyte]]:
    buffer = (ctypes.c_ubyte * len(data)).from_buffer_copy(data)
    return DataBlob(len(data), buffer), buffer


def _copy_dpapi_output(pointer: ctypes.c_void_p, size: int) -> bytearray:
    copied = bytearray(size)
    if size:
        destination = (ctypes.c_ubyte * size).from_buffer(copied)
        ctypes.memmove(destination, pointer, size)
    return copied


def _random_seed() -> bytearray:
    if os.name != "nt":
        raise RuntimeError("secure signing-key generation is supported only on Windows")
    seed = bytearray(32)
    destination = (ctypes.c_ubyte * len(seed)).from_buffer(seed)
    status = ctypes.windll.bcrypt.BCryptGenRandom(None, destination, len(seed), 0x2)
    if status != 0:
        wipe_bytearray(seed)
        raise OSError(f"BCryptGenRandom failed with NTSTATUS 0x{status & 0xffffffff:08x}")
    return seed


def _dpapi(data: bytes | bytearray, protect: bool) -> bytearray:
    if os.name != "nt":
        raise RuntimeError("DPAPI signing keys are supported only on Windows")
    source, source_buffer = _blob(data)
    entropy, entropy_buffer = _blob(ENTROPY)
    output = DataBlob()
    crypt32 = ctypes.windll.crypt32
    function = crypt32.CryptProtectData if protect else crypt32.CryptUnprotectData
    description = "InputLeap update signing key" if protect else None
    if protect:
        ok = function(ctypes.byref(source), description, ctypes.byref(entropy), None, None,
                      0x1, ctypes.byref(output))
    else:
        ok = function(ctypes.byref(source), None, ctypes.byref(entropy), None, None,
                      0x1, ctypes.byref(output))
    try:
        if not ok:
            raise ctypes.WinError()
        return _copy_dpapi_output(output.pbData, output.cbData)
    finally:
        ctypes.memset(source_buffer, 0, len(source_buffer))
        ctypes.memset(entropy_buffer, 0, len(entropy_buffer))
        if output.pbData:
            ctypes.memset(output.pbData, 0, output.cbData)
            ctypes.windll.kernel32.LocalFree(output.pbData)


def _write_private(path: Path, protected: bytes | bytearray) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    with temporary.open("xb") as stream:
        stream.write(protected)
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, path)
    os.chmod(path, 0o600)


def _load_private(path: Path) -> Ed25519PrivateKey:
    protected = bytearray(path.read_bytes())
    try:
        if not protected or len(protected) > 4096:
            raise ValueError("invalid protected signing key")
        seed = _dpapi(protected, protect=False)
        try:
            if len(seed) != 32:
                raise ValueError("invalid signing key length")
            return Ed25519PrivateKey.from_private_bytes(seed)
        finally:
            wipe_bytearray(seed)
    finally:
        wipe_bytearray(protected)


def _public_hex(key: Ed25519PrivateKey) -> str:
    return key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()


def validate_new_key_id(key_id: str) -> None:
    if key_id in PRODUCTION_PUBLIC_KEYS:
        raise ValueError("a pinned production key ID cannot be recreated; use a new rotation ID")
    if re.fullmatch(r"inputleap-modernized-release-[0-9]{4}-[0-9]{2}", key_id) is None:
        raise ValueError("key ID must use inputleap-modernized-release-YYYY-NN")


def validate_signing_key(key: Ed25519PrivateKey, expected_public_hex: str) -> None:
    actual = _public_hex(key)
    if actual != expected_public_hex.lower():
        raise ValueError("signing key does not match the pinned production public key")


def initialize(path: Path, key_id: str) -> None:
    validate_new_key_id(key_id)
    if path.exists():
        raise FileExistsError(f"refusing to overwrite existing key: {path}")
    seed = _random_seed()
    try:
        private_key = Ed25519PrivateKey.from_private_bytes(seed)
        protected = _dpapi(seed, protect=True)
        try:
            _write_private(path, protected)
        finally:
            wipe_bytearray(protected)
    finally:
        wipe_bytearray(seed)
    print(json.dumps({"key_id": key_id, "public_key_hex": _public_hex(private_key)}, sort_keys=True))


def stable_package_metadata(path: Path) -> tuple[int, str]:
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0)
    descriptor = os.open(path, flags)
    try:
        before = os.fstat(descriptor)
        if before.st_size < 1 or before.st_size > MAX_PACKAGE_BYTES:
            raise ValueError("package size is outside the supported range")
        digest = hashlib.sha256()
        byte_count = 0
        with os.fdopen(descriptor, "rb", closefd=False) as stream:
            for block in iter(lambda: stream.read(1024 * 1024), b""):
                byte_count += len(block)
                if byte_count > MAX_PACKAGE_BYTES:
                    raise ValueError("package size is outside the supported range")
                digest.update(block)
        after = os.fstat(descriptor)
        path_after = path.stat()
        identity_before = (before.st_dev, before.st_ino, before.st_size,
                           before.st_mtime_ns, before.st_ctime_ns)
        identity_after = (after.st_dev, after.st_ino, after.st_size,
                          after.st_mtime_ns, after.st_ctime_ns)
        path_identity = (path_after.st_dev, path_after.st_ino, path_after.st_size,
                         path_after.st_mtime_ns, path_after.st_ctime_ns)
        if byte_count != before.st_size or identity_before != identity_after or \
                identity_after != path_identity:
            raise ValueError("package changed while its release metadata was being computed")
        return byte_count, digest.hexdigest()
    finally:
        os.close(descriptor)


def _base64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _decode_base64url(value: str) -> bytes:
    if not value or re.fullmatch(r"[A-Za-z0-9_-]+", value) is None:
        raise ValueError("invalid canonical base64url")
    padded = value + "=" * ((4 - len(value) % 4) % 4)
    try:
        decoded = base64.b64decode(padded, altchars=b"-_", validate=True)
    except ValueError as error:
        raise ValueError("invalid canonical base64url") from error
    if _base64url(decoded) != value:
        raise ValueError("invalid canonical base64url")
    return decoded


def build_signature_contribution(payload: bytes, key_id: str,
                                 signer: Ed25519PrivateKey) -> bytes:
    if re.fullmatch(r"[A-Za-z0-9._-]{1,64}", key_id) is None:
        raise ValueError("signing key ID is invalid")
    contribution = {
        "keyId": key_id,
        "payload": _base64url(payload),
        "payloadSha256": hashlib.sha256(payload).hexdigest(),
        "schema": 1,
        "signature": _base64url(signer.sign(payload)),
    }
    return json.dumps(contribution, ensure_ascii=False, separators=(",", ":"),
                      sort_keys=True).encode("utf-8")


def assemble_threshold_envelope(
    contribution_documents: list[bytes],
    trusted_public_keys: dict[str, str] = PRODUCTION_PUBLIC_KEYS,
) -> bytes:
    if len(contribution_documents) < 2 or len(contribution_documents) > 16:
        raise ValueError("two to sixteen independent contributions are required")
    payload: bytes | None = None
    signatures: list[dict[str, str]] = []
    seen: set[str] = set()
    for document in contribution_documents:
        try:
            item = json.loads(document)
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise ValueError("signature contribution is not valid JSON") from error
        canonical = json.dumps(item, ensure_ascii=False, separators=(",", ":"),
                               sort_keys=True).encode("utf-8")
        if canonical != document or not isinstance(item, dict) or set(item) != {
                "keyId", "payload", "payloadSha256", "schema", "signature"} or \
                item.get("schema") != 1:
            raise ValueError("signature contribution is not canonical")
        key_id = item.get("keyId")
        if not isinstance(key_id, str) or key_id in seen:
            raise ValueError("duplicate or invalid signing key ID")
        public_hex = trusted_public_keys.get(key_id)
        if public_hex is None:
            raise ValueError(f"signing key ID is not pinned for production: {key_id}")
        item_payload = _decode_base64url(item.get("payload", ""))
        signature = _decode_base64url(item.get("signature", ""))
        if len(signature) != 64 or item.get("payloadSha256") != hashlib.sha256(item_payload).hexdigest():
            raise ValueError("signature contribution digest is invalid")
        try:
            Ed25519PublicKey.from_public_bytes(bytes.fromhex(public_hex)).verify(
                signature, item_payload)
        except (ValueError, InvalidSignature) as error:
            raise ValueError("signature contribution is invalid") from error
        if payload is None:
            payload = item_payload
        elif payload != item_payload:
            raise ValueError("signature contributions do not cover the same payload")
        seen.add(key_id)
        signatures.append({"keyId": key_id, "signature": item["signature"]})

    signatures.sort(key=lambda item: item["keyId"])
    envelope = {
        "payload": _base64url(payload or b""),
        "schema": 2,
        "signatures": signatures,
    }
    return json.dumps(envelope, ensure_ascii=False, separators=(",", ":"),
                      sort_keys=True).encode("utf-8")


def validate_manifest_fields(version: str, package_url: str, issued: str,
                             expires: str, notes: str) -> None:
    match = re.fullmatch(
        r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)", version
    )
    if match is None or any(int(component) > 999999 for component in match.groups()):
        raise ValueError("version must be stable semantic version MAJOR.MINOR.PATCH")

    if len(package_url) > 2048:
        raise ValueError("package URL is too long")
    try:
        parsed_url = urlsplit(package_url)
        hostname = parsed_url.hostname
    except ValueError as error:
        raise ValueError("package URL is invalid") from error
    if (parsed_url.scheme != "https" or not hostname or parsed_url.username is not None or
            parsed_url.password is not None or parsed_url.fragment or
            not parsed_url.path.lower().endswith(".msi")):
        raise ValueError("package URL must be HTTPS without credentials or fragment")

    def strict_utc(value: str) -> datetime:
        if re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z", value) is None:
            raise ValueError("manifest times must use YYYY-MM-DDTHH:MM:SSZ")
        try:
            return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ")
        except ValueError as error:
            raise ValueError("manifest time is invalid") from error

    issued_time = strict_utc(issued)
    expires_time = strict_utc(expires)
    validity_seconds = (expires_time - issued_time).total_seconds()
    if validity_seconds <= 0 or validity_seconds > 30 * 24 * 60 * 60:
        raise ValueError("manifest validity interval must be positive and at most 30 days")

    utf16_units = len(notes.encode("utf-16-le")) // 2
    if (not notes or utf16_units > 16384 or len(notes.encode("utf-8")) > 32768 or
            any((ord(character) < 0x20 and character not in "\n\r\t") or
                ord(character) == 0x7f for character in notes)):
        raise ValueError("release notes are empty, too long, or contain unsafe control text")


def _atomic_write(path: Path, content: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    with temporary.open("xb") as stream:
        stream.write(content)
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, path)


def sign_contribution(arguments: argparse.Namespace) -> None:
    validate_manifest_fields(arguments.version, arguments.package_url, arguments.issued,
                             arguments.expires, arguments.notes)
    package = Path(arguments.package)
    size, digest_hex = stable_package_metadata(package)
    signer_digest = arguments.authenticode_signer_sha256
    if re.fullmatch(r"[0-9a-f]{64}", signer_digest) is None:
        raise ValueError(
            "Authenticode signer SHA-256 must be 64 lowercase hex characters")
    payload_object = {
        "authenticodeSignerSha256": signer_digest,
        "channel": "stable",
        "expiresAtUtc": arguments.expires,
        "issuedAtUtc": arguments.issued,
        "notes": arguments.notes,
        "packageUrl": arguments.package_url,
        "packageType": "windows-msi",
        "schema": 2,
        "sha256": digest_hex,
        "size": size,
        "version": arguments.version,
    }
    payload = json.dumps(payload_object, ensure_ascii=False, separators=(",", ":"),
                         sort_keys=True).encode("utf-8")
    if "=" not in arguments.signer:
        raise ValueError("signer must use KEY_ID=PATH")
    key_id, path_text = arguments.signer.split("=", 1)
    expected_public = PRODUCTION_PUBLIC_KEYS.get(key_id)
    if expected_public is None:
        raise ValueError(f"signing key ID is not pinned for production: {key_id}")
    private_key = _load_private(Path(path_text))
    validate_signing_key(private_key, expected_public)
    encoded = build_signature_contribution(payload, key_id, private_key)
    _atomic_write(Path(arguments.output), encoded)
    print(json.dumps({"contribution": str(arguments.output), "key_id": key_id,
                      "package_size": size, "payload_sha256": hashlib.sha256(payload).hexdigest()},
                     sort_keys=True))


def assemble_manifest(arguments: argparse.Namespace) -> None:
    documents = []
    for path_text in arguments.contribution:
        path = Path(path_text)
        if path.stat().st_size < 1 or path.stat().st_size > 128 * 1024:
            raise ValueError("signature contribution size is invalid")
        documents.append(path.read_bytes())
    envelope = assemble_threshold_envelope(documents)
    _atomic_write(Path(arguments.output), envelope)
    print(json.dumps({"contributions": len(documents), "manifest": str(arguments.output)},
                     sort_keys=True))


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser()
    commands = root.add_subparsers(dest="command", required=True)
    init = commands.add_parser("init")
    init.add_argument("--key", type=Path, default=DEFAULT_KEY_PATH)
    init.add_argument("--key-id", required=True)
    sign = commands.add_parser("sign-contribution")
    sign.add_argument("--signer", required=True,
                      help="exactly one production signer in KEY_ID=PATH form")
    sign.add_argument("--package", required=True)
    sign.add_argument("--package-url", required=True)
    sign.add_argument("--version", required=True)
    sign.add_argument("--issued", required=True)
    sign.add_argument("--expires", required=True)
    sign.add_argument("--notes", required=True)
    sign.add_argument("--authenticode-signer-sha256", required=True,
                      help="SHA-256 of the Authenticode leaf signer certificate")
    sign.add_argument("--output", required=True)
    assemble = commands.add_parser("assemble")
    assemble.add_argument("--contribution", action="append", required=True,
                          help="independently produced contribution; specify at least two")
    assemble.add_argument("--output", required=True)
    return root


def main() -> int:
    arguments = parser().parse_args()
    try:
        if arguments.command == "init":
            initialize(arguments.key, arguments.key_id)
        elif arguments.command == "sign-contribution":
            sign_contribution(arguments)
        else:
            assemble_manifest(arguments)
        return 0
    except Exception as error:
        print(f"error: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
