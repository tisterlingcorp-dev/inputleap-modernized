from __future__ import annotations

import unittest
import json
import ctypes
import os
from pathlib import Path
from types import SimpleNamespace
import tempfile
from unittest import mock

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from update_manifest import (
    KEY_ID,
    PRODUCTION_PUBLIC_KEYS,
    _copy_dpapi_output,
    validate_manifest_fields,
    validate_new_key_id,
    validate_signing_key,
    wipe_bytearray,
    assemble_threshold_envelope,
    build_signature_contribution,
    sign_contribution,
    stable_package_metadata,
    _random_seed,
)


class ManifestInputValidationTests(unittest.TestCase):
    def test_threshold_envelope_is_schema_two_and_sorted_by_key_id(self) -> None:
        first = Ed25519PrivateKey.from_private_bytes(bytes(range(1, 33)))
        second = Ed25519PrivateKey.from_private_bytes(bytes(range(41, 73)))
        payload = b'{"schema":1}'
        trusted = {
            "release-a": first.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex(),
            "release-b": second.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex(),
        }
        envelope = json.loads(assemble_threshold_envelope([
            build_signature_contribution(payload, "release-b", second),
            build_signature_contribution(payload, "release-a", first),
        ], trusted))
        self.assertEqual(envelope["schema"], 2)
        self.assertEqual([item["keyId"] for item in envelope["signatures"]],
                         ["release-a", "release-b"])
        self.assertEqual(len(envelope["signatures"]), 2)

    def test_assembly_rejects_contributions_for_different_payloads(self) -> None:
        first = Ed25519PrivateKey.from_private_bytes(bytes(range(1, 33)))
        second = Ed25519PrivateKey.from_private_bytes(bytes(range(41, 73)))
        trusted = {
            "release-a": first.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex(),
            "release-b": second.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex(),
        }
        with self.assertRaises(ValueError):
            assemble_threshold_envelope([
                build_signature_contribution(b'{"schema":1}', "release-a", first),
                build_signature_contribution(b'{"schema":2}', "release-b", second),
            ], trusted)

    def test_package_metadata_rejects_size_snapshot_changed_during_hash(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            package = Path(directory) / "package.bin"
            package.write_bytes(b"0123456789abcdefghij")
            actual = package.stat()
            stale = SimpleNamespace(
                st_dev=actual.st_dev, st_ino=actual.st_ino, st_size=10,
                st_mtime_ns=actual.st_mtime_ns, st_ctime_ns=actual.st_ctime_ns,
            )
            with mock.patch("update_manifest.os.fstat", return_value=stale):
                with self.assertRaises(ValueError):
                    stable_package_metadata(package)
            size, digest = stable_package_metadata(package)
            self.assertEqual(size, 20)
            self.assertEqual(len(digest), 64)

    def test_mutable_secret_buffer_is_zeroed(self) -> None:
        secret = bytearray(b"sensitive seed material")
        wipe_bytearray(secret)
        self.assertEqual(secret, bytearray(len(secret)))

    @unittest.skipUnless(os.name == "nt", "Windows CNG is required")
    def test_key_seed_is_generated_directly_in_mutable_storage(self) -> None:
        seed = _random_seed()
        self.assertIsInstance(seed, bytearray)
        self.assertEqual(len(seed), 32)
        self.assertNotEqual(seed, bytearray(32))
        wipe_bytearray(seed)
        self.assertEqual(seed, bytearray(32))

    def test_dpapi_output_is_copied_directly_into_mutable_storage(self) -> None:
        source = (ctypes.c_ubyte * 4)(1, 2, 3, 4)
        copied = _copy_dpapi_output(source, 4)
        self.assertIsInstance(copied, bytearray)
        self.assertEqual(copied, bytearray((1, 2, 3, 4)))
        wipe_bytearray(copied)
        self.assertEqual(copied, bytearray(4))

    def test_signer_rejects_private_key_that_does_not_match_pinned_public_key(self) -> None:
        key = Ed25519PrivateKey.from_private_bytes(bytes(range(1, 33)))
        expected = key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()
        validate_signing_key(key, expected)
        with self.assertRaises(ValueError):
            validate_signing_key(key, "00" * 32)

    def test_init_refuses_to_recreate_established_production_key_id(self) -> None:
        for key_id in PRODUCTION_PUBLIC_KEYS:
            with self.subTest(key_id=key_id), self.assertRaises(ValueError):
                validate_new_key_id(key_id)
        validate_new_key_id("inputleap-modernized-release-2028-01")

    def test_accepts_fields_consumed_by_cpp_verifier(self) -> None:
        validate_manifest_fields(
            version="3.2.0",
            package_url="https://updates.example/releases/input-leap-3.2.0.msi",
            issued="2026-07-19T05:00:00Z",
            expires="2026-07-26T05:00:00Z",
            notes="Correções de segurança e estabilidade.",
        )

    def test_rejects_non_msi_package_url(self) -> None:
        with self.assertRaises(ValueError):
            validate_manifest_fields("3.2.0", "https://updates.example/package.exe",
                                     "2026-07-19T05:00:00Z", "2026-07-26T05:00:00Z", "Notas")

    def test_signer_emits_schema_two_windows_msi_payload(self) -> None:
        key = Ed25519PrivateKey.from_private_bytes(bytes(range(1, 33)))
        with tempfile.TemporaryDirectory() as directory:
            package = Path(directory) / "inputleap.msi"
            package.write_bytes(b"synthetic private msi fixture")
            output = Path(directory) / "contribution.json"
            arguments = SimpleNamespace(
                version="3.2.0", package_url="https://updates.example/inputleap.msi",
                issued="2026-07-19T05:00:00Z", expires="2026-07-26T05:00:00Z",
                notes="Notas", package=str(package),
                authenticode_signer_sha256="ab" * 32,
                signer="release-test=ignored", output=str(output))
            with mock.patch("update_manifest.PRODUCTION_PUBLIC_KEYS", {"release-test": "00" * 32}), \
                    mock.patch("update_manifest._load_private", return_value=key), \
                    mock.patch("update_manifest.validate_signing_key"):
                sign_contribution(arguments)
            contribution = json.loads(output.read_bytes())
            payload = json.loads(__import__("base64").urlsafe_b64decode(
                contribution["payload"] + "=" * (-len(contribution["payload"]) % 4)))
            self.assertEqual(payload["schema"], 2)
            self.assertEqual(payload["packageType"], "windows-msi")
            self.assertEqual(payload["authenticodeSignerSha256"], "ab" * 32)

    def test_rejects_package_urls_cpp_verifier_will_reject(self) -> None:
        for value in (
            "http://updates.example/package.exe",
            "https://user:secret@updates.example/package.exe",
            "https://updates.example/package.exe#fragment",
            "https:///package.exe",
            "https://updates.example/" + "a" * 2048,
        ):
            with self.subTest(value=value), self.assertRaises(ValueError):
                validate_manifest_fields("3.2.0", value, "2026-07-19T05:00:00Z",
                                         "2026-07-26T05:00:00Z", "Notas")

    def test_rejects_invalid_or_excessive_validity_interval(self) -> None:
        for issued, expires in (
            ("2026-07-19 05:00:00Z", "2026-07-26T05:00:00Z"),
            ("2026-07-19T05:00:00+00:00", "2026-07-26T05:00:00Z"),
            ("2026-07-26T05:00:00Z", "2026-07-19T05:00:00Z"),
            ("2026-07-01T00:00:00Z", "2026-08-01T00:00:01Z"),
        ):
            with self.subTest(issued=issued, expires=expires), self.assertRaises(ValueError):
                validate_manifest_fields("3.2.0", "https://updates.example/package.msi",
                                         issued, expires, "Notas")

    def test_rejects_notes_cpp_verifier_will_reject(self) -> None:
        for notes in ("", "linha\u0000oculta", "x" * 16385, "ç" * 16385):
            with self.subTest(length=len(notes)), self.assertRaises(ValueError):
                validate_manifest_fields("3.2.0", "https://updates.example/package.msi",
                                         "2026-07-19T05:00:00Z",
                                         "2026-07-26T05:00:00Z", notes)


if __name__ == "__main__":
    unittest.main()
