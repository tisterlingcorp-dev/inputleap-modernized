from __future__ import annotations

from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[3]
EXPECTED_URL = (
    "https://github.com/nelsonjchen/mDNSResponder/releases/download/"
    "v2019.05.08.1/x64_RelWithDebInfo.zip"
)
EXPECTED_SHA256 = "aad489258d047e396a43efff4270571c82e7da5d33cba1710b784b66fd4011f9"
DOWNLOADERS = (
    ROOT / ".github" / "workflows" / "builds.yml",
    ROOT / "clean_build.ps1",
)


class DependencyDownloadPolicyTests(unittest.TestCase):
    def test_bonjour_archive_is_version_pinned_and_verified_before_extract(self):
        for path in DOWNLOADERS:
            with self.subTest(path=path.relative_to(ROOT)):
                text = path.read_text(encoding="utf-8")
                download = text.find(EXPECTED_URL)
                checksum = text.find(EXPECTED_SHA256)
                verification = text.find("Get-FileHash")
                extraction = text.find("Expand-Archive")

                self.assertGreaterEqual(download, 0, "Bonjour URL must pin the release tag")
                self.assertGreaterEqual(checksum, 0, "Bonjour archive SHA-256 must be pinned")
                self.assertGreaterEqual(verification, 0, "Bonjour archive hash must be verified")
                self.assertGreater(extraction, verification, "hash verification must precede extraction")


if __name__ == "__main__":
    unittest.main()
