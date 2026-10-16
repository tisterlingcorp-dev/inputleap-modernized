from __future__ import annotations

from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[3]
MDNS_REVISION = "f783506af3836b39b83fc14115bc2728a49db4b2"


class DependencyDownloadPolicyTests(unittest.TestCase):
    def test_dns_sd_source_revision_is_pinned_across_build_paths(self):
        workflow = (ROOT / ".github" / "workflows" / "builds.yml").read_text(encoding="utf-8")
        local_build = (ROOT / "clean_build.ps1").read_text(encoding="utf-8")
        build_script = (ROOT / "scripts" / "windows" / "build_mdns_responder.ps1").read_text(
            encoding="utf-8"
        )
        notices = (ROOT / "THIRD_PARTY_NOTICES.md").read_text(encoding="utf-8")
        installer = (ROOT / "dist" / "inno" / "input-leap.iss.in").read_text(encoding="utf-8")

        for path, text in (
            ("workflow", workflow),
            ("local build", local_build),
            ("build script", build_script),
            ("third-party notices", notices),
        ):
            with self.subTest(path=path):
                self.assertIn(MDNS_REVISION, text)
        self.assertIn("apple-oss-distributions/mDNSResponder", workflow)
        self.assertIn("apple-oss-distributions/mDNSResponder", local_build)
        self.assertIn('DestName: "THIRD_PARTY_NOTICES.md"', installer)
        self.assertNotIn("x64_RelWithDebInfo.zip", workflow + local_build)

    def test_dns_sd_build_produces_and_installs_the_runtime_and_notices(self):
        build_script = (ROOT / "scripts" / "windows" / "build_mdns_responder.ps1").read_text(
            encoding="utf-8"
        )
        cmake = (ROOT / "src" / "gui" / "CMakeLists.txt").read_text(encoding="utf-8")
        installer = (ROOT / "dist" / "inno" / "input-leap.iss.in").read_text(encoding="utf-8")

        for project in (
            "mDNSWindows\\DLL\\dnssd.vcxproj",
            "mDNSWindows\\DLLStub\\DLLStub.vcxproj",
            "mDNSWindows\\SystemService\\mDNSResponder.vcxproj",
        ):
            with self.subTest(project=project):
                self.assertIn(project, build_script)
        for artifact in (
            "Bin\\x64\\dnssd.dll",
            "Bin\\x64\\mDNSResponder.exe",
            "Licenses\\mDNSResponder\\LICENSE",
        ):
            with self.subTest(artifact=artifact):
                self.assertIn(artifact, build_script)
        self.assertIn("Bin/x64/dnssd.dll", cmake)
        self.assertIn("Bin/x64/mDNSResponder.exe", cmake)
        self.assertIn("Licenses/mDNSResponder/LICENSE", cmake)
        self.assertIn('DestName: "THIRD_PARTY_NOTICES.md"', installer)
        self.assertIn("IsInputLeapManagedDnsSdService", installer)
        self.assertIn("BeforeInstall: StopManagedDnsSdService", installer)
        self.assertIn("AfterInstall: InstallManagedDnsSdService", installer)
        self.assertIn("-install", installer)
        self.assertIn("-remove", installer)

    def test_application_does_not_download_or_execute_legacy_bonjour_installer(self):
        main_window = (ROOT / "src" / "gui" / "src" / "MainWindow.cpp").read_text(
            encoding="utf-8"
        )
        main_window_header = (ROOT / "src" / "gui" / "src" / "MainWindow.h").read_text(
            encoding="utf-8"
        )

        for forbidden in (
            "binaries.symless.com/bonjour",
            "downloadBonjour",
            "installBonjour",
            "m_BonjourInstall",
            "DataDownloader",
            "CommandProcess",
            "Bonjour.msi",
            "msiexec",
        ):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, main_window)
                self.assertNotIn(forbidden, main_window_header)


if __name__ == "__main__":
    unittest.main()
