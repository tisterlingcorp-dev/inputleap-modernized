from __future__ import annotations

from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[3]
MDNS_REVISION = "f783506af3836b39b83fc14115bc2728a49db4b2"
APACHE_LICENSE_SHA256 = "cfc7749b96f63bd31c3c42b5c471bf756814053e847c10f3eb003417bc523d30"


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
        workflow = (ROOT / ".github" / "workflows" / "builds.yml").read_text(encoding="utf-8")
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
            "LICENSE-APACHE-2.0.txt",
        ):
            with self.subTest(artifact=artifact):
                self.assertIn(artifact, build_script)
        self.assertIn("Bin/x64/dnssd.dll", cmake)
        self.assertIn("Bin/x64/mDNSResponder.exe", cmake)
        self.assertIn("Licenses/mDNSResponder/LICENSE", cmake)
        self.assertIn("Licenses/mDNSResponder/LICENSE-APACHE-2.0.txt", cmake)
        self.assertIn(f"$expectedApacheLicenseSha256 = '{APACHE_LICENSE_SHA256}'", build_script)
        self.assertIn("https://www.apache.org/licenses/LICENSE-2.0.txt", build_script)
        self.assertIn('DestName: "THIRD_PARTY_NOTICES.md"', installer)
        self.assertIn(
            "if ($requireMdns -and $notices -notmatch",
            workflow,
            "The current DNS-SD revision is required for the candidate, not the older upgrade baseline",
        )
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

    def test_windows_package_sbom_is_validated_for_runtime_inventory_and_hashes(self):
        workflow = (ROOT / ".github" / "workflows" / "builds.yml").read_text(encoding="utf-8")
        validation = workflow.split("- name: Validate dependency SBOM coverage", 1)[1].split(
            "- name:", 1
        )[0]

        self.assertIn("input-leap-windows-x64.cdx.json", validation)
        self.assertIn("$bom.metadata.component.name", validation)
        self.assertIn("$_.hashes | Where-Object { $_.alg -eq 'SHA-256' -and $_.content }", validation)
        for component in (
            "dnssd.dll", "mDNSResponder.exe", "input-leap.exe", "input-leapc.exe", "input-leaps.exe",
            "LICENSE.txt", "License.rtf", "THIRD_PARTY_NOTICES.md", "GPL-2.0.txt",
            "LICENSE", "LICENSE-APACHE-2.0.txt", "SOURCE.txt", "SHA256SUMS.txt",
        ):
            with self.subTest(component=component):
                self.assertIn(component, validation)

        workflow = (ROOT / ".github" / "workflows" / "builds.yml").read_text(encoding="utf-8")
        windows_sbom = workflow.split("- name: Generate Windows package SBOM", 1)[1].split(
            "- name:", 1
        )[0]
        self.assertIn("SYFT_FILE_METADATA_SELECTION: all", windows_sbom)
        self.assertIn("build\\windows-installer-sbom-input", windows_sbom)

    def test_windows_package_installs_selected_qt_license_and_source_information(self):
        cmake = (ROOT / "CMakeLists.txt").read_text(encoding="utf-8")
        workflow = (ROOT / ".github" / "workflows" / "builds.yml").read_text(encoding="utf-8")
        notices = (ROOT / "THIRD_PARTY_NOTICES.md").read_text(encoding="utf-8")
        smoke = (ROOT / "scripts" / "windows" / "smoke_installer_clean.ps1").read_text(encoding="utf-8")
        project_license = (ROOT / "LICENSE").read_text(encoding="utf-8")
        source_info = (ROOT / "licenses" / "Qt" / "SOURCE.txt").read_text(encoding="utf-8")
        gpl_offset = project_license.index("GNU GENERAL PUBLIC LICENSE")
        gpl = project_license[gpl_offset:]

        self.assertTrue(gpl.startswith("GNU GENERAL PUBLIC LICENSE"))
        self.assertIn("Version 2, June 1991", gpl)
        self.assertGreater(len(gpl), 15_000)
        self.assertIn('string(FIND "${INPUTLEAP_LICENSE_TEXT}" "GNU GENERAL PUBLIC LICENSE"', cmake)
        self.assertIn('"${INPUTLEAP_QT_GPL2_TEXT}"', cmake)
        self.assertIn('"${CMAKE_CURRENT_SOURCE_DIR}/licenses/Qt/SOURCE.txt"', cmake)
        self.assertIn("licenses\\Qt\\GPL-2.0.txt", workflow)
        self.assertIn("Installed Qt license file is not the complete GPL-2.0 text", workflow)
        self.assertIn("Installed Qt license file is not the complete GPL-2.0 text", smoke)
        self.assertIn("Installed third-party notices do not identify the selected Qt GPL-2.0-only terms", workflow)
        self.assertIn("qt-everywhere-src-6.8.3.tar.xz", source_info)
        self.assertIn("https://download.qt.io/archive/qt/6.8/6.8.3/single/", source_info)
        self.assertIn("https://download.qt.io/archive/qt/6.8/6.8.3/single/", workflow)
        self.assertNotIn("https://download.qt.io/official_releases/qt/6.8/6.8.3/single/", workflow)
        self.assertIn("cdd3a69967208276bb01af7ace7dba0ba53e679f886a4cbe624225c60fb73f2c", source_info)
        self.assertIn("every deployed Qt DLL/plugin and bundled third-party file", notices)
        self.assertIn("distribution gate remains closed until", notices)

    def test_legacy_baseline_installer_is_not_required_to_have_new_qt_legal_payload(self):
        workflow = (ROOT / ".github" / "workflows" / "builds.yml").read_text(encoding="utf-8")
        smoke = workflow.split("- name: Smoke-test Windows installer lifecycle", 1)[1].split(
            "- uses: actions/upload-artifact", 1
        )[0]

        self.assertIn("[bool]$requireCurrentLegalPayload = $true", smoke)
        self.assertIn("if ($requireCurrentLegalPayload)", smoke)
        self.assertIn("Install-Package $previousPath 'Previous' $false $false", smoke)
        self.assertIn("Install-Package $previousPath 'Rollback' $false $false", smoke)
        self.assertIn("Install-Package $installer.FullName 'Current upgrade'", smoke)
        self.assertIn("Install-Package $installer.FullName 'Current repair/reinstall'", smoke)
        self.assertIn("Assert-InstalledPackage '' $requireMdns $requireCurrentLegalPayload", smoke)

    def test_release_installer_is_smoke_tested_on_a_separate_fresh_windows_runner(self):
        workflow = (ROOT / ".github" / "workflows" / "builds.yml").read_text(encoding="utf-8")
        clean_job = workflow.split("  windows-clean-installer-smoke:", 1)[1].split("  freebsd-build:", 1)[0]
        smoke = (ROOT / "scripts" / "windows" / "smoke_installer_clean.ps1").read_text(encoding="utf-8")

        self.assertIn("needs: [win-build, windows-qt-source]", clean_job)
        self.assertIn("runs-on: windows-2022", clean_job)
        self.assertIn("actions/download-artifact@v7", clean_job)
        self.assertIn("windows-installer-Windows Qt6", clean_job)
        self.assertIn("SHA256SUMS.txt", smoke)
        self.assertIn("input-leap-windows-x64.cdx.json", smoke)
        self.assertIn("input-leap-server-dependencies.cdx.json", smoke)
        self.assertIn("Get-FileHash -Algorithm SHA256", smoke)
        self.assertIn("Install and uninstall package on a fresh Windows runner", clean_job)
        self.assertIn("THIRD_PARTY_NOTICES.md", smoke)
        self.assertIn("Uninstall removed shared ProgramData", smoke)

    def test_windows_package_records_and_verifies_exact_deployed_qt_payload(self):
        workflow = (ROOT / ".github" / "workflows" / "builds.yml").read_text(encoding="utf-8")
        build = workflow.split("- name: Run build system", 1)[1].split("- name:", 1)[0]
        sbom = workflow.split("- name: Validate dependency SBOM coverage", 1)[1].split(
            "- name:", 1
        )[0]
        smoke = workflow.split("- name: Smoke-test Windows installer lifecycle", 1)[1].split(
            "- name:", 1
        )[0]

        self.assertIn("DEPLOYED-PAYLOAD.json", build)
        self.assertIn("FileVersionInfo]::GetVersionInfo", build)
        self.assertIn("Get-FileHash -Algorithm SHA256", build)
        self.assertIn("manifest is evidence for license review", build)
        self.assertIn("DEPLOYED-PAYLOAD.json", sbom)
        self.assertIn("$qtPayload.Count -eq 0", sbom)
        self.assertIn("$componentNames -notcontains (Split-Path -Leaf $entry.path)", sbom)
        self.assertIn("licenses\\Qt\\DEPLOYED-PAYLOAD.json", smoke)
        self.assertIn("$actualHash -ne $entry.sha256", smoke)


if __name__ == "__main__":
    unittest.main()
