param(
    [Parameter(Mandatory = $true)]
    [string]$ArtifactDirectory
)

$ErrorActionPreference = 'Stop'
$installDir = Join-Path $env:ProgramFiles 'InputLeap'
$stateDir = Join-Path $env:ProgramData 'InputLeap'
$sentinel = Join-Path $stateDir 'clean-runner-smoke-preserve.txt'
$installers = @(Get-ChildItem -LiteralPath $ArtifactDirectory -Filter 'InputLeapSetup-*.exe' -File)
if ($installers.Count -ne 1) { throw "Expected exactly one Windows installer, found $($installers.Count)" }
$installer = $installers[0]
$manifest = Join-Path $ArtifactDirectory 'SHA256SUMS.txt'
if (-not (Test-Path -LiteralPath $manifest -PathType Leaf)) { throw 'Installer SHA-256 manifest is missing' }
$manifestEntries = @(Select-String -LiteralPath $manifest -Pattern ('^([0-9a-fA-F]{64})\s+' + [regex]::Escape($installer.Name) + '$'))
if ($manifestEntries.Count -ne 1) { throw 'Installer is not covered exactly once by SHA256SUMS.txt' }
$manifestHash = $manifestEntries[0].Matches[0].Groups[1].Value.ToLowerInvariant()
$actualInstallerHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $installer.FullName).Hash.ToLowerInvariant()
if ($manifestHash -ne $actualInstallerHash) { throw 'Installer SHA-256 does not match SHA256SUMS.txt' }
$sbomNames = @(
    'input-leap-windows-x64.cdx.json',
    'input-leap-rust-workspace.cdx.json',
    'input-leap-tauri-dependencies.cdx.json',
    'input-leap-agent-dependencies.cdx.json',
    'input-leap-server-dependencies.cdx.json'
)
foreach ($name in $sbomNames) {
    $sbomPath = Join-Path $ArtifactDirectory $name
    if (-not (Test-Path -LiteralPath $sbomPath -PathType Leaf)) { throw "SBOM missing from artifact: $name" }
    $sbom = Get-Content -Raw -LiteralPath $sbomPath | ConvertFrom-Json
    if ($sbom.bomFormat -ne 'CycloneDX' -or $sbom.specVersion -notmatch '^1\.[4-7]$') {
        throw "Invalid CycloneDX SBOM: $name"
    }
    if (-not $sbom.metadata.timestamp -or -not $sbom.metadata.tools) { throw "SBOM metadata is incomplete: $name" }
    $components = @($sbom.components)
    if ($components.Count -lt 10) { throw "SBOM has implausibly few components: $name ($($components.Count))" }
    if ($name -eq 'input-leap-windows-x64.cdx.json') {
        $componentNames = @($components | ForEach-Object { ($_.name -replace '\\', '/').Split('/')[-1] })
        foreach ($required in @(
            'dnssd.dll', 'mDNSResponder.exe', 'input-leap.exe', 'input-leapc.exe',
            'input-leaps.exe', 'LICENSE.txt', 'License.rtf', 'THIRD_PARTY_NOTICES.md',
            'GPL-3.0.txt', 'LGPL-3.0.txt', 'DEPLOYED-PAYLOAD.json', 'LICENSE',
            'LICENSE-APACHE-2.0.txt', 'SOURCE.txt', 'SHA256SUMS.txt'
        )) {
            if ($componentNames -notcontains $required) { throw "Windows SBOM omits: $required" }
        }
    }
    # File inventories produced by Syft intentionally describe package contents
    # without a dependency graph. Relationship checks apply only to package
    # manager dependency SBOMs, where purls and graph edges are meaningful.
    if ($name -ne 'input-leap-windows-x64.cdx.json') {
        $purls = @($components | Where-Object { $_.purl }).Count
        $edges = @($sbom.dependencies | Where-Object { @($_.dependsOn).Count -gt 0 }).Count
        if ($purls -lt 10) { throw "SBOM has insufficient package identifiers: $name ($purls)" }
        if ($edges -lt 5) { throw "SBOM has insufficient dependency relationships: $name ($edges)" }
    }
}

if (Get-Service -Name 'InputLeap' -ErrorAction SilentlyContinue) {
    throw 'Clean installer runner already has the InputLeap service'
}
if (Get-Service -Name 'Bonjour Service' -ErrorAction SilentlyContinue) {
    throw 'Clean installer runner already has a DNS-SD service'
}

New-Item -ItemType Directory -Path $stateDir -Force | Out-Null
Set-Content -LiteralPath $sentinel -Value 'preserve shared state on uninstall'
$silentArgs = @('/VERYSILENT', '/SUPPRESSMSGBOXES', '/NORESTART', '/SP-')
$result = Start-Process -FilePath $installer.FullName -ArgumentList $silentArgs -Wait -PassThru
if ($result.ExitCode -ne 0) { throw "Installer failed with exit code $($result.ExitCode)" }

foreach ($file in @(
    'input-leap-tauri.exe', 'input-leap.exe', 'input-leaps.exe',
    'input-leapc.exe', 'input-leapd.exe', 'LICENSE.txt', 'License.rtf',
    'THIRD_PARTY_NOTICES.md', 'licenses\Qt\GPL-3.0.txt',
    'licenses\Qt\LGPL-3.0.txt', 'licenses\Qt\DEPLOYED-PAYLOAD.json',
    'dnssd.dll', 'mDNSResponder.exe', 'licenses\mDNSResponder\LICENSE',
    'licenses\mDNSResponder\LICENSE-APACHE-2.0.txt',
    'licenses\mDNSResponder\SOURCE.txt', 'licenses\mDNSResponder\SHA256SUMS.txt'
)) {
    if (-not (Test-Path -LiteralPath (Join-Path $installDir $file) -PathType Leaf)) {
        throw "Required installed file missing: $file"
    }
}

$qtPayload = @(Get-Content -Raw -LiteralPath (Join-Path $installDir 'licenses\Qt\DEPLOYED-PAYLOAD.json') | ConvertFrom-Json)
if ($qtPayload.Count -eq 0) { throw 'Installed Qt deployed-payload manifest is empty' }
foreach ($entry in $qtPayload) {
    $qtPath = Join-Path $installDir $entry.path.Replace('/', '\')
    if (-not (Test-Path -LiteralPath $qtPath -PathType Leaf)) {
        throw "Installed Qt payload file missing: $($entry.path)"
    }
    $actualHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $qtPath).Hash.ToLowerInvariant()
    if ($actualHash -ne $entry.sha256) { throw "Installed Qt payload hash mismatch: $($entry.path)" }
}

$notices = Get-Content -Raw -LiteralPath (Join-Path $installDir 'THIRD_PARTY_NOTICES.md')
if ($notices -notmatch 'licenses/Qt/GPL-3\.0\.txt' -or
    $notices -notmatch 'licenses/Qt/LGPL-3\.0\.txt') {
    throw 'Third-party notices do not identify both Qt license texts'
}
if ($notices -notmatch 'Do not distribute this candidate until the source/offer and technical relinking obligations are demonstrated') {
    throw 'Third-party notices do not preserve the unresolved Qt distribution blocker'
}
if ($notices -notmatch 'f783506af3836b39b83fc14115bc2728a49db4b2') {
    throw 'Third-party notices do not identify the bundled DNS-SD source revision'
}

$service = Get-Service -Name 'InputLeap' -ErrorAction SilentlyContinue
if ($null -eq $service -or $service.Status -ne 'Running') {
    throw 'InputLeap service is missing or stopped after install'
}
$mdnsService = $null
for ($attempt = 0; $attempt -lt 30; $attempt++) {
    $mdnsService = Get-Service -Name 'Bonjour Service' -ErrorAction SilentlyContinue
    if ($mdnsService -and $mdnsService.Status -eq 'Running') { break }
    Start-Sleep -Seconds 1
}
if ($null -eq $mdnsService -or $mdnsService.Status -ne 'Running') {
    throw 'DNS-SD service is missing or stopped after install'
}

$uninstaller = Join-Path $installDir 'unins000.exe'
if (-not (Test-Path -LiteralPath $uninstaller -PathType Leaf)) { throw 'Uninstaller missing after install' }
$remove = Start-Process -FilePath $uninstaller -ArgumentList $silentArgs -Wait -PassThru
if ($remove.ExitCode -ne 0) { throw "Uninstaller failed with exit code $($remove.ExitCode)" }
if (Test-Path -LiteralPath (Join-Path $installDir 'input-leap-tauri.exe')) {
    throw 'Application files remain after uninstall'
}
for ($attempt = 0; $attempt -lt 30 -and (Get-Service -Name 'InputLeap' -ErrorAction SilentlyContinue); $attempt++) {
    Start-Sleep -Seconds 1
}
if (Get-Service -Name 'InputLeap' -ErrorAction SilentlyContinue) {
    throw 'InputLeap service remains after uninstall'
}
for ($attempt = 0; $attempt -lt 30 -and (Get-Service -Name 'Bonjour Service' -ErrorAction SilentlyContinue); $attempt++) {
    Start-Sleep -Seconds 1
}
if (Get-Service -Name 'Bonjour Service' -ErrorAction SilentlyContinue) {
    throw 'InputLeap-owned DNS-SD service remains after uninstall'
}
if (Get-NetFirewallRule -DisplayName 'InputLeap Listener' -ErrorAction SilentlyContinue) {
    throw 'InputLeap listener firewall rule remains after uninstall'
}
if (Get-NetFirewallRule -DisplayName 'InputLeap File Transfer' -ErrorAction SilentlyContinue) {
    throw 'InputLeap file-transfer firewall rule remains after uninstall'
}
if (-not (Test-Path -LiteralPath $sentinel -PathType Leaf)) {
    throw 'Uninstall removed shared ProgramData; user state must be preserved'
}
Remove-Item -LiteralPath $sentinel -Force
