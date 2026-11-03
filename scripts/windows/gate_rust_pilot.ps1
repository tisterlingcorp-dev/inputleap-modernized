param([switch]$SkipDependencyAudit)
$ErrorActionPreference = 'Stop'
$root = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$previousToolchain = $env:RUSTUP_TOOLCHAIN
$toolchain = ((Get-Content (Join-Path $root 'rust\rust-toolchain.toml') | Select-String '^channel\s*=\s*"([^"]+)"').Matches.Groups[1].Value)
if (!$toolchain) { throw 'Pinned toolchain missing' }
$auditTool = Join-Path $root 'rust\.tools\bin\cargo-deny.exe'
if (!(Test-Path -LiteralPath $auditTool -PathType Leaf)) {
    $auditTool = (Get-Command cargo-deny -ErrorAction SilentlyContinue).Source
}
if (!$SkipDependencyAudit -and !$auditTool) { throw 'cargo-deny 0.20.2 required; see rust/README.md' }
if (!$SkipDependencyAudit) {
    $auditVersion = & $auditTool --version
    if ($LASTEXITCODE -ne 0 -or $auditVersion.Trim() -ne 'cargo-deny 0.20.2') { throw 'Expected cargo-deny 0.20.2' }
}
$manifests = @(
    'rust/Cargo.toml',
    'rust/bins/input-leap-agent/Cargo.toml',
    'rust/bins/input-leap-server/Cargo.toml',
    'rust/apps/input-leap/src-tauri/Cargo.toml'
)
function Invoke-CargoGate([string[]]$CargoArguments) {
    & cargo "+$toolchain" @CargoArguments
    if ($LASTEXITCODE -ne 0) { throw "Cargo gate failed: $($CargoArguments -join ' ')" }
}
Push-Location $root
try {
    $env:RUSTUP_TOOLCHAIN = $toolchain
    $compilerInfo = & rustc "+$toolchain" -vV
    if ($LASTEXITCODE -ne 0 -or !($compilerInfo -contains 'host: x86_64-pc-windows-msvc')) {
        throw 'Windows x64 MSVC host toolchain required'
    }
    foreach ($manifest in $manifests) {
        if (!(Test-Path -LiteralPath $manifest -PathType Leaf)) { throw "Manifest missing: $manifest" }
        Invoke-CargoGate @('metadata', '--locked', '--no-deps', '--format-version', '1', '--manifest-path', $manifest) | Out-Null
        Invoke-CargoGate @('fmt', '--manifest-path', $manifest, '--all', '--check')
        Invoke-CargoGate @('clippy', '--manifest-path', $manifest, '--locked', '--workspace', '--all-targets', '--', '-D', 'warnings')
        Invoke-CargoGate @('test', '--manifest-path', $manifest, '--locked', '--workspace', '--all-targets')
        Invoke-CargoGate @('build', '--manifest-path', $manifest, '--locked', '--release', '--workspace')
        if (!$SkipDependencyAudit) {
            & $auditTool --manifest-path $manifest --locked check
            if ($LASTEXITCODE -ne 0) { throw "Dependency policy failed for $manifest" }
        }
    }
    if ($SkipDependencyAudit) {
        Write-Warning 'RUST_PILOT_LOCAL_CHECKS_PASS_WITHOUT_AUDIT: not a release gate.'
    } else {
        Write-Output 'RUST_PILOT_GATE_PASS'
    }
} finally {
    Pop-Location
    $env:RUSTUP_TOOLCHAIN = $previousToolchain
}
