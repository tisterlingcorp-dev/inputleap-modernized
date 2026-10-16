param(
    [Parameter(Mandatory = $true)][string]$SourceDirectory,
    [Parameter(Mandatory = $true)][string]$OutputDirectory,
    [string]$WindowsSdkVersion = '10.0.26100.0'
)

$ErrorActionPreference = 'Stop'
$source = (Resolve-Path -LiteralPath $SourceDirectory).Path
$output = [System.IO.Path]::GetFullPath($OutputDirectory)
$expectedRevision = 'f783506af3836b39b83fc14115bc2728a49db4b2'
$actualRevision = (& git -C $source rev-parse HEAD).Trim()
if ($LASTEXITCODE -ne 0 -or $actualRevision -ne $expectedRevision) {
    throw "mDNSResponder source revision mismatch: expected $expectedRevision, got $actualRevision"
}
New-Item -ItemType Directory -Force -Path $output | Out-Null
$hashManifest = Join-Path $output 'SHA256SUMS.txt'
if (Test-Path -LiteralPath $hashManifest) { Remove-Item -LiteralPath $hashManifest -Force }

$msbuildCommand = Get-Command msbuild.exe -ErrorAction SilentlyContinue
if ($msbuildCommand) {
    $msbuildPath = $msbuildCommand.Source
} else {
    $vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
    if (-not (Test-Path -LiteralPath $vswhere)) { throw 'MSBuild is not on PATH and Visual Studio vswhere.exe was not found' }
    $msbuildPath = (& $vswhere -latest -products '*' -requires Microsoft.Component.MSBuild -find 'MSBuild\**\Bin\MSBuild.exe' | Select-Object -First 1)
    if ($LASTEXITCODE -ne 0 -or -not $msbuildPath -or -not (Test-Path -LiteralPath $msbuildPath)) {
        throw 'Could not locate Visual Studio MSBuild through vswhere'
    }
}
$projects = @(
    'mDNSWindows\DLL\dnssd.vcxproj',
    'mDNSWindows\DLLStub\DLLStub.vcxproj',
    'mDNSWindows\SystemService\mDNSResponder.vcxproj'
)
$previousCl = $env:CL
$env:CL = '/D UINT32_MAX=0xFFFFFFFFU /FIassert.h'
try {
    foreach ($relativeProject in $projects) {
        $project = Join-Path $source $relativeProject
        if (-not (Test-Path -LiteralPath $project)) { throw "Pinned mDNSResponder project missing: $relativeProject" }
        & $msbuildPath $project /m /nologo /verbosity:minimal `
            /p:Configuration=Release /p:Platform=x64 `
            /p:PlatformToolset=v143 /p:WindowsTargetPlatformVersion=$WindowsSdkVersion
        if ($LASTEXITCODE -ne 0) { throw "mDNSResponder build failed for $relativeProject with exit code $LASTEXITCODE" }
    }
} finally {
    if ($null -eq $previousCl) { Remove-Item Env:CL -ErrorAction SilentlyContinue }
    else { $env:CL = $previousCl }
}

$artifacts = @{
    'mDNSWindows\DLL\x64\Release\dnssd.dll' = 'Bin\x64\dnssd.dll'
    'mDNSWindows\DLLStub\x64\Release\dnssd_stub.lib' = 'Lib\x64\dnssd.lib'
    'mDNSWindows\SystemService\x64\Release\mDNSResponder.exe' = 'Bin\x64\mDNSResponder.exe'
    'mDNSShared\dns_sd.h' = 'Include\dns_sd.h'
    'LICENSE' = 'Licenses\mDNSResponder\LICENSE'
}
foreach ($entry in $artifacts.GetEnumerator()) {
    $from = Join-Path $source $entry.Key
    $to = Join-Path $output $entry.Value
    if (-not (Test-Path -LiteralPath $from -PathType Leaf)) { throw "Required mDNSResponder output missing: $from" }
    New-Item -ItemType Directory -Force -Path (Split-Path -Parent $to) | Out-Null
    Copy-Item -LiteralPath $from -Destination $to -Force
}

$sourceInfo = @(
    'Project: https://github.com/apple-oss-distributions/mDNSResponder',
    "Commit: $expectedRevision",
    "Windows SDK: $WindowsSdkVersion",
    'Build configuration: Release x64',
    'dnssd.lib is the upstream DLLStub import library, renamed for the existing CMake find_library contract.'
)
Set-Content -LiteralPath (Join-Path $output 'SOURCE.txt') -Value $sourceInfo -Encoding utf8
Get-ChildItem -LiteralPath $output -Recurse -File | Get-FileHash -Algorithm SHA256 |
    ForEach-Object { '{0}  {1}' -f $_.Hash.ToLowerInvariant(), $_.Path.Substring($output.Length + 1) } |
    Set-Content -LiteralPath (Join-Path $output 'SHA256SUMS.txt') -Encoding ascii
