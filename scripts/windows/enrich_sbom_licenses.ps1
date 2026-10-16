param(
    [Parameter(Mandatory = $true)]
    [string]$SbomPath,

    [Parameter(Mandatory = $true)]
    [string[]]$ManifestPaths
)

$ErrorActionPreference = 'Stop'

if (-not (Test-Path -LiteralPath $SbomPath -PathType Leaf)) {
    throw "SBOM does not exist: $SbomPath"
}
$licenseByPackage = @{}
foreach ($manifestPath in $ManifestPaths) {
    if (-not (Test-Path -LiteralPath $manifestPath -PathType Leaf)) {
        throw "Cargo manifest does not exist: $manifestPath"
    }

    $metadataLines = & cargo metadata --manifest-path $manifestPath --format-version 1 --locked
    if ($LASTEXITCODE -ne 0) {
        throw "cargo metadata failed for $manifestPath with exit code $LASTEXITCODE"
    }
    $metadata = ($metadataLines -join [Environment]::NewLine) | ConvertFrom-Json

    foreach ($package in $metadata.packages) {
        if (-not $package.license) {
            if ($package.source -like 'registry+*') {
                throw "Cargo registry package has no SPDX license expression: $($package.name)@$($package.version)"
            }
            continue
        }

        # Cargo metadata still exposes this legacy shorthand for a small number
        # of crates. CycloneDX requires an SPDX expression, so normalize its
        # common dual-license meaning to the current SPDX OR form.
        $licenseExpression = [string]$package.license
        if ($licenseExpression -eq 'MIT/Apache-2.0') {
            $licenseExpression = 'MIT OR Apache-2.0'
        }

        $key = ('{0}@{1}' -f $package.name.ToLowerInvariant(), $package.version)
        if ($licenseByPackage.ContainsKey($key) -and $licenseByPackage[$key] -ne $licenseExpression) {
            throw "Conflicting Cargo license metadata for $key"
        }
        $licenseByPackage[$key] = $licenseExpression
    }
}

$bom = Get-Content -Raw -LiteralPath $SbomPath | ConvertFrom-Json
if ($bom.bomFormat -ne 'CycloneDX' -or $bom.specVersion -notmatch '^1\.[4-7]$') {
    throw "Not a supported CycloneDX SBOM: $SbomPath"
}

$cargoComponents = @($bom.components | Where-Object { $_.purl -like 'pkg:cargo/*' })
if ($cargoComponents.Count -eq 0) {
    throw "No Cargo components found in SBOM: $SbomPath"
}

$enrichedCount = 0
foreach ($component in $cargoComponents) {
    if (-not $component.name -or -not $component.version) {
        throw "Cargo SBOM component is missing name or version: $($component.'bom-ref')"
    }

    $key = ('{0}@{1}' -f $component.name.ToLowerInvariant(), $component.version)
    if (-not $licenseByPackage.ContainsKey($key)) {
        throw "No Cargo SPDX metadata matched SBOM component $key"
    }

    $component | Add-Member -NotePropertyName licenses -NotePropertyValue @(
        [ordered]@{ expression = $licenseByPackage[$key] }
    ) -Force
    $enrichedCount++
}

$missingLicenses = @($cargoComponents | Where-Object { -not $_.licenses -or @($_.licenses).Count -eq 0 })
if ($missingLicenses.Count -gt 0) {
    throw "SBOM still has $($missingLicenses.Count) Cargo components without licenses"
}

$json = $bom | ConvertTo-Json -Depth 100
Set-Content -LiteralPath $SbomPath -Value $json -Encoding utf8
Write-Host "Enriched $enrichedCount Cargo SBOM components with Cargo SPDX license expressions: $SbomPath"
