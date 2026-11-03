param(
    [Parameter(Mandatory = $true)][string]$OutputPath,
    [string]$RuntimeDirectory,
    [string]$InstallerPath,
    [string]$PeerAddress,
    [ValidateRange(5, 120)][int]$SampleSeconds = 10
)

$ErrorActionPreference = 'Stop'
if ($RuntimeDirectory -and !(Test-Path -LiteralPath $RuntimeDirectory -PathType Container)) { throw 'Runtime directory missing' }
if ($InstallerPath -and !(Test-Path -LiteralPath $InstallerPath -PathType Leaf)) { throw 'Installer missing' }
$names = @('input-leap-tauri', 'input-leapd', 'input-leaps', 'input-leapc')
function Get-RuntimeSample {
    $all = @(Get-Process -ErrorAction SilentlyContinue)
    $ids = [Collections.Generic.HashSet[int]]::new()
    $all | Where-Object { $_.ProcessName -in $names } | ForEach-Object { [void]$ids.Add($_.Id) }
    $relations = @(Get-CimInstance Win32_Process | Select-Object ProcessId,ParentProcessId)
    do {
        $added = $false
        foreach ($relation in $relations) {
            if ($ids.Contains([int]$relation.ParentProcessId) -and $ids.Add([int]$relation.ProcessId)) { $added = $true }
        }
    } while ($added)
    @($all | Where-Object { $ids.Contains($_.Id) } | ForEach-Object {
        $cpu = try { $_.TotalProcessorTime.TotalSeconds } catch { $null }
        [pscustomobject]@{ Name = $_.ProcessName; Id = $_.Id; WorkingSetBytes = $_.WorkingSet64; CpuSeconds = $cpu }
    })
}
$before = Get-RuntimeSample
if (!$before.Count) { throw 'No operational runtime found; cannot establish baseline' }
$clock = [Diagnostics.Stopwatch]::StartNew()
Start-Sleep -Seconds $SampleSeconds
$after = Get-RuntimeSample
$clock.Stop()
$processes = @($after | ForEach-Object {
    $current = $_
    $initial = $before | Where-Object Id -eq $current.Id
    $cpu = if ($initial -and $null -ne $initial.CpuSeconds -and $null -ne $current.CpuSeconds) {
        [math]::Round(100 * ($current.CpuSeconds - $initial.CpuSeconds) / $clock.Elapsed.TotalSeconds, 3)
    } else { $null }
    [pscustomobject]@{ Name = $current.Name; WorkingSetBytes = $current.WorkingSetBytes; CpuPercentOneCore = $cpu; StableProcess = [bool]$initial }
})
$network = $null
if ($PeerAddress) {
    $pinger = [Net.NetworkInformation.Ping]::new()
    try {
        $replies = @(1..40 | ForEach-Object {
            $reply = $pinger.Send($PeerAddress, 700)
            if ($reply.Status -eq [Net.NetworkInformation.IPStatus]::Success) { [double]$reply.RoundtripTime }
            Start-Sleep -Milliseconds 200
        })
        $sorted = @($replies | Sort-Object)
        $network = [pscustomobject]@{
            Sent = 40; Received = $replies.Count
            AverageMs = if ($replies.Count) { ($replies | Measure-Object -Average).Average } else { $null }
            P95Ms = if ($sorted.Count) { $sorted[[math]::Ceiling($sorted.Count * 0.95) - 1] } else { $null }
            MaxMs = if ($sorted.Count) { $sorted[-1] } else { $null }
            Caveat = 'ICMP round-trip, not input processing latency. Missing replies do not prove TCP loss.'
        }
    } finally { $pinger.Dispose() }
}
$payloadBytes = $null
$qtFiles = $null
if ($RuntimeDirectory) {
    $files = @(Get-ChildItem -LiteralPath $RuntimeDirectory -Recurse -File | Where-Object { $_.Extension -in '.exe', '.dll' })
    $payloadBytes = ($files | Measure-Object -Property Length -Sum).Sum
    $qtFiles = @($files | Where-Object Name -match '^Qt[56].*\.dll$').Count
}
$installer = if ($InstallerPath) {
    [pscustomobject]@{ Bytes = (Get-Item -LiteralPath $InstallerPath).Length; Sha256 = (Get-FileHash -LiteralPath $InstallerPath -Algorithm SHA256).Hash }
} else { $null }
$result = [ordered]@{
    SchemaVersion = 1; CapturedAtUtc = [DateTime]::UtcNow.ToString('o')
    WorkspaceHead = (git rev-parse HEAD).Trim()
    WorkspaceDirty = ![string]::IsNullOrWhiteSpace((git status --porcelain | Out-String))
    OperationalRuntimeRevision = $null
    Label = 'operational-hybrid-observed-not-clean-idle'
    SampleSeconds = $clock.Elapsed.TotalSeconds; Processes = $processes
    RuntimeWorkingSetBytes = ($processes | Measure-Object WorkingSetBytes -Sum).Sum
    WebView2ChildrenIncluded = $true; RuntimeExecutablePayloadBytes = $payloadBytes; QtDllCount = $qtFiles
    Installer = $installer; Network = $network
    Limitations = @('Live working session, not a controlled idle run.', 'Workspace HEAD is not evidence of the installed runtime revision.', 'Unavailable CPU counters are null, never zero.', 'Process-tree descendants included when observable; live process exits may make snapshots differ.', 'An optional installer is only an observed file: its provenance and baseline comparability require independent verification.', 'No clipboard, credentials, hostnames or process command lines captured.')
}
$resolvedOutput = [IO.Path]::GetFullPath($OutputPath)
New-Item -ItemType Directory -Path ([IO.Path]::GetDirectoryName($resolvedOutput)) -Force | Out-Null
$result | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $resolvedOutput -Encoding UTF8
$result | ConvertTo-Json -Depth 6
