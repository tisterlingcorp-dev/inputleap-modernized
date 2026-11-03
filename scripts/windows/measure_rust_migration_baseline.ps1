param(
    [Parameter(Mandatory = $true)][string]$OutputPath,
    [string]$RuntimeDirectory,
    [string]$InstallerPath,
    [string]$PeerAddress,
    [ValidateRange(5, 120)][int]$SampleSeconds = 10,
    [switch]$RequireIdle,
    [switch]$RequireCompleteCounters,
    [ValidateRange(5, 60)][int]$WaitForIdleSeconds = 30
)

$ErrorActionPreference = 'Stop'
if ($RuntimeDirectory -and !(Test-Path -LiteralPath $RuntimeDirectory -PathType Container)) { throw 'Runtime directory missing' }
if ($InstallerPath -and !(Test-Path -LiteralPath $InstallerPath -PathType Leaf)) { throw 'Installer missing' }
$names = @('input-leap-tauri', 'input-leapd', 'input-leaps', 'input-leapc')
if (!('InputLeapBaselineIdleV1' -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
public static class InputLeapBaselineIdleV1 {
    [StructLayout(LayoutKind.Sequential)]
    private struct LastInput { public uint Size; public uint Tick; }
    [DllImport("user32.dll", SetLastError=true)]
    private static extern bool GetLastInputInfo(ref LastInput info);
    [DllImport("kernel32.dll")]
    private static extern uint GetTickCount();
    public static uint[] Snapshot() {
        var info = new LastInput { Size = (uint)Marshal.SizeOf(typeof(LastInput)) };
        if (!GetLastInputInfo(ref info)) throw new Win32Exception(Marshal.GetLastWin32Error());
        return new uint[] { info.Tick, unchecked(GetTickCount() - info.Tick) };
    }
}
'@
}
if ($RequireIdle) {
    $idleWait = [Diagnostics.Stopwatch]::StartNew()
    while ([InputLeapBaselineIdleV1]::Snapshot()[1] -lt 5000) {
        if ($idleWait.Elapsed.TotalSeconds -ge $WaitForIdleSeconds) { throw 'No idle measurement window available; operational input was not interrupted' }
        Start-Sleep -Milliseconds 250
    }
}
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
$idleBefore = [InputLeapBaselineIdleV1]::Snapshot()
$before = Get-RuntimeSample
if (!$before.Count) { throw 'No operational runtime found; cannot establish baseline' }
$clock = [Diagnostics.Stopwatch]::StartNew()
Start-Sleep -Seconds $SampleSeconds
$after = Get-RuntimeSample
$clock.Stop()
$idleAfter = [InputLeapBaselineIdleV1]::Snapshot()
$idleVerified = $idleBefore[0] -eq $idleAfter[0] -and $idleBefore[1] -ge 5000
$processes = @($after | ForEach-Object {
    $current = $_
    $initial = $before | Where-Object Id -eq $current.Id
    $cpu = if ($initial -and $null -ne $initial.CpuSeconds -and $null -ne $current.CpuSeconds) {
        [math]::Round(100 * ($current.CpuSeconds - $initial.CpuSeconds) / $clock.Elapsed.TotalSeconds, 3)
    } else { $null }
    [pscustomobject]@{ Name = $current.Name; WorkingSetBytes = $current.WorkingSetBytes; CpuPercentOneCore = $cpu; StableProcess = [bool]$initial }
})
$rootsBefore = @($before | Where-Object Name -in $names)
$rootsAfter = @($processes | Where-Object Name -in $names)
$rootCountersComplete = $rootsBefore.Count -gt 0 -and $rootsBefore.Count -eq $rootsAfter.Count -and
    @($rootsAfter | Where-Object { !$_.StableProcess -or $null -eq $_.CpuPercentOneCore }).Count -eq 0
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
    Label = if ($idleVerified) { 'operational-hybrid-session-input-idle' } else { 'operational-hybrid-observed-not-clean-idle' }
    IdleVerified = $idleVerified
    IdleBeforeMs = $idleBefore[1]
    IdleAfterMs = $idleAfter[1]
    RootCountersComplete = $rootCountersComplete
    SampleSeconds = $clock.Elapsed.TotalSeconds; Processes = $processes
    RuntimeWorkingSetBytes = ($processes | Measure-Object WorkingSetBytes -Sum).Sum
    WebView2ChildrenIncluded = $true; RuntimeExecutablePayloadBytes = $payloadBytes; QtDllCount = $qtFiles
    Installer = $installer; Network = $network
    Limitations = @('Live working session; input-idle verification does not control other applications, power state or system load.', 'GetLastInputInfo observes this Windows session only; no keyboard or mouse content is captured.', 'Workspace HEAD is not evidence of the installed runtime revision.', 'Unavailable CPU counters are null, never zero.', 'Process-tree descendants included when observable; live process exits may make snapshots differ.', 'An optional installer is only an observed file: its provenance and baseline comparability require independent verification.', 'ICMP is not input-queue or acknowledgement latency.', 'No clipboard, credentials, hostnames or process command lines captured.')
}
$resolvedOutput = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($OutputPath)
New-Item -ItemType Directory -Path ([IO.Path]::GetDirectoryName($resolvedOutput)) -Force | Out-Null
$result | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $resolvedOutput -Encoding UTF8
$result | ConvertTo-Json -Depth 6
if ($RequireIdle -and !$idleVerified) { throw 'Input occurred during the sample; recorded evidence is not an idle baseline' }
if ($RequireCompleteCounters -and !$result.RootCountersComplete) { throw 'Some root process CPU counters remain unavailable; recorded evidence is incomplete' }
