param(
    [Parameter(Mandatory = $true)][string]$BinaryDirectory,
    [Parameter(Mandatory = $true)][string]$OutputPath
)

$ErrorActionPreference = 'Stop'
$principal = [Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())
if (!$principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Native SCM smoke requires an elevated Windows test session' }
$serviceName = 'InputLeapRustPilot'
$programFiles = [Environment]::GetFolderPath([Environment+SpecialFolder]::ProgramFiles)
$installRoot = [IO.Path]::GetFullPath((Join-Path $programFiles 'InputLeapRustPilot'))
if ([IO.Path]::GetDirectoryName($installRoot) -ne [IO.Path]::GetFullPath($programFiles)) { throw 'Unexpected pilot installation target' }
if (Get-Service -Name $serviceName -ErrorAction SilentlyContinue) { throw 'Pilot service already exists; refusing to replace it' }
if (Test-Path -LiteralPath $installRoot) { throw 'Pilot installation directory already exists; refusing to overwrite it' }
$programData = [Environment]::GetFolderPath([Environment+SpecialFolder]::CommonApplicationData)
$dataRoot = [IO.Path]::GetFullPath((Join-Path $programData 'InputLeapRustPilot'))
if ([IO.Path]::GetDirectoryName($dataRoot) -ne [IO.Path]::GetFullPath($programData)) { throw 'Unexpected pilot data target' }
if (Test-Path -LiteralPath $dataRoot) { throw 'Pilot data directory already exists; refusing to touch an identity' }
$snapshotPath = Join-Path $dataRoot 'security-state.dpapi'
$snapshotHash = $null
$files = @('input-leap-rust-service.exe', 'input-leap-rust-worker.exe')
$sources = @{}
foreach ($name in $files) {
    $path = Join-Path (Resolve-Path -LiteralPath $BinaryDirectory).Path $name
    $item = Get-Item -LiteralPath $path
    if (!$item.PSIsContainer -and !($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -and $item.Length -gt 0) {
        $sources[$name] = @{ Path = $item.FullName; Hash = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash }
    } else { throw "Invalid source executable: $name" }
}
$result = [ordered]@{ SchemaVersion=2; ScmLifecyclePassed=$false; InteractiveIpcExercised=$false; SecurityStateReloadPassed=$false; CrossAccountDecryptDenied=$false; CorruptStateStartupDenied=$false; PayloadHashes=@{}; AutoStartEnabled=$false }
$createdService = $false
$createdRoot = $false
function Invoke-PilotControl([string]$Executable, [string]$Argument) {
    # Release binaries use the Windows GUI subsystem to avoid terminal flashes.
    # PowerShell 5 does not reliably wait/set LASTEXITCODE for such binaries.
    $info = [Diagnostics.ProcessStartInfo]::new()
    $info.FileName = $Executable
    $info.Arguments = $Argument
    $info.UseShellExecute = $false
    $info.CreateNoWindow = $true
    $info.RedirectStandardOutput = $true
    $info.RedirectStandardError = $true
    $process = [Diagnostics.Process]::new()
    $process.StartInfo = $info
    try {
        if (!$process.Start()) { throw 'Could not start the pilot diagnostic client' }
        $stdout = $process.StandardOutput.ReadToEndAsync()
        $stderr = $process.StandardError.ReadToEndAsync()
        if (!$process.WaitForExit(5000)) { $process.Kill(); $process.WaitForExit(); throw 'Pilot diagnostic client timed out' }
        $output = $stdout.GetAwaiter().GetResult()
        $errorText = $stderr.GetAwaiter().GetResult()
        if ($process.ExitCode -ne 0) { throw "Pilot diagnostic client failed: $errorText" }
        return ($output | ConvertFrom-Json)
    } finally { $process.Dispose() }
}
function Set-PilotAcl([string]$Path, [bool]$Directory) {
    $acl = if ($Directory) { [Security.AccessControl.DirectorySecurity]::new() } else { [Security.AccessControl.FileSecurity]::new() }
    $acl.SetAccessRuleProtection($true, $false)
    $acl.SetOwner([Security.Principal.SecurityIdentifier]::new('S-1-5-32-544'))
    foreach ($sid in @('S-1-5-18', 'S-1-5-32-544', 'S-1-5-32-545')) {
        $rights = if ($sid -eq 'S-1-5-32-545') { [Security.AccessControl.FileSystemRights]::ReadAndExecute } else { [Security.AccessControl.FileSystemRights]::FullControl }
        $inheritance = if ($Directory) { [Security.AccessControl.InheritanceFlags]'ContainerInherit,ObjectInherit' } else { [Security.AccessControl.InheritanceFlags]::None }
        $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new($sid), $rights, $inheritance, [Security.AccessControl.PropagationFlags]::None, [Security.AccessControl.AccessControlType]::Allow))
    }
    Set-Acl -LiteralPath $Path -AclObject $acl
    if ((Get-Acl -LiteralPath $Path).GetOwner([Security.Principal.SecurityIdentifier]).Value -ne 'S-1-5-32-544') { throw 'Pilot binary/directory owner was not protected' }
}
try {
    New-Item -ItemType Directory -Path $installRoot | Out-Null
    $createdRoot = $true
    Set-PilotAcl $installRoot $true
    foreach ($name in $files) {
        $destination = Join-Path $installRoot $name
        Copy-Item -LiteralPath $sources[$name].Path -Destination $destination
        Set-PilotAcl $destination $false
        $hash = (Get-FileHash -LiteralPath $destination -Algorithm SHA256).Hash
        if ($hash -ne $sources[$name].Hash) { throw "Copied payload hash mismatch: $name" }
        $result.PayloadHashes[$name] = $hash
    }
    $executable = Join-Path $installRoot 'input-leap-rust-service.exe'
    $registration = New-Service -Name $serviceName -DisplayName 'InputLeap Rust Pilot (SCM smoke)' -BinaryPathName ('"' + $executable + '" --service-provision') -StartupType Manual
    $registration.Dispose()
    $createdService = $true
    Start-Service -Name $serviceName
    $service = Get-Service -Name $serviceName
    $service.WaitForStatus([ServiceProcess.ServiceControllerStatus]::Running, [TimeSpan]::FromSeconds(20))
    $service.Dispose()
    $native = Get-CimInstance Win32_Service -Filter "Name='InputLeapRustPilot'"
    if ($native.StartMode -ne 'Manual' -or $native.State -ne 'Running' -or !$native.ProcessId) { throw 'Pilot did not reach manual-start Running state' }
    $verified = Invoke-PilotControl $executable '--scm-status'
    if ($verified.service_pid -ne $native.ProcessId -or $verified.account -ne 'LocalSystem') { throw 'Rust and Windows SCM identities disagree' }
    if ((Get-Process -Id $native.ProcessId).SessionId -ne 0) { throw 'Supervisor must run in Session 0' }
    $dataItem = Get-Item -LiteralPath $dataRoot
    if ($dataItem.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Unexpected reparse point in pilot data' }
    $dataAcl = Get-Acl -LiteralPath $dataRoot
    if (!$dataAcl.AreAccessRulesProtected -or $dataAcl.GetOwner([Security.Principal.SecurityIdentifier]).Value -ne 'S-1-5-18') { throw 'Pilot data owner/DACL not protected by LocalSystem' }
    $snapshotHash = (Get-FileHash -LiteralPath $snapshotPath -Algorithm SHA256).Hash
    $ciphertext = [IO.File]::ReadAllBytes($snapshotPath)
    if ([Security.Principal.WindowsIdentity]::GetCurrent().User.Value -ne 'S-1-5-18') {
        Add-Type -AssemblyName System.Security
        $entropy = [Text.Encoding]::UTF8.GetBytes('InputLeap/Rust/DPAPI/SecurityState/v1')
        $unexpectedCleartext = $null
        try {
            $unexpectedCleartext = [Security.Cryptography.ProtectedData]::Unprotect($ciphertext, $entropy, [Security.Cryptography.DataProtectionScope]::CurrentUser)
        } catch [Security.Cryptography.CryptographicException] { $result.CrossAccountDecryptDenied = $true }
        if ($null -ne $unexpectedCleartext) { [Array]::Clear($unexpectedCleartext, 0, $unexpectedCleartext.Length); throw 'Administrator unexpectedly decrypted LocalSystem state' }
        if (!$result.CrossAccountDecryptDenied) { throw 'Cross-account DPAPI denial was not demonstrated' }
    }
    $session = (Get-Process -Id $PID).SessionId
    if ($session -ne 0) {
        $status = Invoke-PilotControl $executable '--query'
        if ($status.status.state -ne 'stopped' -or $status.status.error_code -ne 'authenticated_runtime_not_ready') { throw 'Unpaired service advertised an active runtime' }
        $result.InteractiveIpcExercised = $true
    }
    Stop-Service -Name $serviceName
    $service = Get-Service -Name $serviceName
    $service.WaitForStatus([ServiceProcess.ServiceControllerStatus]::Stopped, [TimeSpan]::FromSeconds(10))
    $service.Dispose()
    $change = Invoke-CimMethod -InputObject (Get-CimInstance Win32_Service -Filter "Name='InputLeapRustPilot'") -MethodName Change -Arguments @{ PathName=('"' + $executable + '" --service') }
    if ($change.ReturnValue -ne 0) { throw 'Could not switch to ordinary existing-state startup' }
    Start-Service -Name $serviceName
    $service = Get-Service -Name $serviceName
    $service.WaitForStatus([ServiceProcess.ServiceControllerStatus]::Running, [TimeSpan]::FromSeconds(20))
    $service.Dispose()
    if ((Get-FileHash -LiteralPath $snapshotPath -Algorithm SHA256).Hash -ne $snapshotHash) { throw 'Ordinary startup rewrote the identity snapshot' }
    $result.SecurityStateReloadPassed = $true
    Stop-Service -Name $serviceName
    $service = Get-Service -Name $serviceName
    $service.WaitForStatus([ServiceProcess.ServiceControllerStatus]::Stopped, [TimeSpan]::FromSeconds(10))
    $service.Dispose()
    [IO.File]::WriteAllBytes($snapshotPath, [Text.Encoding]::UTF8.GetBytes('synthetic corrupted SCM smoke state'))
    try { Start-Service -Name $serviceName } catch { }
    $service = Get-Service -Name $serviceName
    $service.WaitForStatus([ServiceProcess.ServiceControllerStatus]::Stopped, [TimeSpan]::FromSeconds(10))
    $service.Dispose()
    $failed = Get-CimInstance Win32_Service -Filter "Name='InputLeapRustPilot'"
    if (!$failed.ExitCode -or $failed.State -ne 'Stopped') { throw 'Corrupt snapshot was not rejected before Running' }
    $result.CorruptStateStartupDenied = $true
    [IO.File]::WriteAllBytes($snapshotPath, $ciphertext)
    if ((Get-FileHash -LiteralPath $snapshotPath -Algorithm SHA256).Hash -ne $snapshotHash) { throw 'Synthetic fixture restore failed' }
    $result.ScmLifecyclePassed = $true
} finally {
    if ($createdService) {
        $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
        if ($service) {
            if ($service.Status -ne [ServiceProcess.ServiceControllerStatus]::Stopped) { Stop-Service -Name $serviceName; $service.WaitForStatus([ServiceProcess.ServiceControllerStatus]::Stopped, [TimeSpan]::FromSeconds(10)) }
            $service.Dispose()
            & sc.exe delete $serviceName | Out-Null
            if ($LASTEXITCODE -ne 0) { throw 'Could not remove the temporary pilot service; installation retained for inspection' }
        }
    }
    if ($createdRoot) {
        foreach ($name in $files) {
            $destination = Join-Path $installRoot $name
            if (Test-Path -LiteralPath $destination) {
                if ((Get-FileHash -LiteralPath $destination -Algorithm SHA256).Hash -ne $sources[$name].Hash) { throw 'Unexpected changed file retained for inspection' }
                Remove-Item -LiteralPath $destination
            }
        }
        # Never recurse: unexpected files must remain rather than be deleted.
        Remove-Item -LiteralPath $installRoot
    }
    if ($snapshotHash -and (Test-Path -LiteralPath $dataRoot)) {
        if ((Get-Item -LiteralPath $dataRoot).Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Changed data directory retained for inspection' }
        if ((Get-FileHash -LiteralPath $snapshotPath -Algorithm SHA256).Hash -ne $snapshotHash) { throw 'Changed synthetic state retained for inspection' }
        Remove-Item -LiteralPath $snapshotPath
        $lockPath = Join-Path $dataRoot 'writer.lock'
        if (Test-Path -LiteralPath $lockPath) {
            $lock = Get-Item -LiteralPath $lockPath
            if ($lock.Length -ne 0 -or ($lock.Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'Unexpected writer lock retained' }
            Remove-Item -LiteralPath $lockPath
        }
        # No recursive deletion: unexpected data remains for inspection.
        Remove-Item -LiteralPath $dataRoot
    }
}
$output = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($OutputPath)
New-Item -ItemType Directory -Path ([IO.Path]::GetDirectoryName($output)) -Force | Out-Null
$result | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $output -Encoding UTF8
$result | ConvertTo-Json -Depth 4
Write-Output 'RUST_PILOT_SCM_LIFECYCLE_PASS'
