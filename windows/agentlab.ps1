<#
.SYNOPSIS
  Builds and operates the two-VM agent lab on Hyper-V (Windows 11 Pro/Enterprise/Education).

.DESCRIPTION
  Commands:
    build     Create the AgentLab private switch and both VMs, ready for Ubuntu installs.
    cutover   Move the sandbox VM onto the AgentLab switch for good and eject its ISO.
    baseline  Shut down the sandbox and save (or replace) the clean-baseline checkpoint.
    revert    Power off the sandbox and restore clean-baseline. Add -Start to boot it.
    run       Revert, launch a run through the gateway, then revert again.
    stop      Hard power-off of the sandbox (the off-switch).
    check     Host-side isolation checks.
    status    Show VM state, adapters and checkpoints.
    reopen    Maintenance only: revert, then put the sandbox back on the Default
              Switch so you can install tools. Cut over and re-check afterward.

.EXAMPLE
  .\agentlab.ps1 build -IsoPath C:\ISO\ubuntu-24.04.3-live-server-amd64.iso
  .\agentlab.ps1 run -Task ..\templates\escape-test.md -Turns 40 -Time 30m
#>
[CmdletBinding()]
param(
    [Parameter(Position = 0, Mandatory = $true)]
    [ValidateSet('build', 'cutover', 'baseline', 'revert', 'run', 'stop', 'check', 'status', 'reopen')]
    [string]$Command,

    [string]$IsoPath,
    [string]$VmRoot = 'C:\HyperV\AgentLab',

    [int]$GatewayCpus = 2,
    [int]$GatewayMemoryGB = 2,
    [int]$GatewayDiskGB = 20,
    [int]$SandboxCpus = 4,
    [int]$SandboxMemoryGB = 8,
    [int]$SandboxDiskGB = 80,

    # run
    [string]$Task,
    [string]$Target,
    [ValidateRange(1, 500)][int]$Turns = 60,
    # Case-sensitive and anchored with \z, as agentlab-run reads them: .NET's $ also
    # matches before a final newline, which would split the ssh command. 0 would
    # mean no limit; agentlab-run also caps the time at 24h.
    [ValidatePattern('^[1-9][0-9]{0,5}[smh]?\z', Options = 'None')][string]$Time = '2h',
    [ValidatePattern('^claude-[a-z0-9.-]+\z', Options = 'None')][string]$Model = 'claude-opus-5-5',
    [switch]$Interactive,
    [switch]$KeepRunning,
    [string]$GatewayHost,
    [string]$GatewayUser = $env:USERNAME,

    # revert
    [switch]$Start
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 3

$SwitchName = 'AgentLab'
$GwName = 'agentlab-gw'
$SbxName = 'agentlab-sbx'
$Baseline = 'clean-baseline'

function Write-Step([string]$msg) { Write-Host "==> $msg" -ForegroundColor Cyan }
function Write-Ok([string]$msg) { Write-Host "    PASS  $msg" -ForegroundColor Green }
function Write-Bad([string]$msg) { Write-Host "    FAIL  $msg" -ForegroundColor Red }
function Write-Note([string]$msg) { Write-Host "    $msg" -ForegroundColor Yellow }

function Assert-Admin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $p = New-Object Security.Principal.WindowsPrincipal($id)
    if (-not $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'Run this from an elevated PowerShell (Run as administrator).'
    }
}

function Assert-HyperV {
    $caption = (Get-CimInstance Win32_OperatingSystem).Caption
    if ($caption -match 'Home') {
        throw "This is $caption. Hyper-V needs Windows 11 Pro, Enterprise or Education."
    }
    $feature = Get-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V
    if ($feature.State -ne 'Enabled') {
        Write-Note 'Hyper-V is not enabled. Enable it with:'
        Write-Note '  Enable-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V -All'
        throw 'Enable Hyper-V, reboot, then run build again.'
    }
    if (-not (Get-Module -ListAvailable -Name Hyper-V)) {
        throw 'The Hyper-V PowerShell module is missing. Enable "Hyper-V Module for Windows PowerShell".'
    }
}

function Get-LabVM([string]$name) {
    Get-VM -Name $name -ErrorAction SilentlyContinue
}

function New-LabVM([string]$name, [int]$cpus, [int]$memGB, [int]$diskGB, [string]$firstSwitch) {
    if (Get-LabVM $name) {
        Write-Note "$name already exists; leaving it as is."
        return
    }
    $vhd = Join-Path $VmRoot "$name.vhdx"
    if (Test-Path $vhd) { throw "$vhd already exists. Remove it or choose another -VmRoot." }

    Write-Step "Creating $name ($cpus vCPU, $memGB GB RAM, $diskGB GB disk)"
    New-VM -Name $name -Generation 2 -MemoryStartupBytes ([int64]$memGB * 1GB) `
        -NewVHDPath $vhd -NewVHDSizeBytes ([int64]$diskGB * 1GB) `
        -SwitchName $firstSwitch -Path $VmRoot | Out-Null
    Set-VMProcessor -VMName $name -Count $cpus
    Set-VMMemory -VMName $name -DynamicMemoryEnabled $false
    Set-VM -Name $name -AutomaticCheckpointsEnabled $false -CheckpointType Standard `
        -AutomaticStartAction Nothing -AutomaticStopAction ShutDown
    Set-VMFirmware -VMName $name -EnableSecureBoot On -SecureBootTemplate MicrosoftUEFICertificateAuthority
    Add-VMDvdDrive -VMName $name -Path $IsoPath

    # Disk first, then DVD: the empty disk falls through to the installer once,
    # and the VM boots from disk after Ubuntu is installed.
    $hdd = Get-VMHardDiskDrive -VMName $name
    $dvd = Get-VMDvdDrive -VMName $name
    $net = Get-VMNetworkAdapter -VMName $name | Select-Object -First 1
    Set-VMFirmware -VMName $name -BootOrder $hdd, $dvd, $net
}

function Invoke-Build {
    Assert-HyperV
    if (-not $IsoPath) { throw 'build needs -IsoPath <path to the Ubuntu Server 24.04 ISO>.' }
    if (-not (Test-Path $IsoPath)) { throw "ISO not found: $IsoPath" }
    New-Item -ItemType Directory -Force -Path $VmRoot | Out-Null

    $sw = Get-VMSwitch -Name $SwitchName -ErrorAction SilentlyContinue
    if ($sw) {
        if ($sw.SwitchType -ne 'Private') { throw "Switch $SwitchName exists but is $($sw.SwitchType), not Private." }
        Write-Note "Switch $SwitchName already exists (Private)."
    }
    else {
        Write-Step "Creating private switch $SwitchName"
        New-VMSwitch -Name $SwitchName -SwitchType Private | Out-Null
    }
    if (-not (Get-VMSwitch -Name 'Default Switch' -ErrorAction SilentlyContinue)) {
        throw 'Hyper-V Default Switch not found. It is created automatically on Windows 10/11; reboot after enabling Hyper-V.'
    }

    New-LabVM $GwName $GatewayCpus $GatewayMemoryGB $GatewayDiskGB 'Default Switch'
    if (-not (Get-VMNetworkAdapter -VMName $GwName | Where-Object SwitchName -eq $SwitchName)) {
        Add-VMNetworkAdapter -VMName $GwName -SwitchName $SwitchName -Name 'AgentLab'
    }

    New-LabVM $SbxName $SandboxCpus $SandboxMemoryGB $SandboxDiskGB 'Default Switch'
    foreach ($svc in 'Guest Service Interface', 'Key-Value Pair Exchange') {
        Disable-VMIntegrationService -VMName $SbxName -Name $svc
    }

    Write-Step 'Done. Next:'
    Write-Note "1. Start $GwName, install Ubuntu Server with hostname '$GwName' and OpenSSH."
    Write-Note "2. Start $SbxName, install Ubuntu Server with hostname '$SbxName' and OpenSSH."
    Write-Note '3. Follow the README from "Set up the gateway".'
    Write-Note '   vmconnect localhost agentlab-gw   opens a VM console.'
}

function Invoke-Cutover {
    $vm = Get-LabVM $SbxName
    if (-not $vm) { throw "$SbxName not found. Run build first." }
    Write-Step "Moving $SbxName to $SwitchName permanently"
    $adapters = @(Get-VMNetworkAdapter -VMName $SbxName)
    if ($adapters.Count -ne 1) { throw "$SbxName has $($adapters.Count) network adapters; expected exactly 1." }
    Connect-VMNetworkAdapter -VMName $SbxName -SwitchName $SwitchName
    foreach ($dvd in @(Get-VMDvdDrive -VMName $SbxName)) {
        if ($dvd.Path) { Set-VMDvdDrive -VMName $SbxName -ControllerNumber $dvd.ControllerNumber `
                -ControllerLocation $dvd.ControllerLocation -Path $null }
    }
    Write-Note "Now, in the $SbxName console: sudo ~/agentlab/linux/sandbox-setup.sh cutover"
}

function Invoke-Reopen {
    Write-Host 'This gives the sandbox internet access for maintenance. Never run agents while it is open.' -ForegroundColor Yellow
    $answer = Read-Host 'Type REOPEN to continue'
    if ($answer -ne 'REOPEN') { throw 'Cancelled.' }
    Reset-Sandbox
    Connect-VMNetworkAdapter -VMName $SbxName -SwitchName 'Default Switch'
    Start-VM -Name $SbxName
    Write-Note "In the $SbxName console: sudo ~/agentlab/linux/sandbox-setup.sh reopen"
    Write-Note 'Then rerun install, .\agentlab.ps1 cutover, the sandbox cutover, the checks, finalize and baseline.'
}

function Stop-Sandbox([switch]$Graceful) {
    $vm = Get-LabVM $SbxName
    if (-not $vm) { throw "$SbxName not found." }
    if ($vm.State -eq 'Off') { return }
    if ($Graceful) {
        Write-Step "Shutting down $SbxName"
        Stop-VM -Name $SbxName -Force
    }
    else {
        Write-Step "Powering off $SbxName"
        Stop-VM -Name $SbxName -TurnOff -Force
    }
}

function Invoke-Baseline {
    Stop-Sandbox -Graceful
    $old = Get-VMSnapshot -VMName $SbxName -Name $Baseline -ErrorAction SilentlyContinue
    if ($old) {
        Write-Step "Replacing existing $Baseline checkpoint"
        Remove-VMSnapshot -VMName $SbxName -Name $Baseline
    }
    Checkpoint-VM -Name $SbxName -SnapshotName $Baseline
    Write-Ok "Saved $Baseline. Re-run the escape test after any baseline change."
}

function Reset-Sandbox([switch]$Boot) {
    if (-not (Get-VMSnapshot -VMName $SbxName -Name $Baseline -ErrorAction SilentlyContinue)) {
        throw "No $Baseline checkpoint on $SbxName. Run baseline first."
    }
    Stop-Sandbox
    Write-Step "Restoring $Baseline"
    Restore-VMSnapshot -VMName $SbxName -Name $Baseline -Confirm:$false
    if ($Boot) {
        Start-VM -Name $SbxName
        Write-Ok "$SbxName started from $Baseline"
    }
}

function Resolve-Gateway {
    if ($GatewayHost) { return $GatewayHost }
    $name = "$GwName.mshome.net"
    try {
        Resolve-DnsName -Name $name -Type A -ErrorAction Stop | Out-Null
        return $name
    }
    catch { }
    $ip = (Get-VMNetworkAdapter -VMName $GwName | Where-Object SwitchName -eq 'Default Switch').IPAddresses |
        Where-Object { $_ -match '^\d+\.\d+\.\d+\.\d+$' } | Select-Object -First 1
    if ($ip) { return $ip }
    throw "Can't find the gateway's address. Pass -GatewayHost <ip> (run 'ip -4 addr' on $GwName)."
}

function Invoke-Run {
    if (-not $Task) { throw 'run needs -Task <path to a task file>.' }
    if (-not (Test-Path $Task -PathType Leaf)) { throw "Task file not found: $Task" }
    if ($Target -and -not (Test-Path $Target -PathType Container)) { throw "Target folder not found: $Target" }
    if (-not (Select-String -Path $Task -Pattern '^## Scope' -Quiet)) {
        throw 'Task file has no "## Scope" section. Start from templates\task-template.md.'
    }
    if (-not (Get-Command ssh -ErrorAction SilentlyContinue)) { throw 'OpenSSH client not found (Settings > System > Optional features).' }
    $gwVm = Get-LabVM $GwName
    if (-not $gwVm -or $gwVm.State -ne 'Running') { throw "$GwName is not running. Start-VM $GwName" }

    $gw = "$GatewayUser@$(Resolve-Gateway)"
    $id = Get-Date -Format 'yyyyMMdd-HHmmss'
    $stage = "agentlab-staging/$id"

    Reset-Sandbox -Boot
    try {
        Write-Step "Staging inputs on the gateway ($gw)"
        ssh $gw "mkdir -p $stage" ; if ($LASTEXITCODE) { throw 'ssh to the gateway failed.' }
        scp -q $Task "${gw}:$stage/task.md" ; if ($LASTEXITCODE) { throw 'Copying the task failed.' }
        $targetArg = ''
        if ($Target) {
            scp -q -r $Target "${gw}:$stage/target" ; if ($LASTEXITCODE) { throw 'Copying the target failed.' }
            $targetArg = "--target $stage/target"
        }
        $modeArg = ''
        if ($Interactive) { $modeArg = '--interactive' }

        Write-Step 'Launching (Ctrl+C stops the run; .\agentlab.ps1 stop is the hard off-switch)'
        ssh -t $gw "agentlab-run --run-id $id --task $stage/task.md $targetArg --turns $Turns --time $Time --model $Model $modeArg"
        $rc = $LASTEXITCODE
        Write-Note "Run $id finished with exit code $rc. Evidence: /var/log/agentlab/runs/$id on the gateway."
    }
    finally {
        if ($KeepRunning) {
            Write-Note "Sandbox left running (-KeepRunning). Revert before the next run."
        }
        else {
            Reset-Sandbox
            Write-Ok "$SbxName reverted to $Baseline and powered off"
        }
    }
}

function Invoke-Check {
    function T([bool]$ok, [string]$what) {
        if ($ok) { Write-Ok $what } else { Write-Bad $what; $script:fail++ }
    }
    $script:fail = 0
    Write-Step 'Host-side checks'

    $sw = Get-VMSwitch -Name $SwitchName -ErrorAction SilentlyContinue
    T ($null -ne $sw -and $sw.SwitchType -eq 'Private') "$SwitchName switch exists and is Private"
    $hostNic = Get-NetAdapter -IncludeHidden -ErrorAction SilentlyContinue | Where-Object { $_.Name -like "*($SwitchName)*" }
    T ($null -eq $hostNic) "Windows has no adapter on $SwitchName"

    $sbx = Get-LabVM $SbxName
    T ($null -ne $sbx) "$SbxName exists"
    if ($sbx) {
        $na = @(Get-VMNetworkAdapter -VMName $SbxName)
        T ($na.Count -eq 1 -and $na[0].SwitchName -eq $SwitchName) "$SbxName has exactly one adapter, on $SwitchName"
        foreach ($svc in 'Guest Service Interface', 'Key-Value Pair Exchange') {
            $s = Get-VMIntegrationService -VMName $SbxName -Name $svc
            T (-not $s.Enabled) "$SbxName integration service '$svc' is off"
        }
        $disks = @(Get-VMHardDiskDrive -VMName $SbxName)
        T ($disks.Count -eq 1 -and -not $disks[0].DiskNumber) "$SbxName has one virtual disk and no pass-through disks"
        $isos = @(Get-VMDvdDrive -VMName $SbxName | Where-Object Path)
        T ($isos.Count -eq 0) "$SbxName has no ISO attached"
        if (Get-Command Get-VMAssignableDevice -ErrorAction SilentlyContinue) {
            $dda = @(Get-VMAssignableDevice -VMName $SbxName -ErrorAction SilentlyContinue)
            T ($dda.Count -eq 0) "$SbxName has no assigned host devices"
        }
        T (-not (Get-VM $SbxName).AutomaticCheckpointsEnabled) "$SbxName automatic checkpoints are off"
        $snap = Get-VMSnapshot -VMName $SbxName -Name $Baseline -ErrorAction SilentlyContinue
        if ($snap) { Write-Ok "$Baseline checkpoint exists ($($snap.CreationTime))" }
        else { Write-Note "No $Baseline checkpoint yet (expected before the first baseline)" }
    }

    $gw = Get-LabVM $GwName
    T ($null -ne $gw) "$GwName exists"
    if ($gw) {
        $gna = @(Get-VMNetworkAdapter -VMName $GwName)
        $onDefault = @($gna | Where-Object SwitchName -eq 'Default Switch').Count
        $onLab = @($gna | Where-Object SwitchName -eq $SwitchName).Count
        T ($gna.Count -eq 2 -and $onDefault -eq 1 -and $onLab -eq 1) "$GwName has one adapter on Default Switch and one on $SwitchName"
    }

    if ($script:fail -gt 0) { Write-Bad "$script:fail check(s) failed"; exit 1 }
    Write-Ok 'All host-side checks passed'
}

function Invoke-Status {
    foreach ($n in $GwName, $SbxName) {
        $vm = Get-LabVM $n
        if (-not $vm) { Write-Host "$n : not created"; continue }
        Write-Host ("{0,-14} {1,-8} uptime {2}" -f $n, $vm.State, $vm.Uptime)
        Get-VMNetworkAdapter -VMName $n | ForEach-Object {
            Write-Host ("    adapter on {0,-15} {1}" -f $_.SwitchName, (($_.IPAddresses | Where-Object { $_ -match '\.' }) -join ', '))
        }
        Get-VMSnapshot -VMName $n -ErrorAction SilentlyContinue | ForEach-Object {
            Write-Host ("    checkpoint {0} ({1})" -f $_.Name, $_.CreationTime)
        }
    }
}

Assert-Admin
switch ($Command) {
    'build' { Invoke-Build }
    'cutover' { Invoke-Cutover }
    'baseline' { Invoke-Baseline }
    'revert' { Reset-Sandbox -Boot:$Start }
    'run' { Invoke-Run }
    'stop' { Stop-Sandbox }
    'check' { Invoke-Check }
    'status' { Invoke-Status }
    'reopen' { Invoke-Reopen }
}
