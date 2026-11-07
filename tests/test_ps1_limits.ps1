# Checks agentlab.ps1's -Time and -Model validation in Windows PowerShell 5.1 and
# PowerShell 7 (CI runs it under both). Parameters bind before the script body
# runs, so a refused value never reaches Hyper-V. A value that binds fails later,
# at the admin check or at "run needs -Task", which is not a binding error.
$ErrorActionPreference = 'Stop'
$script = Join-Path $PSScriptRoot '..\windows\agentlab.ps1'

function Test-Binds([hashtable]$params) {
    try { & $script run @params *> $null; $true }
    catch { -not ($_.Exception -is [System.Management.Automation.ParameterBindingException]) }
}

$bad = @()
foreach ($t in @('0', '0s', '00', '05m', '30M', "30m`n", '1234567h')) {
    if (Test-Binds @{ Time = $t }) { $bad += "Time '$t' should be refused" }
}
foreach ($t in @('1', '30m', '2h', '5400s')) {
    if (-not (Test-Binds @{ Time = $t })) { $bad += "Time '$t' should be accepted" }
}
foreach ($m in @('claude-OPUS-5-5', "claude-opus-5-5`n--interactive")) {
    if (Test-Binds @{ Model = $m }) { $bad += "Model '$m' should be refused" }
}
if (-not (Test-Binds @{ Model = 'claude-opus-5-5' })) { $bad += "Model 'claude-opus-5-5' should be accepted" }

if ($bad) { $bad | ForEach-Object { Write-Host "FAIL  $_" }; exit 1 }
Write-Host "agentlab.ps1 validates -Time and -Model as agentlab-run does ($($PSVersionTable.PSVersion))"
