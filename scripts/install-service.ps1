# Install SecureAgentNet as a background task on Windows using Task Scheduler.
# Run from an Administrator PowerShell prompt.

$TaskName = "SecureAgentNet"
$ActionPath = Join-Path $PSScriptRoot ".." "venv" "Scripts" "python.exe"
if (-not (Test-Path $ActionPath)) {
    $ActionPath = (Get-Command python).Source
}
$Arguments = "-m secureagentnet.daemon.daemon"
$WorkingDir = Join-Path $env:USERPROFILE ".secureagentnet"

New-Item -ItemType Directory -Force -Path $WorkingDir | Out-Null

$Action = New-ScheduledTaskAction -Execute $ActionPath -Argument $Arguments -WorkingDirectory $WorkingDir
$Trigger = New-ScheduledTaskTrigger -AtLogOn
$Principal = New-ScheduledTaskPrincipal -UserId "$env:USERDOMAIN\$env:USERNAME" -LogonType Interactive
$Settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable

Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
Register-ScheduledTask -TaskName $TaskName -Action $Action -Trigger $Trigger -Principal $Principal -Settings $Settings -Force | Out-Null
Start-ScheduledTask -TaskName $TaskName

Write-Host "SecureAgentNet scheduled task installed and started."
