# Fire-B.ps1
# Arm one playbook B run for the M5 baseline (run on DC01 as Administrator):
#   .\Fire-B.ps1 -Run B-1 -Account test.rogue11
# Registers a one-shot scheduled task (SYSTEM) that runs Invoke-PlaybookBTest.ps1 for the account after a
# random 0-120 s delay, so neither the analyst nor the person arming it knows the exact moment. Prints only
# "armed". The account should exist already (Invoke-PlaybookBTest.ps1 -Prepare), so the task only resets its
# password and does the misuse. Output and times go to C:\LabScripts\soc\baseline\<run>.log.
# Clean up afterwards with:  .\Fire-B.ps1 -Cleanup   (removes the finished tasks)
param(
    [ValidatePattern('^(AUTO-)?B-\d+$')] [string] $Run,
    [ValidatePattern('^test\.rogue\d+$')] [string] $Account,
    [switch] $Cleanup
)
$ErrorActionPreference = 'Stop'
$dir = 'C:\LabScripts\soc\baseline'
New-Item -ItemType Directory -Force $dir | Out-Null

if ($Cleanup) {
    Get-ScheduledTask -TaskName 'SocBaseline-*' -ErrorAction SilentlyContinue | Where-Object State -ne 'Running' |
        ForEach-Object { Unregister-ScheduledTask -TaskName $_.TaskName -Confirm:$false; "removed task $($_.TaskName)" }
    return
}
if (-not $Run -or -not $Account) { throw 'pass -Run B-<n> -Account test.rogueN, or -Cleanup' }

$delay = Get-Random -Minimum 0 -Maximum 121
$at = (Get-Date).AddSeconds($delay + 5)          # +5 s so the trigger is never in the past when registered
$log = Join-Path $dir "$Run.log"
"$((Get-Date).ToUniversalTime().ToString('o')) armed $Run account=$Account delay=$($delay + 5)s" | Out-File -Append -Encoding ascii $log
# The task runs a small script file: quoting a command through Task Scheduler's argument string is fragile
$runScript = Join-Path $dir "$Run.ps1"
@(
    "`"`$((Get-Date).ToUniversalTime().ToString('o')) fired $Run`" | Out-File -Append -Encoding ascii '$log'",
    "& 'C:\LabScripts\soc\Invoke-PlaybookBTest.ps1' -Account $Account *>&1 | Out-File -Append -Encoding ascii '$log'"
) | Set-Content -Encoding ascii $runScript
$action    = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument "-NoProfile -NonInteractive -File `"$runScript`""
$trigger   = New-ScheduledTaskTrigger -Once -At $at
$principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
Register-ScheduledTask -TaskName "SocBaseline-$Run" -Action $action -Trigger $trigger -Principal $principal -Force | Out-Null
"armed ${Run}: the change happens within the next 2 minutes"
