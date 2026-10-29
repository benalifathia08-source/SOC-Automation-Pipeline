# soc-disable-account.ps1: Wazuh active response on DC01 for playbook B of the SOC automation pipeline.
# Wazuh runs soc-disable-account.cmd as SYSTEM with the request as one JSON line on stdin; the launcher
# starts this script. It disables ONE domain user account after strict checks, reads the account back
# from AD to verify, and writes one JSON line to active-responses.log, where Wazuh turns it into alert
# 100711-100715 (wazuh/rules/soc_pipeline_rules.xml). It never deletes, moves or edits anything else.
#
# Refused (a second check after n8n's, on the DC itself):
#   - built-in accounts: Administrator (RID 500), Guest (501), krbtgt (502)
#   - names on the protected list or with a protected prefix (svc_*, adm.*)
#   - members, direct or nested, of Domain Admins, Enterprise Admins, Schema Admins or Administrators
#     (tier 0: a compromised tier-0 account is handled by hand, not by automation)
#   - anything that is not a valid user name (computer accounts like DC01$ never pass)
# Undo: Enable-ADAccount -Identity <name>, by an administrator, after the investigation.
# Local test that changes nothing and writes no log line:
#   Get-Content request.json | powershell -NoProfile -File soc-disable-account.ps1 -DryRun
param([switch] $DryRun)
$ErrorActionPreference = 'Stop'

$Log               = Join-Path (Split-Path $PSScriptRoot -Parent) 'active-responses.log'
$ProtectedNames    = @('administrator', 'guest', 'krbtgt', 'fathia')
$ProtectedPrefixes = @('svc_', 'adm.')
$Tier0Groups       = @('Domain Admins', 'Enterprise Admins', 'Schema Admins', 'Administrators')

function Write-Result([hashtable] $Result) {
    $Result.check = 'account'
    $Result.checked_at = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffZ')
    $json = @{ soc = $Result } | ConvertTo-Json -Compress -Depth 4
    $line = '{0} active-response/bin/soc-disable-account: {1}' -f (Get-Date -Format 'yyyy/MM/dd HH:mm:ss'), $json
    if ($DryRun) { $line; return }      # tests print only: no log line, so no alert and no Telegram message
    [IO.File]::AppendAllText($Log, $line + "`n", (New-Object Text.UTF8Encoding($false)))
}

# 1. Read and validate the request. An invalid name is not echoed back into the log.
try {
    $request = [Console]::In.ReadLine() | ConvertFrom-Json
} catch {
    Write-Result @{ status = 'invalid'; reason = 'request is not valid JSON' }; exit 1
}
if ($request.command -and $request.command -ne 'add') { exit 0 }     # nothing to do on "delete"
$name = [string] $request.parameters.alert.data.dstuser
if ($name -notmatch '^[A-Za-z0-9][A-Za-z0-9._-]{0,19}$') {
    Write-Result @{ status = 'invalid'; reason = 'account name failed validation' }; exit 1
}

try {
    Import-Module ActiveDirectory
    # The name passed the check above (letters, digits, . _ -), so it is safe inside the filter
    $user = Get-ADUser -Filter "sAMAccountName -eq '$name'" -Properties Enabled
    if (-not $user) { Write-Result @{ status = 'not_found'; account = $name }; exit 1 }

    # 2. Protection checks
    $lower = $name.ToLowerInvariant()
    $rid = [int] ($user.SID.Value -split '-')[-1]
    $reason = $null
    if ($rid -in 500, 501, 502) { $reason = "built-in account (RID $rid)" }
    elseif ($ProtectedNames -contains $lower) { $reason = 'on the protected list' }
    elseif ($ProtectedPrefixes | Where-Object { $lower.StartsWith($_) }) { $reason = 'protected name prefix' }
    else {
        $tier0 = foreach ($g in $Tier0Groups) {
            $members = Get-ADGroupMember -Identity $g -Recursive | Where-Object objectClass -eq 'user'
            if ($members.SID -contains $user.SID) { $g }
        }
        if ($tier0) { $reason = "tier-0 member ($($tier0 -join ', '))" }
    }
    if ($reason) { Write-Result @{ status = 'refused'; account = $name; reason = $reason }; exit 0 }
    if (-not $user.Enabled) { Write-Result @{ status = 'already_disabled'; account = $name }; exit 0 }
    if ($DryRun) { Write-Result @{ status = 'would_disable'; account = $name }; exit 0 }

    # 3. Act, then read the account back from AD: the result line is the verification
    Disable-ADAccount -Identity $user
    $enabled = (Get-ADUser -Identity $user.ObjectGUID -Properties Enabled).Enabled
    Write-Result @{ status = $(if ($enabled) { 'still_enabled' } else { 'disabled' }); account = $name }
} catch {
    $msg = ($_.Exception.Message -replace '[\r\n]+', ' ')
    Write-Result @{ status = 'error'; account = $name; reason = $msg.Substring(0, [Math]::Min(150, $msg.Length)) }
    exit 1
}
