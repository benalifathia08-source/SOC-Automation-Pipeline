# Test-SocDisableAccount.ps1
# Dry-run tests of soc-disable-account.ps1 on DC01 (run as Administrator). Every case runs with -DryRun:
# nothing is disabled and no line is written to active-responses.log (so no alert, no Telegram message).
#   .\Test-SocDisableAccount.ps1                       # name, RID, prefix and input checks
#   .\Test-SocDisableAccount.ps1 -Tier0Account test.rogue1
#       also checks the tier-0 group path: the account is put in Domain Admins for a few seconds, tested,
#       and removed again (Wazuh logs this as an approved admin change, rule 100500)
param([ValidatePattern('^test\.rogue\d$')] [string] $Tier0Account)
$ErrorActionPreference = 'Stop'
$script = 'C:\Program Files (x86)\ossec-agent\active-response\bin\soc-disable-account.ps1'

function Invoke-Case([string] $Name, [string] $Json, [string] $Expect) {
    $out = $Json | powershell.exe -NoProfile -NonInteractive -File $script -DryRun
    $status = if ($out) { (($out -split ': ', 2)[1] | ConvertFrom-Json).soc.status } else { '(no output)' }
    $reason = if ($out) { (($out -split ': ', 2)[1] | ConvertFrom-Json).soc.reason } else { '' }
    $ok = $status -eq $Expect
    $script:failed += [int](-not $ok)
    '{0} {1,-34} -> {2,-16} {3}' -f $(if ($ok) { 'PASS' } else { 'FAIL' }), $Name, $status, $reason
}
function Request([string] $user) { '{"command":"add","parameters":{"alert":{"data":{"dstuser":"' + $user + '"}}}}' }

$failed = 0
Invoke-Case 'Administrator (RID 500)'          (Request 'Administrator')   'refused'
Invoke-Case 'krbtgt (RID 502)'                 (Request 'krbtgt')          'refused'
Invoke-Case 'Guest (RID 501)'                  (Request 'Guest')           'refused'
Invoke-Case 'adm.amira (admin prefix, tier 0)' (Request 'adm.amira')       'refused'
Invoke-Case 'svc_backup (service prefix)'      (Request 'svc_backup')      'refused'
Invoke-Case 'omar.chaabane (normal user)'      (Request 'omar.chaabane')   'would_disable'
Invoke-Case 'DC01$ (computer account)'         (Request 'DC01$')           'invalid'
Invoke-Case "quote injection x' -or 1 -eq 1"   (Request "x' -or 1 -eq 1")  'invalid'
Invoke-Case 'name longer than 20 characters'   (Request 'abcdefghijklmnopqrstu') 'invalid'
Invoke-Case 'unknown account'                  (Request 'no.such.user')    'not_found'
Invoke-Case 'request is not JSON'              'not json'                  'invalid'
Invoke-Case 'command "delete" (nothing to do)' '{"command":"delete","parameters":{"alert":{"data":{"dstuser":"omar.chaabane"}}}}' '(no output)'

if ($Tier0Account) {
    Import-Module ActiveDirectory
    Add-ADGroupMember -Identity 'Domain Admins' -Members $Tier0Account
    try {
        Invoke-Case "$Tier0Account while in Domain Admins" (Request $Tier0Account) 'refused'
    } finally {
        Remove-ADGroupMember -Identity 'Domain Admins' -Members $Tier0Account -Confirm:$false
    }
    Invoke-Case "$Tier0Account after removal"          (Request $Tier0Account) 'would_disable'
}
if ($failed) { "$failed case(s) FAILED" } else { 'all cases passed' }
