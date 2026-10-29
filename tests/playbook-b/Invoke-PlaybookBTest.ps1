# Invoke-PlaybookBTest.ps1
# Live test scenario for playbook B (run on DC01 as Administrator). Synthetic lab accounts only.
#
#   .\Invoke-PlaybookBTest.ps1 -Account test.rogue1 -Prepare   # create the account + delegation only
#   .\Invoke-PlaybookBTest.ps1 -Account test.rogue1            # prepare if needed, then the "attack"
#   .\Invoke-PlaybookBTest.ps1 -Account svc_soctest1           # same, with an actor protected by name (svc_*)
#   .\Invoke-PlaybookBTest.ps1 -Cleanup                        # remove every test account and its delegation
#
# The scenario: a normal user was delegated the right to change the members of DnsAdmins (a known path to
# code execution on DNS servers, which DC01 is). It misuses that right and adds omar.chaabane to DnsAdmins.
# Event 4732 names the test account as the actor, which is not an approved admin, so Project 1's rule
# 100505 fires and the pipeline proposes to disable the test account (playbook B).
#
# - Each run gets a new random password, held in memory only and never displayed or stored.
# - The change is made over the network with -Credential (an ADWS call), so the test account needs no
#   right to log on to the DC.
# - The membership is removed again a few seconds later by Administrator (an approved admin, rule 100502,
#   not forwarded to the pipeline). The test account stays as it is, so the pipeline can act on it.
# - The pipeline suppresses repeats from the same actor for 60 minutes: use a new test.rogueN per run.
# - svc_soctestN is protected by its name: the pipeline must offer no buttons, and DC01 would refuse too.
param(
    [ValidatePattern('^(test\.rogue|svc_soctest)\d{1,2}$')] [string] $Account,
    [switch] $Prepare,
    [switch] $Cleanup
)
$ErrorActionPreference = 'Stop'
Import-Module ActiveDirectory
$group = Get-ADGroup 'DnsAdmins'
$memberAttr = [Guid] 'bf9679c0-0de6-11d0-a285-00aa003049e2'     # schemaIDGUID of the "member" attribute

function New-RandomPassword {
    $bytes = New-Object byte[] 24
    [Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)
    ConvertTo-SecureString ([Convert]::ToBase64String($bytes) + 'a1!') -AsPlainText -Force
}
function Get-Ace([System.Security.Principal.SecurityIdentifier] $Sid) {
    (Get-Acl "AD:$($group.DistinguishedName)").Access | Where-Object {
        $_.ObjectType -eq $memberAttr -and $_.ActiveDirectoryRights -match 'WriteProperty' -and
        $_.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]) -eq $Sid }
}
function Step([string] $Text) { '{0}Z  {1}' -f (Get-Date).ToUniversalTime().ToString('HH:mm:ss.fff'), $Text }

if ($Cleanup) {
    $acl = Get-Acl "AD:$($group.DistinguishedName)"
    foreach ($u in Get-ADUser -Filter "sAMAccountName -like 'test.rogue*' -or sAMAccountName -like 'svc_soctest*'") {
        foreach ($ace in Get-Ace $u.SID) { [void] $acl.RemoveAccessRule($ace) }
        Set-Acl -AclObject $acl "AD:$($group.DistinguishedName)"
        Remove-ADUser -Identity $u -Confirm:$false
        Step "removed $($u.SamAccountName) and its delegation on DnsAdmins"
    }
    $left = @(Get-ADUser -Filter "sAMAccountName -like 'test.rogue*' -or sAMAccountName -like 'svc_soctest*'").Count
    $members = @(Get-ADGroupMember 'DnsAdmins').Count
    "cleanup check: test accounts left $left, DnsAdmins members $members"
    return
}
if (-not $Account) { throw 'pass -Account test.rogueN, or -Cleanup' }

# 1. The test account (created, or re-enabled with a fresh password)
$root = (Get-ADOrganizationalUnit -Filter "Name -eq 'Users'" | Select-Object -First 1).DistinguishedName
$password = New-RandomPassword
$user = Get-ADUser -Filter "sAMAccountName -eq '$Account'"
if (-not $user) {
    New-ADUser -Name $Account -SamAccountName $Account -Path $root -AccountPassword $password -Enabled $true `
        -Description 'Temporary SOC pipeline test account (playbook B)'
    $user = Get-ADUser -Identity $Account
    Step "created $Account in $root"
} else {
    Set-ADAccountPassword -Identity $user -Reset -NewPassword $password
    Enable-ADAccount -Identity $user
    Step "$Account already existed: new random password, enabled"
}

# 2. The delegation: write the "member" attribute of DnsAdmins
if (-not (Get-Ace $user.SID)) {
    $acl = Get-Acl "AD:$($group.DistinguishedName)"
    $ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule($user.SID, 'WriteProperty', 'Allow', $memberAttr)
    $acl.AddAccessRule($ace)
    Set-Acl -AclObject $acl "AD:$($group.DistinguishedName)"
    Step "delegated 'write members' on DnsAdmins to $Account"
}
if ($Prepare) { 'prepared; run again without -Prepare for the attack'; return }

# 3. The misuse, under the test account's identity
Start-Sleep -Seconds 5      # let AD settle after the password reset
$cred = New-Object System.Management.Automation.PSCredential("FTOU7\$Account", $password)
"start_utc=$((Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fff'))"
Add-ADGroupMember -Identity 'DnsAdmins' -Members 'omar.chaabane' -Credential $cred
Step "$Account added omar.chaabane to DnsAdmins (event 4732 -> rule 100505 expected)"
$password = $null; $cred = $null

# 4. Revert the membership as Administrator; the test account stays enabled for the pipeline
Start-Sleep -Seconds 5
Remove-ADGroupMember -Identity 'DnsAdmins' -Members 'omar.chaabane' -Confirm:$false
Step 'Administrator removed omar.chaabane from DnsAdmins again'
"DnsAdmins members now: $(@(Get-ADGroupMember 'DnsAdmins').Count); $Account enabled: $((Get-ADUser $Account).Enabled)"
