# Install-SocResponse.ps1
# Installs the pipeline's Windows active response on DC01 (run on DC01 as Administrator).
# Copies soc-disable-account.cmd and .ps1 from the folder this script is in to the Wazuh agent's
# active-response\bin folder, which only Administrators and SYSTEM can write to. Safe to re-run.
$ErrorActionPreference = 'Stop'
$bin = 'C:\Program Files (x86)\ossec-agent\active-response\bin'
foreach ($f in 'soc-disable-account.cmd', 'soc-disable-account.ps1') {
    Copy-Item -Path (Join-Path $PSScriptRoot $f) -Destination (Join-Path $bin $f) -Force
}
Get-ChildItem $bin -Filter 'soc-*' | Select-Object Name, Length, LastWriteTime | Format-Table -AutoSize | Out-String
'== who can write to the folder'
(Get-Acl $bin).Access | Where-Object { $_.FileSystemRights -match 'Write|Modify|FullControl' } |
    ForEach-Object { '{0} : {1}' -f $_.IdentityReference, $_.FileSystemRights }
