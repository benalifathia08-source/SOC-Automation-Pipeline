# Deploy-Workflow.ps1
# Copies the pipeline files to the tools VM, then imports and publishes a workflow template there
# (credential IDs, Code node files and settings are filled in by tools-vm/import_workflow.py).
# n8n restarts at the end, which takes about 10 seconds.
#
#   .\scripts\Deploy-Workflow.ps1                                   # the intake workflow
#   .\scripts\Deploy-Workflow.ps1 -Workflow n8n/workflows/other.json

param(
    [ValidatePattern('^n8n/workflows/[\w.-]+\.json$')]
    [string] $Workflow = 'n8n/workflows/soc-intake.json',
    [string] $ToolsVM  = '192.168.145.20',
    [string] $User     = 'fathia',
    [string] $KeyPath  = (Join-Path $env:USERPROFILE '.ssh\ftou7_lab')
)
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$ssh  = @('-i', $KeyPath, '-o', 'BatchMode=yes', '-o', 'ConnectTimeout=15')
$dirs = 'tools-vm', 'n8n', 'scoring', 'tests' | ForEach-Object { Join-Path $root $_ }

ssh @ssh "$User@$ToolsVM" 'cd ~/soc-pipeline 2>/dev/null && rm -rf tools-vm n8n scoring tests; mkdir -p ~/soc-pipeline'
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
scp @ssh -q -r $dirs "${User}@${ToolsVM}:soc-pipeline/"
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
ssh @ssh "$User@$ToolsVM" "cd ~/soc-pipeline && sudo python3 tools-vm/import_workflow.py $Workflow"
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

# n8n 2.x keeps using the response workflow as it was when the intake workflow (its caller) was last
# published (seen on 2026-10-10: a changed button label only took effect after the intake was re-published).
# So a change to the response workflow is always followed by re-publishing the intake.
if ($Workflow -eq 'n8n/workflows/soc-response.json') {
    'Re-publishing the intake workflow so it calls the new response workflow'
    ssh @ssh "$User@$ToolsVM" 'cd ~/soc-pipeline && sudo python3 tools-vm/import_workflow.py n8n/workflows/soc-intake.json'
}
exit $LASTEXITCODE
