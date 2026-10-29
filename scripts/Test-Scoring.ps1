# Test-Scoring.ps1
# Scores every fixture in tests\scoring\fixtures.json with your scoring\score.js and prints the result.
# Runs on the tools VM with the Node.js inside the n8n container, so nothing is installed on the laptop.
#
#   .\scripts\Test-Scoring.ps1
#
# Fill in "expect" (low / medium / high / critical) in fixtures.json to turn a fixture into a real test.

param(
    [string] $ToolsVM = '192.168.145.20',
    [string] $User    = 'fathia',
    [string] $KeyPath = (Join-Path $env:USERPROFILE '.ssh\ftou7_lab')
)
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$ssh  = @('-i', $KeyPath, '-o', 'BatchMode=yes', '-o', 'ConnectTimeout=15')

ssh @ssh "$User@$ToolsVM" 'rm -rf ~/soc-pipeline/scoring ~/soc-pipeline/tests && mkdir -p ~/soc-pipeline'
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
scp @ssh -q -r (Join-Path $root 'scoring') (Join-Path $root 'tests') "${User}@${ToolsVM}:soc-pipeline/"
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
ssh @ssh "$User@$ToolsVM" 'bash ~/soc-pipeline/tests/scoring/run.sh'
exit $LASTEXITCODE
