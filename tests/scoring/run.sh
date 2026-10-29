#!/bin/bash
# Run scoring/score.js against tests/scoring/fixtures.json with the Node.js inside the n8n container
# (nothing extra to install). Run on the tools VM; scripts/Test-Scoring.ps1 does it from the laptop.
set -e
cd "$(dirname "$0")/../.."
{
    cat scoring/score.js
    echo
    echo -n 'const FIXTURES = '
    cat tests/scoring/fixtures.json
    echo ';'
    cat tests/scoring/runner.js
} | sudo docker exec -i n8n node -
