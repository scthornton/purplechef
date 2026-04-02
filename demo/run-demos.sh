#!/bin/bash
# PurpleChef Demo Script
# Run each command one at a time for screenshots.
# Usage: bash demo/run-demos.sh
# Or run individual sections by copying commands.

set -e
cd "$(dirname "$0")/.."

# Ensure env vars are set for dry-run mode
export CHEF_CALDERA_URL=http://localhost:8888
export CHEF_CALDERA_API_KEY=demo-key
export CHEF_LC_OID=demo-org
export CHEF_LC_API_KEY=demo-key
export CHEF_SAFETY_DRY_RUN=true

RECIPES=recipe_book/src/chef_recipes/recipes

echo ""
echo "═══════════════════════════════════════════════════════"
echo "  DEMO 1: Recipe List — all available purple team recipes"
echo "═══════════════════════════════════════════════════════"
echo ""
echo "\$ chef recipe list $RECIPES/"
echo ""
uv run chef recipe list $RECIPES/

read -p "Press Enter for next demo..."

echo ""
echo "═══════════════════════════════════════════════════════"
echo "  DEMO 2: Sigma Templates — deterministic detection rules"
echo "═══════════════════════════════════════════════════════"
echo ""
echo "\$ chef detect templates"
echo ""
uv run chef detect templates

read -p "Press Enter for next demo..."

echo ""
echo "═══════════════════════════════════════════════════════"
echo "  DEMO 3: Generate Detection Rule — T1059.001 PowerShell"
echo "═══════════════════════════════════════════════════════"
echo ""
echo "\$ chef detect generate T1059.001"
echo ""
uv run chef detect generate T1059.001

read -p "Press Enter for next demo..."

echo ""
echo "═══════════════════════════════════════════════════════"
echo "  DEMO 4: Sigma → KQL Conversion"
echo "═══════════════════════════════════════════════════════"
echo ""
echo "\$ chef detect convert $RECIPES/credential-access/sigma-rules/lsass-access.yml --to kql"
echo ""
uv run chef detect convert $RECIPES/credential-access/sigma-rules/lsass-access.yml --to kql

read -p "Press Enter for next demo..."

echo ""
echo "═══════════════════════════════════════════════════════"
echo "  DEMO 5: Recipe Lint — validate before running"
echo "═══════════════════════════════════════════════════════"
echo ""
echo "\$ chef recipe lint $RECIPES/credential-access/recipe.yml"
echo ""
uv run chef recipe lint $RECIPES/credential-access/recipe.yml

read -p "Press Enter for next demo..."

echo ""
echo "═══════════════════════════════════════════════════════"
echo "  DEMO 6: Scaffold New Recipe — T1550.002 Pass the Hash"
echo "═══════════════════════════════════════════════════════"
echo ""
INIT_DIR=$(mktemp -d)
echo "\$ chef recipe init T1550.002 -o $INIT_DIR"
echo ""
uv run chef recipe init T1550.002 -o "$INIT_DIR"

read -p "Press Enter for next demo..."

echo ""
echo "═══════════════════════════════════════════════════════"
echo "  DEMO 7: Test Data Generation — synthetic events"
echo "═══════════════════════════════════════════════════════"
echo ""
echo "\$ chef detect test-data T1003.001"
echo ""
uv run chef detect test-data T1003.001

read -p "Press Enter for next demo..."

echo ""
echo "═══════════════════════════════════════════════════════"
echo "  DEMO 8: Coverage Diff — track detection improvements"
echo "═══════════════════════════════════════════════════════"
echo ""
echo "\$ chef recipe diff demo/mock-run-before.json demo/mock-run-after.json"
echo ""
uv run chef recipe diff demo/mock-run-before.json demo/mock-run-after.json

read -p "Press Enter for next demo..."

echo ""
echo "═══════════════════════════════════════════════════════"
echo "  DEMO 9: Aggregate Dashboard"
echo "═══════════════════════════════════════════════════════"
echo ""
DASH_DIR=$(mktemp -d)
cp demo/mock-run-before.json "$DASH_DIR/run1.json"
cp demo/mock-run-after.json "$DASH_DIR/run2.json"
echo "\$ chef dashboard $DASH_DIR"
echo ""
uv run chef dashboard "$DASH_DIR"

read -p "Press Enter for next demo..."

echo ""
echo "═══════════════════════════════════════════════════════"
echo "  DEMO 10: Recipe Run (dry-run) — full purple team cycle"
echo "═══════════════════════════════════════════════════════"
echo ""
echo "\$ chef recipe run $RECIPES/credential-access/recipe.yml"
echo ""
uv run chef recipe run $RECIPES/credential-access/recipe.yml

echo ""
echo "═══════════════════════════════════════════════════════"
echo "  DEMO 11: HTML Report (open in browser)"
echo "═══════════════════════════════════════════════════════"
echo ""
REPORT_DIR=$(mktemp -d)
uv run chef recipe report-only demo/mock-run-after.json -o "$REPORT_DIR"
echo ""
echo "Opening HTML report..."
open "$REPORT_DIR"/*.html 2>/dev/null || echo "Report at: $REPORT_DIR"

echo ""
echo "══════════════════════════════════════"
echo "  All demos complete!"
echo "══════════════════════════════════════"
