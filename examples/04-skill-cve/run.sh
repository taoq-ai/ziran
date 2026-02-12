#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"

echo "🛡️  ZIRAN — Skill CVE Database Example"
echo "   Check agent tools against known LLM-tool vulnerabilities."
echo ""

uv run python main.py
