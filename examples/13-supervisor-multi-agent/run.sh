#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"

echo "🏢 ZIRAN — Supervisor Multi-Agent Scan"
echo "   Test a supervisor that delegates to HR, Finance, and IT sub-agents."
echo ""

if [[ -z "${OPENAI_API_KEY:-}" ]]; then
    echo "❌ OPENAI_API_KEY is not set."
    echo "   cp ../.env.example ../.env   # then fill in your key"
    exit 1
fi

uv run python main.py
