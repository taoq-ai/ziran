#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"

echo "🔀 ZIRAN — Router RAG Scan"
echo "   Test a dynamic retrieval router that picks the right data source."
echo ""

if [[ -z "${OPENAI_API_KEY:-}" ]]; then
    echo "❌ OPENAI_API_KEY is not set."
    echo "   cp ../.env.example ../.env   # then fill in your key"
    exit 1
fi

uv run python main.py
