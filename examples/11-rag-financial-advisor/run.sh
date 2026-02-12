#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"

echo "💰 ZIRAN — RAG Financial Advisor Scan"
echo "   Test a retrieval-augmented agent with confidential data in the vector store."
echo ""

if [[ -z "${OPENAI_API_KEY:-}" ]]; then
    echo "❌ OPENAI_API_KEY is not set."
    echo "   cp ../.env.example ../.env   # then fill in your key"
    exit 1
fi

uv run python main.py
