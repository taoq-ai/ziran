#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"

echo "🚀 ZIRAN — AgentCore Scan Example"
echo "   Scan an AgentCore-deployed agent in-process."
echo ""

# The mock agent doesn't need any API keys.
# Only the LLM judge needs OPENAI_API_KEY (optional).
if [[ "${1:-}" == "--llm-judge" ]] && [[ -z "${OPENAI_API_KEY:-}" ]]; then
    echo "❌ --llm-judge requires OPENAI_API_KEY."
    echo "   cp ../.env.example ../.env   # then fill in your key"
    exit 1
fi

uv run python main.py "$@"
