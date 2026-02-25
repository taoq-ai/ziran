#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"

echo "☁️  ZIRAN — Amazon Bedrock Agent Scan"
echo "   Scan a Bedrock Agent via the AWS SDK."
echo ""

# Check AWS credentials
if ! aws sts get-caller-identity &>/dev/null; then
    echo "❌ AWS credentials not configured."
    echo "   Run: aws configure"
    echo "   Or set AWS_ACCESS_KEY_ID + AWS_SECRET_ACCESS_KEY"
    exit 1
fi
echo "✅ AWS credentials detected."

# Check agent config
CONFIG="bedrock-agent.yaml"
if grep -q "XXXXXXXXXX" "$CONFIG"; then
    echo "❌ Please edit $CONFIG with your Bedrock Agent ID."
    echo "   Find it in: AWS Console → Bedrock → Agents → [your agent]"
    exit 1
fi

echo ""
uv run python main.py "$@"
