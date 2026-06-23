#!/usr/bin/env bash
# Scan the Quanta AgentCore agent and surface the exfiltration composition.
set -euo pipefail
cd "$(dirname "$0")"
uv run python main.py
