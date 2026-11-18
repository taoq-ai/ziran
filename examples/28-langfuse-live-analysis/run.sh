#!/usr/bin/env bash
# Pull Langfuse traces live and analyse them for dangerous tool chains.
set -euo pipefail
cd "$(dirname "$0")"

for var in LANGFUSE_PUBLIC_KEY LANGFUSE_SECRET_KEY; do
  if [ -z "${!var:-}" ]; then
    echo "Set $var (Langfuse project settings, API keys)." >&2
    exit 2
  fi
done

exec ziran analyze-traces --source langfuse --out reports "$@"
