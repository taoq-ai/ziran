#!/usr/bin/env bash
set -euo pipefail

echo "Installing browser dependencies..."
pip install ziran[browser] 2>/dev/null || pip install -e "../../[browser]"
playwright install chromium

echo ""
echo "Running browser agent scan example..."
python main.py
