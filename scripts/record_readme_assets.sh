#!/usr/bin/env bash
# ──────────────────────────────────────────────────────────────────────────────
# Record README assets: demo GIF (via VHS) + report screenshot (via Chrome)
# Usage:  ./scripts/record_readme_assets.sh
# ──────────────────────────────────────────────────────────────────────────────
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
ASSETS="$ROOT/docs/assets"
mkdir -p "$ASSETS"

info() { printf '\033[1;36m▸ %s\033[0m\n' "$1"; }
ok()   { printf '\033[1;32m✓ %s\033[0m\n' "$1"; }
warn() { printf '\033[1;33m⚠ %s\033[0m\n' "$1"; }

# ── 1. Check / install VHS ──────────────────────────────────────────────────

info "Checking dependencies…"

if ! command -v vhs &>/dev/null; then
    info "Installing VHS (terminal GIF recorder) via Homebrew…"
    brew install charmbracelet/tap/vhs
fi
ok "VHS ready"

# ── 2. Record demo GIF ──────────────────────────────────────────────────────
# Showcases example 01 (static analysis) — fast, visual, no API key needed.

TAPE="$(mktemp /tmp/ziran_demo_XXXXXX)"
mv "$TAPE" "$TAPE.tape"
TAPE="$TAPE.tape"
cat > "$TAPE" << TAPE
Output "${ASSETS}/demo.gif"

Set FontSize 15
Set Width 1200
Set Height 700
Set Theme "Catppuccin Mocha"
Set Padding 20
Set TypingSpeed 40ms

Type "uv run python examples/01-static-analysis/main.py"
Sleep 500ms
Enter
Sleep 8s
TAPE

info "Recording demo GIF (runs the example in a real terminal)…"
cd "$ROOT"
vhs "$TAPE"
rm -f "$TAPE"
ok "GIF saved → docs/assets/demo.gif"

# ── 3. Screenshot HTML report ───────────────────────────────────────────────
# Uses the latest HTML report in reports/. Tries Chrome headless first,
# then falls back to a temporary playwright venv.

REPORT="$(ls -t "$ROOT"/reports/campaign_*_report.html 2>/dev/null | head -1 || true)"

if [[ -z "$REPORT" ]]; then
    warn "No HTML reports found in reports/."
    warn "Run a live scan example (09-14) first, then re-run this script."
else
    info "Capturing report screenshot from $(basename "$REPORT")…"

    CHROME="/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"

    if [[ -x "$CHROME" ]]; then
        "$CHROME" \
            --headless \
            --disable-gpu \
            --screenshot="$ASSETS/report.png" \
            --window-size=1400,900 \
            --force-device-scale-factor=2 \
            --hide-scrollbars \
            "file://$REPORT" 2>/dev/null
        ok "Screenshot saved → docs/assets/report.png (Chrome headless)"

    elif command -v playwright &>/dev/null || command -v python3 &>/dev/null; then
        info "Chrome not found — using playwright (temporary venv)…"
        TMPENV="$(mktemp -d /tmp/ziran_screenshot_XXXX)"
        python3 -m venv "$TMPENV/venv"
        "$TMPENV/venv/bin/pip" install -q playwright 2>/dev/null
        "$TMPENV/venv/bin/playwright" install chromium 2>/dev/null

        "$TMPENV/venv/bin/python" - "$REPORT" "$ASSETS/report.png" << 'PYEOF'
import sys
from playwright.sync_api import sync_playwright

report_path, output_path = sys.argv[1], sys.argv[2]

with sync_playwright() as p:
    browser = p.chromium.launch()
    page = browser.new_page(
        viewport={"width": 1400, "height": 900},
        device_scale_factor=2,
    )
    page.goto(f"file://{report_path}")
    page.wait_for_timeout(3000)
    page.screenshot(path=output_path)
    browser.close()
PYEOF
        rm -rf "$TMPENV"
        ok "Screenshot saved → docs/assets/report.png (playwright)"

    else
        warn "Neither Chrome nor Python 3 found — skipping report screenshot."
    fi
fi

# ── 4. Summary ──────────────────────────────────────────────────────────────

echo ""
info "Generated assets:"
ls -lh "$ASSETS"/demo.gif "$ASSETS"/report.png 2>/dev/null || true
echo ""
ok "Done! Commit docs/assets/ and push."
