# Quickstart: Web UI Foundation

## Prerequisites

- Python 3.11+
- PostgreSQL running locally (or set `ZIRAN_DATABASE_URL`)
- Node.js 20+ (for frontend development only — not needed for end users)

## End User

```bash
# Install with UI dependencies
pip install ziran[ui]

# Set database URL (optional — defaults to localhost:5432/ziran)
export ZIRAN_DATABASE_URL="postgresql+asyncpg://localhost:5432/ziran"

# Create the database (PostgreSQL must be running)
createdb ziran

# Launch the dashboard
ziran ui
# → Dashboard: http://127.0.0.1:8484
```

## Developer

```bash
# Clone and install
git clone https://github.com/taoq-ai/ziran.git
cd ziran
uv sync --extra ui

# Set up database
export ZIRAN_DATABASE_URL="postgresql+asyncpg://localhost:5432/ziran"
createdb ziran

# Terminal 1: Start backend (dev mode)
ziran ui --dev

# Terminal 2: Start frontend (with HMR)
cd ui
npm install
npm run dev
# → Frontend dev server: http://localhost:5173 (proxies API to :8484)
```

## Build for Distribution

```bash
# Build frontend + Python wheel
cd ui && npm ci && npm run build && cd ..
uv build

# The wheel at dist/ziran-*.whl contains bundled static assets
```

## Quality Checks

```bash
uv run ruff check .
uv run ruff format --check .
uv run mypy ziran/
uv run pytest --cov=ziran
```
