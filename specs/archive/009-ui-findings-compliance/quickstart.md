# Quickstart: Findings Management, Compliance & Design System

## End-User Workflow

### 1. Install and start

```bash
pip install ziran[ui]
export ZIRAN_DATABASE_URL="postgresql+asyncpg://localhost:5432/ziran"
ziran ui
```

Open `http://127.0.0.1:8484` — you'll see the TaoQ-branded dark dashboard.

### 2. Run a scan

Navigate to **New Run**, fill in target URL, select coverage level, and click **Start Scan**. The scan runs in the background with live progress.

### 3. View findings

After the scan completes, navigate to **Findings** in the sidebar. All discovered vulnerabilities appear in a sortable table. Use the filter bar to narrow by severity, status, or OWASP category.

### 4. Triage findings

Click a finding row to open its detail view. Review the attack transcript, check the remediation guidance, then set the status (Fixed, False Positive, or Ignored). Use bulk select + status change for batch triage.

### 5. Check OWASP compliance

Navigate to **Compliance** or view the OWASP matrix on the Run Detail page. Each of the 10 LLM categories shows coverage status and finding counts. Click a category to jump to filtered findings.

### 6. Export results

Use the export buttons to download findings as CSV or JSON. Export run configs as YAML or generate a Markdown report for stakeholders.

## Developer Workflow

### Backend development

```bash
cd /path/to/ziran
uv sync --extra ui
export ZIRAN_DATABASE_URL="postgresql+asyncpg://localhost:5432/ziran"
ziran ui --dev
```

### Frontend development (HMR)

```bash
cd ui
npm install
npm run dev
```

Frontend runs on `http://localhost:5173` with API proxy to `http://localhost:8484`.

### Running tests

```bash
uv run pytest tests/unit/test_findings_extractor.py -v
uv run pytest tests/integration/test_findings_api.py -v
uv run pytest --cov=ziran
```

### Database migrations

Migrations auto-apply on server startup. To generate a new migration:

```bash
cd ziran/interfaces/web
alembic revision --autogenerate -m "description"
```
