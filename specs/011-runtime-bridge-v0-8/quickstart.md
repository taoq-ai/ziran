# Quickstart: v0.8 — Runtime Bridge

## Export Findings as Guardrail Policies

```bash
# After a Ziran scan, export findings as OPA Rego policies
ziran export-policy --result scan_results/campaign_report.json --format rego --out policies/

# Export as NeMo Guardrails flows (only high+ severity)
ziran export-policy --result scan_results/campaign_report.json --format nemo --severity-floor high --out guardrails/
```

## Analyze Production Traces

```bash
# Analyze OTel traces from a file
ziran analyze-traces --source otel --input traces.jsonl --out reports/

# Analyze Langfuse traces from the last 24 hours
ziran analyze-traces --source langfuse --project-id my-project --since 24h --out reports/
```

## Watch MCP Registries for Drift

```bash
# Create a registry config
cat > registry.yaml << 'EOF'
servers:
  - name: "my-mcp-server"
    url: "http://localhost:3000"
    transport: "streamable-http"
allowlist:
  - "official-weather-server"
EOF

# Run the watcher
ziran watch-registry --config registry.yaml
```

## The Full Loop

```bash
# 1. Scan your agent pre-deploy
ziran scan --target agent.yaml --coverage comprehensive

# 2. Deploy and collect production traces
# (your agent runs in production, emitting OTel traces)

# 3. Analyze production traces
ziran analyze-traces --source otel --input prod-traces.jsonl --out reports/

# 4. Export observed dangerous chains as guardrail policies
ziran export-policy --result reports/trace_analysis_report.json --format rego --out policies/

# 5. Apply policies to your runtime guardrail
# (copy policies/ to your OPA/NeMo/Invariant deployment)
```

## CI Integration (non-GitHub)

Copy the template for your CI platform from `examples/07-cicd-quality-gate/`:
- GitLab: `gitlab-ci.yml`
- Jenkins: `Jenkinsfile`
- CircleCI: `circleci-config.yml`
- Azure: `azure-pipelines.yml`

Each mirrors the GitHub Action's `essential | standard | comprehensive` coverage knob.
