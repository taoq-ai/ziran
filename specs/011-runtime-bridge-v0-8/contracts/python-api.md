# Python API Contract: v0.8 Runtime Bridge

## Policy Export

```python
from ziran.application.policy_export import ExportService
from ziran.infrastructure.policy_renderers import RegoRenderer, CedarRenderer, ColangRenderer, InvariantRenderer
from ziran.domain.entities.policy import PolicyFormat

# Initialize with desired renderer
service = ExportService(renderer=RegoRenderer())

# Export from a campaign result file
policies = service.export_from_file(
    result_path="scan_results/campaign_report.json",
    severity_floor="medium",
)

# Export from a CampaignResult object
from ziran.domain.entities.phase import CampaignResult
result = CampaignResult.model_validate_json(raw_json)
policies = service.export(result=result, severity_floor="medium")

# Each policy is a GuardrailPolicy with .content (str), .finding_id, .skipped, etc.
for policy in policies:
    if not policy.skipped:
        Path(f"policies/{policy.finding_id}.rego").write_text(policy.content)
```

## Trace Analysis

```python
from ziran.application.trace_analysis import AnalyzerService
from ziran.infrastructure.trace_ingestors import OTelIngestor, LangfuseIngestor

# OTel file analysis
service = AnalyzerService(ingestor=OTelIngestor())
result = await service.analyze(source="traces.jsonl")
# result is a CampaignResult with source="trace-analysis"

# Langfuse API analysis
service = AnalyzerService(ingestor=LangfuseIngestor())
result = await service.analyze(
    project_id="my-project",
    since="24h",
)
# result.dangerous_tool_chains contains DangerousChain objects
# with observed_in_production=True, first_seen, last_seen, occurrence_count
```

## Registry Watcher

```python
from ziran.application.registry_watch import WatcherService
from ziran.infrastructure.snapshot_stores import JsonFileStore

store = JsonFileStore(snapshot_dir=".ziran/snapshots/")
service = WatcherService(snapshot_store=store)

findings = await service.watch(config_path="registry.yaml")
# findings is a list of DriftFinding objects
for f in findings:
    print(f.drift_type, f.server_name, f.severity, f.message)
```

## Notes

- All async methods require an event loop. CLI commands handle this via `asyncio.run()`.
- Langfuse API mode requires the `langfuse` extra: `pip install ziran[langfuse]`.
- All services accept their ports via constructor injection for testability.
