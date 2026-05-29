# Contract: AlertSink Port

**File**: `ziran/domain/ports/alert_sink.py` (new)

```python
from abc import ABC, abstractmethod
from ziran.domain.entities.alerting import AlertableFinding, DeliveryResult


class AlertSink(ABC):
    """Driving-side-out port: delivers a finding to one external destination."""

    name: str  # stable identifier, e.g. "slack", "github_issue"

    @abstractmethod
    async def emit(self, finding: AlertableFinding) -> DeliveryResult:
        """Deliver one finding.

        Contract:
        - MUST be idempotent for the github_issue sink: re-emitting a finding
          whose fingerprint already exists (open OR closed issue) returns
          status="deduped" without creating a duplicate.
        - MUST NOT raise on remote/transport errors; capture them as
          DeliveryResult(status="failed", detail=<message>). Programmer errors
          (bad config constructed despite validation) MAY raise.
        - MUST NOT perform network I/O when wrapped by the dry-run decorator.
        """
```

## Severity-floor filtering

Filtering is performed by the dispatcher (`application/alerting/dispatch.py`), **not** inside each sink, so the rule lives in one place:

```python
async def dispatch(
    findings: list[AlertableFinding],
    sinks: list[tuple[AlertSink, Severity]],   # (sink, severity_floor)
    *, dry_run: bool = False,
) -> AlertOutcome: ...
```

- For each `(finding, sink)`: if `severity_rank(finding.severity) < severity_rank(floor)` → `DeliveryResult(status="skipped_below_floor")`, no `emit` call.
- Otherwise `await sink.emit(finding)` (all pairs gathered with `asyncio.gather(..., return_exceptions=False)`; sinks never raise per contract).
- Aggregate into `AlertOutcome`.

## Dry-run wrapper

```python
class DryRunSink(AlertSink):
    def __init__(self, inner: AlertSink) -> None: ...
    async def emit(self, finding) -> DeliveryResult:
        # prints intended destination + serialized payload to stdout
        return DeliveryResult(sink_name=self._inner.name, fingerprint=finding.fingerprint,
                              status="dry_run", detail="<payload preview>")
```

Guarantee: when `--dry-run-alerts` is set, every real sink is wrapped, so zero network I/O occurs (SC-007).
