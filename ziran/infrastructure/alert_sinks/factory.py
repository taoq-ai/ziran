"""Build concrete alert sinks from configuration (composition helper).

Lives in infrastructure because it wires concrete adapters; the domain and
application layers depend only on the :class:`AlertSink` port.
"""

from __future__ import annotations

import os
from typing import TYPE_CHECKING

from ziran.infrastructure.alert_sinks.dry_run_sink import DryRunSink
from ziran.infrastructure.alert_sinks.github_issue_sink import GitHubIssueSink
from ziran.infrastructure.alert_sinks.slack_sink import SlackWebhookSink

if TYPE_CHECKING:
    from ziran.domain.entities.alerting import AlertConfig, AlertSinkConfig
    from ziran.domain.entities.attack import Severity
    from ziran.domain.ports.alert_sink import AlertSink

SinkBinding = tuple["AlertSink", "Severity"]


def _build_one(cfg: AlertSinkConfig) -> AlertSink:
    if cfg.kind == "slack":
        assert cfg.webhook_url is not None  # guaranteed by AlertSinkConfig validation
        return SlackWebhookSink(webhook_url=cfg.webhook_url)
    assert cfg.repo is not None  # guaranteed by AlertSinkConfig validation
    token = cfg.token or os.environ.get("GITHUB_TOKEN")
    return GitHubIssueSink(
        repo=cfg.repo,
        token=token,
        labels=cfg.labels,
        assignees=cfg.assignees,
    )


def build_sinks(config: AlertConfig, *, dry_run: bool = False) -> list[SinkBinding]:
    """Instantiate sink bindings ``(sink, severity_floor)`` from *config*.

    When *dry_run* is set, every sink is wrapped in :class:`DryRunSink` so the
    run performs zero network I/O.
    """
    bindings: list[SinkBinding] = []
    for cfg in config.alerts:
        sink = _build_one(cfg)
        if dry_run:
            sink = DryRunSink(sink)
        bindings.append((sink, cfg.severity_floor))
    return bindings
