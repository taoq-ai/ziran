"""ZIRAN - AI Agent Security Testing Framework.

Test AI agents for vulnerabilities using multi-phase scan campaigns
and knowledge graph-based attack tracking.
"""

from importlib.metadata import version

__version__ = version("ziran")

# Pentesting agent exports (requires 'pentest' extra)
try:
    from ziran.application.pentesting.orchestrator import PentestOrchestrator
    from ziran.application.pentesting.progress import PentestProgressDisplay
    from ziran.domain.entities.pentest import (
        DeduplicatedFinding,
        PentestPlan,
        PentestSession,
        PentestStatus,
    )

    __all__ = [
        "DeduplicatedFinding",
        "PentestOrchestrator",
        "PentestPlan",
        "PentestProgressDisplay",
        "PentestSession",
        "PentestStatus",
        "__version__",
    ]
except ImportError:
    __all__ = ["__version__"]
