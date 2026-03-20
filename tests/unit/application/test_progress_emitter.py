"""Unit tests for the ProgressEmitter and progress event model."""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from ziran.application.agent_scanner.progress import (
    ProgressEmitter,
    ProgressEvent,
    ProgressEventType,
)


@pytest.mark.unit
class TestProgressEventType:
    """Verify ProgressEventType enum values."""

    def test_campaign_start_value(self) -> None:
        assert ProgressEventType.CAMPAIGN_START == "campaign_start"

    def test_campaign_complete_value(self) -> None:
        assert ProgressEventType.CAMPAIGN_COMPLETE == "campaign_complete"

    def test_phase_start_value(self) -> None:
        assert ProgressEventType.PHASE_START == "phase_start"

    def test_phase_complete_value(self) -> None:
        assert ProgressEventType.PHASE_COMPLETE == "phase_complete"

    def test_attack_start_value(self) -> None:
        assert ProgressEventType.ATTACK_START == "attack_start"

    def test_attack_complete_value(self) -> None:
        assert ProgressEventType.ATTACK_COMPLETE == "attack_complete"

    def test_attack_streaming_value(self) -> None:
        assert ProgressEventType.ATTACK_STREAMING == "attack_streaming"

    def test_phase_attacks_loaded_value(self) -> None:
        assert ProgressEventType.PHASE_ATTACKS_LOADED == "phase_attacks_loaded"

    def test_all_members_count(self) -> None:
        assert len(ProgressEventType) == 8


@pytest.mark.unit
class TestProgressEvent:
    """Verify ProgressEvent dataclass fields and defaults."""

    def test_required_event_field(self) -> None:
        event = ProgressEvent(event=ProgressEventType.CAMPAIGN_START)
        assert event.event == ProgressEventType.CAMPAIGN_START

    def test_default_values(self) -> None:
        event = ProgressEvent(event=ProgressEventType.ATTACK_START)
        assert event.phase is None
        assert event.phase_index == 0
        assert event.total_phases == 0
        assert event.attack_index == 0
        assert event.total_attacks == 0
        assert event.attack_name == ""
        assert event.message == ""
        assert event.extra == {}

    def test_extra_field_is_independent_per_instance(self) -> None:
        """Each instance should get its own extra dict (default_factory)."""
        a = ProgressEvent(event=ProgressEventType.CAMPAIGN_START)
        b = ProgressEvent(event=ProgressEventType.CAMPAIGN_COMPLETE)
        a.extra["key"] = "value"
        assert "key" not in b.extra

    def test_all_fields_set(self) -> None:
        event = ProgressEvent(
            event=ProgressEventType.ATTACK_COMPLETE,
            phase="reconnaissance",
            phase_index=1,
            total_phases=3,
            attack_index=2,
            total_attacks=10,
            attack_name="test_attack",
            message="Done: test_attack",
            extra={"successful": True},
        )
        assert event.phase == "reconnaissance"
        assert event.phase_index == 1
        assert event.total_phases == 3
        assert event.attack_index == 2
        assert event.total_attacks == 10
        assert event.attack_name == "test_attack"
        assert event.message == "Done: test_attack"
        assert event.extra == {"successful": True}


@pytest.mark.unit
class TestProgressEmitter:
    """Verify ProgressEmitter callback dispatch."""

    def test_emit_with_callback_fires_callback(self) -> None:
        callback = MagicMock()
        emitter = ProgressEmitter(callback=callback)
        event = ProgressEvent(event=ProgressEventType.CAMPAIGN_START)

        emitter.emit(event)

        callback.assert_called_once_with(event)

    def test_emit_multiple_events(self) -> None:
        callback = MagicMock()
        emitter = ProgressEmitter(callback=callback)

        events = [
            ProgressEvent(event=ProgressEventType.CAMPAIGN_START),
            ProgressEvent(event=ProgressEventType.PHASE_START, phase="recon"),
            ProgressEvent(event=ProgressEventType.CAMPAIGN_COMPLETE),
        ]
        for e in events:
            emitter.emit(e)

        assert callback.call_count == 3

    def test_emit_with_none_callback_no_crash(self) -> None:
        emitter = ProgressEmitter(callback=None)
        event = ProgressEvent(event=ProgressEventType.CAMPAIGN_START)

        # Should not raise
        emitter.emit(event)

    def test_emit_default_no_callback(self) -> None:
        emitter = ProgressEmitter()
        event = ProgressEvent(event=ProgressEventType.CAMPAIGN_COMPLETE)

        # Should not raise
        emitter.emit(event)

    def test_active_property_true_when_callback_set(self) -> None:
        emitter = ProgressEmitter(callback=lambda e: None)
        assert emitter.active is True

    def test_active_property_false_when_no_callback(self) -> None:
        emitter = ProgressEmitter()
        assert emitter.active is False

    def test_active_property_false_when_callback_none(self) -> None:
        emitter = ProgressEmitter(callback=None)
        assert emitter.active is False
