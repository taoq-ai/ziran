"""hybrid_route_share and typed chains as user settings (spec 067)."""

from __future__ import annotations

from pathlib import Path

import click
import pytest
from click.testing import CliRunner
from pydantic import ValidationError

from ziran.application.detectors.thresholds import DetectorThresholds
from ziran.infrastructure.config.detectors import load_detector_thresholds
from ziran.interfaces.cli.main import _scan_detector_config, cli


@pytest.mark.unit
def test_the_defaults_are_deterministic_mode() -> None:
    t = DetectorThresholds()
    assert t.hybrid_route_share == 0.0 and t.typed_chains is False


@pytest.mark.unit
@pytest.mark.parametrize("share", [-0.1, 1.01, "half"])
def test_a_share_outside_0_to_1_is_refused(share: object) -> None:
    with pytest.raises(ValidationError):
        DetectorThresholds(hybrid_route_share=share)


@pytest.mark.unit
def test_the_config_file_sets_both(tmp_path: Path) -> None:
    path = tmp_path / "detectors.yaml"
    path.write_text("hybrid_route_share: 0.25\ntyped_chains: true\n")
    t = load_detector_thresholds(path)
    assert t.hybrid_route_share == 0.25 and t.typed_chains is True


@pytest.mark.unit
@pytest.mark.parametrize("share", ["0.5", "1"])
def test_scan_refuses_a_share_above_0_with_no_model_client(share: str) -> None:
    result = CliRunner().invoke(cli, ["scan", "--hybrid-route-share", share])
    assert result.exit_code == 2 and "needs a model client" in result.output


@pytest.mark.unit
def test_scan_refuses_a_share_from_the_config_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The file is read where ziran scan reads it today: with an LLM backbone (spec 041)."""
    monkeypatch.chdir(tmp_path)
    Path(".ziran").mkdir()
    Path(".ziran/detectors.yaml").write_text("hybrid_route_share: 0.75\n")
    with pytest.raises(click.UsageError, match="needs a model client"):
        _scan_detector_config(
            llm_provider="litellm", llm_rpm=None, llm_tpm=None, llm_max_retries=None
        )


@pytest.mark.unit
@pytest.mark.parametrize("share", ["1.5", "-1"])
def test_scan_refuses_a_share_out_of_range(share: str) -> None:
    result = CliRunner().invoke(cli, ["scan", "--hybrid-route-share", share])
    assert result.exit_code == 2 and "--hybrid-route-share" in result.output


@pytest.mark.unit
def test_scan_at_share_0_goes_on_as_before() -> None:
    result = CliRunner().invoke(cli, ["scan", "--hybrid-route-share", "0"])
    assert result.exit_code != 0 and "model client" not in result.output


def _agent_dir(root: Path) -> Path:
    agents = root / ".claude" / "agents"
    agents.mkdir(parents=True)
    (agents / "banker.md").write_text(
        "---\nname: banker\ndescription: Pays bills.\ntools: get_iban, send_money\n---\nPay.\n"
    )
    return root


@pytest.mark.unit
@pytest.mark.parametrize(
    ("args", "config", "typed"),
    [
        ([], None, False),
        (["--typed-chains"], None, True),
        ([], "typed_chains: true\n", True),
        (["--no-typed-chains"], "typed_chains: true\n", False),
    ],
)
def test_audit_types_chains_only_when_a_setting_turns_them_on(
    args: list[str], config: str | None, typed: bool
) -> None:
    runner = CliRunner()
    with runner.isolated_filesystem() as here:
        _agent_dir(Path(here))
        if config is not None:
            Path(".ziran").mkdir()
            Path(".ziran/detectors.yaml").write_text(config)
        result = runner.invoke(cli, ["audit", ".", "--format", "json", *args])
    assert ("typed_data_exfiltration via get_iban -> send_money" in result.output) is typed


@pytest.mark.unit
def test_audit_refuses_typed_chains_with_a_baseline() -> None:
    runner = CliRunner()
    with runner.isolated_filesystem() as here:
        _agent_dir(Path(here))
        result = runner.invoke(cli, ["audit", ".", "--typed-chains", "--write-baseline", "b.json"])
    assert result.exit_code == 2 and "baseline holds no typed chains" in result.output
