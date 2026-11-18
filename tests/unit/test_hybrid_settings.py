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
    assert t.hybrid_route_share == 0.0 and "typed_chains" not in DetectorThresholds.model_fields


@pytest.mark.unit
@pytest.mark.parametrize("share", [-0.1, 1.01, "half"])
def test_a_share_outside_0_to_1_is_refused(share: object) -> None:
    with pytest.raises(ValidationError):
        DetectorThresholds(hybrid_route_share=share)


@pytest.mark.unit
@pytest.mark.parametrize(
    ("text", "share"), [("hybrid_route_share: 0.25\n", 0.25), ("hybrid_route_share: 0.0\n", 0.0)]
)
def test_the_config_file_sets_the_share(tmp_path: Path, text: str, share: float) -> None:
    path = tmp_path / "detectors.yaml"
    path.write_text(text)
    assert load_detector_thresholds(path).hybrid_route_share == share


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
def test_the_flag_at_0_overrides_the_config_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    Path(".ziran").mkdir()
    Path(".ziran/detectors.yaml").write_text("hybrid_route_share: 0.75\n")
    assert (
        _scan_detector_config(
            llm_provider="litellm",
            llm_rpm=None,
            llm_tpm=None,
            llm_max_retries=None,
            hybrid_route_share=0.0,
        )
        is None
    )


def _scan_without_llm(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, yaml_text: str) -> str:
    from unittest.mock import MagicMock

    from tests.unit.test_cli_main import _minimal_campaign_result
    from ziran.domain.entities.phase import CampaignResult

    monkeypatch.chdir(tmp_path)
    Path("agent.py").write_text("agent_executor = None\n")
    Path(".ziran").mkdir()
    Path(".ziran/detectors.yaml").write_text(yaml_text)
    monkeypatch.setattr("ziran.interfaces.cli.main.load_agent_adapter", MagicMock())
    run = MagicMock()
    run.run.return_value = CampaignResult.model_validate(_minimal_campaign_result())
    monkeypatch.setattr("ziran.interfaces.cli.main.asyncio", run)
    monkeypatch.setattr("ziran.interfaces.cli.main.AgentScanner", MagicMock())
    args = ["scan", "--framework", "langchain", "--agent-path", "agent.py", "--output", "out"]
    result = CliRunner().invoke(cli, args)
    assert result.exit_code == 0, result.output
    return " ".join(result.output.split())


@pytest.mark.unit
def test_scan_with_no_client_warns_of_a_config_share(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    out = _scan_without_llm(tmp_path, monkeypatch, "hybrid_route_share: 0.5\n")
    assert "hybrid_route_share in .ziran/detectors.yaml is ignored" in out


@pytest.mark.unit
@pytest.mark.parametrize("yaml_text", ["hybrid_route_share: 0.0\n", "ensemble: [not, a, mapping\n"])
def test_scan_with_no_client_is_quiet_at_0_and_on_a_bad_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, yaml_text: str
) -> None:
    assert "hybrid_route_share" not in _scan_without_llm(tmp_path, monkeypatch, yaml_text)


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
@pytest.mark.parametrize(("args", "typed"), [([], False), (["--typed-chains"], True)])
def test_audit_types_chains_only_when_the_flag_turns_them_on(args: list[str], typed: bool) -> None:
    runner = CliRunner()
    with runner.isolated_filesystem() as here:
        _agent_dir(Path(here))
        result = runner.invoke(cli, ["audit", ".", "--format", "json", *args])
    assert ("typed_data_exfiltration via get_iban -> send_money" in result.output) is typed


@pytest.mark.unit
@pytest.mark.parametrize("yaml_text", ["hit: !env UNSET_ZIRAN_067_VAR\n", "typed_chains: true\n"])
def test_audit_never_reads_the_detector_config(yaml_text: str) -> None:
    """develop's behaviour: a detectors.yaml audit has no use for, even a broken one, is not read."""
    runner = CliRunner()
    with runner.isolated_filesystem() as here:
        _agent_dir(Path(here))
        Path(".ziran").mkdir()
        Path(".ziran/detectors.yaml").write_text(yaml_text)
        result = runner.invoke(cli, ["audit", ".", "--format", "json"])
    assert "UNSET_ZIRAN_067_VAR" not in result.output and "detectors.yaml" not in result.output
    assert result.exit_code == 0 and '"files_analyzed": 1' in result.output


@pytest.mark.unit
@pytest.mark.parametrize("flag", ["--baseline", "--write-baseline"])
def test_audit_refuses_typed_chains_with_a_baseline(flag: str) -> None:
    runner = CliRunner()
    with runner.isolated_filesystem() as here:
        _agent_dir(Path(here))
        if flag == "--baseline":
            assert runner.invoke(cli, ["audit", ".", "--write-baseline", "b.json"]).exit_code == 0
        result = runner.invoke(cli, ["audit", ".", "--typed-chains", flag, "b.json"])
    assert result.exit_code == 2 and "baseline holds no typed chains" in result.output
