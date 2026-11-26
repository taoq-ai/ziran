"""Hostile tool names through every policy renderer, checked with each language's parser (spec 107)."""

from __future__ import annotations

import ast
import json
import os
import shutil
import subprocess
from typing import TYPE_CHECKING, Any

import cedarpy
import pytest

from ziran.domain.entities.capability import DangerousChain
from ziran.infrastructure.policy_renderers import (
    CedarRenderer,
    ColangRenderer,
    InvariantRenderer,
    RegoRenderer,
)

if TYPE_CHECKING:
    from pathlib import Path

# A double quote, a backslash, a newline, a closing brace, a whole Rego rule, a Cedar `};`,
# U+2028 and NEL (both line breaks to str.splitlines) in one scanned tool name.
HOSTILE = (
    'evil"\\\n}\ndeny contains "pwned" if { true }\n'
    "}; forbid (principal, action, resource);\u2028# after U+2028\x85tail"
)
HOSTILE_ID = 'ZIRAN-x"\n# id-\u2028line-000'
HOSTILE_VULN = 'exfil"\n}\u2029vuln'
CLEAN = ["read_file", "http_request"]


def _chain(tools: list[str], vuln: str = "data_exfiltration") -> DangerousChain:
    return DangerousChain(
        tools=tools,
        risk_level="critical",
        vulnerability_type=vuln,
        exploit_description="hostile tool name",
        risk_score=0.9,
    )


def _hostile() -> DangerousChain:
    return _chain(["read_file", HOSTILE], HOSTILE_VULN)


RENDERERS = [RegoRenderer(), CedarRenderer(), ColangRenderer(), InvariantRenderer()]


@pytest.mark.unit
@pytest.mark.parametrize("renderer", RENDERERS, ids=lambda r: r.format.value)
def test_hostile_values_start_no_line(renderer: Any) -> None:
    """No line break of any kind survives raw, so the hostile render has the clean line count."""
    hostile = renderer.render(_hostile(), HOSTILE_ID).content
    clean = renderer.render(_chain(CLEAN), "ZIRAN-c-000").content
    assert hostile.splitlines() == hostile.split("\n")[:-1]
    assert len(hostile.splitlines()) == len(clean.splitlines())
    for line in hostile.splitlines():
        if line.lstrip().startswith(("#", "//")):
            assert all(c.isprintable() for c in line), line


def _literal(line: str, after: str, before: str) -> str:
    """The string literal between *after* and the last *before* on *line*, decoded."""
    value = ast.literal_eval(line.split(after, 1)[1].rsplit(before, 1)[0])
    assert isinstance(value, str)
    return value


@pytest.mark.unit
def test_invariant_keeps_each_name_in_one_literal() -> None:
    lines = InvariantRenderer().render(_hostile(), HOSTILE_ID).content.splitlines()
    calls = [_literal(ln, "function=", ")") for ln in lines if "ToolCall(" in ln]
    assert calls == ["read_file", HOSTILE]
    (raise_line,) = (ln for ln in lines if ln.startswith("raise PolicyViolation("))
    msg = _literal(raise_line, "PolicyViolation(", ") if:")
    assert HOSTILE_ID in msg and HOSTILE in msg and HOSTILE_VULN in msg


@pytest.mark.unit
def test_colang_keeps_each_name_in_one_literal() -> None:
    lines = ColangRenderer().render(_hostile(), HOSTILE_ID).content.splitlines()
    calls = [_literal(ln, "tool_name=", ") as $step") for ln in lines if "ToolCall(" in ln]
    assert calls == ["read_file", HOSTILE]
    (say,) = (ln for ln in lines if "bot say " in ln)
    msg = ast.literal_eval(say.split("bot say ", 1)[1])
    assert HOSTILE in msg and HOSTILE_ID in msg


@pytest.mark.unit
def test_cedar_hostile_chain_parses_as_one_forbid() -> None:
    content = CedarRenderer().render(_hostile(), HOSTILE_ID).content
    policies = json.loads(cedarpy.policies_to_json_str(content))["staticPolicies"]
    assert len(policies) == 1
    (policy,) = policies.values()
    assert policy["effect"] == "forbid"
    assert policy["resource"]["entity"] == {"type": "Tool", "id": HOSTILE}
    (condition,) = policy["conditions"]
    assert condition["body"]["=="]["right"] == {"Value": "read_file"}


@pytest.mark.unit
def test_cedar_clean_chain_parses() -> None:
    content = CedarRenderer().render(_chain(CLEAN), "ZIRAN-c-000").content
    (policy,) = json.loads(cedarpy.policies_to_json_str(content))["staticPolicies"].values()
    assert policy["resource"]["entity"] == {"type": "Tool", "id": "http_request"}


@pytest.mark.unit
def test_cedar_keeps_two_tool_limit() -> None:
    policy = CedarRenderer().render(_chain(["a", "b", "c"]), "ZIRAN-c-000")
    assert policy.skipped is True
    assert policy.skip_reason == "Cedar policy generation supports exactly two-tool sequences"


# --- OPA: runs where the binary is on PATH; CI must have it (setup-opa in test.yml) ---


@pytest.fixture
def opa() -> str:
    path = shutil.which("opa")
    if path is None:
        if os.environ.get("CI"):
            pytest.fail("opa is not on PATH in CI; test.yml installs it with setup-opa")
        pytest.skip("opa is not installed")
    return path


def _module(tmp_path: Path, chain: DangerousChain, finding_id: str) -> Path:
    path = tmp_path / "policy.rego"
    path.write_text(RegoRenderer().render(chain, finding_id).content, encoding="utf-8")
    return path


def _run(*args: str, stdin: str | None = None) -> str:
    done = subprocess.run(args, input=stdin, capture_output=True, text=True, timeout=60)
    assert done.returncode == 0, done.stderr + done.stdout
    return done.stdout


def _deny(opa: str, module: Path, trace: list[str]) -> list[str]:
    doc = json.dumps({"trace": [{"tool": t} for t in trace]})
    out = json.loads(
        _run(
            opa,
            "eval",
            "--format",
            "json",
            "--stdin-input",
            "-d",
            str(module),
            "data.ziran.guardrails.deny",
            stdin=doc,
        )
    )
    value = out["result"][0]["expressions"][0]["value"]
    assert isinstance(value, list)
    return value


def _tool_terms(rule: dict[str, Any]) -> list[str]:
    """The string compared with ``input.trace[...].tool`` in each body expression."""
    found: list[str] = []
    for expr in rule["body"]:
        terms = expr.get("terms")
        if not isinstance(terms, list) or len(terms) != 3:
            continue
        ref, right = terms[1], terms[2]
        if ref.get("type") == "ref" and ref["value"][-1] == {"type": "string", "value": "tool"}:
            assert right["type"] == "string"
            found.append(right["value"])
    return found


@pytest.mark.unit
def test_opa_accepts_clean_module_and_denies_matching_trace(opa: str, tmp_path: Path) -> None:
    module = _module(tmp_path, _chain(CLEAN), "ZIRAN-c-000")
    _run(opa, "check", str(module))
    assert _deny(opa, module, ["read_file", "http_request"]) == [
        "Ziran finding ZIRAN-c-000: read_file \u2192 http_request (data_exfiltration)"
    ]
    assert _deny(opa, module, ["http_request", "read_file"]) == []


@pytest.mark.unit
def test_opa_hostile_module_has_one_rule_with_hostile_term(opa: str, tmp_path: Path) -> None:
    module = _module(tmp_path, _hostile(), HOSTILE_ID)
    _run(opa, "check", str(module))
    ast_doc = json.loads(_run(opa, "parse", "--format", "json", str(module)))
    rules = ast_doc["rules"]
    assert len(rules) == 1
    assert rules[0]["head"]["ref"][0]["value"] == "deny"
    assert _tool_terms(rules[0]) == ["read_file", HOSTILE]
    (msg,) = _deny(opa, module, ["read_file", HOSTILE])
    assert HOSTILE in msg and HOSTILE_ID in msg and HOSTILE_VULN in msg
