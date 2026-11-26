"""CycloneDX 1.6 AI-BOM of an audited Claude Code plugin, and shadow servers from traces (spec 123).

The BOM lists what ZIRAN found and cites where (``ziran:source``, a path relative to the audited
root, with the line when the parser keeps one). What it cannot know reads ``unknown``; nothing is
guessed. Components: the plugin (``metadata.component``), each subagent (``application``) and each
model a subagent names (``machine-learning-model``). Services: each MCP server. Vulnerabilities:
skill CVE database matches on an agent's declared tools, in triage (a name match, not a proof).

MCP ``args``, ``env``, ``headers`` and a URL's credentials, query and fragment never reach the BOM:
they may hold secrets. A server's version is read only from a pinned package argument
(``pkg@1.2.3`` or ``pkg==1.2.3``).
"""

from __future__ import annotations

import json
import os
import re
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any
from urllib.parse import urlsplit, urlunsplit

from ziran import __version__
from ziran.application.skill_cve import SkillCVEDatabase
from ziran.application.static_analysis.claude_code_audit import declared_tools
from ziran.domain.entities.claude_code import claude_code_tool_capability

if TYPE_CHECKING:
    from ziran.domain.entities.claude_code import ClaudeCodeScan
    from ziran.domain.entities.registry import ServerEntry
    from ziran.domain.entities.trace import TraceSession

SPEC_VERSION = "1.6"
UNKNOWN = "unknown"
_PINNED = re.compile(r"(?P<pkg>@?[^@=\s]+)(?:@|==)(?P<ver>\d[\w.+-]*)")


def _prop(name: str, value: str) -> dict[str, str]:
    return {"name": f"ziran:{name}", "value": value}


def _endpoint(url: str) -> str:
    """The URL without credentials, query or fragment."""
    parts = urlsplit(url)
    return urlunsplit((parts.scheme, parts.netloc.rpartition("@")[2], parts.path, "", ""))


def _service(server: ServerEntry, source: str, config_file: str) -> dict[str, Any]:
    props = [_prop("source", source), _prop("transport", server.transport)]
    entry: dict[str, Any] = {"bom-ref": f"mcp:{server.name}", "name": server.name}
    if server.command is not None:
        root = str(Path(config_file).parent.resolve())
        props.append(_prop("command", server.command.replace(root, "${CLAUDE_PLUGIN_ROOT}")))
    arg = next((a for a in server.args if not a.startswith("-")), None)
    pinned = _PINNED.fullmatch(arg) if server.command is not None and arg else None
    if pinned:
        entry["version"] = pinned["ver"]
        props.append(_prop("package", pinned["pkg"]))
    else:
        props.append(_prop("version", UNKNOWN))
    if server.url is not None:
        entry["endpoints"] = [_endpoint(server.url)]
    return entry | {"properties": props}


def build_aibom(scan: ClaudeCodeScan) -> dict[str, Any]:
    """CycloneDX 1.6 BOM (a JSON-ready dict) of the plugin, agents, models and MCP servers."""
    base = scan.root if os.path.isdir(scan.root) else os.path.dirname(scan.root)

    def where(file: str, line: int | None = None) -> str:
        rel = Path(os.path.relpath(file, base)).as_posix()
        return f"{rel}:{line}" if line else rel

    metadata: dict[str, Any] = {
        "timestamp": datetime.now(UTC).isoformat(timespec="seconds"),
        "tools": {"components": [{"type": "application", "name": "ziran", "version": __version__}]},
    }
    if scan.plugin is not None:
        plugin = scan.plugin
        subject: dict[str, Any] = {"type": "application", "bom-ref": f"plugin:{plugin.name}"}
        subject["name"] = plugin.name
        props = [_prop("source", where(plugin.file))]
        if plugin.version:
            subject["version"] = plugin.version
        else:
            props.append(_prop("version", UNKNOWN))
        metadata["component"] = subject | {"properties": props}

    services: dict[str, dict[str, Any]] = {}
    for server in scan.mcp_servers:  # a later duplicate name is skipped, as in mcp_sources
        config_file = scan.mcp_sources.get(server.name, scan.root)
        services.setdefault(server.name, _service(server, where(config_file), config_file))

    components: dict[str, dict[str, Any]] = {}
    dependencies: list[dict[str, Any]] = []
    vulns: dict[str, dict[str, Any]] = {}
    cve_db = SkillCVEDatabase()
    for agent in scan.agents:
        ref = f"agent:{agent.name}"
        props = [_prop("source", where(agent.file, agent.line_of("name")))]
        depends: list[str] = []
        if agent.model and agent.model != "inherit":
            model_ref = f"model:{agent.model}"
            model = components.setdefault(
                model_ref,
                {"type": "machine-learning-model", "bom-ref": model_ref, "name": agent.model},
            )
            model.setdefault("properties", []).append(
                _prop("source", where(agent.file, agent.line_of("model")))
            )
            depends.append(model_ref)
        else:
            props.append(_prop("model", UNKNOWN))  # inherits the session's model
        tools = declared_tools(agent)
        if tools is None:
            props.append(_prop("tools", UNKNOWN))  # inherits every tool of the session
        for tool in tools or []:
            props.append(_prop("tool", tool))
            parts = tool.split("__", 2)
            if tool.startswith("mcp__") and len(parts) == 3 and parts[1] in services:
                depends.append(f"mcp:{parts[1]}")
            for cve in cve_db.check_agent([claude_code_tool_capability(tool)]):
                vuln = vulns.setdefault(
                    cve.cve_id,
                    {
                        "bom-ref": f"vuln:{cve.cve_id}",
                        "id": cve.cve_id,
                        "source": {"name": "ZIRAN skill CVE database"},
                        "ratings": [{"severity": cve.severity}],
                        "description": cve.description,
                        "analysis": {
                            "state": "in_triage",
                            "detail": "Tool name matches the database entry; not confirmed.",
                        },
                        "affects": [],
                    },
                )
                if {"ref": ref} not in vuln["affects"]:
                    vuln["affects"].append({"ref": ref})
        entry: dict[str, Any] = {"type": "application", "bom-ref": ref, "name": agent.name}
        if agent.description:
            entry["description"] = agent.description
        components[ref] = entry | {"properties": props}
        dependencies.append({"ref": ref, "dependsOn": list(dict.fromkeys(depends))})

    return {
        "bomFormat": "CycloneDX",
        "specVersion": SPEC_VERSION,
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": metadata,
        "components": list(components.values()),
        "services": list(services.values()),
        "dependencies": dependencies,
        "vulnerabilities": list(vulns.values()),
    }


def load_bom(path: Path) -> dict[str, Any]:
    """Read a CycloneDX 1.6 JSON BOM. Raises ValueError (no file content in the message)."""
    try:
        bom = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError(f"{path}: invalid JSON at line {exc.lineno}") from None
    if (
        not isinstance(bom, dict)
        or bom.get("bomFormat") != "CycloneDX"
        or bom.get("specVersion") != SPEC_VERSION
    ):
        raise ValueError(f"{path}: not a CycloneDX {SPEC_VERSION} JSON BOM")
    return bom


def add_shadow(bom: dict[str, Any], sessions: list[TraceSession]) -> list[str]:
    """Add the MCP servers and agents seen in *sessions* that *bom* lacks, flagged shadow.

    A trace names a server in a tool id ``mcp__<server>__<tool>``; Claude Code names a plugin's
    server ``plugin_<plugin>_<server>``, which matches the BOM's server too. An agent is the
    session's ``agent_name`` (``unknown`` is skipped). Returns the added refs, in trace order,
    and bumps the BOM ``version`` when it adds one.
    """
    subject = bom.get("metadata", {}).get("component", {}).get("name")
    servers = {s.get("name") for s in bom.setdefault("services", [])}
    if subject:
        servers |= {f"plugin_{subject}_{name}" for name in list(servers)}
    agents = {c.get("name") for c in bom.setdefault("components", [])} | {subject}
    added: list[str] = []
    for session in sessions:
        source = _prop("source", f"trace {session.source} session {session.session_id}")
        shadow = [_prop("shadow", "true"), source]
        if session.agent_name != UNKNOWN and session.agent_name not in agents:
            agents.add(session.agent_name)
            ref = f"shadow-agent:{session.agent_name}"
            bom["components"].append(
                {"type": "application", "bom-ref": ref, "name": session.agent_name}
                | {"properties": shadow}
            )
            added.append(ref)
        for call in session.tool_calls:
            parts = call.tool_name.split("__", 2)
            if call.tool_name.startswith("mcp__") and len(parts) == 3 and parts[1] not in servers:
                servers.add(parts[1])
                ref = f"shadow-mcp:{parts[1]}"
                bom["services"].append({"bom-ref": ref, "name": parts[1], "properties": shadow})
                added.append(ref)
    if added:
        bom["version"] = int(bom.get("version", 1)) + 1
    return added
