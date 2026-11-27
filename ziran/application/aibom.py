"""CycloneDX 1.6 AI-BOM of an audited Claude Code plugin or a scanned target, and shadow servers
from traces (specs 123, 135).

The BOM lists what ZIRAN found and cites where (``ziran:source``, a path relative to the audited
root, with the line when the parser keeps one). What it cannot know reads ``unknown``; nothing is
guessed. Components: the plugin (``metadata.component``), each subagent and skill
(``application``) and each model a subagent names (``machine-learning-model``). Services: each MCP
server. Vulnerabilities: skill CVE database matches on declared tools, in triage (a name match,
not a proof). :func:`build_scan_aibom` writes the same shape for a ``ziran scan`` target.

MCP ``args``, ``env``, ``headers`` and a URL's credentials, query and fragment never reach the BOM:
they may hold secrets. ``${VAR}`` is never expanded. A server's version is read only from the
package a known runner starts (``npx -y pkg@1.2.3``, ``uvx pkg==1.2.3``): any other argument may be
an option's value.
"""

from __future__ import annotations

import json
import os
import re
import uuid
from datetime import UTC, datetime
from pathlib import Path, PurePath
from typing import TYPE_CHECKING, Any
from urllib.parse import urlsplit, urlunsplit

from ziran import __version__
from ziran.application.skill_cve import SkillCVEDatabase
from ziran.application.static_analysis.claude_code_audit import declared_tools
from ziran.domain.entities.capability import AgentCapability, CapabilityType
from ziran.domain.entities.claude_code import claude_code_tool_capability

if TYPE_CHECKING:
    from ziran.domain.entities.a2a import A2AAgentCard
    from ziran.domain.entities.claude_code import ClaudeCodeScan
    from ziran.domain.entities.registry import ServerEntry
    from ziran.domain.entities.target import TargetConfig
    from ziran.domain.entities.trace import TraceSession

SPEC_VERSION = "1.6"
UNKNOWN = "unknown"
_PINNED = re.compile(r"(?P<pkg>@?[^@=\s]+)(?:@|==)(?P<ver>\d[\w.+-]*)")
# runner -> (its subcommand before the package, its flags that take no value)
_RUNNERS: dict[str, tuple[tuple[str, ...], frozenset[str]]] = {
    "npx": ((), frozenset({"-y", "--yes", "-q", "--quiet"})),
    "bunx": ((), frozenset({"--bun", "--silent", "--verbose"})),
    "uvx": ((), frozenset({"-q", "--quiet", "--offline", "--isolated", "--refresh"})),
    "pipx": (("run",), frozenset({"-q", "--quiet", "-v", "--verbose", "--no-cache"})),
    "pnpm": (("dlx",), frozenset({"-s", "--silent"})),
    "yarn": (("dlx",), frozenset({"-q", "--quiet"})),
}


def _prop(name: str, value: str) -> dict[str, str]:
    return {"name": f"ziran:{name}", "value": value}


def _host_port(url: str) -> str | None:
    """``host`` or ``host:port`` of *url*; the port tells two servers on one host apart."""
    try:
        parts = urlsplit(url)
        return f"{parts.hostname}:{parts.port}" if parts.hostname and parts.port else parts.hostname
    except ValueError:  # an out-of-range port
        return None


def _endpoint(url: str) -> str:
    """The URL without credentials, query or fragment."""
    parts = urlsplit(url)
    return urlunsplit((parts.scheme, parts.netloc.rpartition("@")[2], parts.path, "", ""))


def _pinned(command: str, args: list[str]) -> re.Match[str] | None:
    """The pinned package a known runner starts: its first argument after the runner's own flags.

    An unknown flag may take a value (``--token pass@123``), so it ends the search.
    """
    runner = _RUNNERS.get(PurePath(command).name)
    if runner is None:
        return None
    sub, flags = runner
    if tuple(args[: len(sub)]) != sub:
        return None
    arg = next((a for a in args[len(sub) :] if a not in flags), "-")
    return None if arg.startswith("-") else _PINNED.fullmatch(arg)


def _service(server: ServerEntry, ref: str, source: str, config_file: str) -> dict[str, Any]:
    props = [_prop("source", source), _prop("transport", server.transport)]
    entry: dict[str, Any] = {"bom-ref": ref, "name": server.name}
    if server.command is not None:
        root = str(Path(config_file).parent.resolve())
        props.append(_prop("command", server.command.replace(root, "${CLAUDE_PLUGIN_ROOT}")))
    pinned = _pinned(server.command, server.args) if server.command is not None else None
    if pinned:
        entry["version"] = pinned["ver"]
        props.append(_prop("package", pinned["pkg"]))
    else:
        props.append(_prop("version", UNKNOWN))
    if server.url is not None:
        entry["endpoints"] = [_endpoint(server.url)]
    return entry | {"properties": props}


def build_aibom(scan: ClaudeCodeScan) -> dict[str, Any]:
    """CycloneDX 1.6 BOM of the plugin, agents, skills, models and MCP servers.

    Agent, skill and server refs carry the plugin's name (``agent:<plugin>/<name>``) when a
    manifest names one, so two plugins' agents of one name never share a ref (spec 135).
    """
    base = scan.root if os.path.isdir(scan.root) else os.path.dirname(scan.root)
    prefix = f"{scan.plugin.name}/" if scan.plugin is not None else ""

    def where(file: str, line: int | None = None) -> str:
        rel = Path(os.path.relpath(file, base)).as_posix()
        return f"{rel}:{line}" if line else rel

    subject: dict[str, Any] | None = None
    if scan.plugin is not None:
        plugin = scan.plugin
        subject = {"type": "application", "bom-ref": f"plugin:{plugin.name}"}
        subject["name"] = plugin.name
        props = [_prop("source", where(plugin.file))]
        if plugin.version:
            subject["version"] = plugin.version
        else:
            props.append(_prop("version", UNKNOWN))
        subject["properties"] = props

    services: dict[str, dict[str, Any]] = {}
    for server in scan.mcp_servers:  # a later duplicate name is skipped, as in mcp_sources
        config_file = scan.mcp_sources.get(server.name, scan.root)
        if server.name not in services:
            ref = f"mcp:{prefix}{server.name}"
            services[server.name] = _service(server, ref, where(config_file), config_file)

    def mcp_refs(tools: list[str]) -> list[str]:
        """Refs of the configured servers that ``mcp__<server>__<tool>`` ids name."""
        names = [t.split("__", 2) for t in tools if t.startswith("mcp__")]
        return [f"mcp:{prefix}{p[1]}" for p in names if len(p) == 3 and p[1] in services]

    components: dict[str, dict[str, Any]] = {}
    dependencies: list[dict[str, Any]] = []
    vulns: dict[str, dict[str, Any]] = {}
    cve_db = SkillCVEDatabase()
    for agent in scan.agents:
        ref = f"agent:{prefix}{agent.name}"
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
        props += [_prop("tool", tool) for tool in tools or []]
        depends += mcp_refs(tools or [])
        _add_cves(vulns, cve_db, [claude_code_tool_capability(t) for t in tools or []], ref)
        components[ref] = _component(ref, agent.name, agent.description, props)
        dependencies.append({"ref": ref, "dependsOn": list(dict.fromkeys(depends))})
    for skill in scan.skills:  # allowed-tools are pre-approvals; no key means none (spec 125)
        ref = f"skill:{prefix}{skill.name}"
        if ref in components:
            continue
        props = [_prop("kind", "skill"), _prop("source", where(skill.file, skill.line_of("name")))]
        props += [_prop("allowed-tool", tool) for tool in skill.effective_tools]
        _add_cves(vulns, cve_db, skill.capabilities, ref)
        components[ref] = _component(ref, skill.name, skill.description, props)
        depends = list(dict.fromkeys(mcp_refs(skill.effective_tools)))
        dependencies.append({"ref": ref, "dependsOn": depends})

    return _bom(subject, components, services, dependencies, vulns)


_LISTED_TOOLS = frozenset(
    {CapabilityType.TOOL, CapabilityType.DATA_ACCESS, CapabilityType.EXTERNAL_API}
)


def build_scan_aibom(
    capabilities: list[AgentCapability],
    *,
    source: str,
    target: TargetConfig | None,
    protocol: str,
    card: A2AAgentCard | None = None,
    server_name: str | None = None,
) -> dict[str, Any]:
    """CycloneDX 1.6 BOM of a scanned target (spec 135), in the shape of :func:`build_aibom`.

    The subject is the target (``agent:<name>``): the config's ``name``, else the agent card's
    name, else the MCP server's *server_name* (``serverInfo.name``), else the URL's ``host`` or
    ``host:port``, else the stem of *source* (spec 137). It lists the discovered tools and skills (auth schemes and
    ``probe_*`` guesses from reply text are not listed), the model the target config names, the target as an MCP server when *protocol*
    is ``mcp``, the A2A peer of *card* with its skills, and skill CVE matches. Headers, auth
    and env values are never read; endpoints drop credentials, query and fragment.
    """
    # probe_* ids are guesses from reply text (the adapters' probe discovery), not declared tools
    capabilities = [c for c in capabilities if not c.id.startswith("probe_")]
    name = (
        (target.ref_name if target is not None else None)
        or (card.name if card is not None else "")
        or (server_name if protocol == "mcp" else None)
        or _host_port(target.url if target is not None else "")
        or Path(source).stem
    )
    ref = f"agent:{name}"
    props = [_prop("source", source), _prop("protocol", protocol)]
    props += [_prop("tool", c.id) for c in capabilities if c.type in _LISTED_TOOLS]
    props += [_prop("skill", c.id) for c in capabilities if c.type == CapabilityType.SKILL]
    components: dict[str, dict[str, Any]] = {}
    services: dict[str, dict[str, Any]] = {}
    model = target.openai.model if target is not None and target.openai is not None else None
    if model:
        model_ref = f"model:{model}"
        components[model_ref] = {"type": "machine-learning-model", "bom-ref": model_ref}
        components[model_ref] |= {"name": model, "properties": [_prop("source", source)]}
    else:
        props.append(_prop("model", UNKNOWN))
    if target is not None and protocol == "mcp":
        services[f"mcp:{name}"] = {
            "bom-ref": f"mcp:{name}",
            "name": name,
            "endpoints": [_endpoint(target.url)],
            "properties": [_prop("source", source), _prop("version", UNKNOWN)],
        }
    if card is not None:
        peer: dict[str, Any] = {"bom-ref": f"a2a:{name}", "name": name}
        peer_props = [_prop("source", "A2A agent card")]
        if card.version:
            peer["version"] = card.version
        else:
            peer_props.append(_prop("version", UNKNOWN))
        endpoints = list(dict.fromkeys(_endpoint(i.url) for i in card.supported_interfaces))
        if endpoints:
            peer["endpoints"] = endpoints
        peer_props += [_prop("skill", skill.id) for skill in card.skills]
        services[f"a2a:{name}"] = peer | {"properties": peer_props}
    vulns: dict[str, dict[str, Any]] = {}
    _add_cves(vulns, SkillCVEDatabase(), capabilities, ref)
    subject = {"type": "application", "bom-ref": ref, "name": name, "properties": props}
    depends = [*components, *services]
    return _bom(subject, components, services, [{"ref": ref, "dependsOn": depends}], vulns)


def _component(
    ref: str, name: str, description: str, props: list[dict[str, str]]
) -> dict[str, Any]:
    entry: dict[str, Any] = {"type": "application", "bom-ref": ref, "name": name}
    if description:
        entry["description"] = description
    return entry | {"properties": props}


def _add_cves(
    vulns: dict[str, dict[str, Any]],
    cve_db: SkillCVEDatabase,
    capabilities: list[AgentCapability],
    ref: str,
) -> None:
    """Add the skill CVE database matches on *capabilities*, each affecting *ref*, in triage."""
    for cve in cve_db.check_agent(capabilities):
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


def _bom(
    subject: dict[str, Any] | None,
    components: dict[str, dict[str, Any]],
    services: dict[str, dict[str, Any]],
    dependencies: list[dict[str, Any]],
    vulns: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    metadata: dict[str, Any] = {
        "timestamp": datetime.now(UTC).isoformat(timespec="seconds"),
        "tools": {"components": [{"type": "application", "name": "ziran", "version": __version__}]},
    }
    if subject is not None:
        metadata["component"] = subject
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
    except (UnicodeDecodeError, RecursionError):
        raise ValueError(f"{path}: not readable JSON (UTF-8, nested too deep?)") from None
    if (
        not isinstance(bom, dict)
        or bom.get("bomFormat") != "CycloneDX"
        or bom.get("specVersion") != SPEC_VERSION
    ):
        raise ValueError(f"{path}: not a CycloneDX {SPEC_VERSION} JSON BOM")
    # Only the shape add_shadow reads; the full schema is the producer's concern.
    metadata = bom.get("metadata", {})
    if not isinstance(metadata, dict) or not _named(metadata.get("component", {})):
        raise ValueError(f"{path}: 'metadata' must be an object")
    for key in ("components", "services"):
        items = bom.get(key, [])
        if not isinstance(items, list) or not all(_named(item) for item in items):
            raise ValueError(f"{path}: '{key}' must be a list of objects")
    version = bom.get("version", 1)
    if type(version) is not int or version < 1:
        raise ValueError(f"{path}: 'version' must be a positive integer")
    return bom


def _named(item: object) -> bool:
    """An object whose ``name``, when present, is a string."""
    return isinstance(item, dict) and isinstance(item.get("name", ""), str)


def _is_agent(component: dict[str, Any]) -> bool:
    """An ``application`` component that is not a skill (a skill name is not an agent)."""
    props = component.get("properties")
    is_skill = isinstance(props, list) and _prop("kind", "skill") in props
    return component.get("type") == "application" and not is_skill


def add_shadow(bom: dict[str, Any], sessions: list[TraceSession]) -> list[str]:
    """Add the MCP servers and agents seen in *sessions* that *bom* lacks, flagged shadow.

    A trace names a server in a tool id ``mcp__<server>__<tool>``; Claude Code names a plugin's
    server ``plugin_<plugin>_<server>``, which matches the BOM's server too. An agent is the
    session's ``agent_name`` (``unknown`` is skipped), known when an ``application`` component
    other than a skill bears it. Returns the added refs, in trace order,
    and bumps the BOM ``version`` when it adds one.
    """
    subject = bom.get("metadata", {}).get("component", {}).get("name")
    servers = {s.get("name") for s in bom.setdefault("services", [])}
    if subject:
        servers |= {f"plugin_{subject}_{name}" for name in list(servers)}
    agents = {c.get("name") for c in bom.setdefault("components", []) if _is_agent(c)} | {subject}
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
        bom["version"] = bom.get("version", 1) + 1
    return added
