"""Validate the ground truth dataset.

Loads all YAML scenario and agent files, validates against Pydantic
schema, cross-references CVE IDs and agent references, and reports
coverage statistics.

Usage:
    uv run python benchmarks/ground_truth/validate.py
"""

from __future__ import annotations

import sys
from collections import Counter
from pathlib import Path
from typing import Any

import yaml
from pydantic import ValidationError

from benchmarks.ground_truth.schema import AgentDefinition, GroundTruthScenario

GROUND_TRUTH_DIR = Path(__file__).resolve().parent
AGENTS_DIR = GROUND_TRUTH_DIR / "agents"
SCENARIOS_DIR = GROUND_TRUTH_DIR / "scenarios"

CATEGORIES = ["tool_chain", "side_effect", "campaign"]


def _load_yaml(path: Path) -> dict[str, Any]:
    """Load and return a YAML file as a dict."""
    with open(path) as f:
        return yaml.safe_load(f)  # type: ignore[no-any-return]


def validate_agents() -> tuple[dict[str, AgentDefinition], list[str]]:
    """Load and validate all agent definition files."""
    agents: dict[str, AgentDefinition] = {}
    errors: list[str] = []

    yaml_files = sorted(AGENTS_DIR.glob("*.yaml"))
    if not yaml_files:
        errors.append(f"No agent YAML files found in {AGENTS_DIR}")
        return agents, errors

    for path in yaml_files:
        try:
            data = _load_yaml(path)
            agent = AgentDefinition(**data)
            if agent.agent_id in agents:
                errors.append(f"Duplicate agent_id '{agent.agent_id}' in {path.name}")
            agents[agent.agent_id] = agent
        except ValidationError as e:
            errors.append(f"{path.name}: schema validation failed:\n{e}")
        except Exception as e:
            errors.append(f"{path.name}: failed to load: {e}")

    return agents, errors


def validate_scenarios(
    agents: dict[str, AgentDefinition],
) -> tuple[list[GroundTruthScenario], list[str]]:
    """Load and validate all scenario files."""
    scenarios: list[GroundTruthScenario] = []
    errors: list[str] = []
    seen_ids: set[str] = set()

    for category in CATEGORIES:
        cat_dir = SCENARIOS_DIR / category
        if not cat_dir.exists():
            errors.append(f"Category directory missing: {cat_dir}")
            continue

        yaml_files = sorted(cat_dir.glob("*.yaml"))
        if not yaml_files:
            errors.append(f"No scenario files in {cat_dir}")
            continue

        for path in yaml_files:
            try:
                data = _load_yaml(path)
                scenario = GroundTruthScenario(**data)

                # Check unique ID
                if scenario.scenario_id in seen_ids:
                    errors.append(f"Duplicate scenario_id '{scenario.scenario_id}' in {path.name}")
                seen_ids.add(scenario.scenario_id)

                # Check agent reference
                if scenario.agent_ref not in agents:
                    errors.append(
                        f"{path.name}: agent_ref '{scenario.agent_ref}' "
                        f"not found in agents directory"
                    )

                scenarios.append(scenario)
            except ValidationError as e:
                errors.append(f"{path.name}: schema validation failed:\n{e}")
            except Exception as e:
                errors.append(f"{path.name}: failed to load: {e}")

    return scenarios, errors


def cross_reference_cves(scenarios: list[GroundTruthScenario]) -> list[str]:
    """Cross-reference CVE IDs against the SkillCVEDatabase."""
    errors: list[str] = []

    try:
        from ziran.application.skill_cve import SkillCVEDatabase

        db = SkillCVEDatabase()
        known_ids = {cve.cve_id for cve in db.all_cves}

        for scenario in scenarios:
            for ref in scenario.source.references:
                ref_id = ref.id
                # Only check CVE-* and DESIGN-RISK-* IDs, not benchmark names
                # Skip -remediation suffixed references (these reference the fix, not the CVE itself)
                is_checkable = ref_id.startswith(("CVE-", "DESIGN-RISK-")) and not ref_id.endswith(
                    "-remediation"
                )
                if is_checkable and ref_id not in known_ids:
                        errors.append(
                            f"{scenario.scenario_id}: reference '{ref_id}' "
                            f"not found in SkillCVEDatabase"
                        )
    except ImportError:
        errors.append("Could not import SkillCVEDatabase for cross-reference check")

    return errors


def print_report(
    agents: dict[str, AgentDefinition],
    scenarios: list[GroundTruthScenario],
) -> None:
    """Print coverage statistics."""
    print("\n" + "=" * 60)
    print("GROUND TRUTH DATASET — COVERAGE REPORT")
    print("=" * 60)

    # Agent stats
    vulnerable = [a for a in agents.values() if a.known_vulnerabilities]
    safe = [a for a in agents.values() if not a.known_vulnerabilities]
    print(f"\nAgents: {len(agents)} total ({len(vulnerable)} vulnerable, {len(safe)} safe)")

    # Scenario stats
    tp = [s for s in scenarios if s.ground_truth.label == "true_positive"]
    tn = [s for s in scenarios if s.ground_truth.label == "true_negative"]
    print(f"Scenarios: {len(scenarios)} total ({len(tp)} TP, {len(tn)} TN)")

    # By category
    category_counts: Counter[str] = Counter()
    category_tp: Counter[str] = Counter()
    category_tn: Counter[str] = Counter()

    for s in scenarios:
        # Derive category from scenario_id (gt_tc_*, gt_se_*, gt_ca_*)
        parts = s.scenario_id.split("_")
        if len(parts) >= 3:
            cat_code = parts[1]
            cat_map = {"tc": "tool_chain", "se": "side_effect", "ca": "campaign"}
            cat = cat_map.get(cat_code, "unknown")
        else:
            cat = "unknown"
        category_counts[cat] += 1
        if s.ground_truth.label == "true_positive":
            category_tp[cat] += 1
        else:
            category_tn[cat] += 1

    print("\nBy category:")
    for cat in CATEGORIES:
        total = category_counts.get(cat, 0)
        tp_c = category_tp.get(cat, 0)
        tn_c = category_tn.get(cat, 0)
        print(f"  {cat:15s}: {total:3d} total ({tp_c} TP, {tn_c} TN)")

    # By detector
    detector_counts: Counter[str] = Counter()
    for s in scenarios:
        for d in s.ground_truth.expected_detectors:
            if d.should_fire:
                detector_counts[d.detector] += 1

    if detector_counts:
        print("\nExpected detector triggers (TP scenarios):")
        for det, count in detector_counts.most_common():
            print(f"  {det:20s}: {count}")

    # By source type
    source_types: Counter[str] = Counter()
    for s in scenarios:
        source_types[s.source.type] += 1

    print("\nBy source type:")
    for stype, count in source_types.most_common():
        print(f"  {stype:20s}: {count}")

    # CVE references
    cve_refs: set[str] = set()
    for s in scenarios:
        for ref in s.source.references:
            if ref.id.startswith("CVE-"):
                cve_refs.add(ref.id)

    print(f"\nUnique real CVEs referenced: {len(cve_refs)}")
    for cve_id in sorted(cve_refs):
        print(f"  {cve_id}")

    print("\n" + "=" * 60)


def main() -> int:
    """Run validation and report."""
    all_errors: list[str] = []

    # 1. Validate agents
    print("Validating agent definitions...")
    agents, agent_errors = validate_agents()
    all_errors.extend(agent_errors)
    print(f"  Loaded {len(agents)} agents, {len(agent_errors)} errors")

    # 2. Validate scenarios
    print("Validating scenarios...")
    scenarios, scenario_errors = validate_scenarios(agents)
    all_errors.extend(scenario_errors)
    print(f"  Loaded {len(scenarios)} scenarios, {len(scenario_errors)} errors")

    # 3. Cross-reference CVEs
    print("Cross-referencing CVE IDs...")
    cve_errors = cross_reference_cves(scenarios)
    all_errors.extend(cve_errors)
    print(f"  {len(cve_errors)} cross-reference errors")

    # 4. Print report
    print_report(agents, scenarios)

    # 5. Print errors
    if all_errors:
        print("\nERRORS:")
        for i, err in enumerate(all_errors, 1):
            print(f"  {i}. {err}")
        print(f"\nTotal errors: {len(all_errors)}")
        return 1

    print("\nAll validations passed!")
    return 0


if __name__ == "__main__":
    sys.exit(main())
