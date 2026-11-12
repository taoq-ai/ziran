"""Fetch the iterate side of the G-9 AgentDojo split only (never a lockbox, fresh or reserve log).

Usage: python3 -I fetch_iterate.py <ziran-paper> <dest>
Writes <dest>/agentdojo/<rel> for each iterate log and LICENSE, and <dest>/iterate.manifest.json.
"""

import importlib.util
import json
import sys
from pathlib import Path

paper, dest = Path(sys.argv[1]), Path(sys.argv[2])
scripts = paper / "study" / "scripts"
sys.path.insert(0, str(scripts))


def load(name: str):
    spec = importlib.util.spec_from_file_location(name, scripts / f"{name}.py")
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


probe = load("g10_dev_probe")
dev_sets = load("g11_dev_sets")
manifest = json.loads((paper / "prereg/ext-eval-intake/agentdojo.manifest.json").read_text())
runs = [r for r in manifest["files"] if r != manifest["licence"]]
iterate = [r for r in runs if dev_sets.side(r) == "iterate"]
dev_sets.guard(iterate, lockbox=False, who="G10-HARNESS-FRESH dev replay fetch")
files = {r: manifest["files"][r] for r in [*iterate, manifest["licence"]]}
sub = {"files": files, "licence": manifest["licence"], "terms": manifest.get("terms")}
dest.mkdir(parents=True, exist_ok=True)
(dest / "iterate.manifest.json").write_text(json.dumps(sub, sort_keys=True))
n = probe.fetch(sub, probe.BASES["agentdojo"], dest / "agentdojo", workers=16)
print(f"iterate logs {len(iterate)} of {len(runs)}; written {n}")
