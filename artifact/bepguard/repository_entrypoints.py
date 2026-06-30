"""Repository entrypoint and assessor navigation audit."""
from __future__ import annotations
import json
try:
    import tomllib
except ModuleNotFoundError:  # Python 3.10 artifact path
    tomllib = None
from pathlib import Path
from typing import Any, Dict, List

ENTRYPOINTS = [
    "artifact/scripts/run_validation.py",
    "artifact/scripts/run_reproducibility_ladder.py",
    "artifact/scripts/audit_delivery_capsule.py",
    "artifact/scripts/audit_deliverable_trio_readiness.py",
    "artifact/scripts/audit_stale_numeric_surface.py",
    "artifact/bepguard/cli.py",
]
README_TOKENS = ["BEPGuard", "Reproduction", "release validation", "BEP-Deep", "BEP-Max", "anonymous"]


def run_repository_entrypoint_audit(root: Path) -> Dict[str, Any]:
    problems: List[str] = []
    for rel in ENTRYPOINTS:
        if not (root/rel).exists():
            problems.append(f"missing assessor entrypoint {rel}")
    pyproject_text = (root/"artifact/pyproject.toml").read_text(encoding="utf-8")
    if tomllib is not None:
        pyproject = tomllib.loads(pyproject_text)
        scripts = pyproject.get("project", {}).get("scripts", {})
    else:
        scripts = {}
        in_scripts = False
        for raw in pyproject_text.splitlines():
            line = raw.strip()
            if line.startswith("[") and line.endswith("]"):
                in_scripts = line == "[project.scripts]"
                continue
            if in_scripts and "=" in line and not line.startswith("#"):
                key, value = line.split("=", 1)
                scripts[key.strip()] = value.strip().strip('"')
    if scripts.get("bepguard") != "bepguard.cli:main":
        problems.append("pyproject bepguard console entrypoint mismatch")
    readme = (root/"artifact/README.md").read_text(encoding="utf-8")
    missing = [t for t in README_TOKENS if t.lower() not in readme.lower()]
    if missing: problems.append(f"README missing navigation tokens {missing}")
    ladder = json.loads((root/"artifact/reproduction_ladder.json").read_text(encoding="utf-8"))
    commands = ladder.get("commands") or ladder.get("steps") or []
    if len(commands) < 88:
        problems.append(f"reproduction ladder exposes only {len(commands)} commands")
    return {"status":"pass" if not problems else "fail", "problem_count":len(problems), "problems":problems[:100], "entrypoints_checked":len(ENTRYPOINTS), "reproduction_commands_seen":len(commands), "interpretation":"Checks that assessors can find a small set of stable entrypoints instead of reverse-engineering a large script tree."}


def write_json(path: Path, obj: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=2, sort_keys=True)+"\n", encoding="utf-8")
