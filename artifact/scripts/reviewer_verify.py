#!/usr/bin/env python3
"""Run the reviewer triage gate with a clean Python process."""
from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

sys.dont_write_bytecode = True

from common_paths import package_root


def run(root: Path, args: list[str]) -> dict[str, Any]:
    env = os.environ.copy()
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    artifact = str(root / "artifact")
    existing = env.get("PYTHONPATH")
    env["PYTHONPATH"] = artifact if not existing else artifact + os.pathsep + existing
    proc = subprocess.run([sys.executable, *args], cwd=root, env=env, text=True, capture_output=True)
    return {
        "command": [Path(sys.executable).name, *args],
        "returncode": proc.returncode,
        "stdout_tail": proc.stdout.strip().splitlines()[-5:],
        "stderr_tail": proc.stderr.strip().splitlines()[-5:],
    }


def main() -> None:
    root = package_root(__file__)
    commands = [
        ["artifact/scripts/check_artifact_clean.py"],
        ["artifact/scripts/audit_release_consistency.py"],
        ["artifact/scripts/run_validation.py", "--out", "artifact/results/validation_summary.json"],
        ["artifact/scripts/run_dependency_free_test_harness.py"],
        ["-m", "unittest", "discover", "-s", "artifact/tests"],
        ["artifact/scripts/run_strict_reproducibility_smoke.py"],
        ["artifact/scripts/decision_table_oracle.py"],
        ["artifact/scripts/mutation_adequacy_audit.py"],
        ["artifact/scripts/audit_boundary_conditions.py"],
        ["artifact/scripts/audit_assessor_objection_closure.py"],
        ["artifact/scripts/audit_release_consistency.py"],
    ]
    results = [run(root, command) for command in commands]
    failed = [r for r in results if r["returncode"] != 0]
    summary = {
        "status": "pass" if not failed else "fail",
        "commands_executed": len(results),
        "failed_commands": failed,
    }
    print(json.dumps(summary, indent=2, sort_keys=True))
    if failed:
        raise SystemExit(2)


if __name__ == "__main__":
    main()
