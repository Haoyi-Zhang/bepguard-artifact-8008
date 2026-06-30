#!/usr/bin/env python3
"""Execute or audit the deterministic reproduction ladder.

The release validation summary is intentionally memory-stable.  This script gives
assessors a separate, explicit ladder that can execute the main deterministic
closure gates without relying on hidden orchestration or live services.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List

sys.dont_write_bytecode = True

from common_paths import package_root, require_files


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def run_command(root: Path, argv: List[str]) -> Dict[str, object]:
    env = os.environ.copy()
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    cp = subprocess.run(argv, cwd=root, env=env, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False, timeout=180)
    return {
        "argv": argv,
        "returncode": cp.returncode,
        "stdout_tail": cp.stdout[-800:],
        "stderr_tail": cp.stderr[-800:],
    }


def main() -> None:
    ap = argparse.ArgumentParser(description="Run or audit deterministic reproduction ladder.")
    ap.add_argument("--root", default=None)
    ap.add_argument("--spec", default="artifact/reproduction_ladder.json")
    ap.add_argument("--out", default="artifact/results/reproducibility_ladder_audit.json")
    ap.add_argument("--execute", action="store_true", help="Execute commands instead of only checking the ladder contract and existing outputs.")
    args = ap.parse_args()

    root = Path(args.root).resolve() if args.root else package_root(__file__)
    spec_path = root / args.spec
    problems: List[str] = []
    executions: List[Dict[str, object]] = []
    output_hashes: Dict[str, str] = {}

    if not spec_path.exists():
        problems.append(f"missing ladder spec: {args.spec}")
        spec = {"commands": []}
    else:
        spec = load_json(spec_path)

    commands = spec.get("commands", []) if isinstance(spec, dict) else []
    if not isinstance(commands, list) or not commands:
        problems.append("reproduction ladder has no commands")
        commands = []

    seen_ids: set[str] = set()
    for idx, command in enumerate(commands):
        if not isinstance(command, dict):
            problems.append(f"command row {idx} is not an object")
            continue
        cid = str(command.get("id", ""))
        argv = command.get("argv", [])
        outputs = command.get("expected_outputs", [])
        if not cid or cid in seen_ids:
            problems.append(f"command row {idx} has missing or duplicate id {cid!r}")
        seen_ids.add(cid)
        if not isinstance(argv, list) or len(argv) < 2:
            problems.append(f"command {cid} has malformed argv")
            continue
        script = argv[1] if len(argv) > 1 else ""
        if isinstance(script, str) and script.startswith("artifact/scripts/") and not (root / script).exists():
            problems.append(f"command {cid} script is missing: {script}")
        if args.execute:
            executions.append({"id": cid, **run_command(root, [str(x) for x in argv])})
            if executions[-1]["returncode"] != 0:
                problems.append(f"command {cid} failed with return code {executions[-1]['returncode']}")
        if not isinstance(outputs, list) or not outputs:
            problems.append(f"command {cid} has no expected outputs")
            continue
        missing = require_files(root, [str(x) for x in outputs])
        if missing:
            problems.append(f"command {cid} missing expected outputs: {', '.join(missing)}")
        for rel in outputs:
            path = root / str(rel)
            if path.exists():
                output_hashes[str(rel)] = sha256(path)
                if path.suffix == ".json":
                    try:
                        load_json(path)
                    except Exception as exc:
                        problems.append(f"command {cid} output is not valid JSON: {rel}: {exc}")

    result = {
        "status": "pass" if not problems else "fail",
        "problem_count": len(problems),
        "problems": problems,
        "mode": "execute" if args.execute else "audit",
        "commands_declared": len(commands),
        "commands_executed": len(executions),
        "command_ids": sorted(seen_ids),
        "output_hashes": output_hashes,
        "executions": executions,
        "interpretation": "Inspection-facing deterministic reproduction ladder over local closure gates; no live web scanning, hosted scanner calls, private accounts, GPUs, or external inference APIs.",
    }
    out = root / args.out
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({"status": result["status"], "problem_count": len(problems), "commands_declared": len(commands), "commands_executed": len(executions)}, sort_keys=True))
    if problems:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
