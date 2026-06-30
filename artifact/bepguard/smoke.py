"""Executable strict-smoke reproduction gate for BEPGuard.

The full reproduction ladder contains many commands.  This module executes a
small but semantically diverse subset that covers typed IR, SpecBench,
metamorphic properties, certificate replay, evidence-graph closure, and
anti-overfitting leakage checks.  The gate records deterministic output hashes
rather than volatile wall-clock measurements.
"""
from __future__ import annotations

import hashlib
import json
import os
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Sequence


@dataclass(frozen=True)
class SmokeCommand:
    command_id: str
    argv: Sequence[str]
    expected_outputs: Sequence[str]


SMOKE_COMMANDS: Sequence[SmokeCommand] = (
    SmokeCommand("typed_ir_schema", ("python3", "artifact/scripts/audit_ir_schema.py"), ("artifact/results/deep_locked/typed_ir_schema_audit.json",)),
    SmokeCommand("specbench", ("python3", "artifact/scripts/run_specbench.py"), ("artifact/results/deep_locked/specbench_summary.json", "artifact/results/deep_locked/specbench_cases.json", "artifact/results/deep_locked/specbench_results.csv")),
    SmokeCommand("metamorphic_relations", ("python3", "artifact/scripts/verify_metamorphic_relations.py"), ("artifact/results/deep_locked/metamorphic_relation_audit.json", "artifact/results/deep_locked/metamorphic_relation_cases.csv")),
    SmokeCommand("certificate_recheck", ("python3", "artifact/scripts/recheck_witness_certificates.py"), ("artifact/results/deep_locked/certificate_recheck_audit.json", "artifact/results/deep_locked/certificate_recheck_cases.csv")),
    SmokeCommand("evidence_graph", ("python3", "artifact/scripts/audit_evidence_graph.py"), ("artifact/results/evidence_graph_metrics.json", "artifact/results/evidence_graph.json", "artifact/results/evidence_graph_paths.csv")),
    SmokeCommand("anti_overfit_leakage", ("python3", "artifact/scripts/audit_anti_overfit_leakage.py"), ("artifact/results/anti_overfit_leakage_audit.json",)),
)


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def execute(root: Path, commands: Sequence[SmokeCommand] = SMOKE_COMMANDS) -> Dict[str, Any]:
    env = os.environ.copy()
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    problems: List[str] = []
    records: List[Dict[str, Any]] = []
    output_hashes: Dict[str, str] = {}
    for command in commands:
        cp = subprocess.run(list(command.argv), cwd=root, env=env, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=180, check=False)
        record = {
            "id": command.command_id,
            "argv": list(command.argv),
            "returncode": cp.returncode,
            "stdout_tail": cp.stdout[-500:],
            "stderr_tail": cp.stderr[-500:],
        }
        records.append(record)
        if cp.returncode != 0:
            problems.append(f"{command.command_id} returned {cp.returncode}")
        for rel in command.expected_outputs:
            path = root / rel
            if not path.exists():
                problems.append(f"{command.command_id} missing expected output {rel}")
            else:
                output_hashes[rel] = sha256(path)
                if path.suffix == ".json":
                    try:
                        json.loads(path.read_text(encoding="utf-8"))
                    except Exception as exc:  # pragma: no cover - defensive
                        problems.append(f"{command.command_id} output is not parseable JSON: {rel}: {exc}")
    return {
        "status": "pass" if not problems else "fail",
        "problem_count": len(problems),
        "problems": problems,
        "commands_executed": len(commands),
        "command_ids": [c.command_id for c in commands],
        "output_hashes": output_hashes,
        "executions": records,
        "interpretation": "Strict smoke execution over representative deterministic gates; records return codes and output hashes without live services or volatile timing fields.",
    }


def write_json(path: Path, obj: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=2, sort_keys=True) + "\n", encoding="utf-8")
