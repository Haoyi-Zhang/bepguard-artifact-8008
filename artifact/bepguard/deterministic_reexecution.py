"""Deterministic re-execution audit for evidence-facing gates.

The release validation summary intentionally avoids nested subprocesses.  This
module provides a separate anti-flakiness gate: selected lightweight gates are
executed twice into temporary directories, and their stdout plus materialized
outputs must have identical canonical digests.
"""
from __future__ import annotations

import csv
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any, Dict, Iterable, List, Tuple

sys.dont_write_bytecode = True


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _file_digest(path: Path) -> str:
    return _sha256_bytes(path.read_bytes())


def _run(root: Path, spec: Dict[str, Any], pass_index: int, tmp_root: Path) -> Dict[str, Any]:
    out_dir = tmp_root / f"pass{pass_index}" / spec["id"]
    out_dir.mkdir(parents=True, exist_ok=True)
    argv = [sys.executable, str(root / spec["script"])]
    for opt, rel in spec.get("outputs", {}).items():
        argv.extend([opt, str(out_dir / rel)])
    env = dict(os.environ)
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    env["PYTHONPATH"] = str(root / "artifact") + os.pathsep + env.get("PYTHONPATH", "")
    cp = subprocess.run(argv, cwd=str(root), env=env, text=True, capture_output=True, check=False, timeout=120)
    files = []
    for file in sorted(out_dir.rglob("*")):
        if file.is_file():
            files.append({"path": str(file.relative_to(out_dir)), "sha256": _file_digest(file)})
    digest_material = json.dumps({"stdout": cp.stdout, "stderr": cp.stderr, "returncode": cp.returncode, "files": files}, sort_keys=True).encode("utf-8")
    return {
        "command_id": spec["id"],
        "pass_index": pass_index,
        "returncode": cp.returncode,
        "stdout_sha256": _sha256_bytes(cp.stdout.encode("utf-8")),
        "stderr_sha256": _sha256_bytes(cp.stderr.encode("utf-8")),
        "file_count": len(files),
        "combined_sha256": _sha256_bytes(digest_material),
        "stdout_excerpt": cp.stdout.strip()[:240],
        "stderr_excerpt": cp.stderr.strip()[:240],
    }


def run_deterministic_reexecution_audit(root: Path) -> Tuple[List[Dict[str, str]], Dict[str, Any]]:
    commands = [
        {
            "id": "typed_ir_schema",
            "script": "artifact/scripts/audit_ir_schema.py",
            "outputs": {"--out": "typed_ir_schema_audit.json"},
        },
        {
            "id": "decision_purity",
            "script": "artifact/scripts/audit_decision_purity.py",
            "outputs": {"--out": "decision_purity_audit.json"},
        },
        {
            "id": "corpus_stability",
            "script": "artifact/scripts/audit_corpus_stability.py",
            "outputs": {"--rows-out": "corpus_stability_rows.csv", "--out": "corpus_stability_audit.json"},
        },
        {
            "id": "claim_trace_saturation",
            "script": "artifact/scripts/audit_claim_trace_saturation.py",
            "outputs": {"--cards-out": "source_claim_trace_cards.json", "--out": "source_claim_trace_audit.json"},
        },
        {
            "id": "repair_compactness",
            "script": "artifact/scripts/audit_repair_compactness.py",
            "outputs": {"--rows-out": "repair_compactness_rows.csv", "--out": "repair_compactness_audit.json"},
        },
    ]
    rows: List[Dict[str, str]] = []
    problems: List[str] = []
    with tempfile.TemporaryDirectory(prefix="bepguard_determinism_") as tmp:
        tmp_root = Path(tmp)
        for spec in commands:
            first = _run(root, spec, 1, tmp_root)
            second = _run(root, spec, 2, tmp_root)
            same = first["combined_sha256"] == second["combined_sha256"] and first["returncode"] == 0 and second["returncode"] == 0
            if not same:
                problems.append(f"{spec['id']}:non-deterministic or nonzero return code")
            rows.append({
                "command_id": spec["id"],
                "pass1_returncode": str(first["returncode"]),
                "pass2_returncode": str(second["returncode"]),
                "pass1_digest": str(first["combined_sha256"]),
                "pass2_digest": str(second["combined_sha256"]),
                "file_count": str(first["file_count"]),
                "status": "pass" if same else "fail",
            })
    summary = {
        "status": "pass" if not problems else "fail",
        "problem_count": len(problems),
        "problems": problems[:50],
        "commands_reexecuted": len(commands),
        "total_subprocess_runs": len(commands) * 2,
        "matching_digests": sum(1 for r in rows if r["status"] == "pass"),
        "interpretation": "Five evidence-facing gates are executed twice into temporary directories. Return codes and output/stdout/stderr digests must match exactly, guarding against accidental nondeterminism in lightweight reproduction gates.",
    }
    return rows, summary


def write_csv(path: Path, rows: List[Dict[str, str]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fields = ["command_id", "pass1_returncode", "pass2_returncode", "pass1_digest", "pass2_digest", "file_count", "status"]
    with path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=fields)
        writer.writeheader(); writer.writerows(rows)


def write_json(path: Path, obj: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=2, sort_keys=True) + "\n", encoding="utf-8")
