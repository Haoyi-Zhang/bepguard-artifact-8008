"""Lightweight idempotence replay for evidence-facing gates."""
from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any, Dict, List


def _sha(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _load(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def audit_idempotence(root: Path) -> Dict[str, Any]:
    commands = [
        ("package_identity", [sys.executable, "artifact/scripts/audit_package_identity.py", "--out", "{out}"] , "artifact/results/package_identity_audit.json"),
        ("documentation_consistency", [sys.executable, "artifact/scripts/audit_documentation_consistency.py", "--out", "{out}"], "artifact/results/documentation_consistency_audit.json"),
        ("decision_purity", [sys.executable, "artifact/scripts/audit_decision_purity.py", "--out", "{out}"], "artifact/results/decision_purity_audit.json"),
        ("paper_claim_consistency", [sys.executable, "artifact/scripts/audit_paper_claim_consistency.py", "--out", "{out}"], "artifact/results/paper_claim_consistency_audit.json"),
        ("runtime_boundary", [sys.executable, "artifact/scripts/audit_runtime_boundary.py", "--out", "{out}"], "artifact/results/runtime_boundary_audit.json"),
        ("pdf_reference_boundary", [sys.executable, "artifact/scripts/audit_pdf_reference_boundary.py", "--out", "{out}"], "artifact/results/pdf_reference_boundary_audit.json"),
        ("claim_impact", [sys.executable, "artifact/scripts/audit_claim_impact.py", "--out", "{out}", "--matrix-out", "artifact/results/tmp_claim_impact_matrix.csv"], "artifact/results/claim_impact_audit.json"),
        ("witness_hash_chain", [sys.executable, "artifact/scripts/audit_witness_hash_chain.py", "--out", "{out}", "--chain-out", "artifact/results/tmp_witness_hash_chain.csv"], "artifact/results/witness_hash_chain_audit.json"),
    ]
    rows: List[Dict[str, Any]] = []
    problems: List[str] = []
    with tempfile.TemporaryDirectory(prefix="bepguard-idempotence-") as tmp:
        tmpdir = Path(tmp)
        env = dict(os.environ)
        env["PYTHONDONTWRITEBYTECODE"] = "1"

        def _clean_bytecode() -> None:
            for cache in (root / "artifact").rglob("__pycache__"):
                shutil.rmtree(cache, ignore_errors=True)
            for pyc in (root / "artifact").rglob("*.pyc"):
                try:
                    pyc.unlink()
                except FileNotFoundError:
                    pass

        _clean_bytecode()
        for name, template, canonical_rel in commands:
            out = tmpdir / f"{name}.json"
            argv = [arg.format(out=str(out)) for arg in template]
            if argv and Path(argv[0]).name.startswith("python") and "-B" not in argv[:2]:
                argv.insert(1, "-B")
            env = dict(os.environ)
            env["PYTHONDONTWRITEBYTECODE"] = "1"
            proc = subprocess.run(argv, cwd=root, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=120, env=env)
            row: Dict[str, Any] = {"gate": name, "returncode": proc.returncode, "status": "", "problem_count": "", "canonical_sha256": "", "replay_sha256": ""}
            if proc.returncode != 0:
                problems.append(f"{name}: non-zero return code {proc.returncode}")
            if not out.exists():
                problems.append(f"{name}: did not write replay output")
                rows.append(row)
                continue
            try:
                replay = _load(out)
                row["status"] = replay.get("status", "")
                row["problem_count"] = replay.get("problem_count", "")
                if replay.get("status") != "pass" or replay.get("problem_count", 0) != 0:
                    problems.append(f"{name}: replay output is not passing")
            except Exception as exc:
                problems.append(f"{name}: replay JSON parse failed: {exc}")
            canonical = root / canonical_rel
            if canonical.exists():
                row["canonical_sha256"] = _sha(canonical)
                row["replay_sha256"] = _sha(out)
            rows.append(row)
        # Remove helper outputs if scripts wrote them under artifact/results.
        for rel in ["artifact/results/tmp_claim_impact_matrix.csv", "artifact/results/tmp_witness_hash_chain.csv"]:
            p = root / rel
            if p.exists():
                p.unlink()
    return {
        "status": "pass" if not problems else "fail",
        "problem_count": len(problems),
        "problems": problems[:80],
        "commands_reexecuted": len(commands),
        "commands_passing": sum(1 for r in rows if r.get("returncode") == 0 and r.get("status") == "pass"),
        "replay_rows": rows,
        "interpretation": "Representative evidence-facing gates are re-executed to temporary outputs and required to pass without modifying the release ledger, demonstrating idempotence of lightweight checks.",
    }


def write_json(path: Path, obj: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=2, sort_keys=True) + "\n", encoding="utf-8")
