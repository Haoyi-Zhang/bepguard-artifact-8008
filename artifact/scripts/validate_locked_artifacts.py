#!/usr/bin/env python3
"""Validate the release BEP-Deep locked artifacts.

This compatibility entry point checks the release denominator and core validation
outputs rather than the earlier seed workload retained for lineage.
"""
from __future__ import annotations
import sys
sys.dont_write_bytecode = True
import json
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]

def load(rel: str):
    return json.loads((ROOT / rel).read_text(encoding="utf-8"))

# First run the canonical corpus validation.
code = subprocess.call([sys.executable, str(ROOT / "artifact" / "scripts" / "validate_corpus_and_coding.py"), "--root", str(ROOT)])
if code:
    raise SystemExit(code)

metrics = load("artifact/results/deep_locked/full_metrics.json")
summary = load("artifact/results/coding_validation_summary.json")
decision = load("artifact/results/deep_locked/decision_table_oracle_metrics.json")
mutation = load("artifact/results/deep_locked/semantic_mutation_adequacy.json")
certs = load("artifact/results/deep_locked/proof_carrying_witness_metrics.json")
maxv = load("artifact/results/bep_max/adversarial_validation_metrics.json")
frontier = load("artifact/results/bep_max/repair_frontier_metrics.json")
checks = {
    "corpus_validation_pass": summary.get("status") == "pass",
    "deep_fixture_count": metrics.get("fixtures") == 972,
    "deep_positive_detection": metrics.get("expected_findings_detected") == 418,
    "deep_negative_clean": metrics.get("negative_controls_clean") == 554,
    "decision_table_agreement": decision.get("locked_fixture_agreements") == 972 and decision.get("locked_fixture_mismatches") == 0,
    "mutation_adequacy": mutation.get("killed_mutants") == mutation.get("semantic_mutants") == 28,
    "proof_certificates": certs.get("certificates_verified") == 418,
    "bep_max_cases": maxv.get("validation_cases_passed") == 4306,
    "repair_frontiers": frontier.get("frontier_certified") == 418,
}
result = {"status": "pass" if all(checks.values()) else "fail", "checks": checks}
out = ROOT / "artifact" / "results" / "deep_locked" / "locked_artifact_validation_summary.json"
out.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
print(json.dumps(result, sort_keys=True))
raise SystemExit(0 if result["status"] == "pass" else 2)
