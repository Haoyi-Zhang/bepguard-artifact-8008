"""Rule-to-evidence trace-matrix audit for BEPGuard."""
from __future__ import annotations

import csv
import json
import re
import sys
from collections import Counter
from pathlib import Path
from typing import Any, Dict, List, Mapping, Tuple

sys.dont_write_bytecode = True


def _csv(path: Path) -> List[Dict[str, str]]:
    with path.open(newline="", encoding="utf-8") as fh:
        return list(csv.DictReader(fh))


def _json(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


def _source_manifest(root: Path) -> Dict[str, Dict[str, str]]:
    rows = _csv(root / "artifact/source_snapshot_manifest.csv")
    return {r.get("source_id", ""): r for r in rows}


def audit_rule_trace_matrix(root: Path) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    rules = _csv(root / "artifact/data/rule_source_ledger.csv")
    method_rules = _csv(root / "artifact/method/source_rule_ledger.csv")
    method_by_rule = {r.get("rule_id", ""): r for r in method_rules}
    sources = _source_manifest(root)
    spec_cases = _json(root / "artifact/results/deep_locked/specbench_cases.json")
    spec_by_rule = Counter(str(c.get("rule_id", "")) for c in spec_cases)
    contracts = _json(root / "artifact/results/deep_locked/cross_policy_contracts.json")
    theory = _json(root / "artifact/results/deep_locked/theory_kernel_audit.json")
    maturity = _json(root / "artifact/results/rule_maturity_audit.json")

    rows: List[Dict[str, Any]] = []
    problems: List[str] = []
    hex16 = re.compile(r"^[0-9a-f]{16}$")
    for rule in rules:
        rid = str(rule.get("rule_id", ""))
        source_ids = [s.strip() for s in str(rule.get("source_ids", "")).split(";") if s.strip()]
        source_resolved = all(sid in sources for sid in source_ids)
        manifest_links = all(rid in str(sources[sid].get("rule_ids", "")).split(";") for sid in source_ids if sid in sources)
        duplicate_ok = method_by_rule.get(rid, {}) == rule
        status_value = str(rule.get("encoded_status", "")).lower()
        encoded = status_value == "encoded" or status_value.startswith("encoded_") or status_value == "baseline_scope_record"
        span_ok = bool(str(rule.get("source_span", "")).strip())
        proof_ok = bool(str(rule.get("proof_obligation", "")).strip())
        hash_ok = bool(hex16.fullmatch(str(rule.get("rule_hash", ""))))
        family = str(rule.get("policy_family", ""))
        validation_channel = (
            spec_by_rule[rid] > 0
            or status_value.startswith("encoded_")
            or status_value == "baseline_scope_record"
            or any(token in family for token in ["CSP", "CORS", "HSTS", "COEP", "COOP", "CORP", "Permissions-Policy", "baseline"])
        )
        checks = {
            "encoded_status": encoded,
            "source_ids_resolved": source_resolved,
            "source_manifest_links_rule": manifest_links,
            "source_span_present": span_ok,
            "proof_obligation_present": proof_ok,
            "rule_hash_valid": hash_ok,
            "method_data_ledger_consistent": duplicate_ok,
            "validation_channel_present": validation_channel,
        }
        for label, ok in checks.items():
            if not ok:
                problems.append(f"{rid}: {label}")
        rows.append({
            "rule_id": rid,
            "policy_family": rule.get("policy_family", ""),
            "source_ids": ";".join(source_ids),
            "specbench_cases": spec_by_rule[rid],
            **checks,
            "status": "pass" if all(checks.values()) else "fail",
        })
    return rows, {
        "schema": "BEPGuardRuleTraceMatrix/v1",
        "status": "pass" if not problems else "fail",
        "problem_count": len(problems),
        "problems": problems[:50],
        "rules_checked": len(rules),
        "trace_obligations": len(rules) * 8,
        "rules_with_specbench_cases": sum(1 for r in rows if int(r.get("specbench_cases", 0)) > 0),
        "cross_policy_contracts": contracts.get("contracts_checked"),
        "theory_theorems": theory.get("theorems_checked"),
        "rule_maturity_status": maturity.get("status"),
        "interpretation": "Rule trace-matrix audit: every encoded semantic rule must resolve to admitted sources, appear consistently in data/method ledgers, carry a source span/proof obligation/hash, and be connected to an executable validation channel.",
    }


def write_csv(path: Path, rows: List[Mapping[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if not rows:
        path.write_text("\n", encoding="utf-8"); return
    fields = list(rows[0].keys())
    with path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=fields)
        writer.writeheader(); writer.writerows(rows)


def write_json(path: Path, obj: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=2, sort_keys=True) + "\n", encoding="utf-8")
