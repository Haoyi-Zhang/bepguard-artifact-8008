"""Per-issue evidence-depth accounting for BEPGuard."""
from __future__ import annotations

import csv
import json
import sys
import ast
from collections import Counter
from pathlib import Path
from typing import Any, Dict, List, Mapping, Set, Tuple

sys.dont_write_bytecode = True


def _json(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


def _csv(path: Path) -> List[Dict[str, str]]:
    with path.open(newline="", encoding="utf-8") as fh:
        return list(csv.DictReader(fh))


def audit_issue_evidence_depth(root: Path) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    fixtures = _json(root / "artifact/data/deep_locked_fixtures.json")
    certs = _json(root / "artifact/results/deep_locked/proof_carrying_witness_certificates.json")
    repairs = _json(root / "artifact/data/paired_repair_controls.json")
    spec_cases = _json(root / "artifact/results/deep_locked/specbench_cases.json")
    mutation_rows = _csv(root / "artifact/results/deep_locked/mutation_farm_cases.csv")
    causal_rows = _csv(root / "artifact/results/deep_locked/causal_counterfactual_activation_rows.csv")
    shadow_rows = _csv(root / "artifact/results/deep_locked/shadow_generalization_rows.csv")
    blind_rows = _csv(root / "artifact/results/deep_locked/identifier_blind_replay_rows.csv")
    external_rows = _csv(root / "artifact/results/deep_locked/external_contrast_specificity_rows.csv")

    issue_classes: Set[str] = {str(f.get("expected_issue")) for f in fixtures if str(f.get("expected_issue")) not in {"", "none"}}
    pos_by_issue = Counter(str(f.get("expected_issue")) for f in fixtures if str(f.get("expected_issue")) not in {"", "none"})
    controls_by_intent = Counter(str((f.get("intent") or {}).get("class", "")) for f in fixtures if str(f.get("expected_issue")) == "none")
    intent_by_issue = {str(f.get("expected_issue")): str((f.get("intent") or {}).get("class", "")) for f in fixtures if str(f.get("expected_issue")) not in {"", "none"}}
    certs_by_issue = Counter(str(c.get("issue")) for c in certs)
    repairs_by_issue = Counter(str(r.get("paired_target_issue")) for r in repairs)
    spec_by_issue: Counter[str] = Counter()
    for case in spec_cases:
        for issue in case.get("expected_issues", []):
            if issue:
                spec_by_issue[str(issue)] += 1
    mutants_by_issue = Counter(r.get("target_issue", "") for r in mutation_rows if str(r.get("killed", "")).lower() == "true")
    causal_by_issue = Counter()
    for row in causal_rows:
        try:
            values = ast.literal_eval(str(row.get("expected_activation_issue", "[]")))
        except Exception:
            values = []
        for part in values:
            if str(part).strip():
                causal_by_issue[str(part).strip()] += 1
    shadow_by_issue = Counter(str(r.get("expected_issues", "")) for r in shadow_rows if str(r.get("preserved", "")).lower() == "true" and str(r.get("expected_issues", "")) not in {"", "none"})
    blind_by_issue = Counter()
    for r in blind_rows:
        if str(r.get("preserved", "")).lower() != "true":
            continue
        try:
            values = ast.literal_eval(str(r.get("expected", "[]")))
        except Exception:
            values = []
        for v in values:
            if v:
                blind_by_issue[str(v)] += 1
    external_semantic = Counter()

    rows: List[Dict[str, Any]] = []
    problems: List[str] = []
    for issue in sorted(issue_classes):
        intent = intent_by_issue.get(issue, "")
        row = {
            "issue": issue,
            "intent_class": intent,
            "locked_positives": pos_by_issue[issue],
            "matched_intent_controls": controls_by_intent[intent],
            "positive_certificates": certs_by_issue[issue],
            "paired_repairs": repairs_by_issue[issue],
            "specbench_positive_cases": spec_by_issue[issue],
            "killed_mutants": mutants_by_issue[issue],
            "causal_activations": causal_by_issue[issue],
            "shadow_preserved_replays": shadow_by_issue[issue],
            "identifier_blind_preserved_replays": blind_by_issue[issue],
            "external_comparator_rows": external_semantic[issue],
        }
        # Conservative thresholds: every issue must have observed positives,
        # certificates, repairs, independent benchmark pressure, mutation pressure,
        # and at least one anti-overfit behavioral channel.  Some external tools
        # do not expose all issue classes, so external rows are reported but not
        # required per class.
        required = [
            (row["locked_positives"] >= 6, "locked positives"),
            (row["matched_intent_controls"] >= 1, "matched-intent negative controls"),
            (row["positive_certificates"] == row["locked_positives"], "certificate parity"),
            (row["paired_repairs"] == row["locked_positives"], "repair parity"),
            (row["specbench_positive_cases"] >= 1, "specbench coverage"),
            (row["killed_mutants"] >= 1, "mutation coverage"),
            (row["shadow_preserved_replays"] >= row["locked_positives"], "shadow replay coverage"),
            (row["identifier_blind_preserved_replays"] >= row["locked_positives"], "identifier-blind coverage"),
        ]
        for ok, label in required:
            if not ok:
                problems.append(f"{issue}: insufficient {label}")
        row["status"] = "pass" if not any(p.startswith(issue + ":") for p in problems) else "fail"
        rows.append(row)
    summary = {
        "status": "pass" if not problems else "fail",
        "problem_count": len(problems),
        "problems": problems,
        "issue_classes_checked": len(issue_classes),
        "issue_evidence_obligations": len(issue_classes) * 8,
        "total_locked_positives": sum(pos_by_issue.values()),
        "total_specbench_positive_cases": sum(spec_by_issue.values()),
        "total_killed_mutants": sum(mutants_by_issue.values()),
        "interpretation": "Per-issue evidence-depth audit: every drift class must be supported by locked positives, intent-matched controls, certificate parity, repair parity, source-derived SpecBench pressure, mutation pressure, shadow replay, and identifier-blind replay. External comparator rows are reported as contrastive evidence, not required labels.",
    }
    return rows, summary


def write_csv(path: Path, rows: List[Mapping[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fields = list(rows[0].keys()) if rows else []
    with path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=fields)
        writer.writeheader(); writer.writerows(rows)


def write_json(path: Path, obj: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=2, sort_keys=True) + "\n", encoding="utf-8")
