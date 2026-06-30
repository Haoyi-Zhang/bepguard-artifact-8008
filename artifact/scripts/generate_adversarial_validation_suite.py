#!/usr/bin/env python3
"""Generate and check a BEP-Max adversarial validation suite.

The locked BEP-Deep denominator is not changed by this script.  Instead, the
script builds a deterministic validation layer around it: semantic-preserving
surface variants, positive-preserving adversarial variants, and paired-repair
contrast checks.  Each generated case is re-evaluated by the operational oracle
and by the independent decision-table oracle.  The goal is to stress the method
against formatting, irrelevant-header, and near-repair confounders without
claiming live-web prevalence.
"""
from __future__ import annotations
import sys
sys.dont_write_bytecode = True

import argparse, copy, csv, hashlib, json
from pathlib import Path
from typing import Any, Dict, Iterable, List

from bep_semantics import analyze_fixture
from decision_table_oracle import decision_issues, load


def stable_hash(obj: object) -> str:
    return hashlib.sha256(json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()).hexdigest()[:16]


def expected(fx: Dict[str, Any]) -> List[str]:
    e = str(fx.get("expected_issue", "none"))
    return [] if e == "none" else [e]


def op_issues(fx: Dict[str, Any]) -> List[str]:
    return sorted({f.issue for f in analyze_fixture(fx)})


def dt_issues(fx: Dict[str, Any]) -> List[str]:
    return sorted(set(decision_issues(fx)))


def refresh_fixture_hash(fx: Dict[str, Any]) -> Dict[str, Any]:
    fx["fixture_hash"] = stable_hash({k: v for k, v in fx.items() if k != "fixture_hash"})
    return fx


def clone(fx: Dict[str, Any], suffix: str, kind: str) -> Dict[str, Any]:
    g = copy.deepcopy(fx)
    g["id"] = f"{fx['id']}__max_{suffix}"
    g["validation_variant"] = kind
    g.pop("fixture_hash", None)
    return g


def normalize_header_name_case(fx: Dict[str, Any]) -> Dict[str, Any]:
    g = clone(fx, "casefold", "semantic_preserving_header_case")
    for h in g.get("headers", []) if isinstance(g.get("headers"), list) else []:
        h["name"] = str(h.get("name", "")).lower()
    for layer in g.get("layers", []) if isinstance(g.get("layers"), list) else []:
        for h in layer.get("headers", []) if isinstance(layer, dict) else []:
            h["name"] = str(h.get("name", "")).lower()
    return refresh_fixture_hash(g)


def reverse_surface_order(fx: Dict[str, Any]) -> Dict[str, Any]:
    g = clone(fx, "surface_reverse", "semantic_preserving_header_order")
    if isinstance(g.get("headers"), list):
        g["headers"] = list(reversed(g["headers"]))
    return refresh_fixture_hash(g)


def add_irrelevant_header(fx: Dict[str, Any]) -> Dict[str, Any]:
    g = clone(fx, "irrelevant_header", "semantic_preserving_irrelevant_surface")
    hs = g.setdefault("headers", [])
    if not isinstance(hs, list):
        g["headers"] = []
        hs = g["headers"]
    hs.append({"name": "X-BEP-Unrelated", "value": "ignored"})
    return refresh_fixture_hash(g)


def whitespace_variant(fx: Dict[str, Any]) -> Dict[str, Any]:
    g = clone(fx, "policy_whitespace", "semantic_preserving_policy_whitespace")
    for h in g.get("headers", []) if isinstance(g.get("headers"), list) else []:
        v = str(h.get("value", ""))
        if ";" in v:
            h["value"] = " ; ".join(part.strip() for part in v.split(";"))
    return refresh_fixture_hash(g)


def adversarial_nonrepair(fx: Dict[str, Any]) -> Dict[str, Any]:
    """Add a plausible-looking but irrelevant surface that should not repair."""
    g = clone(fx, "near_repair_fail", "positive_preserving_near_repair")
    issue = str(g.get("expected_issue", ""))
    hs = g.setdefault("headers", [])
    if not isinstance(hs, list):
        g["headers"] = []
        hs = g["headers"]
    if issue.startswith("csp"):
        hs.append({"name": "Content-Security-Policy-Report-Only", "value": "default-src 'none'"})
    elif issue.startswith("cors"):
        hs.append({"name": "Access-Control-Expose-Headers", "value": "*"})
    elif issue.startswith("hsts"):
        hs.append({"name": "Strict-Transport-Security-Report-Only", "value": "max-age=63072000"})
    elif issue.startswith("coep") or issue.startswith("corp") or issue.startswith("cross_origin"):
        hs.append({"name": "Cross-Origin-Embedder-Policy-Report-Only", "value": "require-corp"})
    elif issue.startswith("permissions"):
        hs.append({"name": "Permissions-Policy-Report-Only", "value": "geolocation=()"})
    else:
        hs.append({"name": "X-BEP-Comment", "value": "near-repair-no-effect"})
    return refresh_fixture_hash(g)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--fixtures", default="artifact/data/deep_locked_fixtures.json")
    ap.add_argument("--out-dir", default="artifact/results/bep_max")
    args = ap.parse_args()
    fixtures = load(args.fixtures)
    out = Path(args.out_dir); out.mkdir(parents=True, exist_ok=True)
    variants: List[Dict[str, Any]] = []
    for fx in fixtures:
        variants.extend([normalize_header_name_case(fx), reverse_surface_order(fx), add_irrelevant_header(fx), whitespace_variant(fx)])
        if str(fx.get("expected_issue", "none")) != "none":
            variants.append(adversarial_nonrepair(fx))
    rows = []
    failures = []
    for v in variants:
        exp = expected(v)
        op = op_issues(v)
        dt = dt_issues(v)
        ok = (op == exp and dt == exp)
        rows.append({
            "fixture_id": v["id"],
            "source_fixture_id": str(v["id"]).split("__max_")[0],
            "variant": v.get("validation_variant", ""),
            "expected": ";".join(exp) or "none",
            "operational": ";".join(op) or "none",
            "decision_table": ";".join(dt) or "none",
            "passed": str(ok).lower(),
        })
        if not ok and len(failures) < 20:
            failures.append(rows[-1])
    # Paired repair contrast checks are over the locked denominator, not generated
    # variants.  They verify source/intent preservation and exact one-surface flip.
    by_id = {str(f["id"]): f for f in fixtures}
    contrast_rows = []
    for fx in fixtures:
        if str(fx.get("fixture_role", "")) != "paired_repair_negative_control":
            continue
        pid = str(fx.get("paired_positive_fixture_id", ""))
        pos = by_id.get(pid)
        if not pos:
            continue
        surface_fields = ["headers", "layers", "context"]
        diffs = [k for k in surface_fields if pos.get(k) != fx.get(k)]
        same_source = set(pos.get("source_claim_ids", [])) == set(fx.get("source_claim_ids", []))
        same_intent = pos.get("intent", {}) == fx.get("intent", {})
        pos_ok = op_issues(pos) == expected(pos)
        rep_ok = op_issues(fx) == [] and dt_issues(fx) == []
        ok = len(diffs) == 1 and same_source and same_intent and pos_ok and rep_ok
        contrast_rows.append({
            "positive_fixture_id": pid,
            "repair_control_id": fx.get("id", ""),
            "target_issue": fx.get("paired_target_issue", ""),
            "changed_surface": ";".join(diffs) or "none",
            "same_source": str(same_source).lower(),
            "same_intent": str(same_intent).lower(),
            "positive_emits_expected": str(pos_ok).lower(),
            "repair_is_clean": str(rep_ok).lower(),
            "contrast_passed": str(ok).lower(),
        })
    with (out / "adversarial_validation_suite.json").open("w", encoding="utf-8") as fh:
        json.dump(variants, fh, indent=2, sort_keys=True)
        fh.write("\n")
    with (out / "adversarial_validation_audit.csv").open("w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=list(rows[0].keys()))
        w.writeheader(); w.writerows(rows)
    with (out / "contrastive_repair_pair_audit.csv").open("w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=list(contrast_rows[0].keys()))
        w.writeheader(); w.writerows(contrast_rows)
    metrics = {
        "locked_fixtures": len(fixtures),
        "generated_adversarial_validation_cases": len(variants),
        "semantic_preserving_cases": sum(1 for r in rows if str(r["variant"]).startswith("semantic_preserving")),
        "positive_preserving_near_repair_cases": sum(1 for r in rows if r["variant"] == "positive_preserving_near_repair"),
        "validation_cases_passed": sum(1 for r in rows if r["passed"] == "true"),
        "validation_failures": failures,
        "contrastive_repair_pairs": len(contrast_rows),
        "contrastive_repair_pairs_passed": sum(1 for r in contrast_rows if r["contrast_passed"] == "true"),
        "interpretation": "BEP-Max is an adversarial validation suite around the locked BEP-Deep denominator; it is not a prevalence sample.",
    }
    (out / "adversarial_validation_metrics.json").write_text(json.dumps(metrics, indent=2, sort_keys=True)+"\n", encoding="utf-8")
    print(json.dumps(metrics, sort_keys=True))
    if failures or metrics["contrastive_repair_pairs_passed"] != metrics["contrastive_repair_pairs"]:
        sys.exit(1)

if __name__ == "__main__":
    main()
