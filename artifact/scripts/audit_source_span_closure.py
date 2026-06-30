#!/usr/bin/env python3
"""Audit source-span closure for the admitted policy-intent claims.

The paper uses public source spans as the bridge between developer-facing text
and executable semantic obligations. This audit checks that the admitted claim
ledger and the source-span ledger are bijective over claim identifiers and that
each row resolves to a recorded public source snapshot.
"""
from __future__ import annotations
import sys
sys.dont_write_bytecode = True
import csv
import json
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
ART = ROOT / "artifact"
DATA = ART / "data"
RESULTS = ART / "results"


def read_csv(path: Path):
    with path.open(newline="", encoding="utf-8") as fh:
        return list(csv.DictReader(fh))


def write_csv(path: Path, rows, fieldnames):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=fieldnames)
        w.writeheader()
        for r in rows:
            w.writerow({k: r.get(k, "") for k in fieldnames})


def main():
    claims = read_csv(DATA / "corpus_claims.csv")
    spans = read_csv(ART / "source_span_ledger.csv")
    sources = read_csv(ART / "source_snapshot_manifest.csv")
    claim_by_id = {r["claim_id"]: r for r in claims}
    source_ids = {r["source_id"] for r in sources}

    span_counts = Counter(r.get("claim_id", "") for r in spans)
    rows = []
    failures = []
    for claim in claims:
        cid = claim["claim_id"]
        matching = [r for r in spans if r.get("claim_id") == cid]
        problems = []
        if len(matching) != 1:
            problems.append(f"span_row_count:{len(matching)}")
        else:
            span = matching[0]
            if span.get("source_id") != claim.get("source_id"):
                problems.append("source_id_mismatch")
            if span.get("source_span") != claim.get("source_span"):
                problems.append("source_span_mismatch")
            if span.get("public_source_url") != claim.get("source_url"):
                problems.append("source_url_mismatch")
            if not span.get("source_span"):
                problems.append("empty_source_span")
            if span.get("source_id") not in source_ids:
                problems.append("source_not_in_snapshot_manifest")
        if problems:
            failures.append({"claim_id": cid, "problems": problems})
        rows.append({
            "claim_id": cid,
            "source_id": claim.get("source_id", ""),
            "policy_family": claim.get("policy_family", ""),
            "claim_type": claim.get("claim_type", ""),
            "fixture_role": claim.get("fixture_role", ""),
            "source_span_present": "yes" if claim.get("source_span") else "no",
            "source_url_present": "yes" if claim.get("source_url", "").startswith("http") else "no",
            "source_manifest_resolved": "yes" if claim.get("source_id") in source_ids else "no",
            "span_ledger_rows": span_counts.get(cid, 0),
            "status": "pass" if not problems else "needs_action",
            "problems": ";".join(problems),
        })

    orphan_spans = [r.get("claim_id", "") for r in spans if r.get("claim_id") not in claim_by_id]
    duplicate_span_claims = {cid: n for cid, n in span_counts.items() if n != 1}
    metrics = {
        "status": "pass" if not failures and not orphan_spans and not duplicate_span_claims else "needs_action",
        "claims": len(claims),
        "source_span_rows": len(spans),
        "claims_with_exactly_one_source_span_row": sum(1 for r in rows if r["span_ledger_rows"] == 1),
        "source_manifest_rows": len(sources),
        "orphan_source_span_rows": len(orphan_spans),
        "duplicate_or_missing_span_claims": len(duplicate_span_claims),
        "claims_resolving_to_snapshot_manifest": sum(1 for r in rows if r["source_manifest_resolved"] == "yes"),
        "claim_types": dict(Counter(r.get("claim_type", "") for r in claims)),
        "policy_families": dict(Counter(r.get("policy_family", "") for r in claims)),
        "interpretation": "Source-span closure links every admitted public claim to exactly one recorded source span and one source snapshot record; it is a traceability audit, not a public-web prevalence claim.",
    }
    if failures:
        metrics["failures"] = failures[:20]
    if orphan_spans:
        metrics["orphan_source_span_claim_ids"] = orphan_spans[:20]
    write_csv(RESULTS / "source_span_closure_audit.csv", rows,
              ["claim_id", "source_id", "policy_family", "claim_type", "fixture_role", "source_span_present", "source_url_present", "source_manifest_resolved", "span_ledger_rows", "status", "problems"])
    (RESULTS / "source_span_closure_metrics.json").write_text(json.dumps(metrics, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(metrics, sort_keys=True))
    if metrics["status"] != "pass":
        raise SystemExit(2)


if __name__ == "__main__":
    main()
