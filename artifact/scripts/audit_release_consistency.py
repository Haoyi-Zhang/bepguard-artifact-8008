#!/usr/bin/env python3
"""release release-consistency audit for the anonymous artifact package.

This audit checks structural properties that are easy to miss when many
reproducible result files are regenerated: JSON parsability, checksum/index
freshness, absence of self-referential manifest rows, absence of stale root-level
seed/stress-result duplicates, and release result-denominator consistency.  It is a
repository-level consistency check; it does not change locked research labels or
metrics.
"""
from __future__ import annotations
import sys
sys.dont_write_bytecode = True

import argparse, csv, hashlib, json
from pathlib import Path
from typing import Dict, List, Set

SELF_UPDATING_AUDIT_RESULTS = {
    "artifact/results/clean_package_check.json",
    "artifact/results/validation_summary.json",
    "artifact/results/reference_integrity_audit.json",
    "artifact/results/latex_source_integrity_audit.json",
    "artifact/results/materialization_lineage_audit.json",
    "artifact/results/protocol_rq_consistency_audit.json",
    "artifact/results/protocol_amendment_integrity_audit.json",
    "artifact/results/validation_report_consistency_audit.json",
    "artifact/results/bibliographic_metadata_audit.json",
    "artifact/results/pdf_source_compile_audit.json",
    "artifact/results/release_consistency_audit.json",
    "artifact/results/release_language_integrity_audit.json",
    "artifact/results/anonymity_audit.json",
}
EXCLUDED_FROM_CHECKSUM = {
    "artifact/checksum_manifest.csv",
    "artifact/results/result_index.csv",
} | SELF_UPDATING_AUDIT_RESULTS
EXCLUDED_FROM_RESULT_INDEX = {
    "artifact/results/result_index.csv",
} | SELF_UPDATING_AUDIT_RESULTS
STALE_ROOT_RESULTS = {
    "artifact/results/full_metrics.json",
    "artifact/results/full_summary.csv",
    "artifact/results/full_witnesses.json",
    "artifact/results/bep_stress_summary.json",
}
VOLATILE_RESULT_FIELDS = {
    "runtime_seconds",
    "peak_memory_bytes",
    "fixtures_per_second",
    "runtime_per_fixture_ms",
}
FORBIDDEN_TRANSIENT_DIRS = {"__pycache__", ".ipynb_checkpoints", ".git", ".pytest_cache", ".mypy_cache"}
FORBIDDEN_TRANSIENT_SUFFIXES = {".pyc", ".aux", ".bbl", ".blg", ".log", ".out", ".synctex.gz", ".toc", ".fls", ".fdb_latexmk"}


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def read_csv(path: Path) -> List[Dict[str, str]]:
    with path.open(newline="", encoding="utf-8") as fh:
        return list(csv.DictReader(fh))


def read_json(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


def collect_files(root: Path) -> Set[str]:
    files: Set[str] = set()
    for p in root.rglob("*"):
        if p.is_file():
            files.add(str(p.relative_to(root)).replace("\\", "/"))
    return files


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", default=".")
    ap.add_argument("--out", default="artifact/results/release_consistency_audit.json")
    args = ap.parse_args()
    root = Path(args.root).resolve()
    problems: List[str] = []

    all_files = collect_files(root)
    forbidden_transients = sorted([f for f in all_files if any(part in FORBIDDEN_TRANSIENT_DIRS for part in Path(f).parts) or any(f.endswith(suf) for suf in FORBIDDEN_TRANSIENT_SUFFIXES)])
    if forbidden_transients:
        problems.append(f"forbidden transient files present: {forbidden_transients[:10]}")
    top = {p.name for p in root.iterdir() if p.name != ".DS_Store"}
    if top != {"paper", "artifact"}:
        problems.append(f"top-level directories are {sorted(top)}, expected ['artifact', 'paper']")

    # JSON parsability.
    json_errors: List[str] = []
    for rel in sorted(f for f in all_files if f.endswith(".json")):
        try:
            read_json(root / rel)
        except Exception as exc:
            json_errors.append(f"{rel}: {exc}")
    problems.extend([f"json parse error: {e}" for e in json_errors])

    # Checksum manifest closure, excluding intentionally self-updating files.
    manifest_path = root / "artifact/checksum_manifest.csv"
    manifest_rows = read_csv(manifest_path)
    manifest_paths = [r.get("path", "") for r in manifest_rows]
    if "artifact/checksum_manifest.csv" in manifest_paths:
        problems.append("checksum_manifest.csv contains a self-referential row")
    if len(manifest_paths) != len(set(manifest_paths)):
        problems.append("checksum_manifest.csv contains duplicate paths")
    expected_manifest_files = sorted(all_files - EXCLUDED_FROM_CHECKSUM)
    missing_from_manifest = sorted(set(expected_manifest_files) - set(manifest_paths))
    extra_in_manifest = sorted(set(manifest_paths) - set(expected_manifest_files))
    if missing_from_manifest:
        problems.append(f"checksum manifest missing {len(missing_from_manifest)} files: {missing_from_manifest[:10]}")
    if extra_in_manifest:
        problems.append(f"checksum manifest has {len(extra_in_manifest)} extra paths: {extra_in_manifest[:10]}")
    checksum_mismatches = []
    for row in manifest_rows:
        rel = row.get("path", "")
        if not rel or rel in EXCLUDED_FROM_CHECKSUM:
            continue
        p = root / rel
        if not p.exists():
            checksum_mismatches.append(f"{rel}: missing")
            continue
        if int(row.get("bytes", "-1")) != p.stat().st_size:
            checksum_mismatches.append(f"{rel}: byte count mismatch")
            continue
        if row.get("sha256") != sha256(p):
            checksum_mismatches.append(f"{rel}: sha256 mismatch")
    if checksum_mismatches:
        problems.append(f"checksum mismatches: {checksum_mismatches[:10]}")

    # Result index closure for artifact/results, excluding self-updating index/audit.
    result_index_path = root / "artifact/results/result_index.csv"
    result_rows = read_csv(result_index_path)
    result_paths = [r.get("path", "") for r in result_rows]
    if "artifact/results/result_index.csv" in result_paths:
        problems.append("result_index.csv contains a self-referential row")
    if len(result_paths) != len(set(result_paths)):
        problems.append("result_index.csv contains duplicate paths")
    actual_result_files = {f for f in all_files if f.startswith("artifact/results/")} - EXCLUDED_FROM_RESULT_INDEX
    missing_result_index = sorted(actual_result_files - set(result_paths))
    extra_result_index = sorted(set(result_paths) - actual_result_files)
    if missing_result_index:
        problems.append(f"result index missing {len(missing_result_index)} results: {missing_result_index[:10]}")
    if extra_result_index:
        problems.append(f"result index has {len(extra_result_index)} extra paths: {extra_result_index[:10]}")

    stale_present = sorted(STALE_ROOT_RESULTS & all_files)
    if stale_present:
        problems.append(f"stale root-level seed result duplicates present: {stale_present}")

    # Runtime and memory observations are intentionally not part of the
    # deterministic release ledger.  Count-based scalability outputs are
    # reproducible; wall-clock measurements belong in local notes, not in
    # archived result files that are checksum-closed.
    volatile_hits = []
    for rel in sorted(f for f in all_files if f.startswith("artifact/results/") and (f.endswith(".json") or f.endswith(".csv"))):
        try:
            text = (root / rel).read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        for token in VOLATILE_RESULT_FIELDS:
            if token in text:
                volatile_hits.append(f"{rel}:{token}")
                break
    if volatile_hits:
        problems.append(f"volatile runtime fields present in deterministic results: {volatile_hits[:10]}")

    # Denominator-level consistency checks.

    lineage_audit = root / "artifact/results/materialization_lineage_audit.json"
    if lineage_audit.exists():
        mat = read_json(lineage_audit)
        if mat.get("status") != "pass" or mat.get("main_workload") != "BEP-Deep":
            problems.append("materialization-lineage audit is not passing for BEP-Deep main workload")
    rq_audit = root / "artifact/results/protocol_rq_consistency_audit.json"
    if rq_audit.exists():
        rq = read_json(rq_audit)
        if rq.get("status") != "pass" or rq.get("expected_rqs") != ["RQ1", "RQ2", "RQ3", "RQ4", "RQ5"]:
            problems.append("protocol-RQ consistency audit is not passing for RQ1-RQ5")

    denom = read_json(root / "artifact/results/denominator_lock_summary.json")
    if denom.get("workload") != "BEP-Deep" or denom.get("locked_fixtures_total") != 972 or denom.get("expected_positive_fixtures") != 418 or denom.get("negative_control_fixtures") != 554:
        problems.append("denominator_lock_summary.json is not the release BEP-Deep 972/418/554 denominator summary")
    lineage_stress = root / "artifact/results/lineage/bep_stress_lineage_summary.json"
    lineage_seed = root / "artifact/results/lineage/seed_denominator_lock_summary.json"
    if not lineage_stress.exists():
        problems.append("BEP-Stress lineage summary is not segregated under artifact/results/lineage")
    if not lineage_seed.exists():
        problems.append("seed denominator lineage summary is not segregated under artifact/results/lineage")

    deep = read_json(root / "artifact/results/deep_locked/full_metrics.json")
    if deep.get("fixtures") != 972 or deep.get("expected_findings_detected") != 418 or deep.get("negative_controls_clean") != 554:
        problems.append("deep_locked/full_metrics.json does not match the locked 972/418/554 denominator")
    bepmax = read_json(root / "artifact/results/bep_max/adversarial_suite_integrity.json")
    if bepmax.get("status") != "pass" or bepmax.get("suite_cases") != 4306:
        problems.append("BEP-Max suite integrity is not passing for 4,306 cases")
    source_span = read_json(root / "artifact/results/source_span_closure_metrics.json")
    if source_span.get("status") != "pass" or source_span.get("claims_with_exactly_one_source_span_row") != 45:
        problems.append("source-span closure is not passing for 45 admitted claims")

    # Admitted-source manifest closure.  The release intentionally keeps a
    # broader source_manifest.csv for external resources and related evidence,
    # but the source_snapshot_manifest files used by claim admission must agree
    # exactly so that materialization and source-span closure do not consult
    # different source universes.
    root_sources = read_csv(root / "artifact/source_snapshot_manifest.csv")
    data_sources = read_csv(root / "artifact/data/source_snapshot_manifest.csv")
    span_rows = read_csv(root / "artifact/source_span_ledger.csv")
    claim_rows = read_csv(root / "artifact/data/corpus_claims.csv")
    root_source_ids = {r.get("source_id", "") for r in root_sources}
    data_source_ids = {r.get("source_id", "") for r in data_sources}
    span_source_ids = {r.get("source_id", "") for r in span_rows}
    claim_source_ids = {r.get("source_id", "") for r in claim_rows}
    if root_source_ids != data_source_ids:
        problems.append("root/data admitted source-snapshot manifests use different source identifiers")
    if claim_source_ids != span_source_ids:
        problems.append("claim table and source-span ledger use different source identifiers")
    if not claim_source_ids.issubset(data_source_ids):
        problems.append("some admitted claim source identifiers are absent from admitted source snapshots")

    # Validation-report and auxiliary source-ledger freshness.  These files are
    # smaller human-readable summaries that assessors often inspect first; they
    # must not lag behind the release 45-claim, 972-fixture BEP-Deep validation.
    release_claim_report = read_csv(root / "artifact/results/coding_validation_report.csv")
    data_claim_report = read_csv(root / "artifact/data/coding_validation_claims.csv")
    if len(release_claim_report) != 45 or {r.get("claim_id", "") for r in release_claim_report} != {r.get("claim_id", "") for r in claim_rows}:
        problems.append("release coding_validation_report.csv is not synchronized with the 45 admitted claims")
    if len(data_claim_report) != 45 or {r.get("claim_id", "") for r in data_claim_report} != {r.get("claim_id", "") for r in claim_rows}:
        problems.append("data coding_validation_claims.csv is not synchronized with the 45 admitted claims")
    source_acquisition_ids = {r.get("source_id", "") for r in read_csv(root / "artifact/data/source_acquisition_log.csv")}
    source_snapshot_ledger_ids = {r.get("source_id", "") for r in read_csv(root / "artifact/data/source_snapshot_ledger.csv")}
    if source_acquisition_ids != data_source_ids:
        problems.append("source_acquisition_log.csv does not match the admitted-source snapshot universe")
    if source_snapshot_ledger_ids != data_source_ids:
        problems.append("source_snapshot_ledger.csv does not match the admitted-source snapshot universe")
    for rel, expected_scope, expected_fixtures in [
        ("artifact/results/full_locked/lineage_scope.json", "seed-lineage", 116),
        ("artifact/results/extended_locked/lineage_scope.json", "bep-stress-lineage", 554),
    ]:
        marker = root / rel
        if not marker.exists():
            problems.append(f"missing lineage scope marker: {rel}")
        else:
            obj = read_json(marker)
            if obj.get("scope") != expected_scope or obj.get("main_workload") != "BEP-Deep" or obj.get("lineage_not_main_denominator") is not True or obj.get("fixtures") != expected_fixtures:
                problems.append(f"lineage scope marker is stale or ambiguous: {rel}")

    val_report = root / "artifact/results/validation_report_consistency_audit.json"
    if val_report.exists():
        v = read_json(val_report)
        if v.get("status") != "pass" or v.get("release_coding_validation_rows") != 45:
            problems.append("validation-report consistency audit is not passing for 45 claim rows")
    semantic_recompute = root / "artifact/results/semantic_recomputation_audit.json"
    if not semantic_recompute.exists():
        problems.append("semantic recomputation audit is missing")
    else:
        sem = read_json(semantic_recompute)
        if sem.get("status") != "pass" or sem.get("deep_detected_positives") != 418 or sem.get("deep_clean_negative_controls") != 554 or sem.get("bep_max_operational_decision_passed") != 4306:
            problems.append("semantic recomputation audit is not passing for BEP-Deep/BEP-Max counts")
    ref = read_json(root / "artifact/results/reference_integrity_audit.json")
    if ref.get("status") != "pass" or ref.get("cited_keys") != 72:
        problems.append("reference integrity audit is not passing for 72 cited keys")
    anon = read_json(root / "artifact/results/anonymity_audit.json")
    if anon.get("status") != "pass" or anon.get("problem_count") != 0:
        problems.append("anonymous paper delivery audit is not passing")

    result = {
        "status": "pass" if not problems else "fail",
        "problem_count": len(problems),
        "problems": problems,
        "json_files_checked": len([f for f in all_files if f.endswith(".json")]),
        "checksum_manifest_rows": len(manifest_rows),
        "result_index_rows": len(result_rows),
        "stale_root_seed_result_duplicates": stale_present,
        "forbidden_transient_files": forbidden_transients,
        "volatile_result_field_hits": volatile_hits,
        "excluded_self_updating_files": sorted(EXCLUDED_FROM_CHECKSUM | EXCLUDED_FROM_RESULT_INDEX),
        "self_updating_audit_results": sorted(SELF_UPDATING_AUDIT_RESULTS),
        "denominator_check": {"fixtures": deep.get("fixtures"), "positives_detected": deep.get("expected_findings_detected"), "negative_controls_clean": deep.get("negative_controls_clean"), "denominator_summary_workload": denom.get("workload")},
        "interpretation": "Release consistency audit over package structure, JSON parsability, checksum/index freshness, self-updating audit-result exclusions, absence of stale seed/stress-result duplicates and release-denominator summary closure, semantic-recomputation closure, and release validation metrics.",
    }
    out = root / args.out
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({"status": result["status"], "problem_count": result["problem_count"], "checksum_manifest_rows": result["checksum_manifest_rows"], "result_index_rows": result["result_index_rows"]}, sort_keys=True))
    if problems:
        raise SystemExit(2)


if __name__ == "__main__":
    main()
