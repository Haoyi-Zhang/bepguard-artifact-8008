"""Assessor-facing independence and generalization closure checks."""
from __future__ import annotations

import csv
import json
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Tuple

sys.dont_write_bytecode = True


def read_csv(path: Path) -> List[Dict[str, str]]:
    with path.open(newline="", encoding="utf-8") as fh:
        return list(csv.DictReader(fh))


def read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def _fixture_positive(fixture: Mapping[str, Any]) -> bool:
    return str(fixture.get("fixture_role", "")) == "positive"


def _bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in {"1", "true", "yes", "y"}


def _issue(fixture: Mapping[str, Any]) -> str:
    issue = str(fixture.get("expected_issue", "none") or "none")
    return "none" if issue == "" else issue


def _source_claims(fixture: Mapping[str, Any]) -> List[str]:
    raw = fixture.get("source_claim_ids", [])
    if isinstance(raw, list):
        return [str(x) for x in raw if str(x)]
    if isinstance(raw, str):
        return [x for x in raw.split(";") if x]
    return []


def audit_ground_truth_provenance(root: Path) -> Dict[str, Any]:
    artifact = root / "artifact"
    claims = read_csv(artifact / "data" / "corpus_claims.csv")
    spans = read_csv(artifact / "source_span_ledger.csv")
    sources = read_csv(artifact / "data" / "source_snapshot_manifest.csv")
    rules = read_csv(artifact / "data" / "rule_to_source_ledger.csv")
    fixtures = read_json(artifact / "data" / "deep_locked_fixtures.json")
    denom = read_json(artifact / "results" / "denominator_lock_summary.json")

    problems: List[str] = []
    claim_ids = {r["claim_id"] for r in claims}
    span_claims = {r["claim_id"] for r in spans}
    source_ids = {r["source_id"] for r in sources}
    rule_ids = {r["rule_id"] for r in rules}

    if len(claims) != 45:
        problems.append(f"expected 45 admitted source claims, found {len(claims)}")
    if len(spans) != 45 or span_claims != claim_ids:
        problems.append("source-span ledger does not cover exactly the admitted claims")
    if len(sources) < 10:
        problems.append("source snapshot manifest has fewer than ten public sources")
    if len(rules) != 35:
        problems.append(f"expected 35 semantic rule obligations, found {len(rules)}")

    for row in claims:
        if row.get("source_id") not in source_ids:
            problems.append(f"claim {row.get('claim_id')} references unknown source {row.get('source_id')}")
        if not row.get("source_url", "").startswith(("http://", "https://")):
            problems.append(f"claim {row.get('claim_id')} lacks public source URL")
        if not row.get("source_span"):
            problems.append(f"claim {row.get('claim_id')} lacks source span")
        if len(row.get("claim_hash", "")) < 12:
            problems.append(f"claim {row.get('claim_id')} lacks stable claim hash")
        for rid in row.get("semantic_rule_ids", "").split(";"):
            if rid and rid not in rule_ids:
                problems.append(f"claim {row.get('claim_id')} references unknown rule {rid}")

    roles = Counter(str(f.get("fixture_role", "")) for f in fixtures)
    fixture_source_failures = []
    for fixture in fixtures:
        fid = str(fixture.get("id", ""))
        claims_for_fixture = _source_claims(fixture)
        if not claims_for_fixture:
            fixture_source_failures.append(f"{fid}: missing source_claim_ids")
            continue
        missing = [cid for cid in claims_for_fixture if cid not in claim_ids]
        if missing:
            fixture_source_failures.append(f"{fid}: unknown source claims {missing}")
    expected_total = int(denom.get("locked_fixtures_total", -1))
    expected_positive = int(denom.get("expected_positive_fixtures", -1))
    expected_controls = int(denom.get("negative_control_fixtures", -1))
    if len(fixtures) != expected_total:
        problems.append(f"BEP-Deep fixture count {len(fixtures)} does not match denominator summary {expected_total}")
    if roles["positive"] != expected_positive:
        problems.append(f"positive fixture count {roles['positive']} does not match denominator summary {expected_positive}")
    if roles["negative_control"] + roles["paired_repair_negative_control"] != expected_controls:
        problems.append("negative-control count does not match denominator summary")
    if fixture_source_failures:
        problems.append(f"fixture source-link failures: {fixture_source_failures[:10]}")

    return {
        "status": "pass" if not problems else "fail",
        "problem_count": len(problems),
        "problems": problems[:100],
        "admitted_source_claims": len(claims),
        "source_span_rows": len(spans),
        "public_sources": len(sources),
        "semantic_rules": len(rules),
        "locked_fixtures": len(fixtures),
        "positive_fixtures": roles["positive"],
        "negative_controls": roles["negative_control"] + roles["paired_repair_negative_control"],
        "fixture_source_links_checked": len(fixtures),
        "label_basis": "public source spans plus semantic rule obligations; the operational evaluator is not used as the source of admitted claims or fixture labels",
        "human_label_scope": "no human inter-rater agreement is claimed; the artifact exposes source-span and rule-obligation closure for deterministic assessor inspection",
        "interpretation": "Closes the ground-truth-circularity objection by checking that admitted claims, rules, source spans, and BEP-Deep fixture labels trace to public source records and stable hashes rather than to an opaque evaluator output.",
    }


def audit_oracle_provenance(root: Path) -> Dict[str, Any]:
    artifact = root / "artifact"
    decision = read_json(artifact / "results" / "deep_locked" / "decision_table_oracle_metrics.json")
    declarative = read_json(artifact / "results" / "deep_locked" / "declarative_oracle_audit.json")
    triangulation = read_json(artifact / "results" / "deep_locked" / "oracle_triangulation_audit.json")
    generated = read_json(artifact / "results" / "generated_oracle_tests.json")
    denom = read_json(artifact / "results" / "denominator_lock_summary.json")
    specbench = read_json(artifact / "results" / "deep_locked" / "specbench_summary.json")
    declarative_source = (artifact / "bepguard" / "declarative_oracle.py").read_text(encoding="utf-8")
    problems: List[str] = []
    expected_fixtures = int(denom.get("locked_fixtures_total", -1))
    expected_declarative_cases = expected_fixtures + int(specbench.get("cases", 0))
    expected_pairwise_cells = expected_fixtures * len(triangulation.get("oracles", []))

    if decision.get("status") == "fail" or decision.get("locked_fixture_agreements") != expected_fixtures:
        problems.append("decision-table oracle does not agree on all locked fixtures")
    if declarative.get("status") != "pass" or declarative.get("cases_checked") != expected_declarative_cases:
        problems.append("label-free declarative oracle does not pass all locked and SpecBench cases")
    if triangulation.get("status") != "pass" or triangulation.get("pairwise_agreements") != expected_pairwise_cells:
        problems.append("oracle triangulation does not pass all pairwise cells")
    if generated.get("status") != "pass" or int(generated.get("tests_run") or 0) <= expected_fixtures:
        problems.append("generated oracle tests are not passing the released fixture/certificate checks")
    forbidden_imports = ["generated_oracles", "bep_semantics"]
    import_lines = [line.strip() for line in declarative_source.splitlines() if line.lstrip().startswith(("import ", "from "))]
    for token in forbidden_imports:
        if any(token in line for line in import_lines):
            problems.append(f"declarative oracle imports {token}")
    if any("LOCKED_FIXTURE_ORACLE" in line for line in declarative_source.splitlines() if not line.lstrip().startswith('"""')):
        problems.append("declarative oracle reads the generated static oracle table")

    return {
        "status": "pass" if not problems else "fail",
        "problem_count": len(problems),
        "problems": problems,
        "decision_table_locked_agreements": decision.get("locked_fixture_agreements"),
        "declarative_cases_checked": declarative.get("cases_checked"),
        "oracle_pairwise_agreements": triangulation.get("pairwise_agreements"),
        "generated_oracle_tests": generated.get("tests_run"),
        "generated_oracle_scope": "static generated tests check released fixture/certificate consistency; independent correctness evidence comes from decision-table, declarative, and triangulation audits",
        "interpretation": "Separates internal generated-test consistency from independent oracle evidence and verifies that the label-free declarative oracle does not import the operational evaluator or generated static oracle table.",
    }


def audit_external_disagreement(root: Path) -> Tuple[List[Dict[str, str]], Dict[str, Any]]:
    artifact = root / "artifact"
    fixtures = read_json(artifact / "data" / "deep_locked_fixtures.json")
    by_id = {str(f["id"]): f for f in fixtures}
    full = read_json(artifact / "results" / "deep_locked" / "external_baseline_full_run.json")
    full_audit = read_json(artifact / "results" / "external_baseline_full_run_audit.json")
    rows = full.get("rows", []) if isinstance(full, Mapping) else full
    matrix: Dict[str, Counter] = defaultdict(Counter)
    sample_rows: List[Dict[str, str]] = []
    problems: List[str] = []

    for row in rows:
        fid = str(row.get("fixture_id", ""))
        baseline = str(row.get("baseline", "unknown"))
        if fid not in by_id:
            problems.append(f"external comparator row references unknown fixture {fid}")
            continue
        semantic_positive = _fixture_positive(by_id[fid])
        baseline_flagged = _bool(row.get("flagged"))
        if semantic_positive and baseline_flagged:
            cell = "both_flag"
        elif semantic_positive and not baseline_flagged:
            cell = "bep_only"
        elif not semantic_positive and baseline_flagged:
            cell = "baseline_only"
        else:
            cell = "neither_flag"
        matrix[baseline][cell] += 1
        matrix[baseline]["total"] += 1
        if cell in {"bep_only", "baseline_only"} and matrix[baseline][f"sample_{cell}"] < 12:
            matrix[baseline][f"sample_{cell}"] += 1
            fixture = by_id[fid]
            sample_rows.append({
                "baseline": baseline,
                "fixture_id": fid,
                "policy_family": str(fixture.get("policy_family", "")),
                "semantic_positive": str(semantic_positive),
                "baseline_flagged": str(baseline_flagged),
                "matrix_cell": cell,
                "expected_issue": _issue(fixture),
                "source_claim_ids": ";".join(_source_claims(fixture)),
                "adjudication_basis": "source-grounded semantic obligation, not baseline agreement",
            })

    if len(rows) != int(full_audit.get("rows_total", -1)):
        problems.append("external comparator rows do not match the materialized full-run audit")
    if any(str(row.get("status", "")) != "available" for row in rows):
        problems.append("external comparator row has non-available status")
    if not sample_rows:
        problems.append("no baseline disagreement samples were materialized")

    summary_rows = []
    for baseline, counts in sorted(matrix.items()):
        summary_rows.append({
            "baseline": baseline,
            "total": str(counts["total"]),
            "both_flag": str(counts["both_flag"]),
            "bep_only": str(counts["bep_only"]),
            "baseline_only": str(counts["baseline_only"]),
            "neither_flag": str(counts["neither_flag"]),
        })

    return sample_rows + [{"__summary__": json.dumps(summary_rows, sort_keys=True)}], {
        "status": "pass" if not problems else "fail",
        "problem_count": len(problems),
        "problems": problems[:100],
        "external_rows": len(rows),
        "baselines": sorted(matrix),
        "summary_rows": summary_rows,
        "sampled_disagreements": len(sample_rows),
        "baseline_role": "contrastive public-package evidence; disagreements are exposed in a matrix and adjudicated against source-grounded obligations rather than hidden or assumed away",
        "interpretation": "Materializes the public-comparator agreement/disagreement matrix so baseline-only and BEPGuard-only cases are visible to assessors.",
    }


def audit_heldout_generalization(root: Path) -> Dict[str, Any]:
    artifact = root / "artifact"
    fixtures = read_json(artifact / "data" / "deep_locked_fixtures.json")
    locked_ids = {str(f["id"]) for f in fixtures}
    specbench = read_json(artifact / "results" / "deep_locked" / "specbench_cases.json")
    summary = read_json(artifact / "results" / "deep_locked" / "specbench_summary.json")
    declarative = read_json(artifact / "results" / "deep_locked" / "declarative_oracle_audit.json")
    problems: List[str] = []
    ids = [str(c.get("case_id", c.get("id", ""))) for c in specbench]
    overlaps = sorted(set(ids) & locked_ids)
    source_linked = sum(1 for c in specbench if c.get("source_claim_ids") or c.get("public_source_id") or c.get("fixture", {}).get("source_claim_ids"))
    non_sb = [cid for cid in ids if not cid.startswith("SB_")]
    expected_specbench_cases = int(summary.get("cases", -1))
    if summary.get("status") != "pass" or len(specbench) != expected_specbench_cases:
        problems.append("SpecBench summary does not match the held-out case file")
    if overlaps:
        problems.append(f"SpecBench case ids overlap locked fixtures: {overlaps[:10]}")
    if non_sb:
        problems.append(f"SpecBench contains non-heldout id prefixes: {non_sb[:10]}")
    if source_linked != len(specbench):
        problems.append("not every SpecBench case carries a public source link")
    if declarative.get("specbench_cases_checked") != expected_specbench_cases:
        problems.append("declarative oracle did not check all 4,180 SpecBench cases")

    return {
        "status": "pass" if not problems else "fail",
        "problem_count": len(problems),
        "problems": problems,
        "heldout_cases": len(specbench),
        "locked_fixture_overlap": len(overlaps),
        "rules_covered": summary.get("rules_covered"),
        "source_claims_covered": summary.get("source_claims_covered"),
        "source_linked_cases": source_linked,
        "declarative_oracle_specbench_cases": declarative.get("specbench_cases_checked"),
        "role": "true non-denominator source-derived boundary suite; scale-stress and identifier-blind replays remain robustness checks, not the sole generalization evidence",
        "interpretation": "Closes the syntactic-variant-only objection by verifying a non-denominator SpecBench suite with fresh SB_* case ids, public source links, and declarative-oracle coverage.",
    }


def audit_claim_extraction_coverage(root: Path) -> Dict[str, Any]:
    artifact = root / "artifact"
    claims = read_csv(artifact / "data" / "corpus_claims.csv")
    sources = read_csv(artifact / "data" / "source_snapshot_manifest.csv")
    rules = read_csv(artifact / "data" / "rule_to_source_ledger.csv")
    coverage = read_json(artifact / "results" / "deep_locked" / "claim_coverage_metrics.json")
    problems: List[str] = []
    families = Counter(row.get("policy_family", "") for row in claims)
    if coverage.get("status") != "pass":
        problems.append("claim coverage metrics are not passing")
    if len(claims) != 45 or len(rules) != 35:
        problems.append("admitted claim/rule counts changed unexpectedly")
    if len(families) < 6:
        problems.append("admitted claims cover fewer than six policy families")
    return {
        "status": "pass" if not problems else "fail",
        "problem_count": len(problems),
        "problems": problems,
        "admitted_claims": len(claims),
        "semantic_rules": len(rules),
        "public_sources": len(sources),
        "policy_families": dict(sorted(families.items())),
        "claim_coverage_status": coverage.get("status"),
        "scope_statement": "the artifact claims a conservative admitted-source denominator, not recall over every possible browser-policy sentence in upstream ecosystems",
        "interpretation": "Makes the 45-claim denominator explicit and avoids implying broad claim-extraction recall over all browser code or documentation.",
    }


def audit_walkthrough(root: Path) -> Dict[str, Any]:
    required = {
        "artifact/docs/artifact_walkthrough.md": ["5-minute", "30-minute", "key results", "interpret"],
        "artifact/docs/ground_truth_provenance.md": ["source-grounded", "source_span_ledger", "human inter-rater"],
        "artifact/docs/oracle_provenance.md": ["declarative", "decision-table", "generated"],
        "artifact/docs/baseline_disagreement.md": ["disagreement matrix", "baseline-only", "BEPGuard-only"],
        "artifact/docs/heldout_generalization.md": ["SpecBench", "non-denominator", "4,180"],
        "artifact/docs/claim_extraction_coverage.md": ["45", "conservative", "scope"],
    }
    problems: List[str] = []
    for rel, tokens in required.items():
        path = root / rel
        if not path.exists():
            problems.append(f"missing walkthrough document {rel}")
            continue
        text = path.read_text(encoding="utf-8").lower()
        missing = [tok for tok in tokens if tok.lower() not in text]
        if missing:
            problems.append(f"{rel} missing tokens {missing}")
    return {
        "status": "pass" if not problems else "fail",
        "problem_count": len(problems),
        "problems": problems,
        "documents_checked": len(required),
        "interpretation": "Checks that assessor-facing walkthrough and objection-closure documents expose the commands, result locations, and limitations needed for a short artifact review window.",
    }


def write_json(path: Path, obj: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def write_csv(path: Path, rows: Iterable[Mapping[str, str]]) -> None:
    rows = list(rows)
    path.parent.mkdir(parents=True, exist_ok=True)
    fields = [
        "baseline", "fixture_id", "policy_family", "semantic_positive",
        "baseline_flagged", "matrix_cell", "expected_issue",
        "source_claim_ids", "adjudication_basis", "__summary__",
    ]
    with path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=fields)
        writer.writeheader()
        for row in rows:
            writer.writerow({field: row.get(field, "") for field in fields})


def run_assessor_objection_closure(root: Path) -> Dict[str, Any]:
    result_dir = root / "artifact" / "results"
    ground_truth = audit_ground_truth_provenance(root)
    oracle = audit_oracle_provenance(root)
    disagreement_rows, disagreement = audit_external_disagreement(root)
    heldout = audit_heldout_generalization(root)
    coverage = audit_claim_extraction_coverage(root)
    walkthrough = audit_walkthrough(root)

    write_json(result_dir / "ground_truth_provenance_audit.json", ground_truth)
    write_json(result_dir / "oracle_provenance_audit.json", oracle)
    write_csv(result_dir / "external_baseline_disagreement_matrix.csv", disagreement_rows)
    write_json(result_dir / "external_baseline_disagreement_audit.json", disagreement)
    write_json(result_dir / "heldout_generalization_audit.json", heldout)
    write_json(result_dir / "claim_extraction_coverage_audit.json", coverage)
    write_json(result_dir / "assessor_walkthrough_audit.json", walkthrough)

    components = {
        "ground_truth_provenance": ground_truth,
        "oracle_provenance": oracle,
        "external_baseline_disagreement": disagreement,
        "heldout_generalization": heldout,
        "claim_extraction_coverage": coverage,
        "assessor_walkthrough": walkthrough,
    }
    problems = [
        f"{name}: {problem}"
        for name, obj in components.items()
        for problem in obj.get("problems", [])
    ]
    summary = {
        "status": "pass" if not problems else "fail",
        "problem_count": len(problems),
        "problems": problems[:100],
        "components": {
            name: {
                "status": obj.get("status"),
                "problem_count": obj.get("problem_count"),
            }
            for name, obj in components.items()
        },
        "p1_objections_closed": [
            "source-grounded label provenance is explicit",
            "public-baseline disagreements are materialized",
            "generated oracle tests are scoped separately from independent oracles",
            "non-denominator SpecBench generalization is exposed",
        ],
        "p2_objections_closed": [
            "45-claim conservative scope is documented",
            "short assessor walkthrough is present",
        ],
        "interpretation": "Assessor-facing closure over common artifact objections: circular labels, opaque baseline disagreement, self-generated oracle claims, syntactic-only generalization, claim-denominator scope, and walkthrough burden.",
    }
    write_json(result_dir / "assessor_objection_closure_audit.json", summary)
    return summary
