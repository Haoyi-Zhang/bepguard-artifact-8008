"""Oracle explanation-equivalence checks for BEPGuard."""
from __future__ import annotations

import csv
import json
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


def _norm(value: str) -> Tuple[str, ...]:
    raw = str(value).strip()
    if raw in {"", "none", "[]", "null"}:
        return tuple()
    if raw.startswith("["):
        try:
            values = json.loads(raw)
            return tuple(sorted(str(v) for v in values if str(v)))
        except Exception:
            pass
    return tuple(sorted(part.strip() for part in raw.split(";") if part.strip()))


def audit_oracle_equivalence(root: Path) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    rows = _csv(root / "artifact/results/deep_locked/declarative_oracle_rows.csv")
    certificates = _json(root / "artifact/results/deep_locked/proof_carrying_witness_certificates.json")
    cert_by_fixture = {str(c.get("fixture_id", "")): str(c.get("issue", "")) for c in certificates}
    fixtures = _json(root / "artifact/data/deep_locked_fixtures.json")
    role_by_id = {str(f.get("id", "")): str(f.get("fixture_role", "")) for f in fixtures}
    policy_by_id = {str(f.get("id", "")): str(f.get("policy_family", "")) for f in fixtures}

    out: List[Dict[str, Any]] = []
    problems: List[Dict[str, Any]] = []
    by_suite = Counter()
    by_issue = Counter()
    positive_cert_checks = 0
    for row in rows:
        expected = _norm(row.get("expected", ""))
        declarative = _norm(row.get("declarative", ""))
        operational = _norm(row.get("operational", ""))
        case_id = str(row.get("case_id", ""))
        suite = str(row.get("suite", ""))
        certificate_issue = cert_by_fixture.get(case_id, "")
        certificate_equivalent = True
        if suite == "BEP-Deep" and expected and role_by_id.get(case_id) == "positive":
            positive_cert_checks += 1
            certificate_equivalent = certificate_issue in expected
        ok = expected == declarative == operational and certificate_equivalent and str(row.get("status")) == "pass"
        issue = expected[0] if expected else "none"
        by_suite[suite] += 1
        by_issue[issue] += 1
        rec = {
            "suite": suite,
            "case_id": case_id,
            "policy_family": policy_by_id.get(case_id, "specbench" if suite == "BEP-SpecBench" else ""),
            "expected": json.dumps(list(expected), sort_keys=True),
            "declarative": json.dumps(list(declarative), sort_keys=True),
            "operational": json.dumps(list(operational), sort_keys=True),
            "certificate_issue": certificate_issue,
            "certificate_equivalent": certificate_equivalent,
            "oracle_explanation_equivalent": ok,
            "status": "pass" if ok else "fail",
        }
        out.append(rec)
        if not ok:
            problems.append(rec)
    return out, {
        "schema": "BEPGuardOracleExplanationEquivalence/v1",
        "status": "pass" if not problems else "fail",
        "problem_count": len(problems),
        "problems": problems[:25],
        "cases_checked": len(rows),
        "bep_deep_cases": by_suite.get("BEP-Deep", 0),
        "specbench_cases": by_suite.get("BEP-SpecBench", 0),
        "positive_certificate_crosschecks": positive_cert_checks,
        "issue_signatures_checked": len(by_issue),
        "mismatches": len(problems),
        "interpretation": "Oracle explanation-equivalence audit: expected, operational, and label-free declarative issue signatures must agree on every locked and SpecBench case; locked positive cases must also match their proof-carrying certificate issue.",
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
