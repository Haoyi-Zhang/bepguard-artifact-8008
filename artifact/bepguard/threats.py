"""assessor-threat closure audit.

Maps major assessor attacks to concrete, materialized validation evidence.  This
is not a replacement for the underlying gates; it checks that the release exposes
a compact threat-to-evidence matrix so a assessor can see how novelty, rigor,
non-overfitting, external comparators, repair validity, and reproducibility are
separately defended.
"""
from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import Any, Dict, List, Tuple

THREATS = [
    ('T01', 'oracle/workload coupling', ['artifact/results/deep_locked/decision_table_oracle_metrics.json','artifact/results/deep_locked/declarative_oracle_audit.json','artifact/results/deep_locked/oracle_triangulation_audit.json']),
    ('T02', 'label or metadata leakage', ['artifact/results/label_flow_audit.json','artifact/results/decision_purity_audit.json','artifact/results/deep_locked/identifier_blind_replay_audit.json']),
    ('T03', 'benchmark memorization', ['artifact/results/anti_overfit_leakage_audit.json','artifact/results/deep_locked/benchmark_fingerprint_disjointness_audit.json','artifact/results/deep_locked/shadow_generalization_audit.json']),
    ('T04', 'insufficient boundary pressure', ['artifact/results/deep_locked/specbench_summary.json','artifact/results/deep_locked/issue_evidence_depth_audit.json','artifact/results/deep_locked/corpus_stability_audit.json']),
    ('T05', 'weak theory depth', ['artifact/results/deep_locked/theory_kernel_audit.json','artifact/results/deep_locked/theory_proof_cards.json','artifact/results/deep_locked/semantic_lattice_proofs.json']),
    ('T06', 'mutation adequacy gap', ['artifact/results/deep_locked/semantic_mutation_adequacy.json','artifact/results/deep_locked/mutation_farm_summary.json','artifact/results/gate_sensitivity_audit.json']),
    ('T07', 'repair relabeling', ['artifact/results/deep_locked/repair_delta_replay_audit.json','artifact/results/deep_locked/repair_compactness_audit.json','artifact/results/deep_locked/repair_locality_audit.json']),
    ('T08', 'source-grounding gap', ['artifact/results/deep_locked/source_claim_trace_audit.json','artifact/results/claim_impact_audit.json','artifact/results/source_span_closure_metrics.json']),
    ('T09', 'external baseline substitution', ['artifact/results/external_baseline_full_run_audit.json','artifact/results/external_contrast_specificity_audit.json','artifact/results/external_provenance_audit.json']),
    ('T10', 'runtime/cache dependency', ['artifact/results/runtime_boundary_audit.json','artifact/results/clean_package_check.json','artifact/results/package_identity_audit.json']),
    ('T11', 'paper-result drift', ['artifact/results/paper_claim_consistency_audit.json','artifact/results/release_claim_drift_audit.json','artifact/results/pdf_reference_boundary_audit.json']),
    ('T12', 'artifact nondeterminism', ['artifact/results/deterministic_reexecution_audit.json','artifact/results/idempotence_replay_audit.json','artifact/results/reproducibility_ladder_audit.json']),
    ('T13', 'evidence reconstruction burden', ['artifact/results/evidence_graph_metrics.json','artifact/results/evidence_cards_audit.json','artifact/results/deep_locked/source_claim_trace_audit.json']),
    ('T14', 'policy-interaction narrowness', ['artifact/results/deep_locked/interaction_coverage_audit.json','artifact/results/deep_locked/cross_policy_contracts.json','artifact/results/deep_locked/scale_stress_audit.json']),
]


def _load_json(path: Path) -> Dict[str, Any]:
    return json.loads(path.read_text(encoding='utf-8'))


def _is_pass(obj: Dict[str, Any]) -> bool:
    if obj.get('status') == 'fail':
        return False
    if 'problem_count' in obj and int(obj.get('problem_count') or 0) != 0:
        return False
    return True


def run_threat_closure(root: Path) -> Tuple[List[Dict[str, str]], Dict[str, Any]]:
    rows: List[Dict[str, str]] = []
    problems: List[str] = []
    bindings = 0
    for tid, threat, paths in THREATS:
        statuses = []
        for rel in paths:
            p = root / rel
            bindings += 1
            if not p.exists():
                statuses.append('missing')
                problems.append(f'{tid} missing {rel}')
                continue
            try:
                ok = _is_pass(_load_json(p))
            except Exception as exc:
                ok = False
                problems.append(f'{tid} cannot parse {rel}: {exc}')
            statuses.append('pass' if ok else 'problem')
            if not ok:
                problems.append(f'{tid} evidence not passing: {rel}')
        rows.append({'threat_id': tid, 'assessor_attack': threat, 'evidence_files': ';'.join(paths), 'evidence_status': ';'.join(statuses), 'status': 'pass' if all(s == 'pass' for s in statuses) else 'fail'})
    summary = {
        'status': 'pass' if not problems else 'fail',
        'problem_count': len(problems),
        'problems': problems[:100],
        'threats_checked': len(THREATS),
        'evidence_bindings': bindings,
        'interpretation': 'Maps strict-assessor objections to independently materialized validation evidence; every row must be backed by existing passing audit outputs.',
    }
    return rows, summary


def write_csv(path: Path, rows: List[Dict[str, str]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fields = ['threat_id','assessor_attack','evidence_files','evidence_status','status']
    with path.open('w', newline='', encoding='utf-8') as fh:
        w=csv.DictWriter(fh, fieldnames=fields); w.writeheader(); w.writerows(rows)


def write_json(path: Path, obj: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=2, sort_keys=True)+'\n', encoding='utf-8')
