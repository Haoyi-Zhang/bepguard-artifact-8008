"""Contribution-to-result trace audit for assessor-first paper claims."""
from __future__ import annotations
import json
from pathlib import Path
from typing import Any, Dict, List

CONTRIBUTIONS = [
    {"id":"C1", "name":"BEP-IR and source-grounded lowering", "tokens":["BEP-IR", "45 explicit claims", "35 semantic rules"], "evidence":["artifact/results/deep_locked/source_claim_trace_audit.json", "artifact/results/claim_impact_audit.json"]},
    {"id":"C2", "name":"minimal proof-carrying semantic witnesses", "tokens":["minimal semantic conflict witnesses", "proof-carrying"], "evidence":["artifact/results/deep_locked/proof_carrying_witness_metrics.json", "artifact/results/evidence_path_multiplicity_audit.json"]},
    {"id":"C3", "name":"repair-paired counterfactual controls", "tokens":["repair-paired", "counterfactual repair"], "evidence":["artifact/results/deep_locked/repair_compactness_audit.json", "artifact/results/deep_locked/repair_delta_replay_audit.json"]},
    {"id":"C4", "name":"multi-oracle, mutation-adequate validation", "tokens":["declarative third oracle", "600/600", "finite theorem kernel"], "evidence":["artifact/results/deep_locked/declarative_oracle_audit.json", "artifact/results/deep_locked/mutation_farm_summary.json", "artifact/results/deep_locked/theory_kernel_audit.json"]},
]


def run_contribution_trace(root: Path) -> Dict[str, Any]:
    problems: List[str] = []
    tex = (root/"paper/main.tex").read_text(encoding="utf-8")
    rows=[]
    for c in CONTRIBUTIONS:
        missing=[t for t in c["tokens"] if t not in tex]
        bad=[]
        for rel in c["evidence"]:
            p=root/rel
            if not p.exists():
                bad.append(f"missing {rel}")
            else:
                obj=json.loads(p.read_text(encoding="utf-8"))
                if obj.get("status") == "fail" or int(obj.get("problem_count") or 0) != 0:
                    bad.append(f"not passing {rel}")
        if missing or bad:
            problems.append(f"{c['id']}: missing_tokens={missing}, evidence={bad}")
        rows.append({"contribution_id":c["id"], "name":c["name"], "paper_tokens_verified":len(c["tokens"])-len(missing), "evidence_files_verified":len(c["evidence"])-len(bad)})
    return {"status":"pass" if not problems else "fail", "problem_count":len(problems), "problems":problems[:100], "contributions_checked":len(CONTRIBUTIONS), "evidence_files_checked":sum(len(c["evidence"]) for c in CONTRIBUTIONS), "rows":rows, "interpretation":"Checks that each stated paper contribution is visible in the main text and backed by materialized passing evidence rather than only by repository prose."}


def write_json(path: Path, obj: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=2, sort_keys=True)+"\n", encoding="utf-8")
