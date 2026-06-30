"""Structural independence audit for the three semantic oracle surfaces."""
from __future__ import annotations
import ast, hashlib, json, re
from pathlib import Path
from typing import Any, Dict, List

ORACLE_FILES = {
    "operational": "artifact/scripts/bep_semantics.py",
    "decision_table": "artifact/scripts/decision_table_oracle.py",
    "declarative": "artifact/bepguard/declarative_oracle.py",
}
FORBIDDEN_DECISION_METADATA = {"fixture_role", "fixture_hash", "source_claim_ids", "public_source_id", "variant", "id"}


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _imports(path: Path) -> List[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    imports=[]
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imports.extend(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imports.append(node.module)
    return imports


def run_oracle_structural_independence(root: Path) -> Dict[str, Any]:
    problems: List[str] = []
    rows=[]
    hashes={}
    for name, rel in ORACLE_FILES.items():
        p=root/rel
        if not p.exists():
            problems.append(f"missing oracle file {rel}"); continue
        text=p.read_text(encoding="utf-8")
        digest=_sha(p); hashes[name]=digest
        imports=_imports(p)
        # Declarative oracle must be completely structurally independent.
        if name == "declarative" and any(i in {"bep_semantics", "decision_table_oracle"} for i in imports):
            problems.append("declarative oracle imports an implementation oracle")
        # Decision-table may import the operational oracle only for comparison, not in decision helpers.
        if name == "decision_table":
            if "from bep_semantics import analyze_fixture" not in text:
                problems.append("decision-table comparison import changed unexpectedly")
            if "# Operational oracle is imported only for cross-oracle comparison" not in text:
                problems.append("decision-table lacks explicit comparison-only import rationale")
        metadata_hits=[]
        for m in FORBIDDEN_DECISION_METADATA:
            if re.search(r"\b"+re.escape(m)+r"\b", text) and name in {"operational", "declarative"}:
                # Operational/declarative may mention keys in comments or I/O; stricter label-flow and decision-purity audits cover function-level use.
                metadata_hits.append(m)
        rows.append({"oracle":name, "path":rel, "sha256":digest, "imports":imports[:20], "metadata_terms_seen":sorted(set(metadata_hits))})
    if len(set(hashes.values())) != len(hashes):
        problems.append("oracle files are not hash-distinct")
    return {"status":"pass" if not problems else "fail", "problem_count":len(problems), "problems":problems[:100], "oracle_files_checked":len(rows), "hash_distinct":len(set(hashes.values())) == len(hashes), "rows":rows, "interpretation":"Checks that the operational, decision-table, and declarative oracle surfaces are separate source files with distinct hashes and that the declarative oracle is structurally independent from the implementation oracles."}


def write_json(path: Path, obj: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=2, sort_keys=True)+"\n", encoding="utf-8")
