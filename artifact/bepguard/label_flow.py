"""Static label-flow audit for semantic decision code."""
from __future__ import annotations

import ast
import json
import sys
from pathlib import Path
from typing import Any, Dict, Iterable, List

sys.dont_write_bytecode = True

# Files whose decision procedures should not consult ground-truth labels,
# fixture roles, certificates, or source identifiers.  Validation/audit scripts
# may compare against labels; these semantic kernels may not.
PURE_DECISION_FILES = [
    "artifact/scripts/bep_semantics.py",
    "artifact/bepguard/declarative_oracle.py",
]

FORBIDDEN_GET_KEYS = {
    "expected_issue",
    "fixture_role",
    "locked_status",
    "mutation_parent",
    "mutation_operator",
    "source_claim_ids",
    "public_source_id",
    "fixture_hash",
    "certificate_id",
    "paired_positive_fixture_id",
}

PERMITTED_ID_CONTEXTS = {"id"}


def _constant_string(node: ast.AST) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def _scan_path(path: Path) -> List[Dict[str, Any]]:
    src = path.read_text(encoding="utf-8")
    tree = ast.parse(src, filename=str(path))
    problems: List[Dict[str, Any]] = []
    for node in ast.walk(tree):
        # fixture.get("expected_issue") style access.
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "get" and node.args:
            key = _constant_string(node.args[0])
            if key in FORBIDDEN_GET_KEYS:
                problems.append({"line": getattr(node, "lineno", 0), "kind": "get", "key": key})
        # fixture["expected_issue"] style access.
        if isinstance(node, ast.Subscript):
            key = None
            if isinstance(node.slice, ast.Constant) and isinstance(node.slice.value, str):
                key = node.slice.value
            if key in FORBIDDEN_GET_KEYS:
                problems.append({"line": getattr(node, "lineno", 0), "kind": "subscript", "key": key})
    return problems


def audit_label_flow(root: Path) -> Dict[str, Any]:
    problems: List[str] = []
    file_reports: List[Dict[str, Any]] = []
    for rel in PURE_DECISION_FILES:
        path = root / rel
        if not path.exists():
            problems.append(f"missing pure-decision file: {rel}")
            continue
        hits = _scan_path(path)
        file_reports.append({"path": rel, "forbidden_label_accesses": hits, "problem_count": len(hits)})
        for hit in hits:
            problems.append(f"{rel}:{hit['line']} reads {hit['key']}")
    return {
        "status": "pass" if not problems else "fail",
        "problem_count": len(problems),
        "problems": problems,
        "pure_decision_files_checked": len(file_reports),
        "forbidden_keys_guarded": sorted(FORBIDDEN_GET_KEYS),
        "file_reports": file_reports,
        "interpretation": "Static label-flow separation audit: core semantic decision procedures may inspect headers, layers, contexts, and intent classes, but not benchmark labels, roles, source IDs, fixture hashes, or certificates. This prevents ground-truth labels from entering the oracle path.",
    }


def write_json(path: Path, obj: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=2, sort_keys=True) + "\n", encoding="utf-8")
