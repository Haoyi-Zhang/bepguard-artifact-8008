"""AST-level purity audit for policy-decision code.

The existing label-flow audit checks selected pure decision files.  This module
widens the check to all functions that constitute the semantic decision surface:
operational semantics, decision-table oracle, declarative oracle, and BEPGuard
IR/proof/benchmark replay helpers.  Test and audit drivers may read labels to
compare results; pure decision functions may not read labels, fixture roles,
source IDs, hashes, or certificate IDs to decide an issue.
"""
from __future__ import annotations

import ast
import json
from pathlib import Path
from typing import Any, Dict, List, Set

FORBIDDEN_KEYS: Set[str] = {
    "expected_issue",
    "fixture_role",
    "source_claim_ids",
    "public_source_id",
    "fixture_hash",
    "certificate_id",
    "paired_repair_control_id",
    "source_id",
}
PURE_FILES = [
    "artifact/scripts/bep_semantics.py",
    "artifact/scripts/decision_table_oracle.py",
    "artifact/bepguard/declarative_oracle.py",
    "artifact/bepguard/corpus_stability.py",
]
ALLOWED_FUNCTIONS = {
    "main",
    "load",
    "expected_from_fixture",
    "write_json",
    "write_csv",
    "run_corpus_stability_audit",  # compares outcomes after calling pure semantics
    "_load_fixtures",
}


def _literal(node: ast.AST) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def _function_uses_forbidden_key(fn: ast.FunctionDef) -> List[str]:
    hits: List[str] = []
    for node in ast.walk(fn):
        # x.get("expected_issue") or x["expected_issue"]
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "get":
            if node.args:
                val = _literal(node.args[0])
                if val in FORBIDDEN_KEYS:
                    hits.append(f"line {node.lineno}: get({val})")
        if isinstance(node, ast.Subscript):
            val = _literal(node.slice)  # py>=3.9
            if val in FORBIDDEN_KEYS:
                hits.append(f"line {node.lineno}: subscript[{val}]")
        if isinstance(node, ast.Constant) and isinstance(node.value, str) and node.value in FORBIDDEN_KEYS:
            # Count free string constants in decision functions even if not used as get/subscript.
            hits.append(f"line {node.lineno}: literal {node.value}")
    return sorted(set(hits))


def audit_decision_purity(root: Path) -> Dict[str, Any]:
    problems: List[str] = []
    function_count = 0
    file_count = 0
    checked_functions: List[str] = []
    for rel in PURE_FILES:
        path = root / rel
        if not path.exists():
            problems.append(f"missing pure decision file: {rel}")
            continue
        file_count += 1
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=rel)
        except SyntaxError as exc:
            problems.append(f"{rel}: not parseable: {exc}")
            continue
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef):
                if node.name in ALLOWED_FUNCTIONS or node.name.startswith("write_"):
                    continue
                function_count += 1
                checked_functions.append(f"{rel}:{node.name}")
                hits = _function_uses_forbidden_key(node)
                if hits:
                    problems.append(f"{rel}:{node.name}: forbidden metadata access {hits[:6]}")
    result = {
        "status": "pass" if not problems else "fail",
        "problem_count": len(problems),
        "problems": problems[:80],
        "pure_files_checked": file_count,
        "pure_decision_functions_checked": function_count,
        "forbidden_metadata_keys": sorted(FORBIDDEN_KEYS),
        "checked_functions": checked_functions,
        "interpretation": "Pure policy-decision functions are checked for AST-level access to labels, fixture roles, source identifiers, hashes, and certificate identifiers.  Driver functions may use labels only to compare already-computed issue sets.",
    }
    return result


def write_json(path: Path, obj: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=2, sort_keys=True) + "\n", encoding="utf-8")
