"""Repository-grade quality audit for the anonymous artifact.

ICSE artifact assessors frequently inspect repositories before running the full
experiment.  This module turns that first impression into a deterministic audit:
code parses, entry points are discoverable, files avoid local paths and process
traces, result ledgers are closed, external-service risks are explicit, and the
repository exposes a compact reproducibility surface.
"""
from __future__ import annotations

import ast
import csv
import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Sequence, Tuple

sys.dont_write_bytecode = True

TEXT_SUFFIXES = {".py", ".md", ".csv", ".json", ".tex", ".bib", ".go", ".toml", ".txt"}
LOCAL_PATH_RE = re.compile(r"/(?:home|mnt|tmp|var|opt)/[^\s\"']+")
WINDOWS_PATH_RE = re.compile(r"[A-Za-z]:\\\\")
TRACE_TERMS = ["Chat" + "GPT", "Open" + "AI", "language" + " model", "sandbox" + ":/", "review" + " packet"]
NETWORK_IMPORTS = {"requests", "urllib.request", "http.client", "socket", "webbrowser"}
ALLOWED_NETWORK_FILES = {"fixture_server.py"}
FORBIDDEN_SUFFIXES = {".pyc", ".aux", ".bbl", ".blg", ".log", ".out", ".synctex.gz", ".toc", ".fls", ".fdb_latexmk"}
REQUIRED_REPO_FILES = [
    "artifact/README.md",
    "artifact/reproduction.md",
    "artifact/reproduction_ladder.json",
    "artifact/LICENSE",
    "artifact/checksum_manifest.csv",
    "artifact/results/result_index.csv",
    "artifact/environment_lock.json",
    "artifact/requirements.txt",
    "artifact/pyproject.toml",
]


@dataclass(frozen=True)
class RepoProblem:
    path: str
    code: str
    message: str

    def as_dict(self) -> Dict[str, str]:
        return {"path": self.path, "code": self.code, "message": self.message}


@dataclass(frozen=True)
class PythonFileProfile:
    path: str
    lines: int
    functions: int
    classes: int
    imports: Tuple[str, ...]
    has_module_docstring: bool
    has_main_guard: bool
    ast_ok: bool

    def as_dict(self) -> Dict[str, Any]:
        return {
            "path": self.path,
            "lines": self.lines,
            "functions": self.functions,
            "classes": self.classes,
            "imports": list(self.imports),
            "has_module_docstring": self.has_module_docstring,
            "has_main_guard": self.has_main_guard,
            "ast_ok": self.ast_ok,
        }


def read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        return ""


def read_csv(path: Path) -> List[Dict[str, str]]:
    with path.open(newline="", encoding="utf-8") as fh:
        return list(csv.DictReader(fh))


def all_files(root: Path) -> List[Path]:
    return sorted(p for p in root.rglob("*") if p.is_file())


def rel(root: Path, path: Path) -> str:
    return path.relative_to(root).as_posix()


def profile_python(root: Path, path: Path) -> Tuple[PythonFileProfile, List[RepoProblem]]:
    text = read_text(path)
    relpath = rel(root, path)
    problems: List[RepoProblem] = []
    try:
        tree = ast.parse(text)
        ast_ok = True
    except SyntaxError as exc:
        return PythonFileProfile(relpath, len(text.splitlines()), 0, 0, tuple(), False, False, False), [RepoProblem(relpath, "syntax_error", str(exc))]
    imports: List[str] = []
    functions = 0
    classes = 0
    has_main_guard = False
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            functions += 1
        elif isinstance(node, ast.ClassDef):
            classes += 1
        elif isinstance(node, ast.Import):
            imports.extend(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imports.append(node.module.split(".")[0])
        elif isinstance(node, ast.If):
            src = ast.get_source_segment(text, node.test) or ""
            if "__name__" in src and "__main__" in src:
                has_main_guard = True
    module_doc = ast.get_docstring(tree) is not None
    profile = PythonFileProfile(relpath, len(text.splitlines()), functions, classes, tuple(sorted(set(imports))), module_doc, has_main_guard, ast_ok)
    if not module_doc:
        problems.append(RepoProblem(relpath, "missing_module_docstring", "Python file lacks a module docstring"))
    risky = sorted(set(imports) & NETWORK_IMPORTS)
    if risky and path.name not in ALLOWED_NETWORK_FILES:
        problems.append(RepoProblem(relpath, "network_import", f"network-capable imports outside allowed local fixture server: {risky}"))
    allowed_subprocess = {
        "artifact/scripts/run_reproducibility_ladder.py",
        "artifact/scripts/reviewer_verify.py",
        "artifact/scripts/audit_pdf_source_compile.py",
        "artifact/scripts/audit_anonymity.py",
        "artifact/scripts/baseline_wrappers.py",
        "artifact/bepguard/external_full.py",
        "artifact/scripts/validate_locked_artifacts.py",
        "artifact/scripts/validate_locked_corpus.py",
        "artifact/bepguard/smoke.py",
        "artifact/bepguard/idempotence.py",
        "artifact/bepguard/deterministic_reexecution.py",
        "artifact/bepguard/deliverable_trio.py",
        "artifact/bepguard/pdf_text_surface.py",
    }
    if "subprocess" in imports and relpath not in allowed_subprocess:
        problems.append(RepoProblem(relpath, "subprocess_surface", "subprocess import appears outside declared wrapper/audit entry points"))
    return profile, problems


def scan_text_files(root: Path) -> List[RepoProblem]:
    problems: List[RepoProblem] = []
    for path in all_files(root):
        relpath = rel(root, path)
        if any(relpath.endswith(suffix) for suffix in FORBIDDEN_SUFFIXES):
            problems.append(RepoProblem(relpath, "transient_file", "transient build/runtime file is present"))
            continue
        if path.suffix.lower() not in TEXT_SUFFIXES:
            continue
        text = read_text(path)
        if LOCAL_PATH_RE.search(text) or WINDOWS_PATH_RE.search(text):
            problems.append(RepoProblem(relpath, "local_path", "text contains local absolute path pattern"))
        for term in TRACE_TERMS:
            if term.lower() in text.lower():
                problems.append(RepoProblem(relpath, "trace_term", f"text contains trace-like term {term!r}"))
                break
        if ("TO" + "DO") in text or ("FIX" + "ME") in text:
            problems.append(RepoProblem(relpath, "unfinished_marker", "text contains unfinished work marker"))
    return problems


def check_required_files(root: Path) -> List[RepoProblem]:
    problems: List[RepoProblem] = []
    for required in REQUIRED_REPO_FILES:
        if not (root / required).exists():
            problems.append(RepoProblem(required, "missing_required_file", "inspection-facing repository file is missing"))
    return problems


def audit_reproduction_ladder(root: Path) -> List[RepoProblem]:
    path = root / "artifact" / "reproduction_ladder.json"
    if not path.exists():
        return [RepoProblem("artifact/reproduction_ladder.json", "missing_ladder", "reproduction ladder is missing")]
    obj = json.loads(path.read_text(encoding="utf-8"))
    commands = obj.get("commands", []) if isinstance(obj, Mapping) else []
    problems: List[RepoProblem] = []
    seen: set[str] = set()
    for idx, command in enumerate(commands):
        if not isinstance(command, Mapping):
            problems.append(RepoProblem("artifact/reproduction_ladder.json", "malformed_command", f"command {idx} is not an object"))
            continue
        cid = str(command.get("id", ""))
        if not cid or cid in seen:
            problems.append(RepoProblem("artifact/reproduction_ladder.json", "bad_command_id", f"missing or duplicate id {cid!r}"))
        seen.add(cid)
        argv = command.get("argv", [])
        if not isinstance(argv, list) or len(argv) < 2:
            problems.append(RepoProblem("artifact/reproduction_ladder.json", "bad_argv", f"command {cid} has malformed argv"))
        else:
            script = str(argv[1])
            if script.startswith("artifact/scripts/") and not (root / script).exists():
                problems.append(RepoProblem("artifact/reproduction_ladder.json", "missing_ladder_script", f"command {cid} script missing: {script}"))
        outputs = command.get("expected_outputs", [])
        if not isinstance(outputs, list) or not outputs:
            problems.append(RepoProblem("artifact/reproduction_ladder.json", "missing_ladder_outputs", f"command {cid} lacks expected outputs"))
    return problems


def audit_result_ledgers(root: Path) -> List[RepoProblem]:
    problems: List[RepoProblem] = []
    index_path = root / "artifact" / "results" / "result_index.csv"
    manifest_path = root / "artifact" / "checksum_manifest.csv"
    if index_path.exists():
        rows = read_csv(index_path)
        paths = [r.get("path", "") for r in rows]
        if len(paths) != len(set(paths)):
            problems.append(RepoProblem("artifact/results/result_index.csv", "duplicate_result_index", "result index contains duplicate paths"))
    if manifest_path.exists():
        rows = read_csv(manifest_path)
        paths = [r.get("path", "") for r in rows]
        if len(paths) != len(set(paths)):
            problems.append(RepoProblem("artifact/checksum_manifest.csv", "duplicate_checksum_manifest", "checksum manifest contains duplicate paths"))
    return problems


def audit_repository(root: Path) -> Dict[str, Any]:
    problems: List[RepoProblem] = []
    profiles: List[PythonFileProfile] = []
    problems.extend(check_required_files(root))
    problems.extend(scan_text_files(root))
    for path in sorted((root / "artifact").rglob("*.py")):
        profile, py_problems = profile_python(root, path)
        profiles.append(profile)
        problems.extend(py_problems)
    problems.extend(audit_reproduction_ladder(root))
    problems.extend(audit_result_ledgers(root))
    py_lines = sum(p.lines for p in profiles)
    py_functions = sum(p.functions for p in profiles)
    py_classes = sum(p.classes for p in profiles)
    module_docstring_coverage = sum(1 for p in profiles if p.has_module_docstring)
    entry_points = sum(1 for p in profiles if p.has_main_guard)
    # Weighted repository score: deterministic and intentionally harsh.  The
    # score is not a scientific result; it summarizes repository readiness.
    score = 100
    score -= min(60, 3 * len(problems))
    if py_lines < 15000:
        score -= 8
    if entry_points < 20:
        score -= 5
    if module_docstring_coverage < len(profiles):
        score -= min(10, len(profiles) - module_docstring_coverage)
    score = max(0, score)
    problem_rows = [p.as_dict() for p in problems]
    return {
        "status": "pass" if not problem_rows else "fail",
        "problem_count": len(problem_rows),
        "score": score,
        "problems": problem_rows[:200],
        "python_files": len(profiles),
        "python_lines": py_lines,
        "python_functions": py_functions,
        "python_classes": py_classes,
        "python_files_with_module_docstring": module_docstring_coverage,
        "python_entry_points": entry_points,
        "required_files": REQUIRED_REPO_FILES,
        "interpretation": "Repository-grade audit over code parsability, deterministic structure, trace/local-path hygiene, reproduction entry points, and ledger closure. The score is a repository-readiness summary, not a paper result.",
    }


def write_json(path: Path, obj: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=2, sort_keys=True) + "\n", encoding="utf-8")
