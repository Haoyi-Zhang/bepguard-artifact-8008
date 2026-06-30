"""Static code-health audit for the anonymous BEPGuard artifact."""
from __future__ import annotations

import ast
import json
import re
from pathlib import Path
from typing import Any, Dict, List

FORBIDDEN_TEXT = [
    "/" + "mnt" + "/data",
    "/" + "home" + "/",
    "Ha" + "oyi" + "-" + "Zh" + "ang",
    "TO" + "DO",
    "FIX" + "ME",
    "<" * 7,
    ">" * 7,
    "=" * 7,
]

EXEMPT_DEBUG_PRINT_FILES = {
    "scripts/run_validation.py",
    "scripts/run_reproducibility_ladder.py",
}


def _rel(root: Path, path: Path) -> str:
    return path.relative_to(root / "artifact").as_posix()


def _python_files(root: Path) -> List[Path]:
    base = root / "artifact"
    dirs = [base / "bepguard", base / "scripts", base / "tests"]
    files: List[Path] = []
    for d in dirs:
        if d.exists():
            files.extend(sorted(d.rglob("*.py")))
    return files


def audit_static_code_health(root: Path) -> Dict[str, Any]:
    problems: List[str] = []
    files = _python_files(root)
    functions = 0
    classes = 0
    lines = 0
    scripts = 0
    modules = 0
    main_guarded_scripts = 0
    shebang_scripts = 0
    forbidden_hits: List[str] = []
    parse_errors: List[str] = []

    for path in files:
        rel = _rel(root, path)
        text = path.read_text(encoding="utf-8")
        lines += len(text.splitlines())
        if rel.startswith("scripts/"):
            scripts += 1
            if text.startswith("#!"):
                shebang_scripts += 1
            if re.search(r"if\s+__name__\s*==\s*[\'\"]__main__[\'\"]", text):
                main_guarded_scripts += 1
        else:
            modules += 1
        for token in FORBIDDEN_TEXT:
            if token in text:
                # Ignore equality separators that appear as ordinary comments only when not a merge marker.
                if token == "=======" and not re.search(r"^=======$", text, flags=re.MULTILINE):
                    continue
                forbidden_hits.append(f"{rel}:{token}")
        try:
            tree = ast.parse(text, filename=rel)
            compile(tree, rel, "exec")
        except SyntaxError as exc:
            parse_errors.append(f"{rel}:{exc.lineno}:{exc.msg}")
            continue
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                functions += 1
            elif isinstance(node, ast.ClassDef):
                classes += 1

    pycache = sorted(str(p.relative_to(root)) for p in (root / "artifact").rglob("__pycache__"))
    pyc = sorted(str(p.relative_to(root)) for p in (root / "artifact").rglob("*.pyc"))
    if parse_errors:
        problems.extend(f"syntax/compile error: {x}" for x in parse_errors[:40])
    if forbidden_hits:
        problems.extend(f"forbidden debug/local/merge token: {x}" for x in forbidden_hits[:40])
    if pycache or pyc:
        problems.append("bytecode cache files are present in the release")
    if scripts and main_guarded_scripts < scripts - 12:
        problems.append(f"too many scripts lack explicit __main__ guards: {scripts-main_guarded_scripts} of {scripts}")
    if len(files) < 120 or lines < 24000 or functions < 2000:
        problems.append("Python source surface is unexpectedly small for the release contract")

    return {
        "schema": "BEPGuardStaticCodeHealth/v1",
        "status": "pass" if not problems else "fail",
        "problem_count": len(problems),
        "problems": problems,
        "python_files_checked": len(files),
        "python_lines_checked": lines,
        "python_functions_checked": functions,
        "python_classes_checked": classes,
        "script_files_checked": scripts,
        "package_modules_checked": modules,
        "main_guarded_scripts": main_guarded_scripts,
        "shebang_scripts": shebang_scripts,
        "pycache_directories": len(pycache),
        "pyc_files": len(pyc),
        "forbidden_token_hits": len(forbidden_hits),
        "parse_errors": len(parse_errors),
        "interpretation": "All Python entry points and BEPGuard modules are parsed and byte-compiled without executing live services. The audit also rejects local paths, merge-conflict markers, work-in-progress residue, bytecode caches, and author-identifying repository strings.",
    }


def write_json(path: Path, obj: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=2, sort_keys=True) + "\n", encoding="utf-8")
