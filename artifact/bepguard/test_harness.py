"""Dependency-free executable test harness for generated BEPGuard tests."""
from __future__ import annotations

import ast
import importlib
import inspect
import json
import pkgutil
import sys
from pathlib import Path
from typing import Any, Dict, List

sys.dont_write_bytecode = True


def _compile_python_files(root: Path) -> tuple[int, List[str]]:
    problems: List[str] = []
    count = 0
    for rel_root in ["artifact/bepguard", "artifact/scripts", "artifact/tests"]:
        base = root / rel_root
        for path in sorted(base.rglob("*.py")):
            if "__pycache__" in path.parts:
                continue
            count += 1
            try:
                source = path.read_text(encoding="utf-8")
                compile(source, str(path.relative_to(root)), "exec")
                ast.parse(source, filename=str(path.relative_to(root)))
            except Exception as exc:  # pragma: no cover - reported in audit output
                problems.append(f"{path.relative_to(root)}: {exc}")
    return count, problems


def _import_bepguard_modules(root: Path) -> tuple[int, List[str]]:
    problems: List[str] = []
    imported = 0
    artifact_root = root / "artifact"
    if str(artifact_root) not in sys.path:
        sys.path.insert(0, str(artifact_root))
    import bepguard  # type: ignore

    for mod in sorted(pkgutil.iter_modules(bepguard.__path__), key=lambda m: m.name):
        name = "bepguard." + mod.name
        try:
            importlib.import_module(name)
            imported += 1
        except Exception as exc:  # pragma: no cover - reported in audit output
            problems.append(f"{name}: {exc!r}")
    return imported, problems


def _discover_test_modules(root: Path) -> List[str]:
    artifact_root = root / "artifact"
    if str(artifact_root) not in sys.path:
        sys.path.insert(0, str(artifact_root))
    import tests  # type: ignore

    modules: List[str] = []
    for mod in sorted(pkgutil.iter_modules(tests.__path__), key=lambda m: m.name):
        if mod.name.startswith("test_"):
            modules.append(f"tests.{mod.name}")
    return modules


def _requires_pytest_fixture(fn: Any) -> bool:
    signature = inspect.signature(fn)
    for parameter in signature.parameters.values():
        if parameter.default is not inspect._empty:
            continue
        if parameter.kind in (parameter.VAR_POSITIONAL, parameter.VAR_KEYWORD):
            continue
        return True
    return False


def _run_generated_tests(root: Path) -> tuple[int, List[str], Dict[str, int], List[str]]:
    problems: List[str] = []
    skipped: List[str] = []
    executed = 0
    by_module: Dict[str, int] = {}
    for module_name in _discover_test_modules(root):
        module = importlib.import_module(module_name)
        count = 0
        for name, fn in sorted(inspect.getmembers(module, inspect.isfunction)):
            if not name.startswith("test_"):
                continue
            full_name = f"{module_name}.{name}"
            if _requires_pytest_fixture(fn):
                skipped.append(full_name)
                continue
            try:
                fn()
                executed += 1
                count += 1
            except Exception as exc:  # pragma: no cover - reported in audit output
                problems.append(f"{full_name}: {exc!r}")
        by_module[module_name] = count
    return executed, problems, by_module, skipped


def run_test_harness(root: Path) -> Dict[str, Any]:
    compiled, compile_problems = _compile_python_files(root)
    imported, import_problems = _import_bepguard_modules(root)
    executed, test_problems, by_module, skipped_tests = _run_generated_tests(root)
    problems = compile_problems + import_problems + test_problems
    return {
        "schema": "BEPGuardDependencyFreeTestHarness/v1",
        "status": "pass" if not problems else "fail",
        "problem_count": len(problems),
        "problems": problems[:80],
        "python_files_compiled": compiled,
        "bepguard_modules_imported": imported,
        "generated_tests_executed": executed,
        "generated_tests_by_module": by_module,
        "skipped_pytest_style_tests": skipped_tests,
        "skipped_pytest_style_test_count": len(skipped_tests),
        "pytest_dependency_required": False,
        "interpretation": "Executes generated fixture and certificate tests without requiring pytest. This validates that the assessor can run the test surface with the Python standard library plus the released artifact package.",
    }


def write_json(path: Path, obj: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=2, sort_keys=True) + "\n", encoding="utf-8")