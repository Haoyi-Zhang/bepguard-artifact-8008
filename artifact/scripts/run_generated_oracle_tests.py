#!/usr/bin/env python3
"""Run generated oracle tests without depending on pytest.

The generated tests provide one executable function for every locked fixture and
positive proof-carrying certificate.  This runner imports the test modules,
executes all functions whose names start with ``test_``, and writes a stable JSON
summary.  It avoids external test-framework dependencies so the artifact remains
CPU-native and standard-library-only.
"""
from __future__ import annotations

import argparse
import importlib
import json
import sys
from pathlib import Path
from types import ModuleType
from typing import Callable, Dict, List, Tuple

sys.dont_write_bytecode = True

from common_paths import package_root

TEST_MODULES = [
    "tests.test_locked_fixtures_generated",
    "tests.test_witness_certificates_generated",
]


def load_module(name: str, root: Path) -> ModuleType:
    artifact_root = root / "artifact"
    if str(artifact_root) not in sys.path:
        sys.path.insert(0, str(artifact_root))
    return importlib.import_module(name)


def iter_tests(module: ModuleType) -> List[Tuple[str, Callable[[], None]]]:
    tests: List[Tuple[str, Callable[[], None]]] = []
    for name in sorted(dir(module)):
        if not name.startswith("test_"):
            continue
        fn = getattr(module, name)
        if callable(fn):
            tests.append((f"{module.__name__}.{name}", fn))
    return tests


def main() -> None:
    parser = argparse.ArgumentParser(description="Run generated BEP oracle tests.")
    parser.add_argument("--root", default=None)
    parser.add_argument("--out", default="artifact/results/generated_oracle_tests.json")
    args = parser.parse_args()
    root = Path(args.root).resolve() if args.root else package_root(__file__)
    failures: List[Dict[str, str]] = []
    tests_run = 0
    modules_loaded: List[str] = []
    for module_name in TEST_MODULES:
        module = load_module(module_name, root)
        modules_loaded.append(module_name)
        for test_name, fn in iter_tests(module):
            tests_run += 1
            try:
                fn()
            except Exception as exc:
                failures.append({"test": test_name, "error": repr(exc)})
    result = {
        "status": "pass" if not failures else "fail",
        "problem_count": len(failures),
        "tests_run": tests_run,
        "modules_loaded": modules_loaded,
        "failures": failures[:100],
        "interpretation": "Generated oracle tests over every locked fixture and every proof-carrying positive witness certificate; no pytest or external service dependency.",
    }
    out = root / args.out
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({"status": result["status"], "tests_run": tests_run, "problem_count": len(failures)}, sort_keys=True))
    if failures:
        raise SystemExit(2)


if __name__ == "__main__":
    main()
