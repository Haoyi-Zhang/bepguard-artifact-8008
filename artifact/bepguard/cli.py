"""Command-line entry point for BEPGuard artifact audits."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from .evidence import build_graph, write_json, write_paths
from .leakage import audit as audit_leakage, write_json as write_leakage_json
from .smoke import execute as execute_smoke, write_json as write_smoke_json


def _root(anchor: Path | None = None) -> Path:
    start = (anchor or Path.cwd()).resolve()
    if start.is_file():
        start = start.parent
    for candidate in (start, *start.parents):
        if (candidate / "artifact").is_dir() and (candidate / "paper").is_dir():
            return candidate
    raise SystemExit(f"cannot locate release root from {start}")


def cmd_evidence(args: argparse.Namespace) -> int:
    root = _root(Path(args.root) if args.root else None)
    graph, metrics, paths = build_graph(root)
    write_json(root / args.graph_out, graph)
    write_json(root / args.metrics_out, metrics)
    write_paths(root / args.paths_out, paths)
    print(json.dumps({"status": metrics["status"], "problem_count": metrics["problem_count"], "positive_paths_verified": metrics["positive_paths_verified"]}, sort_keys=True))
    return 0 if metrics["status"] == "pass" else 1


def cmd_leakage(args: argparse.Namespace) -> int:
    root = _root(Path(args.root) if args.root else None)
    result = audit_leakage(root)
    write_leakage_json(root / args.out, result)
    print(json.dumps({"status": result["status"], "problem_count": result["problem_count"], "method_files_scanned": result["method_files_scanned"]}, sort_keys=True))
    return 0 if result["status"] == "pass" else 1


def cmd_smoke(args: argparse.Namespace) -> int:
    root = _root(Path(args.root) if args.root else None)
    result = execute_smoke(root)
    write_smoke_json(root / args.out, result)
    print(json.dumps({"status": result["status"], "problem_count": result["problem_count"], "commands_executed": result["commands_executed"]}, sort_keys=True))
    return 0 if result["status"] == "pass" else 1


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="bepguard", description="BEPGuard deterministic artifact commands")
    parser.add_argument("--root", default=None, help="release-package root; auto-detected by default")
    sub = parser.add_subparsers(dest="command", required=True)

    p_e = sub.add_parser("evidence", help="build and audit evidence graph closure")
    p_e.add_argument("--graph-out", default="artifact/results/evidence_graph.json")
    p_e.add_argument("--metrics-out", default="artifact/results/evidence_graph_metrics.json")
    p_e.add_argument("--paths-out", default="artifact/results/evidence_graph_paths.csv")
    p_e.set_defaults(func=cmd_evidence)

    p_l = sub.add_parser("leakage", help="run anti-overfitting leakage audit")
    p_l.add_argument("--out", default="artifact/results/anti_overfit_leakage_audit.json")
    p_l.set_defaults(func=cmd_leakage)

    p_s = sub.add_parser("smoke", help="execute strict deterministic smoke gate")
    p_s.add_argument("--out", default="artifact/results/strict_reproducibility_smoke.json")
    p_s.set_defaults(func=cmd_smoke)

    args = parser.parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
