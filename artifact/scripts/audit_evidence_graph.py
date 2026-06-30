#!/usr/bin/env python3
"""Build and audit the BEPGuard evidence graph."""
from __future__ import annotations
import json
import sys
sys.dont_write_bytecode = True
from pathlib import Path

from common_paths import package_root

ROOT = package_root(__file__)
if str(ROOT / "artifact") not in sys.path:
    sys.path.insert(0, str(ROOT / "artifact"))

from bepguard.evidence import build_graph, write_json, write_paths  # noqa: E402


def main() -> None:
    graph, metrics, paths = build_graph(ROOT)
    write_json(ROOT / "artifact" / "results" / "evidence_graph.json", graph)
    write_json(ROOT / "artifact" / "results" / "evidence_graph_metrics.json", metrics)
    write_paths(ROOT / "artifact" / "results" / "evidence_graph_paths.csv", paths)
    print(json.dumps({"status": metrics["status"], "problem_count": metrics["problem_count"], "node_count": metrics["node_count"], "edge_count": metrics["edge_count"]}, sort_keys=True))
    if metrics["status"] != "pass":
        raise SystemExit(1)


if __name__ == "__main__":
    main()
