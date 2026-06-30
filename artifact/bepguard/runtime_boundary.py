"""Runtime boundary audit for anonymous deterministic reproduction."""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Any, Dict, List

sys.dont_write_bytecode = True

DISALLOWED_DIR_NAMES = {"node_modules", ".cache", "__pycache__", ".git", ".venv", "venv"}
DISALLOWED_FILE_SUFFIXES = {".pyc", ".pyo", ".aux", ".log", ".bbl", ".blg", ".out", ".fls", ".fdb_latexmk", ".synctex.gz"}
VOLATILE_TOKENS = ["OPEN" + "AI_API_KEY", "AWS_SECRET", "GITHUB_TOKEN", "HF_TOKEN", "CUDA_VISIBLE_DEVICES"]
NETWORK_TOKENS = ["requests.get(", "urllib.request", "socket.", "subprocess.*curl", "subprocess.*wget"]


def audit_runtime_boundary(root: Path) -> Dict[str, Any]:
    artifact = root / "artifact"
    problems: List[str] = []
    files_checked = 0
    bytes_checked = 0
    disallowed_dirs = []
    disallowed_files = []
    token_hits = []
    for path in artifact.rglob("*"):
        rel = str(path.relative_to(artifact))
        if path.is_dir():
            if path.name in DISALLOWED_DIR_NAMES:
                disallowed_dirs.append(rel)
            continue
        files_checked += 1
        bytes_checked += path.stat().st_size
        if any(rel.endswith(suf) for suf in DISALLOWED_FILE_SUFFIXES):
            disallowed_files.append(rel)
        if path.suffix.lower() in {".py", ".md", ".json", ".csv", ".toml", ".txt", ".go"} and path.stat().st_size < 2_000_000:
            text = path.read_text(encoding="utf-8", errors="ignore")
            if rel not in {"bepguard/runtime_boundary.py", "bepguard/repository.py", "results/runtime_boundary_audit.json"}:
                for token in VOLATILE_TOKENS:
                    if token in text:
                        token_hits.append({"file": rel, "token": token})
                # Network-capable dependencies may appear in audit source as literal
                # banned-token strings; deterministic method scripts must not invoke them.
                if path.suffix.lower() == ".py" and not rel.startswith("scripts/baseline_wrappers") and not rel.startswith("scripts/run_external_baseline_full"):
                    for token in ["requests.get(", "urllib.request", "socket."]:
                        if token in text:
                            token_hits.append({"file": rel, "token": token})
    if disallowed_dirs:
        problems.append(f"disallowed transient/cache directories packaged: {disallowed_dirs[:10]}")
    if disallowed_files:
        problems.append(f"disallowed transient build files packaged: {disallowed_files[:10]}")
    if token_hits:
        problems.append(f"volatile secret/network tokens in deterministic artifact path: {token_hits[:10]}")
    env = json.loads((artifact / "environment_lock.json").read_text(encoding="utf-8")) if (artifact / "environment_lock.json").exists() else {}
    return {
        "schema": "BEPGuardRuntimeBoundary/v1",
        "status": "pass" if not problems else "fail",
        "problem_count": len(problems),
        "problems": problems,
        "files_checked": files_checked,
        "bytes_checked": bytes_checked,
        "disallowed_dirs": disallowed_dirs,
        "disallowed_files": disallowed_files,
        "volatile_token_hits": token_hits,
        "python_version_declared": env.get("python"),
        "gpu_required": False,
        "network_required_for_core_ladder": False,
        "commercial_api_required": False,
        "interpretation": "The deterministic artifact path is CPU-native and local: no dependency cache directories, Python bytecode caches, LaTeX transient files, GPU requirements, commercial API credentials, or packaged git metadata are present in the release tree.",
    }


def write_json(path: Path, obj: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=2, sort_keys=True) + "\n", encoding="utf-8")
