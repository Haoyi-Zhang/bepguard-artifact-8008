"""Manual repository-upload readiness audit.

The release package is delivered as a two-directory zip.  When the artifact tree
is manually uploaded to the anonymous repository, this audit checks that the
upload manifest points to the correct root and that mandatory entry files are
present while dependency caches and transient files are absent.
"""
from __future__ import annotations
import json
from pathlib import Path
from typing import Any, Dict, List

REQUIRED_INCLUDE = {"README.md", "LICENSE", "pyproject.toml", "requirements.txt", "environment_lock.json", "reproduction.md", "quickstart.md", "triage_index.json", "data/", "bepguard/", "scripts/", "tests/", "results/"}
FORBIDDEN_PRESENT = [".git", "__pycache__", "node_modules", ".pytest_cache"]


def run_repository_upload(root: Path) -> Dict[str, Any]:
    problems: List[str] = []
    path = root / "artifact/repository_upload_manifest.json"
    if not path.exists():
        problems.append("missing repository upload manifest")
        manifest: Dict[str, Any] = {}
    else:
        manifest = json.loads(path.read_text(encoding="utf-8"))
    if manifest.get("repository_name") != "BEPGuard":
        problems.append("repository name is not BEPGuard")
    if manifest.get("manual_upload_root") != "artifact/":
        problems.append("manual upload root must be artifact/")
    include = set(manifest.get("include", []))
    missing_include = sorted(REQUIRED_INCLUDE - include)
    if missing_include:
        problems.append(f"upload manifest missing include entries {missing_include}")
    if manifest.get("current_validation_layers") != 111:
        problems.append("upload manifest validation-layer count is stale")
    if manifest.get("current_reproduction_ladder_commands") != 101:
        problems.append("upload manifest reproduction-ladder count is stale")
    for rel in REQUIRED_INCLUDE:
        p = root / "artifact" / rel.rstrip("/")
        if not p.exists():
            problems.append(f"required upload path missing: artifact/{rel}")
    forbidden_hits = []
    for p in (root / "artifact").rglob("*"):
        if any(part in FORBIDDEN_PRESENT for part in p.relative_to(root / "artifact").parts):
            forbidden_hits.append(str(p.relative_to(root)))
            if len(forbidden_hits) >= 10:
                break
    if forbidden_hits:
        problems.append(f"forbidden upload cache/transient paths present {forbidden_hits}")
    return {
        "status": "pass" if not problems else "fail",
        "problem_count": len(problems),
        "problems": problems[:100],
        "include_entries": len(include),
        "required_include_entries": len(REQUIRED_INCLUDE),
        "preupload_commands": len(manifest.get("required_before_upload", [])),
        "interpretation": "Checks that the artifact tree can be manually uploaded as the BEPGuard repository without dependency caches, git metadata, or transient files.",
    }


def write_json(path: Path, obj: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=2, sort_keys=True) + "\n", encoding="utf-8")
