"""Release package identity and environment-lock consistency audit."""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Dict, List


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8") if path.exists() else ""


def _pyproject_field(text: str, field: str) -> str:
    m = re.search(rf'^{re.escape(field)}\s*=\s*"([^"]+)"', text, re.MULTILINE)
    return m.group(1) if m else ""


def audit_package_identity(root: Path) -> Dict[str, Any]:
    problems: List[str] = []
    pyproject = _read(root / "artifact/pyproject.toml")
    init_text = _read(root / "artifact/bepguard/__init__.py")
    env_path = root / "artifact/environment_lock.json"
    env = json.loads(env_path.read_text(encoding="utf-8")) if env_path.exists() else {}
    name = _pyproject_field(pyproject, "name")
    version = _pyproject_field(pyproject, "version")
    if name != "BEPGuard":
        problems.append(f"unexpected pyproject name {name!r}")
    if version != "0.24.0":
        problems.append(f"unexpected pyproject version {version!r}")
    if f'__version__ = "{version}"' not in init_text:
        problems.append("bepguard.__version__ is not synchronized with pyproject")
    if env.get("artifact_name") != "BEPGuard":
        problems.append("environment lock artifact_name mismatch")
    if env.get("artifact_version") != version:
        problems.append("environment lock artifact_version mismatch")
    if env.get("gpu_required") is not False or env.get("external_inference_api_required") is not False or env.get("private_data_required") is not False:
        problems.append("environment lock no-GPU/no-inference/no-private-data flags are not all false")
    if env.get("network_required_for_core_validation") is not False:
        problems.append("environment lock should mark core validation as network-independent")
    result = {
        "status": "pass" if not problems else "fail",
        "problem_count": len(problems),
        "problems": problems,
        "package_name": name,
        "package_version": version,
        "environment_artifact_version": env.get("artifact_version"),
        "network_required_for_core_validation": env.get("network_required_for_core_validation"),
        "gpu_required": env.get("gpu_required"),
        "external_inference_api_required": env.get("external_inference_api_required"),
        "private_data_required": env.get("private_data_required"),
        "interpretation": "Checks that package identity, Python package version, and environment lock agree and preserve the deterministic CPU-native/no-private-data boundary.",
    }
    return result


def write_json(path: Path, obj: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=2, sort_keys=True) + "\n", encoding="utf-8")
