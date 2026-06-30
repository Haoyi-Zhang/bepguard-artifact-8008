"""assessor quickstart readiness audit."""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Dict, List

LANES = ["Five-minute capsule check", "Twenty-minute semantic replay", "Full assessor ladder", "External comparator note"]
FORBIDDEN = ["gpu", "cuda", "api key", "token", "password", "live website", "crawl", "hosted scanner"]


def run_quickstart_readiness(root: Path) -> Dict[str, Any]:
    problems: List[str] = []
    quick_path = root / "artifact/quickstart.md"
    ladder_path = root / "artifact/reproduction_ladder.json"
    text = quick_path.read_text(encoding="utf-8") if quick_path.exists() else ""
    if not text:
        problems.append("missing quickstart.md")
    for lane in LANES:
        if lane not in text:
            problems.append(f"missing quickstart lane: {lane}")
    for bad in FORBIDDEN:
        if re.search(rf"\b{re.escape(bad)}\b", text, flags=re.IGNORECASE) and bad not in {"gpu"}:
            problems.append(f"forbidden quickstart dependency wording: {bad}")
    if "GPU" in text:
        problems.append("quickstart should not require GPU")
    commands = re.findall(r"(?:PYTHONDONTWRITEBYTECODE=1\s+)?PYTHONPATH=artifact\s+python3\s+([^\n]+)", text)
    for command in commands:
        parts = command.split()
        if not parts:
            continue
        cmd = parts[0]
        if cmd == "-m":
            if len(parts) < 2:
                problems.append("quickstart module command missing module name")
            continue
        if not (root / cmd).exists():
            problems.append(f"quickstart command path missing: {cmd}")
    if not ladder_path.exists():
        problems.append("missing reproduction_ladder.json")
        ladder_commands = 0
    else:
        ladder = json.loads(ladder_path.read_text(encoding="utf-8"))
        ladder_commands = len(ladder.get("commands", [])) if isinstance(ladder, dict) else 0
        if ladder_commands < 101:
            problems.append(f"ladder has too few declared commands for this release: {ladder_commands}")
    return {
        "status": "pass" if not problems else "fail",
        "problem_count": len(problems),
        "problems": problems,
        "lanes_checked": len(LANES),
        "quickstart_commands_checked": len(commands),
        "reproduction_ladder_commands": ladder_commands,
        "interpretation": "Checks that the assessor quickstart exposes short, medium, and full deterministic review paths without requiring private or hosted services.",
    }


def write_json(path: Path, obj: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=2, sort_keys=True) + "\n", encoding="utf-8")
