"""Public-source and data-rights provenance audit.

The release is intended to be anonymous, deterministic, and public-source
based.  This audit checks that admitted sources and external resources expose
URLs, access dates, license/provenance notes, and no private-data markers.
"""
from __future__ import annotations
import csv, json, re
from pathlib import Path
from typing import Any, Dict, List

CSV_FILES = [
    "artifact/source_manifest.csv",
    "artifact/source_snapshot_manifest.csv",
    "artifact/external_resources.csv",
]
PRIVATE_MARKERS = [r"private data", r"real account", r"api key", r"secret", r"password"]
URL_RE = re.compile(r"^https?://")


def _rows(path: Path) -> List[dict[str, str]]:
    with path.open(newline="", encoding="utf-8") as fh:
        return list(csv.DictReader(fh))


def run_public_provenance(root: Path) -> Dict[str, Any]:
    problems: List[str] = []
    rows_checked = 0
    for rel in CSV_FILES:
        path = root / rel
        if not path.exists():
            problems.append(f"missing provenance file {rel}")
            continue
        rows = _rows(path)
        rows_checked += len(rows)
        for i, row in enumerate(rows, start=2):
            url = row.get("url") or row.get("source_url")
            if not url or (not URL_RE.match(url) and url != "project-local"):
                problems.append(f"{rel}:{i} missing public http(s) URL or project-local marker")
            access = row.get("access_date") or row.get("accessed")
            if not access:
                problems.append(f"{rel}:{i} missing access date")
            license_note = row.get("license") or row.get("local_snapshot_policy") or row.get("wrapper_policy")
            if not license_note:
                problems.append(f"{rel}:{i} missing license/provenance note")
            blob = " ".join(str(v) for v in row.values()).lower()
            for pat in PRIVATE_MARKERS:
                if re.search(pat, blob) and "no private" not in blob and "without private" not in blob:
                    problems.append(f"{rel}:{i} contains private-data marker {pat!r}")
    # Release-level locks must state that no private data / external inference API is used.
    env = json.loads((root / "artifact/environment_lock.json").read_text(encoding="utf-8"))
    pyproject = (root / "artifact/pyproject.toml").read_text(encoding="utf-8")
    for token in ["private_data", "external_inference_api", "live_web_scanning"]:
        if token not in pyproject:
            problems.append(f"pyproject missing boundary flag {token}")
    if env.get("private_data_required", env.get("private_data")) not in (False, "false", "no"):
        problems.append("environment lock does not explicitly exclude private data")
    return {
        "status": "pass" if not problems else "fail",
        "problem_count": len(problems),
        "problems": problems[:100],
        "csv_files_checked": len(CSV_FILES),
        "provenance_rows_checked": rows_checked,
        "private_markers_checked": len(PRIVATE_MARKERS),
        "interpretation": "Checks that the source and external-resource ledgers are public-source grounded and do not rely on private data or opaque credentials.",
    }


def write_json(path: Path, obj: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=2, sort_keys=True) + "\n", encoding="utf-8")
