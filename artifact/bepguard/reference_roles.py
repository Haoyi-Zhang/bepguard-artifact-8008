"""Reference role balance and non-padding audit."""
from __future__ import annotations
import csv, json, re
from pathlib import Path
from typing import Any, Dict, List

MIN_PREFIX_COUNTS = {"SPEC": 6, "DOC": 8, "FW": 5, "TOOL": 3, "RW": 10, "SE": 6, "METH": 4}


def run_reference_role_balance(root: Path) -> Dict[str, Any]:
    problems: List[str] = []
    rows = list(csv.DictReader((root/"artifact/reference_ledger.csv").open(encoding="utf-8")))
    bib = (root/"paper/references.bib").read_text(encoding="utf-8")
    tex = (root/"paper/main.tex").read_text(encoding="utf-8") + "\n" + (root/"paper/supplement.tex").read_text(encoding="utf-8")
    counts: Dict[str, int] = {}
    used_keys = set(re.findall(r"\\cite\{([^}]+)\}", tex))
    flat_keys = {k.strip() for group in used_keys for k in group.split(',')}
    seen_keys=set()
    for r in rows:
        prefix = re.match(r"[A-Z]+", r.get("ref_id", "") or "")
        pref = prefix.group(0) if prefix else "OTHER"
        counts[pref]=counts.get(pref,0)+1
        key=r.get("bibtex_key","").strip()
        if not key:
            problems.append(f"missing bibtex_key for {r.get('ref_id')}")
        if key in seen_keys:
            problems.append(f"duplicate bibtex_key {key}")
        seen_keys.add(key)
        if key and key not in bib:
            problems.append(f"ledger key not in BibTeX: {key}")
        if key and key not in flat_keys:
            problems.append(f"ledger key not cited in main/supplement: {key}")
        if (r.get("verification_status") or "") != "source_verified":
            problems.append(f"unverified reference {r.get('ref_id')}")
        if not (r.get("doi") or r.get("url")):
            problems.append(f"reference lacks DOI/URL: {r.get('ref_id')}")
        if not r.get("supporting_claim") or not r.get("section_used"):
            problems.append(f"reference missing claim/section role: {r.get('ref_id')}")
    if len(rows) != 72:
        problems.append(f"expected 72 references, found {len(rows)}")
    for pref, min_count in MIN_PREFIX_COUNTS.items():
        if counts.get(pref,0) < min_count:
            problems.append(f"reference role {pref} has {counts.get(pref,0)} entries, below {min_count}")
    return {"status":"pass" if not problems else "fail", "problem_count":len(problems), "problems":problems[:100], "references_checked":len(rows), "role_counts":counts, "minimum_role_counts":MIN_PREFIX_COUNTS, "interpretation":"Checks that the 70-80 reference set is role-balanced, cited, verified, and tied to paper claims rather than serving as citation padding."}


def write_json(path: Path, obj: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=2, sort_keys=True)+"\n", encoding="utf-8")
