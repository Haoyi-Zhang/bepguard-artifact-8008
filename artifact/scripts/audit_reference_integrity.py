#!/usr/bin/env python3
"""Citation and reference-ledger integrity audit for the paper source."""
from __future__ import annotations
import sys
sys.dont_write_bytecode = True

import argparse, csv, json, re
from pathlib import Path
from typing import Dict, List, Set

BAD_NOTE = re.compile(r"to verify|placeholder|procedural|generated|preflight|accessed later|TBD", re.I)
URL_OR_DOI = re.compile(r"\b(url|doi)\s*=\s*\{([^}]*)\}", re.I)


def bib_entries(text: str) -> Dict[str, str]:
    entries: Dict[str, str] = {}
    starts = [(m.start(), m.group(1)) for m in re.finditer(r"^@\w+\{([^,]+),", text, re.M)]
    for idx, (start, key) in enumerate(starts):
        end = starts[idx + 1][0] if idx + 1 < len(starts) else len(text)
        entries[key] = text[start:end]
    return entries


def cited_keys(tex: str) -> Set[str]:
    keys: Set[str] = set()
    for m in re.finditer(r"\\cite\{([^}]+)\}", tex):
        keys.update(k.strip() for k in m.group(1).split(',') if k.strip())
    return keys


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", default=".")
    ap.add_argument("--out", default="artifact/results/reference_integrity_audit.json")
    args = ap.parse_args()
    root = Path(args.root).resolve()
    tex = (root / "paper" / "main.tex").read_text(encoding="utf-8")
    bib_text = (root / "paper" / "references.bib").read_text(encoding="utf-8")
    entries = bib_entries(bib_text)
    cites = cited_keys(tex)
    missing = sorted(cites - set(entries))
    uncited = sorted(set(entries) - cites)
    weak: List[str] = []
    for key, entry in entries.items():
        if BAD_NOTE.search(entry):
            weak.append(f"{key}: procedural or placeholder note")
        if not URL_OR_DOI.search(entry):
            # Older proceedings references may rely on venue; flag only if no booktitle/journal either.
            if not re.search(r"\b(booktitle|journal)\s*=\s*\{[^}]+\}", entry, re.I):
                weak.append(f"{key}: lacks DOI/URL and venue")
    ledger_path = root / "artifact" / "reference_ledger.csv"
    ledger_keys: Set[str] = set(); non_verified: List[str] = []
    if ledger_path.exists():
        with ledger_path.open(newline="", encoding="utf-8") as fh:
            for row in csv.DictReader(fh):
                key = row.get("BibTeX key") or row.get("bibtex_key") or row.get("key") or row.get("BibTeX Key")
                if key: ledger_keys.add(key)
                status = (row.get("status") or row.get("verification_status") or row.get("Verification status") or "").strip()
                if status and status != "source_verified":
                    non_verified.append(key or row.get("title", "<unknown>"))
    ledger_missing = sorted(cites - ledger_keys) if ledger_keys else []
    ledger_extra = sorted(ledger_keys - cites) if ledger_keys else []
    problems = missing + uncited + weak + [f"ledger missing: {k}" for k in ledger_missing] + [f"ledger extra: {k}" for k in ledger_extra] + [f"ledger not source_verified: {k}" for k in non_verified]
    result = {
        "cited_keys": len(cites),
        "bib_entries": len(entries),
        "missing_bib_entries": missing,
        "uncited_bib_entries": uncited,
        "entries_with_reference_hygiene_warnings": weak,
        "ledger_keys": len(ledger_keys),
        "ledger_missing_cited_keys": ledger_missing,
        "ledger_extra_keys": ledger_extra,
        "ledger_non_source_verified": non_verified,
        "problem_count": len(problems),
        "status": "pass" if not problems else "fail",
        "interpretation": "Reference integrity audit: cited keys, BibTeX entries, ledger rows, verification statuses, and procedural notes must align.",
    }
    out = root / args.out
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({"status": result["status"], "problem_count": len(problems), "cited_keys": len(cites)}, sort_keys=True))
    if problems:
        raise SystemExit(2)

if __name__ == "__main__":
    main()
