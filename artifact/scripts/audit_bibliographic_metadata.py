#!/usr/bin/env python3
"""Bibliographic metadata quality audit for the release cited set.

This gate complements key-level reference integrity. It checks that BibTeX entry
classes match the cited publication surface, and that entries with known
published versions are not left as preprint-only records. It is metadata hygiene;
it does not add or remove citations.
"""
from __future__ import annotations
import sys
sys.dont_write_bytecode = True

import argparse, csv, json, re
from pathlib import Path

EXPECTED_PUBLISHED = {
    "golinelli_nonce_2023": {
        "doi": "10.1007/978-3-031-54129-2_27",
        "venue_contains": "ESORICS 2023 International Workshops",
        "type": "inproceedings",
    },
    "kishnani_secure_headers_2024": {
        "doi": "10.1007/978-3-031-80020-7_5",
        "venue_contains": "Information Systems Security",
        "type": "inproceedings",
    },
    "braun_clarke_thematic_2006": {
        "doi": "10.1191/1478088706qp063oa",
        "venue_contains": "Qualitative Research in Psychology",
        "type": "article",
    },
}


def parse_bib(text: str):
    entries = {}
    for m in re.finditer(r"@(\w+)\s*\{\s*([^,]+),", text):
        typ, key = m.group(1).lower(), m.group(2).strip()
        start = m.end()
        depth = 1
        pos = start
        while pos < len(text) and depth:
            if text[pos] == "{":
                depth += 1
            elif text[pos] == "}":
                depth -= 1
            pos += 1
        body = text[start:pos-1]
        fields = {}
        for fm in re.finditer(r"(\w+)\s*=\s*\{([^{}]*(?:\{[^{}]*\}[^{}]*)*)\}\s*,?", body, re.S):
            fields[fm.group(1).lower()] = re.sub(r"\s+", " ", fm.group(2).strip())
        entries[key] = {"type": typ, "fields": fields}
    return entries


def read_csv(path: Path):
    with path.open(newline="", encoding="utf-8") as fh:
        return list(csv.DictReader(fh))


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", default=".")
    ap.add_argument("--out", default="artifact/results/bibliographic_metadata_audit.json")
    args = ap.parse_args()
    root = Path(args.root)
    problems = []
    details = []
    bib_text = (root / "paper/references.bib").read_text(encoding="utf-8")
    entries = parse_bib(bib_text)
    ledger = {r.get("bibtex_key", ""): r for r in read_csv(root / "artifact/reference_ledger.csv")}

    for key, exp in EXPECTED_PUBLISHED.items():
        ent = entries.get(key)
        row = ledger.get(key)
        if not ent:
            problems.append(f"missing BibTeX entry for expected published key {key}")
            continue
        fields = ent["fields"]
        venue = fields.get("booktitle") or fields.get("journal") or fields.get("howpublished") or ""
        doi = fields.get("doi", "")
        if ent["type"] != exp["type"]:
            problems.append(f"{key}: expected @{exp['type']}, found @{ent['type']}")
        if doi.lower() != exp["doi"].lower():
            problems.append(f"{key}: expected DOI {exp['doi']}, found {doi}")
        if exp["venue_contains"].lower() not in venue.lower():
            problems.append(f"{key}: expected venue containing {exp['venue_contains']}, found {venue}")
        if row:
            row_doi = row.get("doi", "")
            row_venue = row.get("venue_or_source", "")
            if row_doi.lower() != exp["doi"].lower():
                problems.append(f"{key}: reference ledger DOI mismatch {row_doi}")
            if exp["venue_contains"].split()[0].lower() not in row_venue.lower():
                problems.append(f"{key}: reference ledger venue/source mismatch {row_venue}")
        details.append({"key": key, "type": ent["type"], "doi": doi, "venue": venue})

    for key, ent in entries.items():
        fields = ent["fields"]
        venue = " ".join([fields.get("booktitle", ""), fields.get("journal", ""), fields.get("howpublished", "")])
        if ent["type"] == "inproceedings" and re.search(r"\b(preprint|arxiv)\b", venue, re.I):
            problems.append(f"{key}: preprint/arXiv record is typed as inproceedings")
        if ent["type"] == "inproceedings" and fields.get("journal"):
            problems.append(f"{key}: inproceedings entry contains journal field")
        if ent["type"] == "article" and not fields.get("journal"):
            problems.append(f"{key}: article entry missing journal")

    result = {
        "status": "pass" if not problems else "fail",
        "problem_count": len(problems),
        "problems": problems,
        "entries_checked": len(entries),
        "published_version_checks": details,
        "interpretation": "Checks BibTeX class/venue/DOI metadata for the release cited set and published-version upgrades; it does not add or remove citations.",
    }
    out = root / args.out
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({"status": result["status"], "problem_count": len(problems), "entries_checked": len(entries)}, sort_keys=True))
    if problems:
        raise SystemExit(2)

if __name__ == "__main__":
    main()
