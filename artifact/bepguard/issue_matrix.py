"""Issue-class evidence triangulation matrix.

The issue-depth audit checks individual obligations.  This module produces a
compact matrix for assessors: every issue class must have independent evidence
from locked positives, matched controls, certificates, repairs, SpecBench,
mutation pressure, shadow/blind/stability replays, causal activation, third
oracle agreement, and evidence-card traceability.
"""
from __future__ import annotations

import csv
import json
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Dict, List, Tuple


def _read_csv(path: Path) -> List[Dict[str, str]]:
    with path.open(newline="", encoding="utf-8") as fh:
        return list(csv.DictReader(fh))


def _as_int(value: Any) -> int:
    try:
        return int(value)
    except Exception:
        return 0


def run_issue_matrix_audit(root: Path) -> Tuple[List[Dict[str, str]], Dict[str, Any]]:
    issue_rows = _read_csv(root / "artifact/results/deep_locked/issue_evidence_depth_rows.csv")
    oracle_rows = _read_csv(root / "artifact/results/deep_locked/declarative_oracle_rows.csv")
    stability_rows = _read_csv(root / "artifact/results/deep_locked/corpus_stability_rows.csv")
    cards = json.loads((root / "artifact/results/deep_locked/evidence_cards.json").read_text(encoding="utf-8"))

    oracle_by_issue: Counter[str] = Counter()
    for row in oracle_rows:
        exp = row.get("expected", "")
        if row.get("suite") == "BEP-Deep" and exp and exp != "none" and row.get("status") == "pass":
            oracle_by_issue[exp] += 1

    stability_by_issue: Counter[str] = Counter()
    for row in stability_rows:
        issue = row.get("base_issues", "")
        if issue and issue != "none" and row.get("status") == "preserved":
            for part in issue.split(";"):
                if part:
                    stability_by_issue[part] += 1

    cards_by_issue: Counter[str] = Counter()
    for card in cards:
        if card.get("evidence_path_verified") and card.get("certificate_obligations_true"):
            cards_by_issue[str(card.get("issue", ""))] += 1

    channels = [
        "locked_positive",
        "intent_matched_control",
        "positive_certificate",
        "paired_repair",
        "specbench_pressure",
        "mutation_pressure",
        "shadow_replay",
        "blind_replay",
        "stability_replay",
        "causal_activation",
        "declarative_oracle_agreement",
        "evidence_card",
    ]
    rows: List[Dict[str, str]] = []
    problems: List[str] = []
    for src in sorted(issue_rows, key=lambda r: r["issue"]):
        issue = src["issue"]
        values = {
            "locked_positive": _as_int(src.get("locked_positives")),
            "intent_matched_control": _as_int(src.get("matched_intent_controls")),
            "positive_certificate": _as_int(src.get("positive_certificates")),
            "paired_repair": _as_int(src.get("paired_repairs")),
            "specbench_pressure": _as_int(src.get("specbench_positive_cases")),
            "mutation_pressure": _as_int(src.get("killed_mutants")),
            "shadow_replay": _as_int(src.get("shadow_preserved_replays")),
            "blind_replay": _as_int(src.get("identifier_blind_preserved_replays")),
            "stability_replay": stability_by_issue[issue],
            "causal_activation": _as_int(src.get("causal_activations")),
            "declarative_oracle_agreement": oracle_by_issue[issue],
            "evidence_card": cards_by_issue[issue],
        }
        active = sum(1 for name in channels if values[name] > 0)
        if active != len(channels):
            problems.append(f"{issue}: only {active}/{len(channels)} evidence channels active")
        # certificate/repair/card parity must match locked positives exactly.
        locked = values["locked_positive"]
        for parity_channel in ("positive_certificate", "paired_repair", "evidence_card"):
            if values[parity_channel] != locked:
                problems.append(f"{issue}: {parity_channel}={values[parity_channel]} != locked positives {locked}")
        rows.append({
            "issue": issue,
            "intent_class": src.get("intent_class", ""),
            **{name: str(values[name]) for name in channels},
            "active_channels": str(active),
            "status": "pass" if active == len(channels) else "fail",
        })
    summary = {
        "status": "pass" if not problems else "fail",
        "problem_count": len(problems),
        "problems": problems[:50],
        "issue_classes_checked": len(rows),
        "channels_per_issue": len(channels),
        "triangulation_cells": len(rows) * len(channels),
        "complete_issue_classes": sum(1 for r in rows if r["status"] == "pass"),
        "evidence_channels": channels,
        "interpretation": "Per-issue evidence matrix requiring every drift class to be supported by independent locked, control, certificate, repair, boundary-benchmark, mutation, shadow/blind/stability, causal, declarative-oracle, and evidence-card channels.",
    }
    return rows, summary


def write_csv(path: Path, rows: List[Dict[str, str]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if not rows:
        path.write_text("\n", encoding="utf-8")
        return
    fields = list(rows[0].keys())
    with path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=fields)
        writer.writeheader(); writer.writerows(rows)


def write_json(path: Path, obj: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=2, sort_keys=True) + "\n", encoding="utf-8")
