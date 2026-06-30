"""Evidence-graph construction and closure checks for BEPGuard.

The evidence graph is a evidence-facing research object: it connects admitted
public claims, source spans, encoded rules, locked fixtures, emitted witnesses,
proof-carrying certificates, paired repairs, negative controls, SpecBench cases,
metamorphic obligations, and external-baseline probe statuses.  The graph is not
used to generate findings.  It is an independent closure layer that asks whether
all reported claims can be navigated through the released artifact without
consulting hidden state or trusting a single result table.
"""
from __future__ import annotations

import csv
import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, MutableMapping, Optional, Sequence, Set, Tuple


@dataclass(frozen=True)
class Node:
    """A typed vertex in the released evidence graph."""

    node_id: str
    kind: str
    label: str
    attrs: Mapping[str, Any] = field(default_factory=dict)

    def as_dict(self) -> Dict[str, Any]:
        return {
            "id": self.node_id,
            "kind": self.kind,
            "label": self.label,
            "attrs": dict(sorted(self.attrs.items())),
        }


@dataclass(frozen=True)
class Edge:
    """A typed relation between two graph nodes."""

    src: str
    dst: str
    relation: str
    attrs: Mapping[str, Any] = field(default_factory=dict)

    def as_dict(self) -> Dict[str, Any]:
        return {
            "src": self.src,
            "dst": self.dst,
            "relation": self.relation,
            "attrs": dict(sorted(self.attrs.items())),
        }


class EvidenceGraph:
    """Small deterministic graph builder with duplicate-edge coalescing."""

    def __init__(self) -> None:
        self.nodes: Dict[str, Node] = {}
        self.edges: Dict[Tuple[str, str, str, str], Edge] = {}

    def add_node(self, node_id: str, kind: str, label: str, **attrs: Any) -> None:
        if node_id in self.nodes:
            old = self.nodes[node_id]
            merged = dict(old.attrs)
            merged.update({k: v for k, v in attrs.items() if v not in (None, "", [])})
            self.nodes[node_id] = Node(node_id, old.kind, old.label, merged)
            return
        self.nodes[node_id] = Node(node_id, kind, label, {k: v for k, v in attrs.items() if v not in (None, "", [])})

    def add_edge(self, src: str, dst: str, relation: str, **attrs: Any) -> None:
        key_material = json.dumps({"src": src, "dst": dst, "relation": relation, "attrs": attrs}, sort_keys=True, default=str)
        key = (src, dst, relation, hashlib.sha256(key_material.encode("utf-8")).hexdigest()[:12])
        self.edges[key] = Edge(src, dst, relation, {k: v for k, v in attrs.items() if v not in (None, "", [])})

    def to_json(self) -> Dict[str, Any]:
        nodes = [n.as_dict() for n in sorted(self.nodes.values(), key=lambda n: (n.kind, n.node_id))]
        edges = [e.as_dict() for e in sorted(self.edges.values(), key=lambda e: (e.src, e.relation, e.dst, json.dumps(e.attrs, sort_keys=True, default=str)))]
        graph_hash = hashlib.sha256(json.dumps({"nodes": nodes, "edges": edges}, sort_keys=True).encode("utf-8")).hexdigest()
        return {
            "schema": "BEPGuardEvidenceGraph/v1",
            "graph_hash": graph_hash,
            "nodes": nodes,
            "edges": edges,
            "node_count": len(nodes),
            "edge_count": len(edges),
            "interpretation": "Traceability graph over released claims, sources, rules, fixtures, witnesses, certificates, repairs, controls, and auxiliary validation objects; the graph audits closure and is not used to create findings.",
        }


def read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def read_csv(path: Path) -> List[Dict[str, str]]:
    with path.open(newline="", encoding="utf-8") as fh:
        return list(csv.DictReader(fh))


def split_semicolon(value: str) -> List[str]:
    if not value:
        return []
    return [x.strip() for x in value.replace(",", ";").split(";") if x.strip()]


def _node(kind: str, raw_id: str) -> str:
    return f"{kind}:{raw_id}"


def _fixture_claims(fixture: Mapping[str, Any]) -> List[str]:
    claims = fixture.get("source_claim_ids", [])
    if isinstance(claims, list):
        return [str(c) for c in claims if str(c)]
    if isinstance(claims, str):
        return split_semicolon(claims)
    return []


def _witness_key(witness: Mapping[str, Any]) -> Tuple[str, str]:
    return str(witness.get("fixture_id", "")), str(witness.get("issue", ""))


def _cert_key(cert: Mapping[str, Any]) -> Tuple[str, str]:
    return str(cert.get("fixture_id", "")), str(cert.get("issue", ""))


def _positive_path_ok(
    cert: Mapping[str, Any],
    fixture_ids: Set[str],
    witness_keys: Set[Tuple[str, str]],
    repair_ids: Set[str],
    claim_ids: Set[str],
    rule_ids: Set[str],
    span_claim_ids: Set[str],
) -> Tuple[bool, List[str]]:
    problems: List[str] = []
    fid = str(cert.get("fixture_id", ""))
    issue = str(cert.get("issue", ""))
    if fid not in fixture_ids:
        problems.append("missing_fixture")
    if (fid, issue) not in witness_keys:
        problems.append("missing_witness")
    repair_id = str(cert.get("paired_repair_control_id", ""))
    if repair_id not in repair_ids:
        problems.append("missing_paired_repair")
    for cid in [str(x) for x in cert.get("source_claim_ids", []) if str(x)]:
        if cid not in claim_ids:
            problems.append(f"unknown_claim:{cid}")
        if cid not in span_claim_ids:
            problems.append(f"missing_source_span:{cid}")
    cert_rules = [str(x) for x in cert.get("rule_ids", []) if str(x)]
    if not cert_rules:
        problems.append("missing_rule_ids")
    for rid in cert_rules:
        if rid not in rule_ids:
            problems.append(f"unknown_rule:{rid}")
    obligations = cert.get("obligations", {}) if isinstance(cert.get("obligations", {}), Mapping) else {}
    false_obligations = sorted([k for k, v in obligations.items() if v is not True])
    if false_obligations:
        problems.append("failed_certificate_obligations:" + ";".join(false_obligations))
    return not problems, problems


def build_graph(root: Path) -> Tuple[Dict[str, Any], Dict[str, Any], List[Dict[str, Any]]]:
    """Build the evidence graph, metrics, and positive-path audit rows."""

    artifact = root / "artifact"
    g = EvidenceGraph()
    claims = read_csv(artifact / "data" / "corpus_claims.csv")
    rules = read_csv(artifact / "data" / "rule_source_ledger.csv")
    spans = read_csv(artifact / "source_span_ledger.csv")
    source_manifest = read_csv(artifact / "data" / "source_snapshot_manifest.csv")
    fixtures = read_json(artifact / "data" / "deep_locked_fixtures.json")
    witnesses = read_json(artifact / "results" / "deep_locked" / "full_witnesses.json")
    certs = read_json(artifact / "results" / "deep_locked" / "proof_carrying_witness_certificates.json")
    repairs = read_json(artifact / "data" / "paired_repair_controls.json")
    control_audit = read_csv(artifact / "results" / "deep_locked" / "control_certificate_audit.csv")
    specbench = read_json(artifact / "results" / "deep_locked" / "specbench_cases.json")
    metamorphic = read_csv(artifact / "results" / "deep_locked" / "metamorphic_relation_cases.csv")
    baseline_probe = read_json(artifact / "results" / "deep_locked" / "external_baseline_fixture_probe.json")

    claim_ids = {row["claim_id"] for row in claims}
    rule_ids = {row["rule_id"] for row in rules}
    span_claim_ids = {row["claim_id"] for row in spans}
    fixture_ids = {str(f.get("id", "")) for f in fixtures}
    repair_ids = {str(r.get("id", "")) for r in repairs}
    witness_keys = {_witness_key(w) for w in witnesses}

    for source in source_manifest:
        sid = source.get("source_id", "")
        g.add_node(_node("source", sid), "source", source.get("source_name", sid), url=source.get("source_url", ""), version=source.get("source_version", ""))

    for span in spans:
        cid = span.get("claim_id", "")
        sid = span.get("source_id", "")
        g.add_node(_node("source_span", cid), "source_span", span.get("source_span", cid), evidence_kind=span.get("evidence_kind", ""), policy_family=span.get("policy_family", ""))
        g.add_edge(_node("source", sid), _node("source_span", cid), "contains_span")
        g.add_edge(_node("source_span", cid), _node("claim", cid), "supports_claim")

    for claim in claims:
        cid = claim.get("claim_id", "")
        g.add_node(_node("claim", cid), "claim", claim.get("explicit_claim_paraphrase", cid), policy_family=claim.get("policy_family", ""), intent_class=claim.get("intent_class", ""), claim_type=claim.get("claim_type", ""))
        for rid in split_semicolon(claim.get("semantic_rule_ids", "")):
            g.add_edge(_node("claim", cid), _node("rule", rid), "induces_rule")

    for rule in rules:
        rid = rule.get("rule_id", "")
        g.add_node(_node("rule", rid), "rule", rule.get("semantic_obligation", rid), policy_family=rule.get("policy_family", ""), proof_obligation=rule.get("proof_obligation", ""))
        for sid in split_semicolon(rule.get("source_ids", "")):
            g.add_edge(_node("source", sid), _node("rule", rid), "grounds_rule")

    for fixture in fixtures:
        fid = str(fixture.get("id", ""))
        role = str(fixture.get("fixture_role", ""))
        g.add_node(_node("fixture", fid), "fixture", fid, role=role, policy_family=fixture.get("policy_family", ""), expected_issue=fixture.get("expected_issue", ""), fixture_hash=fixture.get("fixture_hash", ""))
        for cid in _fixture_claims(fixture):
            g.add_edge(_node("claim", cid), _node("fixture", fid), "materializes_claim")
        if fixture.get("expected_issue"):
            g.add_edge(_node("fixture", fid), _node("issue", str(fixture.get("expected_issue"))), "expects_issue")
            g.add_node(_node("issue", str(fixture.get("expected_issue"))), "issue", str(fixture.get("expected_issue")))

    for witness in witnesses:
        fid, issue = _witness_key(witness)
        wid = f"{fid}::{issue}"
        g.add_node(_node("witness", wid), "witness", wid, policy_family=witness.get("policy_family", ""), severity=witness.get("severity", ""))
        g.add_edge(_node("fixture", fid), _node("witness", wid), "emits_witness")
        g.add_edge(_node("witness", wid), _node("issue", issue), "demonstrates_issue")

    for repair in repairs:
        rid = str(repair.get("id", ""))
        pos = str(repair.get("paired_positive_fixture_id", ""))
        issue = str(repair.get("paired_target_issue", ""))
        g.add_node(_node("repair", rid), "repair", rid, policy_family=repair.get("policy_family", ""), target_issue=issue, fixture_hash=repair.get("fixture_hash", ""))
        g.add_edge(_node("fixture", pos), _node("repair", rid), "paired_repair")
        g.add_edge(_node("repair", rid), _node("issue", issue), "removes_issue")
        for cid in _fixture_claims(repair):
            g.add_edge(_node("claim", cid), _node("repair", rid), "preserves_claim")

    for cert in certs:
        cid = str(cert.get("certificate_id", ""))
        fid, issue = _cert_key(cert)
        wid = f"{fid}::{issue}"
        g.add_node(_node("certificate", cid), "certificate", cid, fixture_id=fid, issue=issue)
        g.add_edge(_node("witness", wid), _node("certificate", cid), "certified_by")
        g.add_edge(_node("certificate", cid), _node("repair", str(cert.get("paired_repair_control_id", ""))), "checks_repair")
        for rid in [str(x) for x in cert.get("rule_ids", []) if str(x)]:
            g.add_edge(_node("rule", rid), _node("certificate", cid), "checked_in_certificate")
        for scid in [str(x) for x in cert.get("source_claim_ids", []) if str(x)]:
            g.add_edge(_node("claim", scid), _node("certificate", cid), "checked_in_certificate")

    for row in control_audit:
        fid = row.get("fixture_id", "")
        nid = f"NEG::{fid}"
        g.add_node(_node("negative_certificate", nid), "negative_certificate", fid, status=row.get("certificate_status", ""), role=row.get("fixture_role", ""))
        g.add_edge(_node("fixture", fid), _node("negative_certificate", nid), "clean_certificate")

    for case in specbench:
        cid = case.get("case_id", "")
        g.add_node(_node("specbench_case", cid), "specbench_case", cid, rule_id=case.get("rule_id", ""), role=case.get("role", ""), source_claim_id=case.get("source_claim_id", ""))
        if case.get("source_claim_id"):
            g.add_edge(_node("claim", str(case.get("source_claim_id"))), _node("specbench_case", cid), "benchmarks_claim_boundary")
        if case.get("rule_id"):
            g.add_edge(_node("rule", str(case.get("rule_id"))), _node("specbench_case", cid), "benchmarks_rule_boundary")

    for idx, row in enumerate(metamorphic):
        relation = row.get("relation", row.get("relation_id", "MR"))
        fid = row.get("fixture_id", row.get("source_fixture_id", ""))
        mid = row.get("case_id", f"MR::{idx:04d}")
        g.add_node(_node("metamorphic_case", mid), "metamorphic_case", mid, relation=relation, passed=row.get("passed", ""))
        if fid:
            g.add_edge(_node("fixture", fid), _node("metamorphic_case", mid), "metamorphic_variant")

    baseline_results = baseline_probe.get("results", []) if isinstance(baseline_probe, Mapping) else []
    status_counts: Dict[str, int] = {}
    for row in baseline_results:
        status = str(row.get("status", ""))
        status_counts[status] = status_counts.get(status, 0) + 1
        fid = str(row.get("fixture_id", ""))
        baseline = str(row.get("baseline", ""))
        bid = f"{baseline}::{fid}::{status}"
        g.add_node(_node("baseline_probe", bid), "baseline_probe", bid, baseline=baseline, status=status)
        g.add_edge(_node("fixture", fid), _node("baseline_probe", bid), "external_probe_status")

    path_rows: List[Dict[str, Any]] = []
    positive_ok = 0
    positive_problem_count = 0
    for cert in certs:
        ok, problems = _positive_path_ok(cert, fixture_ids, witness_keys, repair_ids, claim_ids, rule_ids, span_claim_ids)
        if ok:
            positive_ok += 1
        positive_problem_count += len(problems)
        path_rows.append({
            "path_type": "positive_witness",
            "fixture_id": cert.get("fixture_id", ""),
            "issue": cert.get("issue", ""),
            "certificate_id": cert.get("certificate_id", ""),
            "source_claim_ids": ";".join([str(x) for x in cert.get("source_claim_ids", []) if str(x)]),
            "rule_ids": ";".join([str(x) for x in cert.get("rule_ids", []) if str(x)]),
            "paired_repair_control_id": cert.get("paired_repair_control_id", ""),
            "path_verified": "yes" if ok else "no",
            "problems": ";".join(problems),
        })

    negative_ok = sum(1 for row in control_audit if row.get("certificate_status") == "verified" and row.get("operational_clean") == "yes" and row.get("decision_table_clean") == "yes")
    negative_problem_count = len(control_audit) - negative_ok

    graph_json = g.to_json()
    metrics = {
        "status": "pass" if positive_problem_count == 0 and negative_problem_count == 0 else "fail",
        "problem_count": positive_problem_count + negative_problem_count,
        "claims": len(claims),
        "rules": len(rules),
        "source_spans": len(spans),
        "fixtures": len(fixtures),
        "positive_witnesses": len(witnesses),
        "positive_certificates": len(certs),
        "positive_paths_verified": positive_ok,
        "negative_control_paths_verified": negative_ok,
        "paired_repairs": len(repairs),
        "specbench_cases_linked": len(specbench),
        "metamorphic_cases_linked": len(metamorphic),
        "baseline_probe_status_counts": dict(sorted(status_counts.items())),
        "node_count": graph_json["node_count"],
        "edge_count": graph_json["edge_count"],
        "graph_hash": graph_json["graph_hash"],
        "interpretation": "Evidence-graph closure verifies that every positive witness has a navigable claim/rule/fixture/witness/certificate/repair path and every negative control has a clean certificate path; auxiliary benchmark and baseline probes are linked without entering the locked denominator.",
    }
    return graph_json, metrics, path_rows


def write_json(path: Path, obj: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def write_paths(path: Path, rows: Sequence[Mapping[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fieldnames = ["path_type", "fixture_id", "issue", "certificate_id", "source_claim_ids", "rule_ids", "paired_repair_control_id", "path_verified", "problems"]
    with path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow({k: row.get(k, "") for k in fieldnames})
