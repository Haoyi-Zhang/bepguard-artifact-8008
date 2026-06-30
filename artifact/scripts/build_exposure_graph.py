#!/usr/bin/env python3
"""Build a typed effective-exposure graph from fixtures and witness output.

The graph is a research object: it connects admitted claims, source-grounded
fixtures, generated policy surfaces, context edges, effective judgments, and
semantic conflict issues. It supports path-level auditing of why a witness was
emitted without depending on live websites or browser accounts.
"""
from __future__ import annotations

import sys
sys.dont_write_bytecode = True

import argparse
import csv
import json
from collections import Counter, defaultdict, deque
from pathlib import Path
from typing import Dict, Iterable, List, Set, Tuple


def read_json(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


def add_node(nodes: Dict[str, Dict[str, object]], node_id: str, node_type: str, **attrs: object) -> None:
    if node_id not in nodes:
        nodes[node_id] = {"id": node_id, "type": node_type, **attrs}
    else:
        nodes[node_id].update({k: v for k, v in attrs.items() if k not in nodes[node_id]})


def add_edge(edges: List[Dict[str, object]], src: str, dst: str, edge_type: str, **attrs: object) -> None:
    edges.append({"source": src, "target": dst, "type": edge_type, **attrs})


def header_node_id(fixture_id: str, index: int, header: Dict[str, str]) -> str:
    return f"header:{fixture_id}:{index}:{header.get('name','')}"


def context_nodes(fixture_id: str, context: Dict[str, object]) -> Iterable[Tuple[str, str]]:
    keys = ["document_origin", "resource_origin", "request_origin", "credentials_mode", "scheme", "request_mode", "feature", "static_render", "shared_cache", "target_origin", "subdomain_request"]
    for key in keys:
        if key in context:
            yield f"ctx:{fixture_id}:{key}={context[key]}", key


def shortest_path(adj: Dict[str, List[str]], start: str, goals: Set[str]) -> List[str]:
    q = deque([(start, [start])])
    seen = {start}
    while q:
        node, path = q.popleft()
        if node in goals:
            return path
        for nxt in adj.get(node, []):
            if nxt not in seen:
                seen.add(nxt)
                q.append((nxt, path + [nxt]))
    return []


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--fixtures", default="artifact/data/extended_fixtures.json")
    ap.add_argument("--witnesses", default="artifact/results/extended_locked/full_witnesses.json")
    ap.add_argument("--out-dir", default="artifact/results/extended_locked")
    ap.add_argument("--certificates", default="")
    ap.add_argument("--paired-repairs", default="")
    args = ap.parse_args()
    fixtures = read_json(Path(args.fixtures))
    witnesses = read_json(Path(args.witnesses))
    out_dir = Path(args.out_dir)
    nodes: Dict[str, Dict[str, object]] = {}
    edges: List[Dict[str, object]] = []
    issue_nodes: Set[str] = set()

    for fixture in fixtures:
        fid = str(fixture["id"])
        fnode = f"fixture:{fid}"
        add_node(nodes, fnode, "fixture", policy_family=fixture.get("policy_family", ""), expected_issue=fixture.get("expected_issue", "none"), mutation_operator_class=fixture.get("mutation_operator_class", "locked_seed"))
        for cid in fixture.get("source_claim_ids", []):
            cnode = f"claim:{cid}"
            add_node(nodes, cnode, "claim")
            add_edge(edges, cnode, fnode, "instantiated_by")
        intent = fixture.get("intent", {}) if isinstance(fixture.get("intent"), dict) else {}
        inode = f"intent:{fid}:{intent.get('class','unspecified')}"
        add_node(nodes, inode, "intent", intent_class=intent.get("class", "unspecified"))
        add_edge(edges, fnode, inode, "has_intent")
        for i, header in enumerate(fixture.get("headers", [])):
            hnode = header_node_id(fid, i, header)
            add_node(nodes, hnode, "generated_policy_surface", header_name=header.get("name", ""), header_value=header.get("value", ""))
            add_edge(edges, fnode, hnode, "emits")
            add_edge(edges, inode, hnode, "constrains_or_expects")
        ctx = fixture.get("context", {}) if isinstance(fixture.get("context"), dict) else {}
        for cnode, key in context_nodes(fid, ctx):
            add_node(nodes, cnode, "context", context_key=key)
            add_edge(edges, fnode, cnode, "has_context")

    for w in witnesses:
        fid = str(w.get("fixture_id", ""))
        issue = str(w.get("issue", ""))
        inode = f"issue:{issue}"
        jnode = f"judgment:{fid}:{issue}"
        fnode = f"fixture:{fid}"
        add_node(nodes, inode, "issue", issue=issue, severity=w.get("severity", ""), policy_family=w.get("policy_family", ""))
        add_node(nodes, jnode, "effective_judgment", issue=issue, severity=w.get("severity", ""), intent_class=w.get("intent_class", ""))
        issue_nodes.add(inode)
        add_edge(edges, fnode, jnode, "evaluates_to")
        add_edge(edges, jnode, inode, "classified_as")
        witness = w.get("witness", {}) if isinstance(w.get("witness"), dict) else {}
        for header in witness.get("headers", []) if isinstance(witness.get("headers", []), list) else []:
            hname = str(header.get("name", ""))
            for node_id, attrs in nodes.items():
                if attrs.get("type") == "generated_policy_surface" and node_id.startswith(f"header:{fid}:") and attrs.get("header_name") == hname:
                    add_edge(edges, node_id, jnode, "participates_in_judgment")
        for node_id, attrs in list(nodes.items()):
            if attrs.get("type") == "context" and node_id.startswith(f"ctx:{fid}:"):
                add_edge(edges, node_id, jnode, "contextualizes_judgment")


    # Optional proof-carrying witness certificates and paired repair controls.
    cert_path = Path(args.certificates) if args.certificates else None
    if cert_path and cert_path.exists():
        certs = read_json(cert_path)
        for cert in certs:
            fid = str(cert.get("fixture_id", ""))
            cid = str(cert.get("certificate_id", f"cert:{fid}"))
            cnode = f"certificate:{cid}"
            issue = str(cert.get("issue", ""))
            fnode = f"fixture:{fid}"
            add_node(nodes, cnode, "proof_carrying_certificate", issue=issue, policy_family=cert.get("policy_family", ""))
            add_edge(edges, fnode, cnode, "certified_by")
            add_edge(edges, cnode, f"issue:{issue}", "certifies_issue")
            for scid in cert.get("source_claim_ids", []):
                add_node(nodes, f"claim:{scid}", "claim")
                add_edge(edges, f"claim:{scid}", cnode, "supports_certificate")
            for rid in cert.get("rule_ids", []):
                rnode = f"rule:{rid}"
                add_node(nodes, rnode, "semantic_rule", rule_id=rid)
                add_edge(edges, rnode, cnode, "used_by_certificate")
            repid = str(cert.get("paired_repair_control_id", ""))
            if repid:
                rnode = f"fixture:{repid}"
                add_node(nodes, rnode, "fixture", policy_family=cert.get("policy_family", ""), expected_issue="none", mutation_operator_class="paired_repair_negative_control")
                add_edge(edges, cnode, rnode, "validated_by_repair_control")
    repair_path = Path(args.paired_repairs) if args.paired_repairs else None
    if repair_path and repair_path.exists():
        repairs = read_json(repair_path)
        for r in repairs:
            pid = str(r.get("paired_positive_fixture_id", ""))
            rid = str(r.get("id", ""))
            if pid and rid:
                add_edge(edges, f"fixture:{pid}", f"fixture:{rid}", "counterfactual_repair_control")

    adj: Dict[str, List[str]] = defaultdict(list)
    for e in edges:
        adj[str(e["source"])].append(str(e["target"]))

    path_rows: List[Dict[str, object]] = []
    for node_id, attrs in nodes.items():
        if attrs.get("type") != "claim":
            continue
        path = shortest_path(adj, node_id, issue_nodes)
        if path:
            path_rows.append({"claim_node": node_id, "issue_node": path[-1], "path_length": len(path) - 1, "path": " -> ".join(path)})

    type_counts = Counter(str(v.get("type", "")) for v in nodes.values())
    edge_counts = Counter(str(e.get("type", "")) for e in edges)
    issue_counts = Counter(str(nodes[i].get("issue", "")) for i in issue_nodes)
    cross_policy_issues = [i for i in issue_nodes if "/" in str(nodes[i].get("policy_family", "")) or "composition" in str(nodes[i].get("policy_family", ""))]
    metrics = {
        "nodes": len(nodes),
        "edges": len(edges),
        "node_type_counts": dict(type_counts),
        "edge_type_counts": dict(edge_counts),
        "issue_node_count": len(issue_nodes),
        "issue_counts": dict(issue_counts),
        "claim_to_issue_paths": len(path_rows),
        "avg_claim_to_issue_path_length": round(sum(int(r["path_length"]) for r in path_rows) / len(path_rows), 3) if path_rows else 0,
        "cross_policy_issue_nodes": len(cross_policy_issues),
        "interpretation": "Typed effective-exposure graph over deterministic fixtures and witnesses; not a live traffic graph.",
    }
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "effective_exposure_graph.json").write_text(json.dumps({"nodes": list(nodes.values()), "edges": edges}, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    (out_dir / "effective_exposure_graph_metrics.json").write_text(json.dumps(metrics, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    with (out_dir / "effective_exposure_graph_paths.csv").open("w", newline="", encoding="utf-8") as fh:
        fieldnames = ["claim_node", "issue_node", "path_length", "path"]
        w = csv.DictWriter(fh, fieldnames=fieldnames)
        w.writeheader(); w.writerows(path_rows)
    print(json.dumps(metrics, sort_keys=True))


if __name__ == "__main__":
    main()
