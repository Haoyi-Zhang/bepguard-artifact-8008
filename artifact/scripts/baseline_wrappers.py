#!/usr/bin/env python3
"""Local wrappers for unmodified browser-policy baseline tools.

The wrappers adapt project fixtures to baseline inputs. They do not implement the
external baseline checks themselves and do not modify external tool internals.
Unavailable external baselines are reported explicitly. Public-network scans are
not performed by these wrappers.
"""
from __future__ import annotations

import sys
sys.dont_write_bytecode = True

import argparse
import json
import os
import re
import shutil
import subprocess
import tempfile
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Dict, Iterable, List, Optional


@dataclass(frozen=True)
class BaselineResult:
    baseline: str
    fixture_id: str
    status: str
    returncode: Optional[int]
    stdout: str
    stderr: str
    notes: str


def sanitize_output(text: str, limit: int = 160) -> str:
    scrubbed = re.sub(r"/(?:home|mnt|tmp|var|opt)/[^\s\"]+", "<local-path>", text)
    scrubbed = re.sub(r"npm error A complete log of this run can be found in:.*", "", scrubbed)
    scrubbed = " ".join(scrubbed.split())
    return scrubbed[:limit]


def _run(
    cmd: List[str],
    timeout: int = 20,
    input_text: Optional[str] = None,
    cwd: Optional[str] = None,
    env: Optional[Dict[str, str]] = None,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        cmd,
        input=input_text,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=timeout,
        check=False,
        cwd=cwd,
        env=env,
    )


def load_fixtures(path: str) -> List[Dict[str, object]]:
    with open(path, "r", encoding="utf-8") as fh:
        data = json.load(fh)
    if not isinstance(data, list):
        raise ValueError("fixture file must contain a JSON list")
    return data


def header_value(headers: Iterable[Dict[str, str]], name: str) -> Optional[str]:
    lname = name.lower()
    for h in headers:
        if h.get("name", "").lower() == lname:
            return h.get("value", "")
    return None


def run_csp_evaluator(fixture: Dict[str, object]) -> BaselineResult:
    fixture_id = str(fixture.get("id", "unknown"))
    headers = fixture.get("headers", [])
    if not isinstance(headers, list):
        headers = []
    csp = header_value(headers, "Content-Security-Policy") or header_value(headers, "Content-Security-Policy-Report-Only")
    if not csp:
        return BaselineResult("csp_evaluator", fixture_id, "not_applicable", None, "", "", "fixture has no CSP header")
    node = shutil.which("node")
    if not node:
        return BaselineResult("csp_evaluator", fixture_id, "unavailable", None, "", "", "node is not available")

    js = """
import {CspEvaluator} from 'csp_evaluator/dist/evaluator.js';
import {CspParser} from 'csp_evaluator/dist/parser.js';
const policy = process.argv[2];
const parsed = new CspParser(policy).csp;
const findings = new CspEvaluator(parsed).evaluate();
console.log(JSON.stringify(findings));
""".strip()
    node_workdir = os.environ.get("BEP_NODE_WORKDIR")
    temp_kwargs = {"mode": "w", "suffix": ".mjs", "delete": False, "encoding": "utf-8"}
    if node_workdir:
        Path(node_workdir).mkdir(parents=True, exist_ok=True)
        temp_kwargs["dir"] = node_workdir
    with tempfile.NamedTemporaryFile(**temp_kwargs) as fh:
        fh.write(js)
        temp_script = fh.name
    try:
        cp = _run([node, temp_script, csp], timeout=20, cwd=node_workdir)
    except Exception as exc:  # pragma: no cover
        return BaselineResult("csp_evaluator", fixture_id, "error", None, "", sanitize_output(str(exc)), "wrapper failed before baseline returned")
    finally:
        try:
            os.unlink(temp_script)
        except OSError:
            pass
    if cp.returncode != 0:
        return BaselineResult("csp_evaluator", fixture_id, "error", cp.returncode, "", "baseline_not_available_or_failed", "package may be absent; no fallback substituted")
    return BaselineResult("csp_evaluator", fixture_id, "available", 0, sanitize_output(cp.stdout, 5000), "", "unmodified npm package import")


def run_hsts_preload_helper(fixture: Dict[str, object], helper_path: Optional[str]) -> BaselineResult:
    fixture_id = str(fixture.get("id", "unknown"))
    headers = fixture.get("headers", [])
    if not isinstance(headers, list):
        headers = []
    hsts = header_value(headers, "Strict-Transport-Security")
    if not hsts:
        return BaselineResult("chromium_hstspreload", fixture_id, "not_applicable", None, "", "", "fixture has no HSTS header")
    helper = helper_path or os.environ.get("HSTSPRELOAD_HELPER") or "artifact/bin/hstspreload_header_helper"
    if not Path(helper).exists():
        return BaselineResult("chromium_hstspreload", fixture_id, "unavailable", None, "", "", "compiled helper absent; build from pinned Go module for executable baseline")
    cp = _run([helper, hsts], timeout=20)
    if cp.returncode != 0:
        return BaselineResult("chromium_hstspreload", fixture_id, "error", cp.returncode, "", "baseline_not_available_or_failed", "unmodified hstspreload module via project Go helper")
    return BaselineResult("chromium_hstspreload", fixture_id, "available", 0, sanitize_output(cp.stdout, 5000), "", "unmodified hstspreload module via project Go helper")


def run_mdn_observatory(host: str) -> BaselineResult:
    allowed_prefixes = ("localhost", "127.0.0.1", "localhost:", "127.0.0.1:")
    if not host.startswith(allowed_prefixes):
        return BaselineResult("mdn_http_observatory", host, "excluded", None, "", "", "non-local scan target refused")
    direct = os.environ.get("MDN_OBSERVATORY_BIN") or shutil.which("mdn-http-observatory-scan")
    if not direct:
        return BaselineResult(
            "mdn_http_observatory",
            host,
            "unavailable",
            None,
            "",
            "",
            "local CLI not found; npx is intentionally not invoked during smoke tests and no fallback is substituted",
        )
    cp = _run([direct, host], timeout=30)
    if cp.returncode != 0:
        return BaselineResult("mdn_http_observatory", host, "error", cp.returncode, "", "baseline_not_available_or_failed", "unmodified local CLI against local fixture host")
    return BaselineResult("mdn_http_observatory", host, "available", 0, sanitize_output(cp.stdout, 5000), "", "unmodified local CLI against local fixture host")

def availability_probe(helper_path: Optional[str]) -> Dict[str, object]:
    tool_paths = {name: shutil.which(name) for name in ["python3", "node", "npm", "go", "mdn-http-observatory-scan"]}
    helper = helper_path or os.environ.get("HSTSPRELOAD_HELPER") or "artifact/bin/hstspreload_header_helper"
    probes: Dict[str, object] = {
        "tools_available": {name: bool(path) for name, path in tool_paths.items()},
        "packages": {},
    }
    probes["tools_available"]["hstspreload_header_helper"] = Path(helper).exists()

    if tool_paths.get("node"):
        node_workdir = os.environ.get("BEP_NODE_WORKDIR")
        cp = _run(["node", "-e", "import('csp_evaluator/dist/evaluator.js').then(()=>process.exit(0)).catch(()=>process.exit(2))"], timeout=8, cwd=node_workdir)
        probes["packages"]["csp_evaluator"] = {"available": cp.returncode == 0, "returncode": cp.returncode}
    else:
        probes["packages"]["csp_evaluator"] = {"available": False, "returncode": None}

    if tool_paths.get("mdn-http-observatory-scan"):
        cp = _run([tool_paths["mdn-http-observatory-scan"], "--help"], timeout=8)
        probes["packages"]["mdn_http_observatory"] = {"available": cp.returncode == 0, "returncode": cp.returncode}
    else:
        probes["packages"]["mdn_http_observatory"] = {"available": False, "returncode": None, "note": "local CLI not found; npx intentionally not invoked in smoke tests"}

    if Path(helper).exists():
        cp = _run([helper, "max-age=31536000; includeSubDomains; preload"], timeout=8)
        probes["packages"]["chromium_hstspreload"] = {"available": cp.returncode == 0, "returncode": cp.returncode}
    else:
        probes["packages"]["chromium_hstspreload"] = {"available": False, "returncode": None}
    return probes

def main() -> None:
    parser = argparse.ArgumentParser(description="Run baseline wrapper probes or fixture-level wrappers.")
    parser.add_argument("--fixtures", default="artifact/data/locked_full_fixtures.json")
    parser.add_argument("--out", default="artifact/results/baseline_probe.json")
    parser.add_argument("--mode", choices=["availability", "fixture-probe"], default="availability")
    parser.add_argument("--observatory-host", default="localhost:8765")
    parser.add_argument("--hstspreload-helper", default=None)
    args = parser.parse_args()

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)

    if args.mode == "availability":
        result = availability_probe(args.hstspreload_helper)
    else:
        fixtures = load_fixtures(args.fixtures)
        availability = availability_probe(args.hstspreload_helper)
        packages = availability.get("packages", {}) if isinstance(availability, dict) else {}
        tools = availability.get("tools_available", {}) if isinstance(availability, dict) else {}
        csp_available = bool(packages.get("csp_evaluator", {}).get("available"))
        hsts_available = bool(tools.get("hstspreload_header_helper"))
        mdn_available = bool(packages.get("mdn_http_observatory", {}).get("available"))

        rows: List[Dict[str, object]] = []
        for fixture in fixtures:
            fixture_id = str(fixture.get("id", "unknown"))
            headers = fixture.get("headers", [])
            if not isinstance(headers, list):
                headers = []
            has_csp = bool(header_value(headers, "Content-Security-Policy") or header_value(headers, "Content-Security-Policy-Report-Only"))
            has_hsts = bool(header_value(headers, "Strict-Transport-Security"))
            if csp_available:
                rows.append(asdict(run_csp_evaluator(fixture)))
            else:
                rows.append(asdict(BaselineResult(
                    "csp_evaluator", fixture_id, "not_applicable" if not has_csp else "unavailable",
                    None, "", "", "availability probe failed; fixture-level baseline invocation not executed because the external baseline is unavailable; no fallback substituted"
                )))
            if hsts_available:
                rows.append(asdict(run_hsts_preload_helper(fixture, args.hstspreload_helper)))
            else:
                rows.append(asdict(BaselineResult(
                    "chromium_hstspreload", fixture_id, "not_applicable" if not has_hsts else "unavailable",
                    None, "", "", "compiled helper absent; fixture-level baseline invocation not executed because the external baseline is unavailable; no fallback substituted"
                )))
        if mdn_available:
            rows.append(asdict(run_mdn_observatory(args.observatory_host)))
        else:
            rows.append(asdict(BaselineResult(
                "mdn_http_observatory", args.observatory_host, "unavailable", None, "", "",
                "local CLI unavailable; no local scan attempted and no project fallback substituted"
            )))
        result = {"availability": availability, "results": rows}

    with out_path.open("w", encoding="utf-8") as fh:
        json.dump(result, fh, indent=2, sort_keys=True)
        fh.write("\n")
    print(json.dumps({"out": str(out_path), "mode": args.mode}, sort_keys=True))


if __name__ == "__main__":
    main()
