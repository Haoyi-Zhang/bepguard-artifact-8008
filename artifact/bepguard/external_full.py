"""Executable external comparator runner for BEPGuard.

This module runs public, unmodified Node packages against the released BEP-Deep
fixtures from a caller-supplied npm work directory.  It does not vendor
``node_modules`` into the artifact and it does not use cached package outputs.
The resulting materialized JSON is a fixture-level comparison record, not an
oracle replacement: external comparators keep their own task definitions and
are summarized separately from BEP semantic judgments.
"""
from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any, Dict, Mapping, Sequence

sys.dont_write_bytecode = True

JS_RUNNER = r"""
import fs from 'node:fs';
import path from 'node:path';
import {createRequire} from 'node:module';
import {CspEvaluator} from 'csp_evaluator/dist/evaluator.js';
import {CspParser} from 'csp_evaluator/dist/parser.js';
import {contentSecurityPolicyTest} from './node_modules/@mdn/mdn-http-observatory/src/analyzer/tests/csp.js';
import {crossOriginResourceSharingTest} from './node_modules/@mdn/mdn-http-observatory/src/analyzer/tests/cors.js';
import {crossOriginResourcePolicyTest} from './node_modules/@mdn/mdn-http-observatory/src/analyzer/tests/cross-origin-resource-policy.js';

const require = createRequire(import.meta.url);
const hstsModule = require('@hint/hint-strict-transport-security');
const StrictTransportSecurityHint = hstsModule.default || hstsModule;

const fixturesPath = process.argv[2];
const outPath = process.argv[3];
const fixtures = JSON.parse(fs.readFileSync(fixturesPath, 'utf8'));

function packageInfo(name) {
  const pkg = JSON.parse(fs.readFileSync(path.join('node_modules', name, 'package.json'), 'utf8'));
  return {name, version: pkg.version || '', license: pkg.license || '', repository: pkg.repository || ''};
}

function headerValues(headers, wanted) {
  const key = wanted.toLowerCase();
  const values = [];
  for (const h of headers || []) {
    if (String(h.name || '').toLowerCase() === key) values.push(String(h.value || ''));
  }
  return values;
}

function lowerHeaderObject(headers) {
  const out = {};
  for (const h of headers || []) {
    const key = String(h.name || '').toLowerCase();
    const value = String(h.value || '');
    if (!key) continue;
    if (Object.prototype.hasOwnProperty.call(out, key)) {
      if (Array.isArray(out[key])) out[key].push(value);
      else out[key] = [out[key], value];
    } else {
      out[key] = value;
    }
  }
  Object.defineProperty(out, 'get', {
    enumerable: false,
    value: (name) => {
      const value = out[String(name || '').toLowerCase()];
      return Array.isArray(value) ? value.join(', ') : (value ?? null);
    }
  });
  return out;
}

function requestObject(fixture) {
  const ctx = fixture.context || {};
  const headers = lowerHeaderObject(fixture.headers || []);
  const requestOrigin = String(ctx.request_origin || ctx.document_origin || 'https://app.example');
  const body = '<!doctype html><html><head></head><body>BEPGuard fixture</body></html>';
  const response = {
    status: 200,
    statusCode: 200,
    headers,
    data: body,
    request: {headers: {origin: requestOrigin}},
    verified: true,
  };
  return {
    responses: {
      auto: response,
      cors: {...response, request: {headers: {origin: requestOrigin}}},
    },
    resources: {path: null},
    session: {url: new URL('https://example.test/')},
    site: {hostname: 'example.test'},
  };
}

function compact(value) {
  if (value === null || value === undefined) return value;
  const text = JSON.stringify(value);
  if (text.length <= 1800) return value;
  return {sha256: sha256(text), truncated: true, prefix: text.slice(0, 600)};
}

function sha256(text) {
  return require('node:crypto').createHash('sha256').update(String(text)).digest('hex');
}

function runCspEvaluator(fixture, rows) {
  const headers = fixture.headers || [];
  const policies = [
    ...headerValues(headers, 'Content-Security-Policy').map((value) => ({delivery: 'enforce', value})),
    ...headerValues(headers, 'Content-Security-Policy-Report-Only').map((value) => ({delivery: 'report-only', value})),
  ];
  for (const [idx, policy] of policies.entries()) {
    try {
      const parsed = new CspParser(policy.value).csp;
      const findings = new CspEvaluator(parsed).evaluate();
      rows.push({baseline: 'csp_evaluator', fixture_id: fixture.id, status: 'available', invocation_index: idx, delivery: policy.delivery, raw: compact(findings.map((f) => ({type: f.type, severity: f.severity, description: f.description}))), flagged: findings.length > 0});
    } catch (err) {
      rows.push({baseline: 'csp_evaluator', fixture_id: fixture.id, status: 'error', invocation_index: idx, delivery: policy.delivery, error: String(err && err.message || err)});
    }
  }
}

function runMdnHeaderTests(fixture, rows) {
  const requests = requestObject(fixture);
  const tests = [
    ['mdn_http_observatory_csp', contentSecurityPolicyTest],
    ['mdn_http_observatory_cors', crossOriginResourceSharingTest],
    ['mdn_http_observatory_corp', crossOriginResourcePolicyTest],
  ];
  for (const [baseline, fn] of tests) {
    try {
      const result = fn(requests);
      rows.push({baseline, fixture_id: fixture.id, status: 'available', raw: compact(result), flagged: result.pass === false, result: result.result || null, pass: result.pass});
    } catch (err) {
      rows.push({baseline, fixture_id: fixture.id, status: 'error', error: String(err && err.message || err)});
    }
  }
}

async function runWebhintHsts(fixture, rows) {
  const ctx = fixture.context || {};
  const scheme = String(ctx.scheme || 'https').toLowerCase() === 'http' ? 'http' : 'https';
  const headers = lowerHeaderObject(fixture.headers || []);
  const reports = [];
  let callback = null;
  const context = {
    language: 'en',
    hintOptions: {minMaxAgeValue: 10886400, checkPreload: false},
    on: (_event, handler) => { callback = handler; },
    report: (resource, message, options) => { reports.push({resource, message, severity: options?.severity ?? null}); },
    fetchContent: async () => null,
  };
  try {
    new StrictTransportSecurityHint(context);
    if (!callback) throw new Error('webhint did not register fetch::end handler');
    await callback({element: null, resource: `${scheme}://example.test/`, response: {headers, statusCode: 200}});
    rows.push({baseline: 'webhint_strict_transport_security', fixture_id: fixture.id, status: 'available', raw: compact(reports), flagged: reports.length > 0, report_count: reports.length});
  } catch (err) {
    rows.push({baseline: 'webhint_strict_transport_security', fixture_id: fixture.id, status: 'error', error: String(err && err.message || err)});
  }
}

const rows = [];
for (const fixture of fixtures) {
  runCspEvaluator(fixture, rows);
  runMdnHeaderTests(fixture, rows);
  await runWebhintHsts(fixture, rows);
}

const byBaseline = {};
const byStatus = {};
for (const row of rows) {
  byBaseline[row.baseline] = (byBaseline[row.baseline] || 0) + 1;
  byStatus[row.status] = (byStatus[row.status] || 0) + 1;
}
const payload = {
  schema: 'BEPGuardExternalBaselineFullRun/v1',
  status: rows.every((r) => r.status === 'available') ? 'pass' : 'fail',
  fixture_file: 'artifact/data/deep_locked_fixtures.json',
  fixtures_evaluated: fixtures.length,
  rows,
  summary: {
    package_info: [
      packageInfo('csp_evaluator'),
      packageInfo('@mdn/mdn-http-observatory'),
      packageInfo('@hint/hint-strict-transport-security'),
    ],
    rows_total: rows.length,
    rows_by_baseline: byBaseline,
    rows_by_status: byStatus,
    unavailable_rows: rows.filter((r) => r.status === 'unavailable').length,
    error_rows: rows.filter((r) => r.status === 'error').length,
    interpretation: 'Full fixture-level execution of public comparator analyzers from a caller-supplied package work directory. These outputs are contrastive baselines, not replacements for the BEP semantic oracle.',
  },
};
payload.summary.result_sha256 = sha256(JSON.stringify(payload.rows));
fs.writeFileSync(outPath, JSON.stringify(payload, null, 2) + '\n', 'utf8');
console.log(JSON.stringify({status: payload.status, rows: rows.length, fixtures: fixtures.length, byBaseline}));
"""


def sha256_path(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def run_external_full(root: Path, fixtures: Path, out: Path, node_workdir: Path) -> Dict[str, Any]:
    node_workdir = node_workdir.resolve()
    if not (node_workdir / "node_modules").is_dir():
        raise FileNotFoundError(f"node_modules not found in {node_workdir}")
    out.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile("w", suffix=".mjs", dir=node_workdir, delete=False, encoding="utf-8") as fh:
        fh.write(JS_RUNNER)
        script = Path(fh.name)
    try:
        cp = subprocess.run(
            ["node", str(script), str(fixtures.resolve()), str(out.resolve())],
            cwd=str(node_workdir),
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=180,
            check=False,
        )
    finally:
        try:
            script.unlink()
        except OSError:
            pass
    if cp.returncode != 0:
        raise RuntimeError(f"external baseline runner failed rc={cp.returncode}\nSTDOUT={cp.stdout[-1000:]}\nSTDERR={cp.stderr[-2000:]}")
    result = json.loads(out.read_text(encoding="utf-8"))
    lock = build_package_lock(node_workdir, result)
    lock_path = root / "artifact" / "external_baseline_package_lock.json"
    lock_path.write_text(json.dumps(lock, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return result


def build_package_lock(node_workdir: Path, result: Mapping[str, Any]) -> Dict[str, Any]:
    package_lock = node_workdir / "package-lock.json"
    package_json = node_workdir / "package.json"
    return {
        "schema": "BEPGuardExternalPackageLock/v1",
        "status": "pass",
        "node_workdir_packaged": False,
        "node_modules_packaged": False,
        "cache_packaged": False,
        "package_lock_sha256": sha256_path(package_lock) if package_lock.exists() else "",
        "package_json_sha256": sha256_path(package_json) if package_json.exists() else "",
        "packages": result.get("summary", {}).get("package_info", []),
        "interpretation": "Public comparator packages are installed outside the released artifact for execution; only version/lock metadata and materialized outputs are released so node_modules and package-manager caches are not shipped.",
    }


def summarize_external_full(result: Mapping[str, Any]) -> Dict[str, Any]:
    summary = dict(result.get("summary", {}))
    rows_by_baseline = dict(summary.get("rows_by_baseline", {}))
    required = {
        "csp_evaluator",
        "mdn_http_observatory_csp",
        "mdn_http_observatory_cors",
        "mdn_http_observatory_corp",
        "webhint_strict_transport_security",
    }
    problems = []
    if int(result.get("fixtures_evaluated", -1)) != 972:
        problems.append("fixture count is not 972")
    if required - set(rows_by_baseline):
        problems.append("missing baselines: " + ",".join(sorted(required - set(rows_by_baseline))))
    if summary.get("error_rows", 0) != 0:
        problems.append(f"error rows present: {summary.get('error_rows')}")
    if summary.get("unavailable_rows", 0) != 0:
        problems.append(f"unavailable rows present: {summary.get('unavailable_rows')}")
    if int(summary.get("rows_total", 0)) < 4000:
        problems.append("too few external baseline invocations")
    return {
        "schema": "BEPGuardExternalBaselineFullRunAudit/v1",
        "status": "pass" if not problems else "fail",
        "problem_count": len(problems),
        "problems": problems,
        "fixtures_evaluated": result.get("fixtures_evaluated"),
        "rows_total": summary.get("rows_total"),
        "rows_by_baseline": rows_by_baseline,
        "rows_by_status": summary.get("rows_by_status", {}),
        "unavailable_rows": summary.get("unavailable_rows", 0),
        "error_rows": summary.get("error_rows", 0),
        "result_sha256": summary.get("result_sha256", ""),
        "interpretation": "Audit over materialized external comparator executions. Pass means the released baseline comparison contains public-package outputs from the supplied package work directory for every BEP-Deep fixture under the executable comparator tasks.",
    }


def write_json(path: Path, obj: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=2, sort_keys=True) + "\n", encoding="utf-8")
