#!/usr/bin/env python3
"""Compile paper sources in an isolated directory and check PDF-level invariants.

This gate catches source-level failures that rendered PDFs alone can hide: BibTeX
metadata errors, undefined citations, page-count drift, and reference-page drift.
It compiles in a temporary directory and leaves no LaTeX intermediates in the
release package.
"""
from __future__ import annotations
import sys
sys.dont_write_bytecode = True

import argparse, json, os, re, shutil, subprocess, tempfile
from types import SimpleNamespace
from pathlib import Path


def run(cmd, cwd: Path, timeout: int):
    env = dict(os.environ)
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    # LaTeX can emit large logs on early passes.  Keep only a bounded tail so
    # the release validation gate is stable in memory-constrained environments.
    with tempfile.NamedTemporaryFile("w+b", delete=False) as fh:
        tmp_name = fh.name
        proc = subprocess.run(cmd, cwd=str(cwd), stdout=fh, stderr=subprocess.STDOUT, timeout=timeout, env=env)
    try:
        data = Path(tmp_name).read_bytes()[-20000:]
        text = data.decode("utf-8", errors="replace")
    finally:
        try:
            Path(tmp_name).unlink()
        except FileNotFoundError:
            pass
    return SimpleNamespace(returncode=proc.returncode, stdout=text, stderr="")


def find_bibtex() -> str | None:
    """Return a usable BibTeX executable, not merely a PATH hit.

    Some minimal TeX installations leave the default BibTeX launcher as a
    dangling alternatives entry while bibtex.original is present.  A source-compile
    gate must therefore validate the candidate before selecting it.
    """
    for name in ["bibtex.original", "bibtex", "bibtex8", "bibtexu"]:
        candidate = shutil.which(name)
        if not candidate:
            continue
        try:
            probe = subprocess.run([candidate, "--version"], text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=5)
        except (OSError, subprocess.SubprocessError):
            continue
        if probe.returncode == 0:
            return candidate
    return None


def pdf_pages(pdf: Path) -> int | None:
    p = subprocess.run(["pdfinfo", str(pdf)], text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30)
    if p.returncode != 0:
        return None
    m = re.search("^Pages:" + r"\s+([0-9]+)", p.stdout, re.M)
    return int(m.group(1)) if m else None


def pdf_text(pdf: Path, first: int | None = None, last: int | None = None) -> str:
    cmd = ["pdftotext"]
    if first is not None:
        cmd += ["-f", str(first)]
    if last is not None:
        cmd += ["-l", str(last)]
    cmd += [str(pdf), "-"]
    p = subprocess.run(cmd, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30)
    return p.stdout if p.returncode == 0 else ""


def log_has_problem(text: str) -> list[str]:
    problems = []
    if re.search(r"undefined citations?|Citation .* undefined|There were undefined references", text, re.I):
        problems.append("undefined citation/reference warning")
    if re.search(r"Overfull \\hbox", text):
        problems.append("overfull hbox warning")
    if re.search(r"! LaTeX Error|Emergency stop|Fatal error", text, re.I):
        problems.append("LaTeX fatal/error marker")
    return problems


def compile_one(work: Path, stem: str, use_bib: bool, bibtex_cmd: str | None):
    logs = []
    p = run(["pdflatex", "-interaction=nonstopmode", f"{stem}.tex"], work, 120)
    logs.append((f"{stem}-pdflatex-1", p.returncode, p.stdout + p.stderr))
    if p.returncode != 0:
        return logs
    if use_bib:
        if not bibtex_cmd:
            logs.append((f"{stem}-bibtex", 127, "No BibTeX executable found"))
            return logs
        b = run([bibtex_cmd, stem], work, 60)
        logs.append((f"{stem}-bibtex", b.returncode, b.stdout + b.stderr))
        if b.returncode != 0:
            return logs
    for i in [2, 3]:
        p = run(["pdflatex", "-interaction=nonstopmode", f"{stem}.tex"], work, 120)
        logs.append((f"{stem}-pdflatex-{i}", p.returncode, p.stdout + p.stderr))
        if p.returncode != 0:
            return logs
    return logs


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", default=".")
    ap.add_argument("--out", default="artifact/results/pdf_source_compile_audit.json")
    args = ap.parse_args()
    root = Path(args.root).resolve()
    problems = []
    details = {}
    bibtex_cmd = find_bibtex()
    with tempfile.TemporaryDirectory(prefix="bep_latex_compile_") as td:
        work_root = Path(td)
        shutil.copytree(root / "paper", work_root / "paper")
        work = work_root / "paper"
        logs = compile_one(work, "main", True, bibtex_cmd)
        details["main_steps"] = [{"step": n, "returncode": rc} for n, rc, _ in logs]
        for name, rc, text in logs:
            if rc != 0:
                problems.append(f"{name} returned {rc}")
        # Only the release LaTeX pass is expected to be warning-free after BibTeX
        # and cross-reference convergence. Earlier passes naturally contain
        # undefined-citation warnings.
        if logs:
            for issue in log_has_problem(logs[-1][2]):
                problems.append(f"{logs[-1][0]}: {issue}")
        main_pdf = work / "main.pdf"
        main_pages = pdf_pages(main_pdf) if main_pdf.exists() else None
        if main_pages != 12:
            problems.append(f"compiled main.pdf page count is {main_pages}, expected 12")
        page10 = pdf_text(main_pdf, 10, 10) if main_pdf.exists() else ""
        page11 = pdf_text(main_pdf, 11, 11) if main_pdf.exists() else ""
        if re.search(r"^\s*References\s*$", page10, re.I | re.M):
            problems.append("References heading appears on body page 10")
        if not re.search(r"R\s*E\s*F\s*E\s*R\s*E\s*N\s*C\s*E\s*S|References", page11, re.I):
            problems.append("References heading not detected on page 11")

        logs_supp = compile_one(work, "supplement", False, None)
        details["supplement_steps"] = [{"step": n, "returncode": rc} for n, rc, _ in logs_supp]
        for name, rc, text in logs_supp:
            if rc != 0:
                problems.append(f"{name} returned {rc}")
        if logs_supp:
            for issue in log_has_problem(logs_supp[-1][2]):
                problems.append(f"{logs_supp[-1][0]}: {issue}")
        supp_pdf = work / "supplement.pdf"
        supp_pages = pdf_pages(supp_pdf) if supp_pdf.exists() else None
        if supp_pages != 8:
            problems.append(f"compiled supplement.pdf page count is {supp_pages}, expected 8")

    result = {
        "status": "pass" if not problems else "fail",
        "problem_count": len(problems),
        "problems": problems,
        "bibtex_command": Path(bibtex_cmd).name if bibtex_cmd else None,
        "main_pages": locals().get("main_pages", None),
        "supplement_pages": locals().get("supp_pages", None),
        "details": details,
        "interpretation": "Compiles paper sources in an isolated temporary directory and checks BibTeX resolution, page counts, reference-page boundary, undefined references, and overfull boxes without adding build products to the release package.",
    }
    out = root / args.out
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({"status": result["status"], "problem_count": len(problems), "main_pages": result["main_pages"], "supplement_pages": result["supplement_pages"]}, sort_keys=True))
    if problems:
        raise SystemExit(2)

if __name__ == "__main__":
    main()
