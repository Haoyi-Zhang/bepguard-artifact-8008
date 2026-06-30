"""LaTeX-native figure and rendered-layout audit."""
from __future__ import annotations

import re
import sys
from pathlib import Path
from typing import Any, Dict, List

sys.dont_write_bytecode = True

RASTER_EXTENSIONS = {".png", ".jpg", ".jpeg", ".gif", ".bmp", ".webp"}


def _render_page_metrics(pdf_path: Path) -> List[Dict[str, Any]]:
    try:
        import fitz  # type: ignore
    except Exception as exc:  # pragma: no cover
        return [{"error": f"PyMuPDF unavailable: {exc}"}]
    doc = fitz.open(str(pdf_path))
    pages: List[Dict[str, Any]] = []
    for index, page in enumerate(doc):
        text = page.get_text("text")
        blocks = page.get_text("blocks")
        pages.append({
            "page": index + 1,
            "has_figure_caption": "Fig." in text or "Figure" in text,
            "has_table_caption": "TABLE" in text or "Table" in text,
            "text_blocks": len(blocks),
            "text_excerpt": " ".join(text.split())[:160],
        })
    return pages


def audit_figure_layout(root: Path) -> Dict[str, Any]:
    problems: List[str] = []
    paper = root / "paper"
    main_tex = paper / "main.tex"
    text = main_tex.read_text(encoding="utf-8")
    input_paths = re.findall(r"\\input\{(figures/[^}]+)\}", text)
    resolved_inputs: List[str] = []
    for inp in input_paths:
        candidates = [paper / inp, paper / f"{inp}.tex", paper / f"{inp}.tikz.tex"]
        found = next((p for p in candidates if p.exists()), None)
        if found is None:
            problems.append(f"unresolved figure input: {inp}")
        else:
            resolved_inputs.append(str(found.relative_to(paper)).replace("\\", "/"))
    figure_files = sorted(p for p in (paper / "figures").glob("**/*") if p.is_file())
    raster = [str(p.relative_to(paper)).replace("\\", "/") for p in figure_files if p.suffix.lower() in RASTER_EXTENSIONS]
    if raster:
        problems.append(f"raster figure files present: {raster}")
    if re.search(r"\\includegraphics", text):
        problems.append("main.tex uses includegraphics; expected LaTeX-native figures only")
    duplicate_nodes: List[str] = []
    tikz_files = [p for p in figure_files if p.suffix == ".tex" or p.name.endswith(".tikz.tex")]
    for path in tikz_files:
        src = path.read_text(encoding="utf-8")
        nodes = re.findall(r"\\node(?:\[[^\]]*\])?\s*\(([^)]+)\)", src)
        seen = set()
        for node in nodes:
            if node in seen:
                duplicate_nodes.append(f"{path.relative_to(paper)}:{node}")
            seen.add(node)
        if "tikzpicture" in src and "rounded corners" not in src and "axis" not in src:
            problems.append(f"figure lacks structured TikZ styling: {path.relative_to(paper)}")
    labels = re.findall(r"\\label\{([^}]+)\}", text)
    if len(labels) != len(set(labels)):
        problems.append("duplicate LaTeX labels in main.tex")
    caption_text = text
    for rel in resolved_inputs:
        try:
            caption_text += "\n" + (paper / rel).read_text(encoding="utf-8")
        except FileNotFoundError:
            pass
    captions = re.findall(r"\\caption\{", caption_text)
    if len(captions) < 5:
        problems.append("fewer than five main-paper figure/table captions")
    if duplicate_nodes:
        problems.append(f"duplicate TikZ node identifiers: {duplicate_nodes[:10]}")
    pdf_metrics = _render_page_metrics(paper / "main.pdf")
    if pdf_metrics and "error" in pdf_metrics[0]:
        problems.append(str(pdf_metrics[0]["error"]))
    if len(pdf_metrics) != 12:
        problems.append(f"main PDF rendered to {len(pdf_metrics)} pages, expected 12")
    figure_pages = [p["page"] for p in pdf_metrics[:10] if p.get("has_figure_caption") or p.get("has_table_caption")]
    if len(figure_pages) < 4:
        problems.append("rendered body contains too few detected figure/table caption pages")
    if len(pdf_metrics) >= 11 and "references" not in str(pdf_metrics[10].get("text_excerpt", "")).lower():
        problems.append("page 11 is not the references boundary in rendered text")
    return {
        "status": "pass" if not problems else "fail",
        "problem_count": len(problems),
        "problems": problems,
        "figure_inputs": resolved_inputs,
        "latex_native_figure_files": [str(p.relative_to(paper)).replace("\\", "/") for p in tikz_files],
        "raster_figure_files": raster,
        "caption_count": len(captions),
        "label_count": len(labels),
        "rendered_pages": len(pdf_metrics),
        "figure_or_table_caption_pages": figure_pages,
        "page_metrics_excerpt": pdf_metrics[:12],
        "interpretation": "Static and rendered-layout audit for LaTeX-native figures/tables: it checks resolved inputs, absence of raster figures, label uniqueness, TikZ node uniqueness, caption coverage, and rendered page boundaries.",
    }


def write_json(path: Path, obj: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(__import__("json").dumps(obj, indent=2, sort_keys=True) + "\n", encoding="utf-8")
