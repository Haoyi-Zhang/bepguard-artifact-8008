#!/usr/bin/env python3
"""Repository path helpers for the BEP artifact.

Scripts in the artifact are commonly launched either from the package root or
from inside ``artifact/``.  These helpers locate the package root from the
calling script rather than relying on the current working directory.
"""
from __future__ import annotations

from pathlib import Path
from typing import Iterable


def package_root(anchor: str | Path | None = None) -> Path:
    """Return the release-package root containing ``artifact`` and ``paper``.

    ``anchor`` may be ``__file__`` from a script or any path inside the release
    package.  The function walks upward until both top-level release directories
    are present.  A clear exception is raised instead of silently resolving paths
    against an arbitrary current working directory.
    """
    start = Path(anchor).resolve() if anchor is not None else Path.cwd().resolve()
    if start.is_file():
        start = start.parent
    for candidate in (start, *start.parents):
        if (candidate / "artifact").is_dir() and (candidate / "paper").is_dir():
            return candidate
    raise RuntimeError(f"cannot locate BEP release root from {start}")


def rel(root: Path, *parts: str) -> Path:
    """Build a normalized path under ``root``."""
    return root.joinpath(*parts)


def require_files(root: Path, relative_paths: Iterable[str]) -> list[str]:
    """Return missing release-relative paths."""
    missing: list[str] = []
    for path in relative_paths:
        if not (root / path).exists():
            missing.append(path)
    return missing
