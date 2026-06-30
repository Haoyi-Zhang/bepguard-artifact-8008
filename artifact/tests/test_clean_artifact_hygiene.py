"""Regression tests for release-root hygiene scanning."""
from __future__ import annotations

import contextlib
import io
import os
import sys
from pathlib import Path
from tempfile import TemporaryDirectory

from scripts.check_artifact_clean import main as clean_main, scan


def test_scan_detects_absolute_path_leaks_in_toml_and_go_sources() -> None:
    with TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / "paper").mkdir()
        (root / "artifact").mkdir()
        (root / "paper" / "stub.md").write_text("ok\n", encoding="utf-8")
        posix_leak = "/" + "data/ICSE2027/8008/artifact"
        windows_leak = "C:" + "\\Users\\ASUS\\Desktop"
        (root / "artifact" / "leak.toml").write_text(f"path = {posix_leak}\n", encoding="utf-8")
        (root / "artifact" / "windows.go").write_text(f"const path = {windows_leak}\n", encoding="utf-8")

        result = scan(root)

        assert result["problem_count"] == 2
        assert any("artifact/leak.toml" in problem for problem in result["problems"])
        assert any("artifact/windows.go" in problem for problem in result["problems"])


def test_clean_main_root_argument_uses_release_root_from_artifact_cwd() -> None:
    with TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / "paper").mkdir()
        artifact = root / "artifact"
        (artifact / "results").mkdir(parents=True)
        old_cwd = Path.cwd()
        old_argv = sys.argv[:]
        stdout = io.StringIO()

        try:
            os.chdir(artifact)
            sys.argv = ["check_artifact_clean.py", "--root", "."]
            with contextlib.redirect_stdout(stdout):
                clean_main()
        finally:
            os.chdir(old_cwd)
            sys.argv = old_argv

        out = stdout.getvalue()
        assert "problem_count" in out
        assert (root / "artifact" / "results" / "clean_package_check.json").exists()
        assert not (artifact / "artifact").exists()
