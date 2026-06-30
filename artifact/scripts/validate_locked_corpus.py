#!/usr/bin/env python3
"""Compatibility entry point for the release BEP-Deep corpus validation.

The release package validates the BEP-Deep denominator through
validate_corpus_and_coding.py. This entry point is retained so older
reproduction commands fail safe rather than checking the superseded seed
workload.
"""
from __future__ import annotations
import sys
sys.dont_write_bytecode = True
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
cmd = [sys.executable, str(ROOT / "artifact" / "scripts" / "validate_corpus_and_coding.py"), "--root", str(ROOT)]
raise SystemExit(subprocess.call(cmd))
