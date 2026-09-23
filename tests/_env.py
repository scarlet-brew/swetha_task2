"""Shared test bootstrap: put `src/` on the import path, and name the fixed
directories once.

The project is deliberately never installed. setuptools is outside the frozen
dependency set (design 10.1), and a `pip install` at demo time is an NFR-02
failure, so `import siem_investigator` has to be arranged explicitly rather
than by an editable install. Every test module imports this one first.

Named with a leading underscore so unittest's `test*.py` discovery pattern
skips it.
"""

from __future__ import annotations

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
SRC_DIR = REPO_ROOT / "src"
TESTS_DIR = REPO_ROOT / "tests"
FIXTURES_DIR = TESTS_DIR / "fixtures"
DATA_DIR = REPO_ROOT / "data"
RAW_DATASET = DATA_DIR / "raw" / "siem_logs.json"

if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))
