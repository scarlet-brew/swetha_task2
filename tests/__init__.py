"""Test package for the SIEM investigator prototype.

The runner is stdlib `unittest` (task T01): pytest is not installed and design
10.1 freezes the dependency set, so the venv that ships the demo has to be the
venv that runs Phase 5's evidence.

    python -m unittest discover -s tests

Under that command `tests/` *is* the top-level directory, so unittest imports
test modules flat and never imports this file. Under the alternative

    python -m unittest discover -s tests -t .

modules import as `tests.<name>` and this file runs first -- but then `tests/`
is not on `sys.path`. The shared bootstrap therefore lives in `tests/_env.py`,
which every test module imports by plain name, and the one line below is what
makes that name resolve under the second form too.
"""

from __future__ import annotations

import sys
from pathlib import Path

_TESTS_DIR = Path(__file__).resolve().parent
if str(_TESTS_DIR) not in sys.path:
    sys.path.insert(0, str(_TESTS_DIR))
