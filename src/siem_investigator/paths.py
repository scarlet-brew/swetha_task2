"""Every path the system reads or writes, in one place.

Two reasons this is a module rather than string literals at each use site.

First, design SS8.3 splits the tree into three *authorities* -- the raw records,
the investigation graph, the ATT&CK catalogue -- and everything else into
*projections*, which are regenerable and never authoritative. That distinction
is invisible if paths are spelled inline, so it is stated here and the
`PROJECTIONS` tuple below makes SS8.3's testable invariant (delete every
projection, regenerate, get byte-identical output) something a test can
actually iterate over.

Second, the package is never installed (see pyproject.toml), so the repository
root has to be found relative to this file rather than from an entry point.
"""

from __future__ import annotations

from pathlib import Path

# src/siem_investigator/paths.py -> src/siem_investigator -> src -> repository root
ROOT = Path(__file__).resolve().parents[2]

# --- authority 1: the raw records. Read-only, byte-for-byte, never rewritten. ---
DATA_RAW = ROOT / "data" / "raw"
RAW_LOGS = DATA_RAW / "siem_logs.json"

# --- authority 2: the ATT&CK catalogue. Retained locally (D-03); never fetched. ---
DATA_ATTACK = ROOT / "data" / "attack"
ATTACK_BUNDLE = DATA_ATTACK / "enterprise-attack-19.2.json"
ATTACK_INDEX = DATA_ATTACK / "index.json"
# The flat catalogue is *derived* from the bundle at build time -- a projection
# of authority 2, not a second authority (T04).
ATTACK_CATALOGUE = DATA_ATTACK / "catalogue_v19.2.json"

# --- vendored schema for the Attack Flow projection (D-04) ---
DATA_SCHEMA = ROOT / "data" / "schema"
ATTACK_FLOW_SCHEMA = DATA_SCHEMA / "attack-flow-2.0.0.json"

# --- authority 3: the investigation graph, as committed sorted JSONL (D-10) ---
DERIVED = ROOT / "data" / "derived"

RECORDS = DERIVED / "01_records.jsonl"
INGEST_REPORT = DERIVED / "01_ingest_report.json"

EVENTS = DERIVED / "02_events.jsonl"
ENTITIES = DERIVED / "02_entities.jsonl"
RESOLUTION = DERIVED / "02_resolution.jsonl"
PARSE_REPORT = DERIVED / "02_parse_report.json"

OBSERVATIONS = DERIVED / "03_observations.jsonl"
EDGES = DERIVED / "03_edges.jsonl"
HYPOTHESES = DERIVED / "03_hypotheses.jsonl"
FINDINGS = DERIVED / "03_findings.jsonl"
TRAJECTORY = DERIVED / "03_trajectory.jsonl"
REJECTIONS = DERIVED / "03_rejections.jsonl"
CORRELATE_REPORT = DERIVED / "03_correlate_report.json"

MAPPINGS = DERIVED / "04_mappings.jsonl"
UNMAPPED = DERIVED / "04_unmapped.jsonl"
ENRICH_REPORT = DERIVED / "04_enrich_report.json"

TIMELINE = DERIVED / "05_timeline.json"
SCOPE = DERIVED / "05_scope.json"
GAPS = DERIVED / "05_gaps.json"
PRIVILEGE = DERIVED / "05_privilege.json"
ATTACK_FLOW = DERIVED / "05_attack_flow.json"
NAVIGATOR_LAYER = DERIVED / "05_navigator_layer.json"
SYNTHESISE_REPORT = DERIVED / "05_synthesise_report.json"

MANIFEST = DERIVED / "manifest.json"

# --- projections that are not committed at all ---
OUTPUTS = ROOT / "outputs"
# SS8.3: SQLite is an internal index, rebuilt from the JSONL on load. Gitignored,
# discardable, never an audit artifact.
INDEX_SQLITE = OUTPUTS / "index.sqlite"
ANSWERS = OUTPUTS / "answers"

# --- documentation and test data ---
DOCS = ROOT / "docs"
SPECS = DOCS / "specs"
WRITEUP = DOCS / "writeup"
FIXTURES = ROOT / "tests" / "fixtures"

# Source trees the D-09 line reporter walks.
CODE_ROOTS = (ROOT / "src", ROOT / "app", ROOT / "scripts", ROOT / "tests")

# SS8.3's projections, in the order a regeneration would produce them. The
# byte-identical invariant (T38) iterates this rather than a hand-kept list in
# the test, so adding a projection without covering it is not possible.
PROJECTIONS = (
    ATTACK_CATALOGUE,
    TIMELINE,
    SCOPE,
    GAPS,
    PRIVILEGE,
    ATTACK_FLOW,
    NAVIGATOR_LAYER,
)


def relative(path: Path) -> str:
    """`path` as a forward-slash string relative to the repository root.

    Artifacts record which file a value came from. An absolute Windows path in
    a committed artifact would make the build machine part of the evidence and
    the JSONL would differ between checkouts, so every recorded path goes
    through here.
    """
    return Path(path).resolve().relative_to(ROOT).as_posix()
