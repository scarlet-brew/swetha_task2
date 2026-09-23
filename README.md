# SIEM Incident Investigation Intelligence

Agentic incident investigation prototype over a synthetic SIEM dataset: multi-source log
correlation, attack timeline reconstruction, MITRE ATT&CK technique mapping, and blast radius
assessment — with an evidence citation behind every claim.

**Status:** Phase 4 (implement) in progress against `docs/specs/tasks.md`. The dependency set,
the test runner and the commands below are settled (T01); the build entry point lands at T28 and
the app at T07.

- `CLAUDE.md` — project context, dataset schema, ground rules
- `docs/assignment/` — the assignment brief
- `docs/specs/` — spec-driven workflow artifacts (requirements, design, tasks)
- `data/raw/siem_logs.json` — provided dataset, committed as part of the repo

## Running it

Python 3.14 on the demo machine. Two commands, deliberately separate: **the build** writes the
committed artifacts under `data/derived/`, and **the app** only reads them. Nothing is computed at
question time that could mint a claim (NFR-01).

### Once — build the environment

```
py -3.14 -m venv .venv
.venv\Scripts\python.exe -m pip install -r requirements.txt
```

The dependency set is frozen (design §10.1): `anthropic`, `streamlit`, `pydantic`, `jsonschema`
plus their pinned transitive closure, and nothing else. A `pip install` at demo time is an NFR-02
failure, so build the venv before the demo and leave it alone.

### Build — reconstruct the incident from the raw logs

```
.venv\Scripts\python.exe -m siem_investigator.build
```

The package is not installed (see `pyproject.toml`), so `src` goes on the import path for this
command — `$env:PYTHONPATH = "src"` in PowerShell, `export PYTHONPATH=src` in bash.

### App — the analyst chat UI over the committed artifacts

```
.venv\Scripts\python.exe -m streamlit run app/main.py
```

Starts with no network and no credential. Technique attribution is reported as unmapped in that
state rather than omitted (NFR-02).

### Tests

```
.venv\Scripts\python.exe -m unittest discover -s tests
```

Stdlib `unittest` is the runner; pytest is not installed and §10.1 forbids adding it, so the venv
that ships the demo is the venv that runs the evidence.

### The credential

The system reads its API key from **`ANTHROPIC_API_KEY` in the environment**, and stores it
nowhere in the tree — no key file, no `.streamlit/secrets.toml`, nothing committed (NFR-10).
`.env.example` names the variable and carries no value; `.env` itself is gitignored and nothing
reads it.

```
$env:ANTHROPIC_API_KEY = "<your key>"      # PowerShell
export ANTHROPIC_API_KEY=<your key>        # bash
```

With the variable unset, the deterministic stages still run and the model-backed stages fail with
a one-line message rather than a traceback.
