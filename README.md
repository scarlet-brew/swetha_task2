# SIEM Incident Investigation Intelligence

Agentic incident investigation prototype over a synthetic SIEM dataset: multi-source log
correlation, attack timeline reconstruction, MITRE ATT&CK technique mapping, and blast radius
assessment — with an evidence citation behind every claim.

**Status:** implemented and running. `python -m siem_investigator.build` reconstructs the
incident end to end and `streamlit run app/main.py` serves the four analyst surfaces over the
committed artifacts. 292 tests pass.

## What it produced on the supplied dataset

| | |
|---|---|
| Records ingested | 242 (0 lost, 22 `note` annotations stripped at the parse boundary) |
| Observations | 1,951, every one reproducible from its recorded transform |
| Factual edges | 1,367 traversed and committed, from 10 atomic relations |
| Findings accepted | 25 |
| Proposals rejected | 8, mostly for naming an identifier that appears in no cited observation |
| ATT&CK techniques | 21 mapped against v19.2; `T1068` correctly mapped by nothing |
| Hypotheses | 24, most unconfirmed or uncoverable — the coverage-gap report |
| Graph invariants | all five hold |
| Accuracy vs the labelled set | recall 59% (13/22), precision 46% (13/28) |

It reconstructs the real intrusion: `WINWORD.EXE` → `cmd.exe` → `powershell.exe` on `WKSTN-07`
under `jdavis`, the C2 channel to `185.220.101.45`, `net.exe` discovery, the port-445 →
`psexesvc` lateral movement, and the 2,473,829,122-byte archive appearing in both endpoint and
cloud-storage records. About half the findings are honest but low-value observations about benign
activity — the cost of anchors that order rather than filter, discussed in
[docs/writeup/product-thinking.md](docs/writeup/product-thinking.md).

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
$env:PYTHONPATH = "src"                              # PowerShell; `export PYTHONPATH=src` in bash
.venv\Scripts\python.exe -m siem_investigator.build
```

The package is not installed (see `pyproject.toml`), so `src` goes on the import path for this
command.

Add `--no-model` to run the deterministic stages only: ingest, parse, the ten factual relations,
the graph invariants, the scope and the coverage report all work with no credential. The
interpretive layer then falls back to a scripted stub and technique attribution is reported as
**unmapped** rather than omitted.

A full model-backed build takes about 12 minutes and writes 23 artifacts to `data/derived/`.
That is a run-once step: the app only reads what it produced, so nothing is computed at question
time that could mint a claim.

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

## The written discussion

- [docs/writeup/trust-and-hallucination.md](docs/writeup/trust-and-hallucination.md) — the
  generator/kernel split, the three places fabrication is made structurally impossible, and the
  limits that remain
- [docs/writeup/agentic-design.md](docs/writeup/agentic-design.md) — the loop, why it is not one
  large prompt, and where agency is deliberately withheld
- [docs/writeup/product-thinking.md](docs/writeup/product-thinking.md) — who it is for, why there
  are no confidence scores, the scope cuts, and what another week would buy

Supporting documents: [docs/egress.md](docs/egress.md) (what leaves the machine, checked rather
than described), [docs/specs/](docs/specs/) (requirements, design, tasks, answer-payload
contract), [docs/architecture/](docs/architecture/) (the four diagrams).
