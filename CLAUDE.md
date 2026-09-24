# CLAUDE.md

Guidance for Claude Code when working in this repository.

## What this is

A prototype **cyber incident investigation** system built for a Deloitte Cyber Engineering
round-2 post-interview assignment (`docs/assignment/`). It ingests a synthetic SIEM dataset,
correlates events across four unrelated log sources, reconstructs the attack timeline, maps
observed behaviour to MITRE ATT&CK, assesses blast radius, and answers analyst questions —
with a citation behind every claim.

**Target user:** a SOC analyst or CISO under time pressure. Today the process takes a senior
analyst 6-8 hours of manual correlation.

**Artifact format:** lightweight web chat UI (`app/`) over a Python pipeline (`src/`).

### The bar

The assignment states it twice, and it drives every design decision:

> "Can the CISO hand this reconstructed attack timeline to their board and legal team with
> confidence?"

> "A correct 'I can see suspicious activity but cannot confirm exfiltration because the relevant
> logs are absent' beats a fabricated conclusion."

A prior attempt failed for being "grep with a UI" — raw results, no correlation, no timeline,
no ATT&CK linkage. It missed a lateral movement event that was obvious in hindsight.
**Correlation and traceability are the product. Search is not.**

## Development workflow — Spec-Driven Development

This project follows **Spec -> Design -> Tasks -> Implement -> Validate**. Planning is
deliberately front-loaded; do not jump to code generation.

| Phase | Artifact | Gate |
|---|---|---|
| 1. Specify | `docs/specs/requirements.md` | User stories + acceptance criteria, written *with* the user after interrogation on edge cases |
| 2. Design | `docs/specs/design.md` | Architecture, data models, contracts, diagrams, 2-3 approaches with tradeoffs argued. Reviewed before any code |
| 3. Tasks | `docs/specs/tasks.md` | Small, independently executable, individually testable steps |
| 4. Implement | code | One task at a time; review each diff against the spec |
| 5. Validate | tests + report | Primary criterion is **spec compliance**, not "it runs" |

Rules:

- **Do not write application code until phases 1-3 are complete and approved.**
- Requirements must be specific and testable. "Correlates events" is vague; "given a network
  event with no `src_host`, resolves candidate hostnames from auth/cloud logs and returns them
  with a confidence label" is actionable.
- If the design needs to change mid-implementation, **update the spec first**, then the code.

### Build vs. adopt

Before designing custom code: identify the problem category, ask whether it is a common solved
problem, research existing solutions, compare build vs. adopt, and only then design something
new. Known decision points for this project — to be resolved in `design.md`, not assumed:

- **ATT&CK catalogue** — the STIX feed is a large JSON graph; MITRE ships `mitreattack-python`.
- **Chat UI** — Streamlit vs. Chainlit vs. FastAPI + HTMX.
- **Correlation/timeline** — at 242 events, a graph library may be over-engineering. Decide
  explicitly.
- **Evidence/citation layer** — the graded differentiator and specific to this problem. Expect
  to build this one rather than adopt generic RAG-citation machinery.

## The dataset

`data/raw/siem_logs.json` — `{ metadata, events }`. 242 events, window
`2026-06-10T08:00Z -> 2026-06-13T08:00Z` (72h), incident `INC-2026-0610-001`,
org "Meridian Health Partners" (synthetic). Events are **shuffled**.

Four source types, **no common join key** — each has its own field names:

| `source_type` | n | Identity fields | Payload fields |
|---|---|---|---|
| `network` | 84 | `src_ip`, `dst_ip`, `src_host`/`dst_host` (*usually absent*) | `dst_port`, `protocol`, `bytes_sent`, `bytes_recv`, `action`, `firewall_rule` |
| `endpoint` | 65 | `hostname`, `username` | `process_name`, `parent_process`, `process_path`, `command_line`, `pid`, `integrity_level`, `file_path`, `file_size_bytes`, `service_name`, `target_process`, `access_rights` |
| `auth` | 62 | `username`, `source_host`, `dest_host`, `source_ip`, `dest_ip` | `logon_type`, `result` |
| `cloud_storage` | 31 | `username`, `source_ip`, `source_host` | `bucket`, `bucket_owner`, `file_name`, `file_size_bytes`, `action`, `user_agent` |

Every event has `event_id`, `source_type`, `timestamp`, `event_name`. Internal space is
`10.0.0.0/8`.

### Correlation realities

- `80/84` network events have no `src_host`; `83/84` have no `dst_host`. Network-to-host
  correlation must go through an IP-to-host map derived from `auth` + `cloud_storage` events.
- **That map is ambiguous.** `WKSTN-01` and `WKSTN-06` each appear with 9 different IPs, and
  `10.0.3.78` maps to *both* `WKSTN-04` and `WKSTN-10`. Only the three compromised hosts have a
  single stable IP. A resolver must return candidates with confidence, never one confident
  answer.
- The strongest cross-source join in the dataset is **exact `file_name` + `file_size_bytes`
  equality** between an endpoint `file_create` and a cloud `file_upload`.
- All 84 firewall records are `action: allowed`. There is no block/deny signal to lean on.
- 14 auth failures are scattered across 8 users with no clustering — all benign. A naive
  failed-logon rule produces 14 false positives and zero true positives.

## Ground rules

### 1. Never use the dataset's leaks as detection signal

Three fields give the answer away. Using any of them makes the prototype worthless as a
demonstration, and the interviewers will ask.

| Leak | Why it is a leak | Permitted use |
|---|---|---|
| `note` field starting `"ATTACK:"` | Developer annotation; the dataset metadata says to strip it | **Phase 5 ground truth only** — labelled test set for precision/recall |
| Timestamp precision | All 22 attack events have whole-second timestamps; all 220 benign events carry microseconds. A `"." not in timestamp` filter scores 100% precision *and* recall | None. Generator artifact |
| `event_id` ordering | Attack events are `EVT-0221`-`EVT-0242` — the final 22 IDs, contiguous | None |

Detection and correlation logic must rest on evidence an analyst would actually have:
process lineage, credential reuse, protocol/port/volume anomalies, entity pivots, temporal
adjacency, cross-source field equality.

### 2. Every claim carries a citation

Each assertion in any output must cite the specific `event_id`(s), `source_type`, and
`timestamp` behind it. An uncited claim is a bug, not a style issue.

### 3. Report uncertainty; never close a gap with inference

Known gaps in this dataset that any honest answer must surface:

- **No email/mail-gateway source.** The spear-phishing email is absent. The initial access
  vector is inferable *only* from `WINWORD.EXE` spawning `cmd.exe` on `WKSTN-07`. Sender,
  subject, and attachment name are unknowable. Do not invent them.
- **No DNS logs.** C2 is an IP (`185.220.101.45`) with no domain or resolution chain.
- **No firewall record corroborates the 2.3 GB egress.** Exfiltration rests on the cloud audit
  log alone — label it a single-source claim.
- **No `file_create` for `C:\Temp\7z.exe`.** Tool transfer is inferred from a 32 KB SMB flow.
- **The LSASS dump was written but never observed being read or transmitted.**
- **Endpoint coverage is uneven.** `AUTH-SRV-01` has 2 endpoint events; `AUTH-SRV-02` has none.
  Further spread cannot be ruled out.
- **`jdavis` has no benign activity in 72h** — no behavioural baseline exists.
- **Days 2-3 are silent.** Eviction vs. dormancy is undecidable from this data.
- **There is no exploit-based privilege escalation event.** Integrity rises
  `medium -> high -> SYSTEM` via stolen credentials (T1078) and service execution (T1569.002).
  Do not map T1068 or a UAC bypass here.

### 4. Scope cuts are encouraged — but must be explicit

The assignment rewards thoughtful reductions stated plainly over silent incompleteness. Record
every cut and its rationale in `docs/specs/design.md`.

## Repository layout

```
data/raw/                     provided dataset (committed — part of the repo)
data/attack/                  cached MITRE ATT&CK catalogue
data/derived/                 structured intermediate representations
docs/assignment/              the assignment PDF (source of truth for requirements)
docs/specs/                   requirements.md, design.md, tasks.md
docs/architecture/            diagrams referenced by design.md
docs/writeup/                 trust & hallucination, agentic design, product thinking
src/siem_investigator/
  ingest/                     load + parse the four source types
  correlate/                  entity resolution, cross-source correlation, timeline
  enrich/                     MITRE ATT&CK technique mapping
  evidence/                   citation + traceability layer
  agent/                      orchestration, tools, verification pass
app/                          chat UI
tests/fixtures/
outputs/                      generated reports (gitignored)
```

`data/` is committed deliberately — see the note at the bottom of `.gitignore`.

## Deliverables

1. Tangible artifact — the running prototype.
2. A 5-10 minute walkthrough: what was built, architectural decisions, where AI/agents were used
   **and where they were deliberately not used**, shortcuts taken, what another day or week
   would add.
3. Short written discussion: trust & hallucination, agentic workflow design, product thinking.

## Status

**Implemented and running.** All five phases are complete: `docs/specs/` holds the
requirements, design and tasks; `src/siem_investigator/` the six-stage pipeline;
`app/` the analyst surfaces; `docs/writeup/` the three written discussions.

```
python -m siem_investigator.build      # reconstruct (needs ANTHROPIC_API_KEY; --no-model works without)
streamlit run app/main.py              # read the result
```

Two notes on figures, because both units appear in different places and each is
right. The staged archive is **2,473,829,122 bytes** — 2.30 GiB, or 2.47 GB. This
file says 2.3 GB above meaning gibibytes; the application reports 2.47 GB
meaning gigabytes. Where it matters, the byte count is the number to quote.

The committed artifacts under `data/derived/` come from a specific run; the
manifest records the interpreter, the step budget and the contract-set hash that
produced them.
