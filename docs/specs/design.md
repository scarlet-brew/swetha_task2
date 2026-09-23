# Design: Cyber Incident Investigation Intelligence

| | |
|---|---|
| **Phase** | 2 of Spec → Design → Tasks → Implement → Validate |
| **Status** | Draft for review. All ten agenda decisions resolved |
| **Requirements** | [requirements.md](requirements.md) — Phase 1, closed |
| **Date** | 2026-09-23 |

> This document says *how*. It resolves every decision the Phase 2 agenda raised, records the
> alternative rejected in each case, and names the residual risks it does not remove.
>
> **No application code exists yet.** Phase 3 (`tasks.md`) breaks this into steps; Phase 4
> implements.

---

## 1. The organising decision

The assignment names a six-stage pipeline:

> **Ingest → parse → correlate → enrich with ATT&CK → synthesise → answer.** Tool use, structured
> intermediate representations, multi-step reasoning, and verification passes are all fair game.

And it describes the predecessor's failure as *"no correlation across sources, no timeline
reconstruction, and no connection to known attack techniques."*

Those three failures are exactly the three middle stages. **The pipeline in the brief is an
inventory of what the predecessor lacked**, which makes it the right skeleton for this design:
six stages, six committed artifacts, **six verification passes** — one per stage, each with its
own failure mode and its own report.

### 1.1 The boundary the whole design turns on

Two things are routinely conflated and must not be:

| | Example | Who does it |
|---|---|---|
| **Factual linkage** | "`EVT-0237` and `EVT-0238` share a file name and an exact byte count" | deterministic code |
| **Interpretation** | "that constitutes data being staged and then removed" | a language model |

A rule that computes the link *and* names it exfiltration has put interpretation inside the
deterministic layer. Two consequences follow, and both are bad: the model has nothing left to do
except narrate, and the system can only ever conclude what someone encoded in advance.

**So the deterministic layer emits facts and decides nothing. The model interprets facts and
computes nothing.** Everything else in this design is downstream of that split.

---

## 2. Architecture

```
 data/raw/siem_logs.json   242 records · 4 source types · read-only
          │
 ╔════════╪═══════ BUILD  (run once, artifacts committed, needs a credential) ══════════╗
 ║        ▼                                                                             ║
 ║   1 INGEST      deterministic   records loaded verbatim, `note` stripped at boundary ║
 ║        ▼                                                                             ║
 ║   2 PARSE       deterministic   normalised events · role-tagged entities ·           ║
 ║        │                        normalisation provenance · address→host candidates   ║
 ║        ▼                                                                             ║
 ║   3 CORRELATE   four layers     facts (code) → interpretation (model) → validation   ║
 ║        ▼                                                                             ║
 ║   4 ENRICH      constrained     technique selected from a retrieved enum, validated  ║
 ║        ▼                                                                             ║
 ║   5 SYNTHESISE  deterministic   timeline · scope · gaps · Attack Flow · Navigator    ║
 ╚════════╪═════════════════════════════════════════════════════════════════════════════╝
          ▼
   data/derived/   sorted JSONL — the committed audit representation
          │
 ══════════╪══════ QUERY  (live, no credential present) ════════════════════════════════
          ▼
     6 ANSWER      model + read-only tools over frozen artifacts, every claim gated
          ▼
   analyst: chat · timeline · impact · pipeline        ·        handover report
```

### 2.1 Stage 1 · INGEST — deterministic

Load every record. **Strip `note` at the parse boundary**, so nothing downstream can see it —
`R7.2` becomes an architectural property rather than a discipline anyone has to remember. The
validation harness reads the raw file on an independent path. Classify addresses internal or
external from the dataset's own `metadata.known_internal_subnets`. Retain every record verbatim,
keyed by id.

**Field presence is data, not a parse error.** The dataset has 14 logical event kinds
(`source_type` + `event_name`), and shapes vary *within* a kind through optional fields:
`network_connection` alone spans three key-sets, because 80 of 84 carry no `src_host`. A parser
written against a fixed key-set would reject the 4 that do — the only network events needing no
address resolution at all, and the evidence `R3.9`/`R3.10` exist to handle.

| | |
|---|---|
| **Artifacts** | `01_records.jsonl` · `01_ingest_report.json` (counts per source type and event kind, missing-field census, absent/empty-string/null encoding census) |
| **Verification** | schema validation per event kind · count reconciliation · assert `note` absent from every downstream record · assert every record retrievable by id |
| **Serves** | `R2.2` `R2.5` `R7.2` `NFR-05` `NFR-06` |

### 2.2 Stage 2 · PARSE — deterministic

**Role-tagged entity references, not flattened fields.** Two of four sources are directional, so a
single `host` field is wrong for `auth` and `network`. Each event carries
`[(entity_type, identifier, role)]`:

| Role | Meaning | Source |
|---|---|---|
| `actor` | the account performing the action | `username` |
| `observed_on` | the host whose telemetry produced the record | `hostname` (endpoint) |
| `origin` | where the action came from | `source_host`/`source_ip`, `src_host`/`src_ip` |
| `target` | what was acted upon | `dest_host`/`dest_ip`, `dst_host`/`dst_ip`, `bucket`, `target_process` |

Entity types: `account` · `host` · `address` · `process` · `file` · `bucket` · `service`.

`observed_on` is deliberately distinct from `origin`, because it makes coverage **computable**
rather than asserted: the set of hosts with endpoint coverage is the set of `observed_on` values.
`AUTH-SRV-02` appears as an auth `target` and never as an `observed_on` — that *is* the gap
`R3.12` asks for, derived rather than hand-noted.

**Normalisation provenance for every value.** Stored as
`record_id · field · raw_value · transform · normalised_value`, with `transform` drawn from a
closed registry: `identity` · `basename` · `lower` · `ipv4_canonical` · `utc_instant`.

- `identity` is recorded **explicitly**, so a missing provenance entry is a bug rather than an
  ambiguity.
- Transforms are **pure and total**. One that cannot normalise its input says so, and the
  observation is withheld under `R2.6` rather than silently carrying a bad value.
- Absence is typed: `not_applicable` (the event kind has no such concept) is distinct from
  `recorded_empty` (the field exists and is empty). Exactly one field in this dataset encodes both
  — `command_line`, absent in 184 records and empty in 50 — and it is the field carrying the
  encoded PowerShell, one of only 8 non-empty command lines.

Why provenance is load-bearing rather than tidy: an observation asserting
`file_name = backup_archive.zip` cites a record reading `file_path = C:\Temp\backup_archive.zip`.
The `R2.6` check passes, and **without the recorded transform a reviewer cannot see that it
passed.** For a system whose purpose is that a sceptic can verify any claim in under 30 seconds,
that is a defect.

| | |
|---|---|
| **Artifacts** | `02_events.jsonl` · `02_entities.jsonl` · `02_resolution.jsonl` (address→host candidates with ambiguity flags) |
| **Verification** | re-apply each recorded transform to its recorded raw value, assert equality · assert every transform is registered · assert no event lost |
| **Serves** | `R1.2` `R2.6` `R3.9` `R3.10` `NFR-09` |

---

## 3. Stage 3 · CORRELATE — the stage the predecessor lacked

```
              DIRECT OBSERVATIONS
                      │
    ══════════════════▼═══════════════════════════════════════════════
              FACTUAL CORRELATION LAYER      deterministic · total · decides nothing
    ══════════════════▼═══════════════════════════════════════════════
              CORRELATION / EVIDENCE GRAPH   virtual; traversed subgraph is committed
                      │
    ══════════════════▼═══════════════════════════════════════════════
              AI INVESTIGATION LAYER         non-deterministic · interpretive
                SELECT → EXPAND → INTERPRET → HYPOTHESISE → SEEK
    ══════════════════▼═══════════════════════════════════════════════
              CANDIDATE FINDINGS → VALIDATION (6 checks) → INVESTIGATION GRAPH
```

### 3.1 Direct observations — deterministic

An observation asserts values that appear at **named fields** of one or more raw records. Nothing
more. It carries its normalisation provenance from stage 2.

### 3.2 The factual correlation layer — deterministic, total, interpretation-free

**Ten atomic relations, and deliberately no composites.**

```
same_account(o1, o2)          same_file(o1, o2)          basename, normalised
same_host(o1, o2)             same_size(o1, o2)          exact byte equality
same_address(o1, o2)          process_parent(o1, o2)     same host
address_resolves_to_host()    temporal_within(o1, o2, Δ) ordered, Δ *reported*
flow_endpoint(o1, o2)         session_bracket(o1, o2)
```

Ten relation *types*. **Zero detection rules.** The layer links everything linkable — benign to
benign included — and makes no claim about the intrusion. Which means **there is no coverage
ceiling here, because nothing is being detected.**

No composites: *"same file ∧ same size ∧ ordered"* is a conjunction the interpretive layer
*observes*. Bundling it into a relation called `staged_then_uploaded` is precisely how
interpretation leaks downward.

**The graph is virtual, not materialised.** `same_account` alone is roughly 44,000 pairs across 11
accounts. Relations are deterministic **functions the interpretive layer queries**, backed by
indexes:

| | Relations | Why |
|---|---|---|
| Materialised | `same_file` · `same_size` · `process_parent` · `flow_endpoint` · `address_resolves_to_host` | sparse and cheap |
| Indexed query | `same_account` · `same_host` · `temporal_within` · `same_address` · `session_bracket` | dense; materialising is waste |

What gets **committed** is the subgraph the investigation actually traversed — smaller, and a
record of what was examined. And because relations are functions, validation **re-evaluates** a
cited edge rather than looking it up: a fresh check rather than trust in a stored value.

**This dissolves the time-window problem.** `temporal_within` **reports** Δ instead of
thresholding it. No global window has to be chosen — and none could be: the intrusion's own gaps
between related activities span **2 seconds** (`cmd.exe` → `powershell.exe`) to **2 h 27 min**
(archive staged → uploaded). Interpretation decides in context whether a gap is meaningful. The
parameter that looked like the hardest open question stops being a parameter.

### 3.3 The AI investigation layer — non-deterministic, interpretive

```
SELECT       which observation or entity next — anchors first, then the frontier
EXPAND       query relations around it → a neighbourhood, with truncation reported
INTERPRET    propose a candidate finding citing specific edges
             · or extend the frontier · or "nothing here"
HYPOTHESISE  what should exist given findings so far — committed BEFORE looking
SEEK         FOUND → new observations · NOT_FOUND · NOT_COVERED
```

**Anchors order; they never attribute.** `R1.10` permits unusualness as grounds for review and
forbids it as evidence. The structural safeguard is that `SELECT` and `SEEK` can reach **any**
record, including records no anchor touched. *An anchor orders; a filter removes* — and a filter
would encode the answer. Anchors come from both deterministic signals and a model pass, so
neither's blind spot stands alone.

This matters because unusualness in this dataset is a shortcut to the right answer for the wrong
reason: exactly one account has no ordinary activity in the whole period and it is the compromised
one, and the only three hosts with a single network address are exactly the three compromised
hosts while every other host shows four to nine. Either is a one-line filter with perfect
precision and recall, and neither would survive contact with real logs.

**`EXPAND` reports what it truncated.** A 1-hop expansion on a busy host returns 60+ observations
through `same_host` alone, so each relation returns up to *k* nearest by time **with the total
stated**:

```
same_account   → 87 observations, showing 10 nearest in time
same_file      →  2 observations (complete)
process_parent →  1 observation  (complete)
```

Without that, the model reasons over a partial view believing it complete. This is the tool
surface being honest about its own limits, held to the same standard as the outputs.

**`coverage(entity, source_type)` is what makes `NOT_FOUND` meaningful.** Without it, "not found"
conflates absence from the environment with blindness of the source — the distinction `A-05`
names as unverifiable and `R3.12` requires reporting.

**Predict, then look.** `HYPOTHESISE` commits the prediction *before* `SEEK` runs, which is what
makes a negative result honest rather than post-hoc rationalised.

Termination: the frontier empties, or a full pass yields no accepted finding, or the budget
exhausts — and exhaustion emits `INSUFFICIENT_EVIDENCE` for open hypotheses rather than
concluding.

### 3.4 Candidate findings

The **cited edge set is the basis.** No rule registry — that is what the fact/interpretation split
made unnecessary.

```
candidate_finding
  statement     the interpretation, in prose
  stage         from a closed intrusion-stage vocabulary
  cites_obs     [observation ids]
  cites_edges   [(relation, o1, o2)]
  rationale     why these edges support this statement
  proposed_at   trajectory step
```

Hypothesis states are `proposed` → `confirmed` | `unconfirmed` | `uncoverable`, and each produces
a different sentence:

| State | Meaning | Sentence |
|---|---|---|
| `confirmed` | sought and found | becomes a finding |
| `unconfirmed` | sought; the source covers it; absent | *"the source covers this and nothing appears"* |
| `uncoverable` | no source could have recorded it | *"this could not be examined"* |

**The unconfirmed and uncoverable sets *are* the coverage-gap report** (`R3.6`), derived rather
than asserted from a checklist.

### 3.5 Validation — six deterministic checks

1. Every cited observation exists
2. **Every cited edge re-evaluates to true** — recomputed from its relation function
3. **Invented-identifier check** — every entity, value, identifier and timestamp named in the
   statement appears in a cited observation
4. `stage` is drawn from the closed vocabulary
5. Layer discipline · acyclicity · termination in raw records
6. **At close only** — no two accepted findings mutually incompatible (`R3.11`)

Check 3 does the most work in practice: a statement naming `PSEXESVC` requires `PSEXESVC` to
appear in a cited observation. Cheap, total, and it catches the commonest fabrication mode.

Check 6 is deferred to close deliberately. Acyclicity and mutual compatibility are **set-level**
properties: two findings can each be individually valid and jointly inconsistent, so they cannot
be evaluated per proposal.

On rejection, the diagnostic is **back-prompted** once or twice — *"finding F12 cites edge
`same_size(O7, O9)` which does not hold"* — then the proposal is abandoned and logged. The
rejection log is not merely a demo artifact: it is the **coverage backlog**, the list of things the
relation set and the interpretive layer between them could not establish.

| | |
|---|---|
| **Artifacts** | `03_observations.jsonl` · `03_edges.jsonl` (traversed subgraph) · `03_hypotheses.jsonl` · `03_findings.jsonl` · `03_trajectory.jsonl` · `03_rejections.jsonl` |
| **Verification** | the six checks above |
| **Serves** | `R1.1`–`R1.10` · `R2.1`–`R2.9` · `R3.2`–`R3.5` · `R3.11` · `R7.4` `R7.5` `R10.2` |

### 3.6 Worked example — the layers doing distinct work

For `EVT-0237` (endpoint `file_create`, `C:\Temp\backup_archive.zip`, 2,473,829,122 bytes) and
`EVT-0238` (cloud `file_upload`, `backup_archive.zip`, same byte count), the factual layer emits
five edges:

```
same_file        basename after normalisation — the raw values are NOT string-equal
same_size        2,473,829,122 exact
temporal_within  Δ = 1 h 27 min, ordered
same_account
same_host        FILE-SRV-02
```

For `EVT-0239` — the *deletion* of the same archive — it emits `same_file` and `same_account` but
**no `same_size`**, because the deletion record carries none.

Neither of those is a finding. The interpretive layer sees two candidate link-sets of visibly
different strength and interprets the first as staging-then-removal. Validation confirms all five
edges recompute and that every value in the statement appears in a cited observation.

Measured: matching on basename **and** exact size yields exactly one join across the whole dataset
— the true one. Matching on basename **alone** yields two, the spurious one being the deletion.
That asymmetry is the design's central claim and verification item 7 tests it before anything
rests on it.

---

## 4. Stage 4 · ENRICH WITH ATT&CK

The brief orders enrichment **after** correlate, so mapping runs over accepted findings rather
than inside the loop.

1. **Retrieve** candidate techniques per finding — deterministic, over locally held catalogue
   names and descriptions.
2. **Select** from that enum via native structured outputs, quoting the field values that
   triggered the choice (`R4.1`).
3. **Validate** — see below.

**A hallucinated technique id is structurally unrepresentable, not merely detectable.** This is
MITRE's own TRAM lesson: TRAM has no catalogue check at prediction time because a closed-label
classifier *cannot* emit an id outside its label set. Constraining generation beats validating
after it.

Validation still checks what constraint cannot:

- the id came from the retrieved enum
- **id ↔ name consistency** against the catalogue — the documented LLM failure is a correct name
  paired with a wrong id, which an existence check alone passes
- the quoted values appear in the cited record
- the tactic is consistent with the finding's stage

**On privilege specifically** (`R4.4`–`R4.9`), this dataset sets a trap. Integrity appears to rise
`medium → high → SYSTEM`, but:

- the three readings sit on **three different hosts**, so no within-host rise is evidenced at all
- nothing records the privilege being **acquired** — the account is executing at high integrity 54
  seconds after authenticating, with no intervening record
- the one session record for that account on that host is a **network** logon, yet interactive
  high-integrity processes appear; fifteen other accounts *do* have interactive logons to the same
  host, so this is an unexplained inconsistency, reported under `R4.7` and not resolved
- **no event kind in this dataset can record a privilege change at all** — the complete vocabulary
  is process/file/service create-delete, `process_access`, logon/logoff/failed_logon,
  `network_connection` and four cloud file actions. So "no escalation observed" is guaranteed true
  regardless of the facts, and is a statement about coverage (`R4.8`)

And the accurate ATT&CK statement is not *"no privilege-escalation mechanism observed"*: ATT&CK
maps **T1078 Valid Accounts** to the Privilege Escalation tactic, so valid-account use is one of
its named forms. What is absent is any **exploitation, elevation-bypass or token-manipulation**
mechanism. **T1569.002 Service Execution** maps to Execution only, so a SYSTEM shell obtained
through a remote service is not itself an escalation technique (`R4.9`).

| | |
|---|---|
| **Artifacts** | `04_mappings.jsonl` (`technique_id`, `technique_ref`, name, tactic, quoted values, catalogue version) · `04_unmapped.jsonl` |
| **Verification** | the four checks above |
| **Serves** | `R4.1`–`R4.9` |

`non_mappable` is a first-class outcome distinct from rejected — *we looked, and there is
legitimately nothing here.*

---

## 5. Stage 5 · SYNTHESISE — deterministic

Project the closed graph into the timeline, the scope of compromise, the coverage-gap report, the
Attack Flow export and the Navigator layer.

**Absence-based conclusions are computed only here**, after the graph is closed. They cannot be
emitted during the loop: a later iteration may find what an earlier one declared unobserved, and
closed-world claims are not monotone under a growing accepted set. *"Persistence was not
observed"* flips the moment iteration 12 finds it.

| | |
|---|---|
| **Artifacts** | `05_timeline.json` · `05_scope.json` · `05_gaps.json` · `05_attack_flow.json` · `05_navigator_layer.json` |
| **Verification** | every projected element traces to graph nodes · absence claims recomputed against the final graph · Attack Flow validates against the vendored schema |
| **Serves** | `R1.1` `R1.5` `R3.5` `R3.6` `R3.12` `R5.1`–`R5.4` `R8.2` `R8.3` |

---

## 6. Stage 6 · ANSWER — model + read-only tools + gate

Agentic retrieval over the frozen artifacts. **No tool can create a node**, which is what makes
this phase structurally incapable of inventing a finding.

| | |
|---|---|
| **Artifacts** | answer + citations + step trace + an **answer record** (question, steps taken, citations returned, model id, provider version, prompt hash, catalogue version, software version) |
| **Verification** | every citation resolves · quoted values present in the cited node · layer discipline on cited nodes · no likelihood term and confidence level in one sentence · **attribution requires a finding** (below) |
| **Serves** | `R2.x` `R6.1`–`R6.7` `R8.1` `R10.1`–`R10.3` `NFR-07` |

**Gate two is weaker than the build-time checks, and says so.** It validates citations, quoted
values, layer discipline and attribution. It **cannot** validate whether a qualitative summary
fairly represents the nodes it cites.

### 6.1 Two tool surfaces, and the loophole between them

| | Build | Query |
|---|---|---|
| Tools | `expand(obs, k)` with truncation counts · `relate(o1, o2)` · `seek(prediction)` · `coverage(entity, source_type)` · `record(id)` | `find_findings()` · `trace(node)` · `observations_for(entity)` · `record(id)` · `gaps()` |

Note what is **absent** from the query surface: **no relation computation.** If query time could
compute relations it could discover links the investigation missed — a finding minted at query
time, which `NFR-01` forbids.

**The loophole and its closure.** `R6.3` requires entity pivot at answer time, so the query layer
must read observations belonging to no finding. A claim could therefore cite only observations and
still assert attribution — *"the attacker also touched WKSTN-04"* — smuggling a finding into a
claim. So: **an answer claim that attributes activity to the intrusion must cite at least one
finding node.** Observation-only citations support factual statements (*"three other accounts used
that host"*) but never attributions.

---

## 7. Where the model appears — exactly three places

| Stage | What the model does |
|---|---|
| 3 | `INTERPRET` — propose a finding citing existing edges · `HYPOTHESISE` — predict what should exist |
| 4 | select a technique from a retrieved enum |
| 6 | retrieve from the frozen graph and render prose |

Everything else is deterministic. Specifically, the model **does not**: parse or normalise ·
resolve entities (it would smooth over the ambiguity `R3.9` exists to expose) · compute support
labels (counted from the graph per `R3.4`) · compute the timeline, scope or gaps · decide what is
accepted · assign confidence of any kind.

That is the stage-precise answer to *"where AI was used and where it was deliberately not"*.

---

## 8. Data model

### 8.1 Nodes and edges

```
 claim ──cites──► finding ──cites──► observation ──cites(field)──► record
   │                 │                    ▲                          ▲
   └──cites──────────┼────────────────────┘                          │
                     │                                               │
                  mapping ──cites──► observation ───────────────────► ┘
```

Five node kinds — `record` · `observation` · `finding` · `mapping` · `claim` — plus `hypothesis`,
and one relation kind, `cites`. Findings additionally cite **edges**.

**Four invariants, all machine-decidable — this is the trust story:**

1. **Layer order** — a record cites nothing; an observation cites only records; a finding cites
   only observations, findings and edges; a claim cites findings, mappings or observations
2. **Termination** — every chain bottoms out in raw records (`R2.4`)
3. **Acyclicity** — no node transitively supports itself
4. **Grounding** — every value an observation asserts appears at a named field of a cited record
   (`R2.6`)

Plus a fifth from stage 2: **every asserted value is reproducible by applying its recorded
transform to its recorded raw value.**

### 8.2 Identity — content-derived, structure only

```
id = <prefix>_ + sha256(canonical_json(identity_fields))[:12]
canonical_json: sorted keys · no whitespace · UTF-8 · ensure_ascii=False
                integers for byte counts · normalised ISO-8601 for times
```

| Node | Identity fields | **Excluded** |
|---|---|---|
| `rec_` | source type, event id, canonical payload | — |
| `obs_` | record id, field, normalised value, transform name | created-at, trajectory step |
| `edg_` | relation name, ordered endpoint ids | computed params — Δt is *derivable* from the endpoints, so including it adds nothing and churns if the time base shifts |
| `fnd_` | sorted cited observation ids, sorted cited edge ids, stage | **`statement` and `rationale` — rendered prose** · `proposed_at` · model id, prompt hash, provider version |
| `map_` | technique id, target finding id, sorted cited observations, quoted values | catalogue version — recorded as provenance, not identity; *"this is T1059.001"* is unchanged by a catalogue bump |
| `hyp_` | premise ids, predicted entity/role/event-kind/source/window | rationale prose · **status**, which changes, and identity must not |

**Excluding prose is the load-bearing part.** Re-run the build with a different model and
structurally identical findings get identical ids — so a diff between two runs shows which
findings changed *structurally*, not which sentences got reworded. It also collapses two
mechanisms into one: the dedup key and the id are the same thing.

Answer claims are **not** in the committed graph. They live in the per-question answer record with
citations pointing into it; otherwise the graph would vary with whatever anyone happened to ask.

### 8.3 Authority and projections

Three authorities, layered. Nothing else is authoritative:

```
raw records          what was logged              immutable, read-only
investigation graph  what we concluded, and why   the authority for findings
ATT&CK catalogue     what a technique is called   versioned, external
```

Everything else — the Attack Flow export, the Navigator layer, the timeline, the scope list, the
gap report, the handover document, **and the SQLite index** — is a **projection**: derived, never
authoritative, always regenerable. One-way: exports come from the graph; the graph is never
reconstructed from an export.

Testable invariant: **delete every export and the index, regenerate from the committed JSONL, get
byte-identical output.** A failure means something authoritative leaked into a projection.

Two vocabulary sources for two layers: **Micropublications / PROV / EVI** for the evidence layer
(`Claim`/`Data`/`Method` + `supports`, transitive closure to evidence,
`used`/`wasGeneratedBy`/`wasDerivedFrom`, `Usage` + `hadRole`, `directlySupports` vs `supports`),
and **Attack Flow** for the adversary-narrative projection — the `technique_id`/`technique_ref`
pair, and nothing else.

---

## 9. UI design — forensic dossier, not dashboard

**Reference class.** The product thesis is *"can the CISO hand this reconstructed timeline to their
board and legal team with confidence?"* So the model is a **case file**, not a SOC dashboard. That
serves the positioning and differentiates from the dark-mode-dashboard look the category defaults
to.

### 9.1 Palette — measured

| Role | Light (parchment) | vs surface | Dark | vs surface |
|---|---|---|---|---|
| Page plane | `#E8DCC4` | — | `#14110D` | — |
| Panel / chart surface | `#F0E6D2` | — | `#1E1A15` | — |
| Primary ink | `#1C1814` | **14.25:1** | `#F5EFE3` | 15.11:1 |
| Secondary ink | `#453D34` | 8.61:1 | `#C0B49F` | 8.46:1 |
| Muted (axis, labels) | `#6E6152` | **4.85:1** | `#8F8474` | 4.71:1 |
| Rule / gridline | `#D6C9AE` | 1.32:1 | `#2E2921` | 1.20:1 |
| Baseline / axis | `#BCAC8E` | 1.80:1 | `#3A3429` | 1.40:1 |

Muted ink was darkened from the first candidate specifically to clear the 4.5:1 text floor on
parchment. Dark mode is **selected** — its own steps against its own surface, not an automatic
flip.

**Status palette, unthemed.** The four support states are a status job, not a categorical one:

| Support state | Role | hex | vs parchment |
|---|---|---|---|
| Corroborated | good | `#0ca30c` | 2.71:1 |
| Single-sourced | warning | `#fab219` | 1.65:1 |
| Absence-based | serious | `#ec835a` | 2.37:1 |
| Conflicted | critical | `#d03b3b` | 3.88:1 |

Three sit below 3:1 on parchment, so **icon + label is mandatory on every one** — which doubles as
`R3.2`–`R3.5`'s requirement that support states are *words*. Colour never carries state alone.

### 9.2 Typography — and no web fonts

Google Fonts from the Streamlit frontend would break `NFR-02`, so system stacks only:

```
display / headings    Georgia, 'Iowan Old Style', 'Palatino Linotype', serif
body prose            same serif · 1.55 line-height · ~68ch measure
chart interiors       system-ui, -apple-system, 'Segoe UI', sans-serif
records / ids / axes  ui-monospace, 'Cascadia Mono', Consolas, monospace
                      + font-variant-numeric: tabular-nums
```

A deliberate boundary: the visualisation method forbids serif *inside charts*, and that holds —
chart labels, ticks and legends stay in the UI sans with tabular figures. The serif is for the
case-file chrome around them.

### 9.3 Only two things are charts

| Surface | Form | Why |
|---|---|---|
| Timeline | **typed table**, expandable per row | its job is to be *read* in order with evidence opened |
| Scope of compromise | **table** | enumeration |
| Technique coverage | **exported Navigator layer** | no in-app chart earns its place |
| Source-type event plot | **chart** — one lane per source type over 72 hours | makes "12 hours of intrusion inside a 3-day window" legible at a glance |
| Coverage matrix | **chart** — hosts × source types, covered / absent / partial | status grid |

**Key decision: position carries identity, colour carries state.** One lane per source type means
the lane *is* the label, freeing colour for intrusion-attributed vs background. Consequence:
**zero categorical series anywhere in the app**, which sidesteps the all-pairs colour-vision
ceiling entirely rather than working around it.

Mark specs: 2px lines · ≥8px markers · 2px surface gap between adjacent fills · 2px surface ring
on overlapping marks · recessive grid and axes · selective direct labels, never a number on every
point. Per-mark hover tooltips on both charts; filters in one row above.

### 9.4 Four surfaces

1. **Chat** — the ten evaluation questions. Citations render as **top-level siblings** of the
   answer body inside `st.chat_message`, because `StreamlitAPIException: Expanders may not be
   nested inside other expanders` makes the natural layout illegal. Expansion state keyed in
   `st.session_state`; record lookup behind `@st.cache_data`. **This is a day-one constraint** —
   retrofitting it is a rewrite of the render loop.
2. **Timeline** — chronological; per-step technique and support state (icon + label); citations
   expandable to raw JSON via `st.json(body, expanded=2)`.
3. **Impact** — hosts, accounts, assets; first and last involvement; confirmed vs observed; what
   cannot be ruled out.
4. **Pipeline** — six stages as `st.status(type="step")`, each expandable to its artifact and
   verification result. **Carries the gap report**, each gap shown beside the hypothesis that went
   looking for it, plus the rejection log.

Theming via `.streamlit/config.toml` — `[theme] base="light"` with the parchment values above, and
`[browser] gatherUsageStats = false`. **No `[[theme.fontFaces]]` pointing at a CDN.**

Accessibility: status always icon + label · every chart has a table view · dark mode selected with
its own validated steps · texture fill at 45°/135° for forced-colors and print · a print
stylesheet, since the dossier framing invites printing.

---

## 10. Decisions

| | Decision | Rejected, and why |
|---|---|---|
| **D-01** | Hand-written parsers per event kind; records retained verbatim; OCSF *naming* borrowed where free, conformance not claimed | OCSF/ECS mapping — a day of mapping tables buying nothing the requirements ask for, while correlation quality is what is graded. Declarative field mapping — the collisions are *transforms* (`file_path` → basename to meet `file_name`) and *role assignments*, not renames, so config becomes a mini-DSL plus an interpreter |
| **D-02** | The six-stage pipeline; correlate split into a deterministic factual layer and an interpretive AI layer; three model sites; build artifacts committed, query live | One monolithic proposal call — correlation becomes a single opaque inference with no answer to *"how would you have caught the movement the last tool missed?"* · A deterministic rule registry producing findings — puts interpretation in the rules, which reintroduces the coverage ceiling · Fully model-driven — `NFR-01` and the 30 s budget |
| **D-03** | **Retain the official ATT&CK bundle locally.** Commit `enterprise-attack-19.2.json` (STIX 2.1, 51 MiB) + `index.json`. The bundle is the **authority**; the ~200 KB flat catalogue derived from it with stdlib `json` is a **projection**. `attack_version` copied verbatim from the `x-mitre-collection` object. Nothing fetched at runtime | `mitreattack-python` — pandas + numpy + pillow + drawsvg (~150–300 MB) for id→name, and its `MitreAttackData` is typed against STIX **2.0** while we commit 2.1 · TAXII — runtime network, breaks `NFR-02` · keeping only the derived subset — the derivation stops being reproducible and the version claim unverifiable |
| **D-04** | **Attack Flow is a projection, not the internal model** — a ~100-line serialiser at stage 5 publishing vanilla Attack Flow plus an `evidence_refs` extension. One idea borrowed back: the `technique_id` + `technique_ref` pair. Priority **Should** | Adopting it internally: (1) **countable mismatch** — 3 of 5 node types and **all 10 relations** have no equivalent; its edges are `effect_refs`/`asset_refs`, with no way to say "these two observations share a value"; (2) it is a **publication format** — every corpus entry was authored after the fact by someone who knew the answer; (3) **conflicts with D-10** — STIX `<type>--<uuid>` ids forfeit content-hash immutability, and per-node `spec_version`/`created`/`modified` destroys diffability |
| **D-05** | Dataclasses + `dict` adjacency; ~40 lines of iterative three-colour DFS, so a cycle yields its **path**. **SQLite is an internal index**, built from the committed JSONL at load, discardable | `networkx` as source of truth — no node schemas, no layer typing, two sources of truth, and every check we need emits a diagnostic it cannot generate · materialising the factual graph · SQLite as the authority |
| **D-06** | Streamlit 1.64.0, four surfaces, citations as top-level siblings | Chainlit — wins live step display outright but has **no multipage primitive**, killing three of four surfaces · Gradio — longest telemetry surface (`api.gradio.app`, background PyPI check, Google Fonts by default) · FastAPI+HTMX — cleanest for the citation requirement, spends the whole budget on plumbing that is explicitly not graded |
| **D-07** | Ten hand-written atomic relation functions; the six validation checks in §3.5; cited edges **re-evaluated**, not looked up | A declarative predicate DSL (`rule-engine`, CEL) — unnecessary once relations are ten fixed functions rather than a growing registry · NLI/entailment scoring — it exists because prose sources cannot be checked exactly, and ours can · guardrails-ai provenance validators — similarity scores where we need set membership · the `prov` library, CASE/UCO, STIX `observed-data` as internal model — correct domain, far too heavy |
| **D-08** | Two tool surfaces (§6.1); attribution requires a finding; structured outputs via `client.messages.parse` with Pydantic; `strict: True` + `additionalProperties: false`; `thinking={"type":"adaptive"}`; bounded back-prompt on rejection | Union-of-N as the primary strategy — **precision is monotone non-increasing in N** (§11) · one shared tool surface across build and query |
| **D-09** | 400-line soft ceiling per source file, reported by the build | A CI gate — no user or evaluator can observe it |
| **D-10** | **Deterministic sorted JSONL is the committed audit representation** — one object per line, sorted by id, `json.dumps(sort_keys=True, ensure_ascii=False)`, LF via `.gitattributes`. Content-derived ids from canonical structured identity only (§8.2) | Pretty JSON — bracket-shifting diffs · YAML — quoting footguns, lossy round-trip · TOML — no stdlib writer · RDF/JSON-LD — needs framing to be deterministic at all · **SQLite as the committed representation** — opaque to diff and review |

### 10.1 Dependencies

`anthropic` · `streamlit` · `pydantic` · `pandera` · `jsonschema` · `streamlit-aggrid` ·
`st-link-analysis`

Catalogue derivation, the ten relation functions, the graph, the validator and serialisation are
**stdlib**. The venv is frozen before any demo; `pip install` at demo time is an `NFR-02` failure.

### 10.2 If the five days compress — cut order

Ratified requirements outrank design preferences, so the handover report survives longer than the
pipeline view even though the pipeline view is worth more to the grading:

```
cut first  →  Navigator layer
              Attack Flow export          Should, ~100 lines
              graph visualisation         st-link-analysis
              pipeline view               design choice, not a requirement
cut last   →  handover report             R8, ratified in scope
```

---

## 11. Design history — four drafts, and why three died

Kept because the assignment asks for architectural decisions and what would be improved, and this
reasoning is the honest answer.

**Draft 1 — one model call over all observations, gated.** Killed because it undersells the ask.
The brief's failure inventory begins with *no correlation*, and correlation inside a single
inference has no answer to *"how would you have caught the movement the last tool missed?"* It also
misread its own supporting paper: HunterAgent is a **bounded search with hard pruning per
expansion**, not one call — the cited precedent validates a *more* agentic design than draft 1
proposed.

**Draft 2 — union N independent proposal passes.** Killed by a result. Because the validator is
deterministic, the contract-satisfying-but-wrong region is a **fixed** subset of accept-space: it
does not average out and cannot be detected by cross-pass agreement. So `E[|FP|]` is also
non-decreasing in N and **precision is monotone non-increasing** (Stroebl, Kapoor & Narayanan,
arXiv:2411.17501 — optimal N often under 10; Beckh et al. measured recall 0.63 → 0.86 *with*
precision 0.74 → 0.57). The sharpest form: *precision was being measured by the same artifact
whose blind spots define it.* Replaced by **back-prompt repair**, which uses the diagnostic
instead of discarding it.

**Draft 3 — model proposes correlation rules; validator tests them against expected matches.**
Killed by the fact/interpretation split. Draft 3 still had interpretation inside the deterministic
layer: a rule named `staged_then_uploaded` both computes a link *and* calls it exfiltration. That
is why draft 3 concluded the model had little to do — its job had been given to the rules. It also
reintroduced the coverage ceiling, since rules that interpret can only interpret what someone
encoded.

**Draft 4 — fact and interpretation separated.** The deterministic layer emits atomic factual
relations and decides nothing; the interpretive layer interprets. Consequences: no coverage ceiling
· the model **cannot invent a relationship**, only interpret ones that factually exist · the rule
registry disappears · the time-window parameter dissolves.

### 11.1 Claims corrected along the way

**"Guaranteed sound" → "sound modulo the checks."** Soundness is relative to what the checks can
express, and the architecture *relocates* that risk into the checks rather than removing it. Never
"guaranteed sound".

**"Reproducible pipeline" → "replay reproducibility."** Given the committed trajectory, the
contract-set hash and the validator version, every accept/reject verdict is bit-for-bit
reproducible. The interpretive layer is an untrusted, out-of-TCB search heuristic affecting
**coverage only**. This is the **de Bruijn / LCF** posture — untrusted tactic, small trusted kernel
— and it is stronger than anything sampling control could give, since temperature-0 is not
determinism anyway: 1,000 temperature-0 completions of one prompt produced 80 distinct outputs, the
cause being batch-invariance in inference kernels rather than the API.

### 11.2 Prior art

- **LLM-Modulo** (Kambhampati et al., ICML 2024) — the pattern, and the soundness-from-the-verifier
  / completeness-from-the-generator split, stated verbatim
- **HunterAgent** (arXiv:2605.29269) — the security instantiation. Key result: **F1 77.9–85.7
  across four different model backbones**, *because soundness is structurally enforced rather than
  dependent on generator strength*. Path-level hallucination 61.5% → 6.4%
- **`google/timesketch`**, `lib/llms/features/log_analyzer.py` — a shipped Apache-2.0 citation gate
  with partial-failure semantics: drop unverifiable citations, keep the finding, discard only at
  zero
- **TRAM** — the constrain-don't-validate lesson
- **Certifying computation** (McConnell et al. 2011), **proof-carrying code** (Necula & Lee 1997) —
  the untrusted-producer / trusted-checker vocabulary
- **Retrieval-Augmented LLMs for Security Incident Analysis** (arXiv:2603.18196) — nearest
  published architecture; no released code

---

## 12. Stress

**10× volume (2,420 records).** Ingest, parse and validation unaffected. The factual layer stays
virtual, so nothing grows quadratically in storage. The interpretive layer's cost is proportional
to **traversal length**, not corpus size — so it scales *better* than a monolithic call, whose
input would grow linearly. `EXPAND` truncation caps per-step context regardless of density.

**Single points of failure.**

1. **The relation set.** A wrong or missing relation makes links wrong or missing, and **no
   downstream check can detect a link that was never computed.** This is the sharpest one.
2. **The aptness of interpretation.** Unchecked by construction; see §13.
3. **The anchor set.** An intrusion matching no anchor is invisible — mitigated by unconstrained
   `SELECT`/`SEEK` and by reading the rejection and unconfirmed logs as a coverage backlog.
4. **Catalogue derivation.** Mitigated by committing the source bundle.

---

## 13. Unsoundness statement — what the checks deliberately do not check

Shipped deliberately, following the soundiness norm from static analysis. Silence here would be
the same failure the rest of this document guards against.

1. **Whether an interpretation is apt.** A finding can cite real observations and real edges, name
   only real identifiers, and still draw the wrong conclusion. This is the **test oracle problem**
   and it is irreducible here.
2. **Whether a qualitative summary fairly represents the nodes it cites.** Gate two checks
   citations, quoted values and attribution; it cannot check fairness of characterisation.
3. **Whether the relation set is complete.** A relationship no relation expresses is invisible at
   every layer.
4. **Log integrity.** Same-record grounding proves a value is present, not that the record is
   truthful — a limit an adversary with log access could exploit. Cross-source corroboration (the
   `Corroborated` label) is the only partial answer, and it is why that label is a *count of
   independent sources* rather than an adjective.
5. **Generalisation.** The ten acceptance scenarios are a **regression suite for one supplied
   incident**, written after reading the developer annotations. `R7.1` constrains *how* the answer
   was reached; nothing here demonstrates performance on unseen data.
6. **False-negative rate.** This architecture structurally biases toward missing things. Measuring
   it requires ground truth we have for one incident only.

Evidence rather than assertion, for items 1–3: an adversarial corpus of proposals the validator
must reject (the invented-identifier probe among them); set-level checks evaluated at close rather
than per proposal; and the rejection and unconfirmed logs read as a coverage backlog.

---

## 14. Traceability

| Requirement | Design |
|---|---|
| `R1.1`–`R1.8` sequence, stages, no-intrusion case | §3.3 loop · §5 projection |
| `R1.9` attribution on evidence only | §3.2 — findings cite edges the factual layer computed |
| `R1.10` unusualness orders, never attributes | §3.3 anchors |
| `R2.1`–`R2.5` layered provenance, records verbatim | §8.1 · §2.1 |
| `R2.6` value grounding | §2.2 provenance · §3.5 check 3 |
| `R2.7`–`R2.9` withhold on failure, not on layer | §3.5 |
| `R3.1`–`R3.5` support labels, structural only | §3.4 · §9.1 status palette |
| `R3.6` gaps unprompted | §3.4 hypothesis ledger · §9.4 pipeline surface |
| `R3.7`, `R3.8` absent sources, eviction undetermined | §3.3 `coverage()` · §5 |
| `R3.9`, `R3.10` ambiguous / unresolvable addresses | §2.2 resolution artifact |
| `R3.11` incompatible conclusions | §3.5 check 6, at close |
| `R3.12` hosts a source does not cover | §2.2 `observed_on` |
| `R4.1`–`R4.3` technique id, name, tactic, unmapped | §4 |
| `R4.4`–`R4.9` privilege | §4 |
| `R5.1`–`R5.4` scope of compromise | §5 |
| `R6.1`–`R6.7` plain-language questions | §6 · §6.1 |
| `R7.1` leak independence | §3.3 anchors · verification 7 |
| `R7.2` annotations for accuracy only | §2.1 boundary strip |
| `R7.3` self-reported accuracy | validation harness |
| `R7.4`, `R7.5` inspectable, followable | §8.1 · §10 D-10 · §9.4 pipeline |
| `R8.1`–`R8.4` handover | §5 · §10.2 |
| `R9.1`–`R9.4` recommendations | §6 |
| `R10.1`–`R10.3` show the working | §9.4 · §6 answer record |
| `NFR-01` same conclusions | §8.2 identity · build/query split |
| `NFR-02`, `NFR-02a` offline, nothing rests on the service | §8.3 · §7 |
| `NFR-03` 5 s reconstruction | committed artifacts, a file read |
| `NFR-04`, `NFR-04a` documented egress, checks regardless of origin | §6 answer record · §3.5 |
| `NFR-05` data unmodified | §2.1 |
| `NFR-06` failure transparency | per-stage verification |
| `NFR-07` version on every output | §6 answer record · §8.2 |
| `NFR-08` documented single command | §10.2 build / app split |
| `NFR-09` timezone | §2.2 `utc_instant` |
| `NFR-10` credentials not stored alongside | build/query split — the app holds no credential |

---

## 15. What Phase 3 must break down

Ordered by dependency, with the three spikes first because each can invalidate a decision cheaply
now rather than expensively later:

1. **Relation spike** — confirm the five edges between `EVT-0237`/`EVT-0238`, and that `EVT-0239`
   yields `same_file` but no `same_size`. §3.6 is the design's central claim
2. **Catalogue derivation spike** — three slices out of the v19.2 bundle; `T1059.001` → PowerShell,
   Execution
3. **Streamlit offline smoke test** — network disabled, confirm no startup hang with
   `gatherUsageStats = false`
4. Stage 1–2 with their verification passes
5. The ten relation functions and the index
6. The six validation checks, plus the adversarial corpus
7. The interpretive loop, tools first
8. Stage 4, then stage 5 projections
9. Stage 6 and the four UI surfaces
10. The validation harness: leak independence, accuracy against annotations, projection purity,
    identity stability
