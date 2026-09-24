# Tasks: Cyber Incident Investigation Intelligence

| | |
|---|---|
| **Phase** | 3 of Spec → Design → Tasks → Implement → Validate |
| **Status** | Draft for review. 45 tasks, one DAG, three cut lines |
| **Requirements** | [requirements.md](requirements.md) — Phase 1, closed |
| **Design** | [design.md](design.md) — Phase 2, all ten decisions locked |
| **Date** | 2026-09-23 |

> Every task below is executable by one person in one sitting, states how you would know it
> worked, names the requirement ids it serves, and declares its dependencies. Sizes are
> unassisted-developer hours; see §4 for the budget reconciliation.

---

## 1. Ordering principle

**Risk first, then the deterministic floor, then the trusted kernel, then the interpretive layer
behind a measurement gate, then the surfaces, then the cut tail — unchained.**

Five properties the order is built to have:

1. **Anything that can invalidate a locked decision runs in the first ten tasks.** T01 (no SDK, no
   credential), T03 (the two external artifacts), T04 (the privilege-tactic facts §4's wording
   rests on), T05 (strict structured outputs), T07 (sibling citations and the unmeasured pandas
   assumption), T09 (§3.6's central claim). Each is cheap, and each failure forces a design change
   rather than a workaround.
2. **The trusted kernel is complete before the untrusted generator exists.** Design §11.1 puts
   this design in the de Bruijn / LCF posture — untrusted tactic, small trusted kernel. So the
   validator (T18) and the adversarial corpus that constrains it (T15, authored first and frozen)
   land before the loop (T21) and before any model call proposes a finding (T22).
3. **Accuracy is a gate, not a closing report.** T30 measures recall, precision and leak
   independence *before* the answer plane (T31) and the surfaces (T36, T37) are built. Design §12
   says the architecture structurally biases toward missing things and §13 item 6 declines to bound
   the false-negative rate, so SC-03 is the loudest unknown in the plan. A shortfall found at T30
   reopens T16, T20 or T22; the same shortfall found after the UI is built is the most expensive
   ordering mistake available here.
4. **The three graded deliverables are tasks, not hopes.** The prototype is deliverable 1; T40 is
   the written discussion, T41 the walkthrough, T39 the spec-compliance evidence Phase 5 is gated
   on. None sits in the cut tail.
5. **The cut tail is four mutually independent tasks.** T42–T45 depend only on spine tasks, never
   on each other, so the cut line falls at any boundary without stranding a dependency — which is
   the whole point of §10.3 and is defeated by chaining them.

### 1.1 How this improves on design §15

§15 is a nine-item layer order written from the top of the stack down. Seven concrete differences:

| # | §15 | Here, and why |
|---|---|---|
| 1 | Three spikes first | **Two are already spent.** §10.2 records the relation spike CONFIRMED and offline startup PASS at 1.5 s. Re-running them buys nothing, so they become a committed regression test (T09, which proves its own teeth by mutation) and an assertion inside T07. Only the catalogue spike is live, and it is T04. |
| 2 | Starts at "stage 1–2", assuming the model plane and catalogue are in hand | **Neither exists.** Measured in this repo: `.venv` has 48 packages and `anthropic` is not among them; `ANTHROPIC_API_KEY` is unset; `data/attack/` holds only `.gitkeep`; `pandera 0.33.1` is still installed despite §10.1 dropping it. T01 and T03 settle all four in the first 1.25 h. |
| 3 | Relations → validation → loop, layer by layer | **Corpus before validator, skeleton before prompts.** T15 freezes the adversarial corpus so T18's validator is written against a fixed target instead of the corpus drifting to match it. T21 drives the whole loop through a *scripted stub interpreter* with zero model calls, so a loop failure is diagnosable as mechanism (T21) or prompt (T22), and the build stays demonstrable with the API down. |
| 4 | Validation harness last (item 10) | **Split by what it feeds.** Leak independence of the anchors is cheap and moves to T20, where it needs only parse plus anchors. Accuracy and whole-pipeline leak independence become the T30 gate. Projection purity and identity stability stay late (T38) because they genuinely need the finished artifacts — but they depend on T28/T29, never on the handover report. |
| 5 | UI at item 9 | **The render constraint is day one.** §9.4 calls retrofitting the sibling-citation loop a rewrite, so T07 proves it, the parchment palette in *both* modes, and the unmeasured `st.dataframe`-over-`pyarrow` assumption on day one — and emits the answer-payload contract that shape implies, so the constraint discovered at T07 is applied at T31 through an artifact rather than from memory. |
| 6 | Silent on nine obligations the design states elsewhere | Each is a task here: the contract-set hash and `validator_version` that §11.1's replay claim needs (T06), the NFR-04 egress inventory (T06), the R7.1 perturbation generator SC-05 rests on (T14), the basis role-fulfilment check R2.7 clauses 2–3 turn on (T18), the six per-stage verification reports §1 promises (T28), the Attack Flow schema three verifications validate against (T03), the cut-proof `trace` CLI for R7.4/R7.5 (T13), the gate-two corpus for the weaker gate (T32), and the artifact-home fix without which `outputs/` is gitignored (T29). |
| 7 | Cut order advisory | **Compiled into the execution order.** T42–T45 are the reverse of §10.3's list. The compliance table (T39) and the harness (T38) appear in no cut list, so they outrank the handover report and precede it. |

### 1.2 Which decomposition this is built on

Based on **risk-first**, which was the only candidate whose serves-lists cover all 67 acceptance
criteria, 12 NFRs, 5 success criteria and 10 scenarios, and which had the single best ordering
judgement in any candidate — accuracy as a gate that reopens the anchors and the loop.

Grafted in:

- **From dependency-first** — the loop split into stub-driven skeleton and model-backed prompts
  (T21/T22); the privilege report as its own deterministic projection (T24); the adversarial corpus
  frozen as an earlier task (T15); three negative controls that prove the perturbation harness
  bites (inside T14); and the cut-order reasoning that the harness outranks the handover.
- **From vertical-slice** — stdlib `unittest` settled at T01, because pytest is absent and §10.1
  forbids adding it; `pandera` uninstalled from the working `.venv`, not merely absent from a clean
  one; the `st.dataframe`/`pyarrow` probe on day one; and the mutation proof on T09.
- **From the critiques** — nineteen missing tasks, all incorporated or merged; the basis
  role-fulfilment check, which all three candidates omitted while claiming R2.7 and SC-02; the
  gate-two answer-prose check; the SC-01 cold read; and NFR-06 fault injection.

Two splits I refused: the ten scenarios are three tasks (T33–T35), not one 21-id task and not ten;
and stage 5 is two tasks (T26 projection, T27 gaps) because the gap report is derived from the
hypothesis ledger, which is a different mechanism from projecting the graph.

---

## 2. Measured corrections found while planning

Four things checked against the data rather than taken from the documents. All four change a task's
verification text.

1. **"Fifteen other accounts" is wrong.** Requirements §2 (R4.7 rationale) and design §4 both state
   that fifteen other accounts have interactive logons to the same host. Measured on
   `AUTH-SRV-01`: **12 interactive logon events across 7 distinct accounts** (`asmith`,
   `bwilliams`, `cjohnson`, `ewhite`, `fmartinez`, `glee`, `jclark`); dataset-wide there are 19
   interactive events across 9 accounts. Neither reading is 15. **R4.7 itself is unaffected** — the
   inconsistency is real (jdavis's only session record on that host is a `network` logon, and the
   data plainly does model interactive logons there) — but the count is not. T24 computes it from
   the data and T39 records the correction. This is exactly the error the document exists to
   prevent, found in the document.
2. **Design §3.2's "2 h 27 min" is a slip.** §3.6 and §10.2 say 1 h 27 min. Measured
   `EVT-0237 → EVT-0238`: **1 h 27 m 41 s**. T09 and T16 assert the measured value.
3. **CLAUDE.md's field table is incomplete.** The dataset carries **40 distinct keys**; the table
   omits `service_path` and `target_pid`. T08's census fixture records all 40.
4. **Network is reachable from here.** `raw.githubusercontent.com/mitre-attack/attack-stix-data`
   returns content, so T03's single network window is viable rather than hoped for.

Also confirmed: 242 records; 84/65/62/31 by source type; 14 event kinds; 22 `ATTACK:` notes;
`command_line` absent 184 / empty 50 / valued 8; `network_connection` spans three key-sets
(80/3/1); 80 records without `src_host`, 83 without `dst_host`; `10.0.3.78` the only ambiguous
address (`WKSTN-04`, `WKSTN-10`); `AUTH-SRV-01`/`FILE-SRV-02`/`WKSTN-07` the only single-address
hosts; 11 accounts; `AUTH-SRV-01` 2 endpoint events and `AUTH-SRV-02` zero across 23 appearances;
integrity `medium`/`high`/`system` on `WKSTN-07`/`AUTH-SRV-01`/`FILE-SRV-02` — three hosts, as §4
claims; `EVT-0228 → EVT-0229` exactly 54 s.

---

## 3. The tasks

**Legend.** Size in hours. `⇒` deliverable · `✓` verification · `§` requirement ids served ·
`⚠` failure forces a design change.

### Wave 0 — settle what can invalidate a locked decision (T01–T09, 7.75 h)

#### T01 · Freeze the dependency set, stand up the test runner, document the start `[0.5 h]`
**depends on:** —
⇒ `.venv` matching §10.1 exactly: `anthropic` installed and pinned (absent today), `pandera`
uninstalled (present at 0.33.1 today, dropped by §10.1 on measured grounds). `requirements.txt`
pinning exactly anthropic, streamlit 1.64.0, pydantic 2.13.5, jsonschema 4.26.0 plus their
transitive set — built from the four declared dependencies, **never from `pip freeze`**. `tests/`
as a stdlib `unittest` package with one passing test. `pyproject.toml`. A `## Running it` README
section giving the build command and the app command separately, and stating the key is read from
`ANTHROPIC_API_KEY` in the environment and stored nowhere in the tree. `.env.example` naming the
variable with no value.
✓ `python -m unittest discover -s tests` exits 0. `pip list` shows anthropic pinned and
**`pandera` absent**. `python -c "import anthropic, streamlit, pydantic, jsonschema"` succeeds.
`pip install -r requirements.txt` into a clean venv succeeds and `pandera` is absent from it too.
`git grep -iE "sk-ant|api[_-]?key\s*="` finds no credential.
**Why the runner is settled here:** pytest is not installed and §10.1 freezes the dependency set,
so every verification in this plan must run under stdlib `unittest`. Settled at T01 it costs 15
minutes; discovered at T20 it is unrecoverable, because the frozen demo venv could no longer run
the tests that constitute Phase 5's evidence.
§ NFR-02 · NFR-08 · NFR-10

#### T02 · The shared kernel: paths, version, content-derived identity, deterministic JSONL `[1.0 h]`
**depends on:** T01
⇒ `src/siem_investigator/__init__.py` exposing `__version__`; `paths.py`; `ids.py` with
`canonical_json` (sorted keys, no whitespace, `ensure_ascii=False`, integers for byte counts,
normalised ISO-8601) and `node_id(prefix, identity_fields)` implementing §8.2's identity table
exactly — prose, created-at, trajectory step, status and catalogue version all excluded;
`jsonl.py` writing one object per line sorted by id with `sort_keys=True` and LF; the D-09
400-line reporter.
✓ The same identity dict supplied in three key orders yields one id, and reproduces across two
processes launched with different `PYTHONHASHSEED`. Every prefix (`rec_ obs_ edg_ fnd_ map_ hyp_`)
yields prefix plus 12 hex chars. Rewording a finding's `statement` leaves `fnd_` unchanged;
changing one cited observation id changes it. Changing a hypothesis `status` leaves `hyp_`
unchanged. Write→read→write of a 500-object file is byte-identical, with no CRLF. A non-ASCII
value round-trips unescaped. The reporter flags a 401-line file and stays silent at 400.
**Why first:** retrofitting identity after nodes exist invalidates every committed artifact.
§ NFR-01 · NFR-07 · R7.4 · D-09 · D-10

#### T03 · One network window: both external artifacts, provenanced `[0.75 h]`
**depends on:** T01
⇒ `data/attack/enterprise-attack-19.2.json` (STIX 2.1, ~51 MiB) and `index.json`;
`data/schema/attack-flow-2.0.0.json`; `data/attack/PROVENANCE.md` and `data/schema/PROVENANCE.md`
recording source URL, retrieval date and sha256 of each file; a `.gitattributes` rule marking both
JSON files `-text`.
✓ `json.load` succeeds on all three. Re-hashing reproduces the digests in PROVENANCE.md.
`git check-attr text -- data/attack/enterprise-attack-19.2.json` reports `text: unset`, so EOL
normalisation cannot alter the committed bytes — verified as currently *wrong*: `* text=auto
eol=lf` with no `.json` exception resolves the bundle to `eol: lf` today, which would make any
sha256 provenance claim about the catalogue source unverifiable, and committing the bundle as a
reproducible authority is the entire reason D-03 exists. `git grep -nE "requests|urllib|httpx|taxii" src/`
returns nothing, so nothing fetches at runtime.
**Why both in one task:** the Attack Flow schema is the plan's *second* hard network dependency,
and three separate verifications ("validates against the vendored schema") depend on a file no
candidate plan fetched. One network window, one provenance discipline, no discovery of it at the
last task.
⚠ If the bundle cannot be fetched, **stop**: D-03 fails, and CLAUDE.md ground rule 4 requires
amending design.md before substituting a hand-authored subset — a quiet substitution would leave
R4.2's version claim unverifiable.
§ R4.2 · NFR-02 · NFR-07 · D-03 · D-04

#### T04 · Derive the flat catalogue, and settle the privilege-tactic facts against the real bundle `[1.0 h]`
**depends on:** T03
⇒ `src/siem_investigator/enrich/catalogue.py` deriving the ~200 KB flat projection (technique id,
`technique_ref` STIX id, official name, tactics, description) with **stdlib `json` only**;
`data/attack/catalogue_v19.2.json`; `attack_version` copied verbatim from the
`x-mitre-collection` object.
✓ Version string reads exactly `19.2`. Three slices asserted **against the bundle, not from
memory**: `T1059.001` → name "PowerShell", tactic Execution; `T1078` → "Valid Accounts" with
**privilege-escalation among its tactics**; `T1569.002` → "Service Execution" with **Execution
only**. `T1068` is present in the catalogue (and must appear in no mapping T23 emits). Deleting the
derived file and regenerating yields byte-identical output. Wall time and peak memory for the
stdlib parse of 51 MiB are recorded and appended to §10.2.
**Why here:** this is §15's one genuinely unrun spike — §10.2 has a measured row for the relation
spike and for offline startup, and none for catalogue derivation.
⚠ R4.9 and AS-03's expected wording rest on exactly these two tactic mappings. If either differs
in v19.2, §4's R4.4–R4.9 paragraph must be corrected **before T24 depends on it**. Asserting them
from memory is precisely the confident-sounding error the whole document exists to prevent.
§ R4.2 · R4.9 · NFR-01 · NFR-02

#### T05 · Model-plane probe: one strict round-trip, and clean behaviour with no credential `[0.5 h]`
**depends on:** T01
⇒ `scripts/probe_model.py`: one `client.messages.parse` call into a Pydantic model with
`strict: True`, `additionalProperties: false` and `thinking={"type":"adaptive"}`, whose technique
field is a closed `Literal` enum. Prints model id and provider version in the shape the answer
record will carry. A measured row appended to §10.2 (facts only, no decision touched).
✓ With the key set, the call returns a parsed instance and a value outside the enum is
**structurally unrepresentable** rather than validated after the fact — constrain-don't-validate
demonstrated, not assumed. With `ANTHROPIC_API_KEY` unset the script exits non-zero with a
one-line message and no traceback. A truncated or refused response surfaces as a handled error.
`grep -rn "anthropic" app/` returns nothing, so the query plane has no path to the service.
⚠ All three model sites in §7 depend on this and the design has **no deterministic fallback** —
the nearest one is the rule registry §11 killed as draft 3. If no credential can be obtained, halt
and reopen D-02 before writing any stage-3 code.
§ NFR-02 · NFR-02a · NFR-04 · NFR-06 · NFR-10 · D-08

#### T06 · The three model-site contracts, the contract-set hash, and the egress inventory `[1.5 h]`
**depends on:** T02, T05
⇒ `agent/schemas.py` — `CitedEdge` (an object with relation name and two *ordered* endpoint ids,
not a tuple), `CandidateFinding`, `Hypothesis`, `TechniqueSelection`, `Answer`; every model strict
with `additionalProperties: false` and `stage` a closed enum. `agent/client.py` wrapping
`messages.parse` and capturing model id, provider version and prompt hash. `agent/contracts.py`
committing the prompt/contract set as a versioned artifact with a **contract-set hash**, and a
`validator_version` constant stamped onto every artifact. `docs/egress.md` — a table of the three
model sites against the categories of incident information each prompt contains.
✓ Each model round-trips and returns a populated instance. The emitted JSON schema shows
`additionalProperties: false` at every nesting level. A stage outside the enum is unrepresentable.
No schema field anywhere carries a probability, percentage or confidence value (R3.4). The prompt
hash is stable across two runs of the same prompt. **NFR-04's second half is tested**: a fixture
captures the exact serialised request body of one INTERPRET, one technique-selection and one
ANSWER call, and asserts every field present maps to a documented category in `docs/egress.md`, and
that nothing beyond it is sent.
**Why the hash is here:** §11.1 defines replay reproducibility as *given the committed trajectory,
the contract-set hash and the validator version*. T21 claims that property; both of its inputs have
to exist first.
⚠ If a list of edge objects cannot be expressed strictly, D-08's native-parse choice changes and
the alternative (tool use with hand-validated JSON) must be recorded in §10 before T21.
§ R3.4 · R4.1 · NFR-01 · NFR-04 · NFR-07 · D-08

#### T07 · The day-one render constraints, in both themes, with the payload contract they imply `[1.25 h]`
**depends on:** T01
⇒ `.streamlit/config.toml` extended with §9.1's parchment `[theme]` values **and** the selected
dark steps (it carries only `[browser]` and `[server]` today), no `[[theme.fontFaces]]`, system
font stacks only. `app/main.py` with the four-page skeleton. `app/components/citation.py` rendering
an answer body and its citation expanders as **top-level siblings** inside `st.chat_message`,
expansion state keyed in `st.session_state`, record lookup behind `@st.cache_data`, raw records via
`st.json(body, expanded=2)`. `app/components/support_badge.py` emitting icon **plus word** for all
four support states. A print stylesheet. `docs/specs/answer_payload.md` — a one-page contract for
the stage-6 answer payload shape this layout requires, consumed by T31.
✓ App accepts connections in under 5 s with an unroutable `HTTPS_PROXY` set and the key unset (the
§10.2 offline case, worse than no network since it hangs on timeout). Three citations expanded at
once raise no `StreamlitAPIException` about nested expanders. A unit test computes WCAG contrast
from the hex values in `config.toml` and asserts 14.25:1 / 8.61:1 / 4.85:1 on parchment and the
dark equivalents. A badge rendered with colour stripped still shows icon and word. All four pages
navigate. **The unmeasured §10.1 assumption is settled**: a real table renders via `st.dataframe`
over `pyarrow.Table.from_pylist` and no code path imports `pandas._libs.join`, the module this
machine's Application Control policy blocks.
⚠ Two design changes ride on this. If siblings cannot be made to work, §9.4 and the stage-6 answer
contract change, and §9.4 says retrofitting is a rewrite of the render loop. If the pyarrow route
does not avoid the blocked module, both table surfaces need hand-rolled rendering — about an extra
hour each, and far better known now than at T37.
§ R2.5 · R3.2 · R10.1 · NFR-02 · NFR-08 · D-06

#### T08 · Pin the measured facts as committed fixtures `[0.75 h]`
**depends on:** T02
⇒ `tests/fixtures/dataset_census.json` — 14 event kinds with counts, 84/65/62/31 by source type,
`network_connection`'s three key-sets (80 at 12 keys, 3 at 13, 1 at 14), 80 without `src_host` and
83 without `dst_host`, `command_line` absent 184 / empty 50 / valued 8, and the **full 40-key
inventory including `service_path` and `target_pid`**, which CLAUDE.md's table omits.
`tests/fixtures/ground_truth.json` — the 22 `ATTACK:`-annotated event ids, with a header stating
R7.2 permits this file for accuracy measurement only.
`tests/fixtures/relation_expectations.json` — §10.2's measured result, with the corrected
Δ = 1 h 27 m 41 s. `scripts/regen_fixtures.py`.
✓ `regen_fixtures.py` rewrites all three and `git diff --exit-code tests/fixtures/` is clean.
`ground_truth.json` contains exactly 22 ids. `git grep -n ground_truth src/ app/` returns nothing —
now and at every later task, so the fixture is reachable only from `tests/` and the accuracy
harness.
§ R7.2 · R7.3 · SC-03 · SC-05

#### T09 · The relation regression at raw-data level, proved by mutation `[0.5 h]`
**depends on:** T08
⇒ `tests/test_relation_spike.py`, reading `data/raw/siem_logs.json` directly with **no project
imports**, asserting §10.2's measured result: `EVT-0237 → EVT-0238` matches on normalised basename
and exact byte count and is time-ordered at Δ = 1 h 27 m 41 s; `EVT-0239 → EVT-0238` matches on
basename but carries no size field and is **reversed** in time (1.74 h after the upload);
dataset-wide cross-source file pairs number **2** on name alone and **1** on name plus exact size.
✓ Test green. Then delete the size predicate by hand: the dataset-wide count must rise 1 → 2 and
the test must **fail**. That mutation is the proof the test has teeth rather than an assertion that
it does, and it locks §3.6 before any code can silently break it.
**Why raw-level:** it can run before any module exists, so T16 reproduces a frozen number rather
than inventing one.
§ R1.4 · R2.3 · NFR-01

### Wave 1 — the deterministic floor (T10–T14, 8.75 h)

#### T10 · Stage 1 INGEST: verbatim load, `note` stripped at the boundary, tolerant per-kind schemas `[1.5 h]`
**depends on:** T02, T08
⇒ `ingest/load.py` (read-only load, `note` removed at the parse boundary so nothing downstream can
see it, records keyed by content-derived `rec_` id); `ingest/schemas.py` (14 hand-written stdlib
`jsonschema` documents, **required = the invariant keys only, optional = the varying ones**);
`ingest/classify.py` (internal/external from `metadata.known_internal_subnets` via stdlib
`ipaddress`); `data/derived/01_records.jsonl` and `01_ingest_report.json` carrying counts per source
type and event kind, the missing-field census, and the absent / `recorded_empty` / null encoding
census.
✓ 242 in, 242 out, and the per-kind table equals `dataset_census.json` exactly.
`grep -c '"note"' data/derived/01_records.jsonl` returns 0, and a test walks every object asserting
the key and the substring `ATTACK:` are absent **at any depth** (22 source records carry it). All
three `network_connection` key-sets load without error — including the 4 carrying `src_host`, the
only network events needing no address resolution and the evidence R3.9/R3.10 exist to handle.
A mutated copy missing `event_id` is rejected **naming that field**. Every record retrievable by
its `rec_` id. sha256 of `data/raw/siem_logs.json` unchanged before and after the run.
**Note on the schemas:** tolerating optional-field variation is not the same as not validating. A
kind silently losing a required field with no report is an NFR-06 exposure, which is why the
required set is the invariant keys and the validation is real.
§ R2.2 · R2.5 · R7.2 · NFR-05 · NFR-06 · D-01

#### T11 · Stage 2a: the closed transform registry and per-value normalisation provenance `[1.5 h]`
**depends on:** T10
⇒ `ingest/transforms.py` — `identity`, `basename`, `lower`, `ipv4_canonical`, `utc_instant`, each
**pure and total**, returning either a normalised value or a typed `cannot_normalise` rather than
raising. `ingest/provenance.py` emitting `record_id · field · raw_value · transform ·
normalised_value` for every field of every record, with `identity` recorded **explicitly** so a
missing row is a bug rather than an ambiguity, and absence typed `not_applicable` versus
`recorded_empty`.
✓ Invariant 5 as a test over all 242 records: re-apply each recorded transform to its recorded raw
value and assert equality with the recorded normalised value; the count of provenance rows equals
the count of asserted values, so a missing row is a failure not an ambiguity. Every transform name
is in the registry; an unregistered name raises. A malformed timestamp and a malformed dotted quad
both return `cannot_normalise` with no exception, and the observation is **withheld** under R2.6
rather than carrying a bad value. `C:\Temp\backup_archive.zip --basename--> backup_archive.zip`
appears explicitly, so a reviewer can see *why* an observation asserting `file_name` may cite a
record holding `file_path`. The `command_line` census reproduces 184 `not_applicable` / 50
`recorded_empty` / 8 valued, so the one field carrying the encoded PowerShell is on the correct
side.
§ R2.6 · NFR-01 · NFR-09

#### T12 · Stage 2b: role-tagged entities, computed coverage, ambiguous address resolution `[2.0 h]`
**depends on:** T11
⇒ `ingest/entities.py` mapping each of the 14 kinds to `[(entity_type, identifier, role)]` over
`actor` / `observed_on` / `origin` / `target` and the seven entity types, keeping `observed_on`
distinct from `origin`. `coverage(entity, source_type)` derived from `observed_on` values.
`ingest/resolution.py` returning, per address, **every** candidate host with the record ids
evidencing it and a flag of `unique | ambiguous | unresolved` — a signature returning a list, never
a scalar, so a single confident answer is unrepresentable. `02_events.jsonl`,
`02_entities.jsonl`, `02_resolution.jsonl`.
✓ Measured expectations, all reproduced: `10.0.3.78` returns both `WKSTN-04` and `WKSTN-10`,
flagged ambiguous, cited on both sides, and is the **only** ambiguous address in the dataset;
`WKSTN-01` and `WKSTN-06` each return 9 distinct addresses; an address with no host association
returns an empty candidate set flagged unresolved and **is never given a host**. `AUTH-SRV-02`
appears as an auth `target` and never as an `observed_on`, so `coverage("AUTH-SRV-02","endpoint")`
is absent and `coverage("AUTH-SRV-01","endpoint")` is 2 — **derived, not hand-noted**, which is
what R3.12 asks for. The `observed_on` host set equals the set of hosts with at least one endpoint
record, computed two independent ways. 11 accounts enumerated. 242 events in, 242 out. A test
asserts no code path returns a bare hostname string for an ambiguous address.
§ R1.2 · R3.9 · R3.10 · R3.12 · R5.4 · NFR-09

#### T13 · Direct observations, the graph store, the five invariants, and the `trace` CLI `[1.75 h]`
**depends on:** T02, T11, T12
⇒ `evidence/nodes.py` — frozen dataclasses for `record`, `observation`, `finding`, `mapping`,
`claim`, plus `hypothesis`, one `cites` relation. `evidence/graph.py` — dict adjacency plus ~40
lines of **iterative three-colour DFS that returns the cycle path**, not a boolean, per D-05.
`evidence/invariants.py` — layer order, termination in records, acyclicity, value grounding, and
normalisation reproducibility. `03_observations.jsonl` carrying each observation's stage-2
provenance. `python -m siem_investigator.trace <node_id>` printing a node and walking its citation
chain down to `rec_` nodes.
✓ A deliberately constructed cycle yields its **full path** in the diagnostic. An observation
constructed to cite a finding is rejected for layer order **naming both node ids**. A claim citing
a record directly is rejected. A chain ending at an observation citing no record is rejected for
termination. An observation asserting a value absent from its cited record's named field is
rejected for grounding — including the `backup_archive.zip` case where `file_path` and `file_name`
are not string-equal and only the recorded basename transform shows why the check passed. Every
chain in a hand-built five-node graph terminates in `rec_`. `trace` on any node prints the chain to
raw records.
**Why the CLI is here:** in every candidate plan R7.4 and R7.5 lived only on the pipeline surface,
which §10.3 cuts second — so two P1 criteria would leave with a design preference. A 20-line stdlib
inspector satisfies them independent of any UI, and is the debugging tool T21 and T22 will need
anyway.
§ R2.1 · R2.2 · R2.4 · R2.6 · R7.4 · R7.5 · D-05

#### T14 · The R7.1 perturbation generator, and three controls proving it bites `[2.0 h]`
**depends on:** T08, T10
⇒ `tests/perturb.py` emitting `tests/fixtures/perturbed_siem_logs.json` with **all five
perturbations named verbatim in R7.1** — developer annotations removed; record identifiers
reassigned in a different order; sub-second precision replaced in a way that leaves true event
order unchanged; ordinary activity added for the one account that has none; distinct network
addresses per host equalised — plus an old-to-new id mapping table for scoring.
✓ The **negative properties are asserted directly**, not by asserting the pipeline agrees with
itself: every timestamp carries sub-second digits, so a `"." not in timestamp` filter scores zero;
the previously-annotated events no longer occupy a contiguous trailing id block; every host reports
the same count of distinct addresses, so `AUTH-SRV-01`, `FILE-SRV-02` and `WKSTN-07` — measured,
and exactly the three compromised hosts — are no longer distinguishable; `jdavis` has ordinary
activity. The full 242-event temporal order under the id mapping is identical to the original.
`data/raw/siem_logs.json` is untouched. **Three negative controls prove the harness bites**: a
build that filters on whole-second timestamps, one that filters on the trailing id block, and one
that filters on single-address hosts must each pass the baseline and **FAIL** the variant.
**Why this is its own task and why it is here:** R7.1 is a black-box test only as good as its
generator, and the generator is written by the same person who writes the anchors. A generator that
quietly preserves a signal the anchors use would pass SC-05 while proving nothing — the most
dangerous failure shape in the plan, because it produces a false clean bill on the exact property
R7 exists to establish. It precedes T20 (anchors) and T30 (the gate) because both consume it.
§ R7.1 · R7.2 · SC-05 · NFR-05

### Wave 2 — the trusted kernel (T15–T20, 8.0 h)

#### T15 · The adversarial validation corpus, frozen before the validator exists `[0.75 h]`
**depends on:** T08, T13
⇒ `tests/fixtures/adversarial/` — one proposal per failure mode, each naming the diagnostic it
expects: a cited observation that does not exist; a cited edge that does not re-evaluate
(`same_size(EVT-0239, EVT-0238)`, where one side records no size); an invented identifier
(`PSEXESVC` in the statement, in no cited observation); a stage outside the closed vocabulary; a
layer-order violation; a planted cycle; a cited edge whose second endpoint is absent from
`cites_obs`; an orphan cited observation participating in no cited edge; and a pair individually
valid but jointly incompatible. Plus **three that must be ACCEPTED**, including the R2.8 case — a
derived finding whose conclusion appears in no single record — so the corpus constrains both
directions.
✓ Every violating entry names exactly one check and the expected diagnostic text; the accept cases
name none. A reviewer can read the file and predict each verdict **without reading any validator
code**.
**Why before the validator:** T18 is then written against a frozen target rather than the corpus
drifting to match whatever the validator happens to do. This is the one coupling where a single
author otherwise writes both the test and the thing it tests.
§ R2.6 · R2.7 · R2.8 · R2.9 · R3.11 · SC-02

#### T16 · The five sparse relations, and §3.6's central claim in real code `[1.5 h]`
**depends on:** T09, T12, T13
⇒ `correlate/relations_sparse.py` — `same_file` (normalised basename), `same_size` (exact byte
equality), `process_parent` (same host only), `flow_endpoint`, `address_resolves_to_host`;
materialised because they are sparse. Pure functions over observations. Zero detection rules, zero
composites, no relation name containing a verb phrase implying interpretation.
✓ `relation_expectations.json` passes **through the real functions**: `EVT-0237 → EVT-0238` yields
`same_file` and `same_size`; `EVT-0239 → EVT-0238` yields `same_file` and **no** `same_size`, and
is temporally reversed; dataset-wide cross-source file pairs number 2 on basename alone and 1 on
basename plus exact size — the 50%-to-0% false-positive result. `process_parent` never links across
hosts. Edge truth is obtained by **calling** the relation function, never by reading a stored
value, which is what lets T18 re-evaluate rather than trust.
⚠ §12 names the relation set the sharpest single point of failure, and §3.6's asymmetry is the
design's central claim. If the counts differ at implementation scale, the worked example is wrong
and §3.6 must be rewritten before T21 rests on it. Note plainly what **no** task can retire: no
downstream check can detect a link that was never computed (§12 item 1), and §13 item 3 admits
relation-set completeness is unchecked. T18 tests rejection, not coverage.
§ R1.4 · R2.3 · AS-06 · D-07

#### T17 · The five dense relations, the discardable index, and honest truncation `[1.5 h]`
**depends on:** T16
⇒ `correlate/relations_dense.py` — `same_account`, `same_host`, `same_address`, `temporal_within`
(**reports Δ, never thresholds**), `session_bracket`; `correlate/index.py` building a discardable
SQLite index from the committed JSONL at load; `expand(obs, k)` returning up to k nearest by time
**with the true total stated**.
✓ `same_account` and `same_host` counts match a brute-force pairwise reference on a 20-record
sample. A grep of the module finds **no numeric time-window constant** and no relation signature
accepting a threshold or window parameter — `temporal_within` returns Δ and the caller decides,
which is what dissolves the parameter §3.2 says stops being a parameter. Both real gaps come back
as reported values: 2 s (`cmd.exe → powershell.exe`) and 1 h 27 m 41 s (archive staged → uploaded).
`expand` on a busy host reports "showing 10 of N" with N verified against the reference count, and
`(complete)` when nothing was dropped. Deleting the SQLite file and reloading produces identical
results, and it never appears in `data/derived/` as an authority — proving it is a projection (§8.3)
rather than an authority.
§ R1.4 · R3.9 · NFR-01 · NFR-03 · D-07

#### T18 · Validation checks 1–5, the basis role-fulfilment check, and specific diagnostics `[1.75 h]`
**depends on:** T15, T16, T17
⇒ `evidence/validate.py` — (1) cited observations exist; (2) every cited edge **re-evaluates** true
by recomputing its relation function rather than reading a stored value; (3) every entity, value,
identifier and timestamp named in the statement appears in a cited observation; (3b) **basis role
fulfilment** — `cites_obs` covers every endpoint of every edge in `cites_edges`, and no cited
observation is an orphan participating in no cited edge; (4) `stage` drawn from the closed
vocabulary; (5) layer order, acyclicity and termination. Every rejection returns a specific
diagnostic naming the failing element.
✓ The T15 corpus runs green in both directions: each violating entry is rejected by exactly the
named check with the named diagnostic, and all three valid entries are accepted — including the
R2.8 case, proving the system does not withhold its primary output on the ground that no single
record contains the whole conclusion. Check 2 is proved to **recompute** by mutating a stored edge
and confirming the verdict is unchanged. Check 3 rejects a statement naming `PSEXESVC` when no
cited observation contains it. Check 3b rejects an edge whose second endpoint is not listed as
support, and rejects an orphan cited observation.
**Why 3b is called out separately:** design §3.4 makes the cited edge set *the basis*, so the role
a basis assigns an observation is "endpoint of a cited edge". R2.7 clause 2 (*omits a supporting
observation its named basis requires*), R2.7 clause 3 (*cites an observation that does not fulfil
the role the basis assigns it*) and SC-02 clause 2 all turn on that correspondence — and SC-02
admits no partial credit. It is about twenty lines, and without it a finding citing an edge whose
second endpoint it never lists as support is accepted while R2.7 and SC-02 are claimed.
§ R2.3 · R2.6 · R2.7 · R2.8 · R2.9 · NFR-04a · NFR-06 · SC-02 · D-07

#### T19 · The build-time tool surface, honest about its own truncation `[1.0 h]`
**depends on:** T17, T18
⇒ `agent/tools_build.py` — `expand(obs, k)` with truncation counts, `relate(o1, o2)`,
`seek(prediction)` returning `FOUND | NOT_FOUND | NOT_COVERED`, `coverage(entity, source_type)`,
`record(id)`. All returning frozen structures.
✓ `expand` on a busy host reports a total strictly greater than the returned count, matching an
independently computed index count. `coverage("AUTH-SRV-02","endpoint")` reports not covered and
`coverage("AUTH-SRV-01","endpoint")` reports 2. `seek` returns all three outcomes on three crafted
predictions, and **any privilege-change prediction returns `NOT_COVERED` rather than `NOT_FOUND`**,
because no event kind in this dataset can record one — the distinction without which "not found"
conflates absence from the environment with blindness of the source, and the thing that makes a
negative result meaningful. `record(id)` returns the verbatim payload with `note` absent. A test
asserts **no tool can create or mutate a node**.
§ R3.6 · R3.7 · R3.12 · R4.8 · R10.1

#### T20 · Anchors that order and never filter, and the cheap proof they do not ride on a leak `[1.5 h]`
**depends on:** T14, T17
⇒ `correlate/anchors.py` — each deterministic anchor signal named and justified in a docstring,
drawn from both a deterministic signal set and a model pass so neither blind spot stands alone,
plus an **explicit exclusion list**: no `note`, no timestamp precision, no `event_id` ordinal, no
"host with a single address", no "account with no ordinary activity". Anchors order the frontier;
they never filter it.
✓ The anchor set computed on the original dataset **equals** the set computed on T14's perturbed
dataset under the id mapping. A test asserts the module reads none of the five excluded signals
(import-level guard plus greps for `note`, sub-second precision and id ordinal), and that no anchor
value appears in any filter or comprehension predicate. A test asserts the reachable candidate set
equals **all 242 records**, and reaches an arbitrary record no anchor touched — so `SELECT` and
`SEEK` are unconstrained. *An anchor orders; a filter would encode the answer.*
⚠ The highest-value cheap test in the plan. Two leak-correlated signals score perfect precision and
recall on this data, so if the anchors only work with one of them, §3.3 changes and SC-05 fails.
It costs 1.5 h here because it needs only parse plus anchors; the equivalent check on a full
pipeline is T30.
§ R1.9 · R1.10 · R7.1 · R7.2 · SC-05 · D-02

### Wave 3 — the interpretive layer and the build plane (T21–T30, 15.25 h)

#### T21 · Loop skeleton against a scripted stub interpreter: ledger, termination, replay `[2.0 h]`
**depends on:** T06, T18, T19, T20
⇒ `correlate/investigate.py` driving SELECT → EXPAND → INTERPRET → HYPOTHESISE → SEEK against a
**scripted stub interpreter with zero model calls**, writing `03_edges.jsonl` (traversed subgraph
only), `03_hypotheses.jsonl`, `03_findings.jsonl`, `03_trajectory.jsonl`, `03_rejections.jsonl`.
Termination on an empty frontier, on a full pass with no accepted finding, or on budget exhaustion
emitting `INSUFFICIENT_EVIDENCE` for open hypotheses rather than concluding. Back-prompt bounded at
two attempts, then abandon and log. A hand-written trajectory covering the staging-to-upload chain.
✓ The scripted trajectory runs with `ANTHROPIC_API_KEY` unset and the network down, produces a
candidate finding that passes all six checks, and lands it in the graph. **Replay reproducibility
(§11.1):** given the committed trajectory, the contract-set hash and the validator version, every
accept/reject verdict reproduces bit-for-bit across runs with no model in the loop. All three
termination conditions fire in separate tests. Every hypothesis row carries a step index strictly
lower than its SEEK result, so **the prediction provably preceded the look** — which is what makes
a negative result honest rather than post-hoc. The committed edge file contains only traversed
edges, not the full relation product. Replaying the same trajectory twice yields byte-identical
artifacts.
**Why the split:** this is the spine. It proves the interpretive-to-validator contract before a
single token is spent, keeps the build demonstrable if the API is down on demo day, and makes a
later loop failure diagnosable as mechanism (here) or prompt (T22).
§ R2.3 · R3.6 · R7.4 · R10.2 · NFR-01 · NFR-02a · NFR-06

#### T22 · The interpretive layer: model-backed INTERPRET and HYPOTHESISE `[2.0 h]`
**depends on:** T05, T06, T21
⇒ Real model-backed `INTERPRET` (propose a finding citing specific **existing** edges, with
rationale) and `HYPOTHESISE` (predict entity, role, event kind, source and window **before** SEEK
runs) through the T06 contracts, replacing the stub.
✓ A full run terminates by one of the three stated conditions and logs which. The model can cite
only edges the factual layer computed — a proposal citing an unknown edge id is rejected by check 2
and logged. Rejection diagnostics are specific strings and the back-prompt stops at two, then
abandons. Token count and wall time for a full build are **recorded**, with a stated threshold
above which iteration across T23–T27 becomes unaffordable. Re-running the validator over the
committed trajectory reproduces every verdict bit-for-bit even though the generator is
non-deterministic. The rejection log and the unconfirmed set are readable as a **coverage
backlog**.
⚠ If the loop cannot terminate inside a sane budget, or accepts nothing, D-02's agentic split needs
revision. NFR-03's 5 s applies to reconstruction from committed artifacts, **not** to the
interpretive search; the build loop has no stated wall-clock budget and this is where one gets set.
§ R1.1 · R1.3 · R1.6 · R1.9 · R2.1 · R2.3 · R10.2 · NFR-01

#### T23 · Stage 4 ENRICH: retrieve an enum, select from it, validate what constraint cannot `[1.5 h]`
**depends on:** T04, T22
⇒ `enrich/retrieve.py` (deterministic candidate retrieval over the local catalogue),
`enrich/select.py` (selection from the retrieved enum via structured outputs, quoting the field
values that triggered the choice), `enrich/validate_mapping.py` (enum membership; **id ↔ name
consistency**; quoted values present in the cited record; tactic consistent with the finding's
stage); `04_mappings.jsonl`, `04_unmapped.jsonl`, with `non_mappable` a first-class outcome
distinct from rejected.
✓ Every emitted id is drawn from its finding's retrieved enum, so an out-of-catalogue id is
**unrepresentable** rather than merely detected. Each of the four checks fails a planted case,
including a correct technique **name** paired with a wrong id — the documented LLM failure that a
bare existence check passes. Quoted values resolve in the cited record. `T1068` and any UAC-bypass
or token-manipulation technique are **absent** from the output. At least one behaviour lands in
`04_unmapped.jsonl` rather than being forced to the nearest available technique.
§ R4.1 · R4.2 · R4.3 · NFR-01

#### T24 · The privilege report as a deterministic projection `[1.5 h]`
**depends on:** T12, T23
⇒ `synthesise/privilege.py` computing, in §4's exact wording: integrity compared **only within a
host**; the statement that the three readings sit on three different hosts (`WKSTN-07` medium,
`AUTH-SRV-01` high, `FILE-SRV-02` system) so no within-host rise is evidenced; that no record
evidences the privilege being **acquired**, citing `EVT-0228` (network logon 11:22:14) and
`EVT-0229` (high-integrity process 54 s later); the network-logon-versus-interactive-process
inconsistency, citing both and **resolving neither**; and that no event kind here can record a
privilege change at all.
✓ Six criteria checked one at a time against the emitted text: no within-host rise asserted; both
sides of the inconsistency cited and neither reading preferred; the coverage statement present; the
privilege-escalation **tactic** is not denied (T1078 maps to it, confirmed at T04) while no
exploitation, elevation-bypass or token-manipulation mechanism is named; `grep` finds no unqualified
sentence of the form *"no escalation occurred"* or *"privilege escalation was not observed"*; and
the account's privilege is never described as one it *"appears to have already held"* — the quiet
resolution R4.7 forbids. **The count of other accounts with interactive logons to that host is
computed from the data, never hard-coded**; measured it is 7 accounts across 12 events, not the
fifteen requirements §2 and design §4 both state (see §2 above). The emitted text states the
measured figure, and T39 records the correction to both documents.
**Why its own task:** six acceptance criteria where one confidently worded sentence fails all six.
Requirements §2 spends three paragraphs on this trap and design §4 another four. Bundling it with
the mapping machinery gives ten ids one verification block and one sitting.
§ R4.4 · R4.5 · R4.6 · R4.7 · R4.8 · R4.9 · AS-03

#### T25 · Close the graph: check 6, structural support labels, and the two flags `[1.5 h]`
**depends on:** T18, T23, T24
⇒ `evidence/close.py` running the set-level mutual-incompatibility check **at close only**, with an
R3.11 report citing every record involved. `evidence/labels.py` computing Corroborated /
Single-sourced / Absence-based from the **count of distinct source types** across a finding's
supporting observations, plus `resolution-dependent` when any cited association has more than one
candidate host and `conflicted` when two cited observations within one support are inconsistent.
✓ Labels recomputed from the graph match the five worked expectations in requirements §3: movement
to the third host **Corroborated** (network and endpoint); the command-and-control channel
**Single-sourced**; the staging-to-upload link **Corroborated** (endpoint and cloud); the
initial-access vector **Single-sourced**; and any claim that the intrusion ended **Absence-based**
and therefore not asserted. The privilege finding comes out **conflicted**. Every label is
recomputed rather than stored, so mutating one in an artifact and regenerating restores it. A test
asserts no label is a number, a percentage or an adjective of belief, and a grep over every emitted
artifact finds no probability or belief adjective (R3.4). Two deliberately incompatible findings
trigger the check-6 report **citing every record on both sides** rather than either being silently
preferred. A test asserts check 6 is not reachable per proposal.
§ R3.2 · R3.3 · R3.4 · R3.5 · R3.11 · AS-06

#### T26 · Stage 5a: timeline, scope of compromise, and the no-intrusion path `[1.75 h]`
**depends on:** T25
⇒ `synthesise/project.py` emitting `05_timeline.json` (one sequence ordered by time of occurrence,
each step naming account, host, action and recording source; cross-source relationships with the
record cited on both sides; first and last intrusion-related activity and the period examined) and
`05_scope.json` (every host and account with first and last involvement, confirmed-compromised
versus merely-observed **with the basis stated**, assets read/collected/removed with volume where
recorded, and what cannot be ruled out including `AUTH-SRV-02`).
✓ Every projected element carries the graph node id it came from, so **no orphan prose exists** —
asserted over the whole file. Each of R1.6's nine stages appears either evidenced with citations or
explicitly reported **not observed**; none is omitted. The stated first and last equal the min and
max timestamp over intrusion-attributed nodes, computed independently, and the period reads
`2026-06-10T08:00Z → 2026-06-13T08:00Z`. **R1.8:** a run over a findings set with nothing
intrusion-attributed emits the no-intrusion statement and **no sequence** — fifteen minutes of
work, and the difference between a system that reconstructs and a system that always finds an
intrusion. Deleting both files and regenerating yields byte-identical output. Projection completes
within the 5 s reconstruction budget.
§ R1.1 · R1.2 · R1.3 · R1.4 · R1.5 · R1.6 · R1.7 · R1.8 · R5.1 · R5.2 · R5.3 · R5.4 · NFR-03 · AS-07

#### T27 · Stage 5b: the coverage-gap report, derived from the hypothesis ledger `[1.25 h]`
**depends on:** T19, T25
⇒ `synthesise/gaps.py` producing `05_gaps.json` from the **unconfirmed plus uncoverable hypothesis
sets** and `coverage()`, never from a hand-written checklist. Absence-based conclusions computed
here only, after the graph is closed.
✓ The report names, unprompted, each tied to the conclusion it limits and each carrying the
hypothesis id that went looking: the absent mail source; the absent name-resolution source; the
absence of any event kind able to record a privilege change; the uncorroborated 2.3 GB transfer
path; the uneven endpoint coverage (`AUTH-SRV-01` two events, `AUTH-SRV-02` none across 23
appearances); the unobserved transfer of `C:\Temp\7z.exe`; and the LSASS dump never observed being
read or transmitted. **An assert proves no absence-based claim was emitted before close** — a later
iteration can find what an earlier one declared unobserved, so closed-world claims are not
monotone. Adding one finding and rerunning flips the affected claim, proving it was recomputed
rather than cached mid-loop. `git grep` finds no literal list of gap strings in `src/`.
§ R3.1 · R3.5 · R3.6 · R3.8 · R3.12 · AS-08

#### T28 · The six per-stage verification reports, the build entry point, and NFR-06 fault injection `[1.5 h]`
**depends on:** T10, T11, T12, T18, T23, T26, T27
⇒ `python -m siem_investigator.build` running all six stages in order; `python -m
siem_investigator.verify` executing each stage's verification set and writing
`0N_verification.json` per stage with the check names and their outcomes; the D-09 line-count table
printed by the build.
✓ Each of the six stages emits a report naming its checks and their results. **NFR-06 is
adversarially tested, not merely claimed:** truncate a copy of the raw file mid-object, and
separately corrupt one committed artifact — in both cases the run reports **what** failed and
refuses to present an incomplete reconstruction as complete. In a fresh shell, following the README
verbatim with no edits runs the build and starts the app (NFR-08). The line table flags anything
over 400.
**Why this exists:** design §1's organising claim is *six stages, six committed artifacts, six
verification passes — one per stage, each with its own report*. Only stage 1 had a report artifact
in any candidate plan, and the only surface displaying per-stage results was the pipeline page,
which §10.3 cuts second. Cut that and the design's headline structural claim plus NFR-06's "report
what failed" has no artifact anywhere. A runner writing `0N_verification.json` is cut-proof, and is
what T44 should *read* rather than recompute.
§ NFR-03 · NFR-06 · NFR-08 · R7.4

#### T29 · Artifact homes, the `.gitignore` negations, the manifest, and the committed derived set `[0.75 h]`
**depends on:** T28
⇒ A decision recorded per artifact on where it lives; the `.gitignore` negations needed to make it
true; the committed `data/derived/*.jsonl` set after a successful build; and
`data/derived/manifest.json` — artifact, sha256, producing stage, software version, data period.
✓ `git status` is clean after a build, and a fresh clone contains every artifact the query plane
reads. `.gitignore` line 55 is `outputs/*` with only `!outputs/.gitkeep`, so the handover document
(T42) and any answer record written there **would not exist in a fresh clone** — verified fixed.
Re-hashing every artifact reproduces its manifest digest. NFR-03's 5 s reconstruction, NFR-02's
offline operation and the entire query plane read nothing but the committed set, so a missing file
is an immediate failure rather than a slow one.
§ NFR-02 · NFR-07 · R8.4

#### T30 · GATE: accuracy against the annotations, and leak independence of the whole pipeline `[1.5 h]`
**depends on:** T14, T28
⇒ `tests/harness/accuracy.py` scoring the cited records of accepted findings against the 22
`ATTACK:`-annotated ids, read on an **independent path** that touches the raw file directly; a full
build over T14's perturbed dataset comparing findings, sequence order, cited edges and technique
ids under the id mapping; a printed confusion report.
✓ **Recall ≥ 80% and precision ≥ 70%**, printed with the three explicit sets — what was found, what
was missed, what was wrongly included — because R7.3 requires the system to report this itself
rather than emit a score. The perturbed run's finding set, sequence order, cited edge set and
technique ids are identical to the original under the mapping (SC-05); because §8.2 excludes prose
from identity, `fnd_` and `edg_` ids are directly diffable and the structural diff is empty even
where sentences differ. A grep proves `note` is read inside this module and **nowhere else** in the
codebase.
⚠ **This is a gate.** If either threshold fails, T16 (relations), T20 (anchors) and T22 (the loop)
reopen before T31 starts. It sits here rather than at the end because a recall shortfall repairs
only upstream, and §12 states outright that this architecture structurally biases toward missing
things while §13 item 6 declines to bound the false-negative rate. Discovering an 80% shortfall
after the UI is built is the single most expensive ordering mistake available in this plan.
§ R7.1 · R7.2 · R7.3 · SC-03 · SC-05

### Wave 4 — the answer plane (T31–T35, 6.75 h)

#### T31 · Stage 6 ANSWER: query tool surface, citation gate, attribution rule, answer record `[1.75 h]`
**depends on:** T07, T25, T27, T30
⇒ `agent/tools_query.py` — `find_findings()`, `trace(node)`, `observations_for(entity)`,
`record(id)`, `gaps()`, and deliberately **no relation computation**. `agent/answer.py` conforming
to T07's answer-payload contract. `agent/gate.py`. An answer-record writer capturing question,
steps taken, citations returned, model id, provider version, prompt hash, catalogue version and
software version.
✓ A test enumerates the query tool list and asserts **no relation function is importable** — if
query time could compute relations it could mint a finding at answer time, which NFR-01 forbids.
**The §6.1 loophole closes:** a crafted claim that attributes activity to the intrusion while
citing only observations is **withheld with the reason given**, while a factual observation-only
claim (*"three other accounts used that host"*) passes. A citation naming a nonexistent event id
withholds the answer and reports the failure. Every citation resolves, every quoted value is present
in its cited node, and layer discipline holds on cited nodes. The same question asked twice returns
identical citations. With the credential unset the timeline, scope, relationships and gap report are
still served and technique-dependent prose degrades to **unmapped** rather than vanishing.
§ R2.1 · R2.2 · R2.3 · R2.4 · R2.5 · R2.9 · R6.1 · R10.3 · NFR-01 · NFR-02 · NFR-02a · NFR-04a · NFR-07

#### T32 · The gate-two adversarial corpus, including the answer-prose likelihood check `[0.75 h]`
**depends on:** T31
⇒ A corpus for the **weaker** gate, matching the treatment gate one already gets: a quoted value
present in a different record than the one cited; a nonexistent event id; a layer violation on a
cited node; an attribution smuggled through a finding citation that does not support it; and a
**likelihood term paired with a confidence level in one sentence**, checked against a term list on
the **rendered answer prose**.
✓ Every entry is refused with its named reason; a matched valid answer passes.
**Why this exists:** design §6's stage-6 verification row names five checks. Four were covered
everywhere; the fifth — *no likelihood term and confidence level in one sentence* — was checked at
the wrong layer in every candidate plan (greps over build artifacts, over `src/`, or over schema
fields). All three constrain the deterministic layer, which was never the risk: R3.4 forbids
substituting an assessment of belief for a structural label, and the only place a belief adjective
can appear is model-generated answer prose. Design §13 item 2 calls gate two the weaker gate, and
every answer the demo reads aloud passes through exactly it.
§ NFR-04a · R3.4 · R2.9

#### T33 · Answer contracts A — the reconstruction and enumeration questions `[1.5 h]`
**depends on:** T26, T31, T32
⇒ Per-scenario contracts and a test module for **AS-01** (walk the timeline), **AS-04** (which
accounts), **AS-05** (which hosts were moved to), **AS-07** (blast radius), plus R6.3's entity
pivot over a named account, host, address, file or bucket.
✓ AS-01 presents one time-ordered sequence covering every evidenced stage, names those it does not,
states first and last, and cites every step. AS-04 separates confirmed compromise from mere
observation and treats `jdavis` having no ordinary activity as **a limitation on the assessment,
never as grounds for it**. AS-05 names the authentication and the remote-service-creation activity
behind each hop and **flags any host identification resting on an uncertain address association**.
AS-07 enumerates every host and account with first and last involvement, names assets and volume,
and states what cannot be ruled out including `AUTH-SRV-02`. A question naming `jdavis` returns
every intrusion-related activity for that account.
**Why these four together:** all four are reconstruction-shaped — they read the timeline and scope
projections and enumerate with citations. Grouping by mechanism keeps each task one sitting; all ten
in one task was the single most overscoped item in every candidate plan, and four of these ten had
no owner at all in one of them.
§ R1.1 · R1.10 · R5.1 · R5.2 · R6.2 · R6.3 · AS-01 · AS-04 · AS-05 · AS-07

#### T34 · Answer contracts B — the evidence-and-absence questions `[1.5 h]`
**depends on:** T24, T27, T31, T32
⇒ Per-scenario contracts and tests for **AS-02** (initial access vector), **AS-03** (techniques,
including the privilege discipline from T24), **AS-06** (exfiltration), **AS-08** (coverage gaps),
plus period restriction and the absent-source refusal.
✓ AS-02 names and cites the document application spawning a command interpreter, **states that no
mail records exist**, names no sender, subject or attachment (grep-asserted), and labels the vector
Single-sourced. AS-03 gives id, official name, tactic and citation for each, states the catalogue
version, reports anything unmapped, and carries T24's privilege wording verbatim. AS-06 answers yes
and names `backup_archive.zip`, exactly 2,473,829,122 bytes, bucket `ext-drop-xf9q2`, owner
`EXTERNAL`, client `python-requests/2.28.1`, time `2026-06-10T18:18:44Z` — then **separates the
three levels of support**: the upload Single-sourced (cloud alone), the staging-to-upload link
Corroborated (endpoint and cloud), and no network record independently corroborating the transfer
path. AS-08 returns T27's report. A question about 2026-07 **states the covered period and that it
falls outside**. Asked whether the intrusion has ended, it reports the last observed activity and
states continuation cannot be determined. **SC-04:** across a fixed set of questions about
information the data does not contain, nothing is fabricated and the absent source is named every
time.
§ R3.1 · R3.7 · R3.8 · R4.1 · R6.2 · R6.4 · R6.5 · SC-04 · AS-02 · AS-03 · AS-06 · AS-08

#### T35 · Answer contracts C — the summary, the recommendations, and the timing sweep `[1.25 h]`
**depends on:** T33, T34
⇒ **AS-09** — a stated-length summary contract, exactly three sentences, every assertion traceable,
residual uncertainty stated. **AS-10/R9** — ordered actions, each citing the specific evidenced
compromise that motivates it, each classified as limiting further damage, removing the adversary's
access or restoring normal operation, at least one addressing an **absent log source**, and an
explicit statement that the system carries none of them out. The R6.7 timing sweep.
✓ AS-09 returns exactly three sentences with residual uncertainty stated and nothing beyond the
evidence. AS-10 returns an ordered list in which every action cites at least one finding node, every
action carries exactly one of the three classes, and at least one references an entry from
`05_gaps.json` rather than confirmed activity. A test asserts **no module in `agent/` or `app/`
performs any write, network call or process action on behalf of a recommendation** (R9.4). Every one
of the ten scenarios returns **inside 30 seconds**, timed per scenario.
**On the timing budget:** R6.7 is tight for an agentic query stage doing multi-hop retrieval with
adaptive thinking, and requirements §8 records that 60 seconds was explicitly rejected because a
minute of silence in a live walkthrough is the worst thing that can happen in the room. If it
breaches, the correct lever is **fewer tool hops per answer**, not a relaxed budget — the budget is
a ratified requirement.
§ R6.6 · R6.7 · R8.1 · R9.1 · R9.2 · R9.3 · R9.4 · AS-09 · AS-10

### Wave 5 — surfaces, evidence and the graded prose (T36–T41, 8.5 h)

#### T36 · Chat surface wired to the answer stage, and the SC-01 cold read `[1.5 h]`
**depends on:** T07, T33, T34, T35
⇒ T07's chat page wired to `agent/answer.py`: the ten evaluation questions as presets, answer body
with sibling citation expanders opening to raw record JSON, and **live step display while the answer
is being produced**.
✓ Each of the ten presets answers with citations expandable to the complete unaltered record without
leaving the page. No nested-expander exception under any expansion combination. Steps are visible
**during** production, not only after (R10.1 — its real home is this surface, not the build tools and
not the second-cut pipeline page). **SC-01 cold read:** a reader with no prior knowledge of the
incident states the initial access, every affected host and account, and whether data was removed,
**inside ten minutes of first use**, against six to eight hours manually.
**Why the trial is scheduled, not hoped for:** SC-01 carries the product claim, it cannot be
automated, and it takes twenty minutes of someone else's time — which is exactly why it needs a slot
or it never happens. It sits here, while there is still budget to change the surface if the reader
cannot tell confirmed from observed.
§ R2.5 · R6.1 · R6.2 · R10.1 · SC-01 · NFR-02

#### T37 · Timeline and Impact surfaces `[1.5 h]`
**depends on:** T26, T36
⇒ The timeline page as a **typed table**, expandable per row, carrying each step's technique and
support state as **icon plus label**; the impact page listing hosts, accounts and assets with first
and last involvement, confirmed versus observed, and what cannot be ruled out. Both with a table
view as the primary form, using the T07 sibling pattern.
✓ Every support badge carries **both** an icon and the word — three of the four status colours sit
below 3:1 on parchment (§9.1), so a render test asserts no state is emitted without its label and
colour never carries state alone. Recorded times display **as they appear in the data with the zone
stated**. Every row expands to its citations and then to raw JSON, so any item is followable down to
the raw records without leaving the page. The full render from committed artifacts completes within
5 seconds with no credential present.
**Constraint restated deliberately:** rows use the top-level-sibling pattern, never nested
expanders. Adopting nesting here is a rewrite of the render loop, not a local change.
§ R1.1 · R1.2 · R1.5 · R3.2 · R3.3 · R5.1 · R5.2 · R5.3 · R5.4 · R7.5 · NFR-03 · NFR-09 · AS-01 · AS-07

#### T38 · Projection purity and identity stability `[1.0 h]`
**depends on:** T28, T29
⇒ `tests/harness/purity.py` and `tests/harness/identity.py`, plus an SC-02 sweep walking **every
node** in the committed graph and reporting the three conditions per node.
✓ **Purity:** delete every export and the SQLite index, regenerate from the committed JSONL, and
`git diff --exit-code` is clean — byte-identical output, the §8.3 invariant whose failure means
something authoritative leaked into a projection. **Identity:** re-run the build with a **different
model id** and the `obs_`, `edg_` and `fnd_` ids for structurally identical findings are unchanged,
so a two-run diff shows structural change rather than reworded prose (§8.2). **SC-02 must read
100%** — every asserted value present in a cited record, every finding naming its basis with
supporting observations each fulfilling the role that basis assigns, every chain terminating in
records. A single failure of any of the three is a defect, not a lower score.
**Cost stated honestly:** the identity check needs two model-backed builds, which is API spend and
wall clock. It depends on T28/T29 and **not** on the handover report, so no schedule compression can
strand it behind a P2 deliverable. If it is skipped, §8.2's central claim stays an assertion rather
than a measurement, which weakens the NFR-01 story precisely where an evaluator would push.
§ R7.4 · R7.5 · NFR-01 · NFR-05 · SC-02

#### T39 · The spec-compliance report, and the design / CLAUDE.md close-out `[1.75 h]`
**depends on:** T28, T30, T35, T37, T38
⇒ A report enumerating **all 67 acceptance criteria, 12 NFRs, 5 success criteria and 10 acceptance
scenarios** with pass / fail / not-built and the evidence for each. Plus the close-out: every scope
cut and its rationale recorded in design.md per CLAUDE.md ground rule 4; the measured rows appended
to §10.2 (T04's parse cost, T05's SDK surface in *this* venv, T07's pyarrow result, T22's build
wall clock); §3.2's "2 h 27 min" corrected to 1 h 27 min; the "fifteen other accounts" figure
corrected in **both** requirements.md §2 and design.md §4 to the measured 7 accounts across 12
events; `synthesise/` added to CLAUDE.md's repository layout; CLAUDE.md's Status section retired
from "Repository skeleton only. No application code yet."
✓ Every row has a verdict and evidence, with **no blank cells** — Phase 5's primary criterion is
that table, not "it runs". A second reader can find any criterion's evidence from the table alone.
`git diff` shows the design and CLAUDE.md amendments.
**Why the close-out is here and not in the tail:** in one candidate plan the obligation to record a
cut lived in the task scheduled to be cut *first*, so the rule was discharged by the task that gets
dropped. A cut-recording obligation belongs in a task that is never cut, and the compliance table
is also the cheapest possible discovery that something was never built at all.
§ SC-02 · NFR-06 · NFR-07

#### T40 · `docs/writeup/`: the three written discussions `[1.5 h]`
**depends on:** T39
⇒ The three discussions CLAUDE.md names as **Deliverable 3**: trust and hallucination, agentic
workflow design, product thinking. Doubling as the §13 unsoundness conformance pass — each of the
six non-checks re-read against the code that actually got built, and each of the three
evidence-rather-than-assertion promises (the adversarial corpus, set-level checks at close, the
rejection log as coverage backlog) confirmed to exist.
✓ Three documents exist in `docs/writeup/`, which holds only `.gitkeep` today. Trust and
hallucination is grounded in §13's six items and §11.1's soundness-modulo-the-checks correction,
each verified against shipped code and cited to a task. Agentic design states the three model sites
of §7 and **where the model deliberately does not appear**. Product thinking states the cuts taken
and why. Each of §13's six items is confirmed still accurately stated, or corrected.
**Why it is a task:** not one candidate plan produced it. §11 (four drafts, three dead), §13 (the
unsoundness statement) and §7 (exactly three model sites) are already the raw material, so the cost
is assembly rather than thought — but at zero tasks it gets written at 2 a.m. or not at all. A plan
that ships forty hours of pipeline and none of the graded prose has mis-scoped the assignment, not
the software.
§ SC-02 · NFR-07

#### T41 · Walkthrough script, and one rehearsed run under demo conditions `[1.25 h]`
**depends on:** T36, T37, T40
⇒ A script for the 5–10 minute walkthrough covering all five things CLAUDE.md asks for: what was
built, architectural decisions, where AI and agents were used **and where they were deliberately
not**, shortcuts taken, and what another day or week would add. Plus one full rehearsal.
✓ The rehearsal runs under **demo conditions**: credential present, build completed, artifacts
committed, app started from the README verbatim with no modification, timed inside ten minutes.
Every claim in the script points at something a viewer can be shown. §7's three model sites answer
one of the five questions; the other four are answered from §11 (the three dead drafts), §10.3 and
§13.
**Why it is a task:** this is Deliverable 2, it had no owner in any candidate plan, and it is the
only task that exercises the whole system under exactly the combination that fails in the room.
§ NFR-08

### Cut tail — reverse of §10.3, mutually independent (T42–T45, 4.75 h)

None of these four depends on another, so the cut line falls at any boundary without stranding a
dependency. Taking a cut is recorded in design.md by T39.

#### T42 · Handover report — §10.3 cuts this **last** `[1.25 h]`
**depends on:** T25, T26, T27
⇒ `synthesise/handover.py` emitting a self-contained Markdown document containing the sequence, the
relationships between activities with the record cited on both sides, the techniques with ids and
tactics, the affected hosts, accounts and assets, the absent sources and what each limits, and every
citation inline. Header stating the data it was built from, the catalogue version, the system version
and when it was produced. **Plus assumptions A-04 and A-05 carried into the document itself.**
✓ Reads correctly with the app stopped, the venv absent and no network — it is plain Markdown. Every
assertion traces to a node id present in the committed JSONL, checked **programmatically, not by
eye**, and no assertion paragraph lacks a citation. The four R8.3 provenance items are all present.
It lands in a committed location, not gitignored `outputs/` (fixed at T29).
**Why A-04 and A-05 belong here:** every temporal-adjacency edge and every `temporal_within` Δ
inherits A-04 (no clock drift between source systems) and the whole absent-source report inherits
A-05 (a missing record reflects collection, not export). Both are unverifiable from inside the data,
and the handover is the one artifact that **leaves the building** — so the limits travel with it
rather than staying in a spec nobody downstream reads. §10.3 places this last in the cut order
because R8 is ratified scope while the pipeline view is a design preference.
§ R8.1 · R8.2 · R8.3 · R8.4 · NFR-07

#### T43 · The two charts — source-type lanes and the coverage matrix `[1.25 h]`
**depends on:** T37
⇒ The source-type lane chart (one lane per source type across the 72-hour window) and the coverage
matrix (hosts × source type, covered / absent / partial), both via
`st.dataframe`/`altair` over `pyarrow.Table.from_pylist`, each with an adjacent table view.
✓ **Zero categorical series** — position carries identity (the lane *is* the source type) and colour
carries only intrusion-attributed versus background, which sidesteps the all-pairs colour-vision
ceiling rather than working around it. The lane chart makes "twelve hours of intrusion inside a
three-day window" legible at a glance. Both have a table view. No code path reaches
`pandas._libs.join`.
**Cut status, stated because it matters:** §9.3 names exactly these two as charts and gives each a
specific job, and §10.3's cut list contains Navigator, Attack Flow, graph visualisation, pipeline
view and handover report — **not** the charts. Cutting them is therefore a *new* cut, which CLAUDE.md
ground rule 4 requires T39 to record in design.md rather than take silently.
§ R3.12 · AS-08

#### T44 · Pipeline surface — §10.3 cuts this second `[1.25 h]`
**depends on:** T13, T27, T28, T37
⇒ The pipeline page: six stages as `st.status(type="step")`, each expandable to its artifact and its
verification result **read from T28's `0N_verification.json`** rather than recomputed; the gap report
with each gap shown beside the hypothesis that went looking for it; and the rejection log presented
as the coverage backlog.
✓ Each stage displays pass or fail with its check names, not a hardcoded tick; corrupting one
artifact makes that stage show failed and the page refuses to present the reconstruction as
complete. Every gap appears next to its hypothesis and that hypothesis's state, so *unconfirmed*
("the source covers this and nothing appears") reads differently from *uncoverable* ("this could not
be examined"). The rejection log shows per-rejection diagnostics. Every derived finding's named basis
is inspectable, showing what it requires and why it applies to the cited observations. Any node is
followable down to the raw records.
**Cut-safety note:** R7.4, R7.5 and R10.2 are also served by T13's `trace` CLI and T37's expandable
rows, so cutting this page costs the surface, not a P1 criterion. That was deliberate.
§ R3.6 · R7.4 · R7.5 · R10.1 · R10.2 · AS-08

#### T45 · Attack Flow export and Navigator layer — §10.3 cuts this **first** `[1.0 h]`
**depends on:** T03, T23, T26
⇒ `synthesise/attack_flow.py`, roughly 100 lines emitting vanilla Attack Flow with an
`evidence_refs` extension and the `technique_id` / `technique_ref` pair, plus
`05_navigator_layer.json`. Strictly projections — one-way, never read back.
✓ `05_attack_flow.json` validates against the schema **vendored at T03** (the verification that
could not have run in any candidate plan, because none fetched the schema). The Navigator layer
loads. Both regenerate byte-identically from the committed graph, and a test asserts nothing imports
either back into the graph. No ratified requirement depends on either artifact, which is exactly why
they are first on the cut list; R4.1's technique identity is already satisfied by
`04_mappings.jsonl`.
§ R4.1 · R7.4 · D-04

---

## 4. Budget, and three cut lines

**45 tasks, 59.75 h at nominal estimate.** The spine through T41 — every P1 requirement, every
success criterion and all three graded deliverables — is **55.0 h**. The §10.3 cut tail is 4.75 h.
Every task falls inside the 0.5–2.0 h range; none is a vague multi-day lump.

Against 3–5 days for one developer (24–40 h) that does not fit, and saying otherwise would be the
fluent-unsupported-conclusion failure this project exists to prevent. Two qualifications and three
cut lines:

**Qualification 1 — the estimates are unassisted-developer hours.** Implementation here is
agent-assisted against a design that specifies exact module names, exact function signatures, exact
artifact names and exact checks. On that basis a 0.6 multiplier is defensible, which puts the spine
near **33 h** and the whole plan near **36 h** — inside five long days. That multiplier is stated
rather than baked into the numbers, so the plan can be judged either way.

**Qualification 2 — no candidate fit either.** risk-first was 54.5 h, dependency-first 57 h, and the
one plan that "fit" at 35 h did so by loading 14–19 requirement ids into single two-hour tasks and by
omitting the charts, the compliance table, R1.8, SC-01, the perturbation generator's negative
controls and the bundle's `-text` rule. Fitting a budget by under-sizing tasks is not fitting the
budget.

| Cut line | Drop | Spine | Surrenders |
|---|---|---|---|
| **1 — §10.3 as written** | T45, then T44, then T43, then T42 | 55.0 h | R8 (P2) and four surfaces/exports. No P1 criterion, because R7.4/R7.5/R10.2 are also served by T13's CLI and T37's rows. T43 is a *new* cut and T39 records it |
| **2 — four days** | Cut line 1, plus: merge T33–T35 into one scenario task (−1.5 h); Timeline only, no Impact page (−0.5 h); identity-stability across two runs of one model instead of two models (−0.5 h); T21 and T22 merged (−1.0 h) | ≈ 51.5 h | Impact rendering (R5.x still served by T26's artifact and T42), §8.2's cross-model identity claim, and the mechanism-versus-prompt diagnosability of a loop failure |
| **3 — three days** | Cut line 2, plus: drop T40's writeup to one combined document (−0.75 h); drop T41's rehearsal, keeping the script (−0.5 h); drop T32's gate-two corpus to the two sharpest cases (−0.5 h); drop T24 into T23 (−0.75 h) | ≈ 49 h | This is the line where **graded scope starts going**, and it should be taken only after the P1 spine is green. Merging T24 back is the worst of these — six criteria where one sentence fails all six |

**What no cut line touches**, in priority order: T18 including the role-fulfilment check (SC-02
admits no partial credit), T30 (the accuracy gate), T14's negative controls (the generator is
worthless unproved), T39 (the Phase 5 gate and the cut record), T28 (six verification reports and
NFR-06), and T20 (leak independence of the anchors).

Every cut actually taken is recorded in design.md §10.3 by T39, per CLAUDE.md ground rule 4.

---

## 5. Risks

Ordered by how much they would cost to discover late.

1. **The relation set is the sharpest single point of failure, and no task can fully retire it.**
   §12 item 1 is exact: no downstream check can detect a link that was never computed, and §13
   item 3 admits relation-set completeness is unchecked. T16 reproduces the one pair that was
   actually measured; the other nine relations have no equivalent evidence. T18's corpus tests
   rejection, not coverage. The only mitigations are the rejection log and the unconfirmed set read
   as a coverage backlog (T22, T44) and SC-03's floor (T30) — and the backlog only works if someone
   reads it, which is a discipline, not a property. T44 is also the second thing cut, which is worth
   noting when the cut is taken.
2. **SC-03 recall is the loudest unknown.** Nothing measured so far bounds how much of the 22-event
   intrusion the loop will reach. T30 finds out before the UI exists rather than after, and its
   failure reopens T16, T20 and T22 — but if it fails late in a compressed schedule there is nowhere
   to go.
3. **Two network-dependent tasks sit at the graph root.** `anthropic` is absent from `.venv` and
   `ANTHROPIC_API_KEY` is unset, so §10.2's SDK-surface result was measured somewhere other than
   this venv; `data/attack/` holds only `.gitkeep`. Network is reachable today (verified), but the
   same Application Control policy that blocks `pandas._libs.join` could block a fresh wheel
   install, and there is no deterministic fallback for the three model sites — the nearest is the
   rule registry §11 killed as draft 3.
4. **Neither gate can check aptness, and the demo ships the output of the weaker one.** §13 item 1
   (whether an interpretation is apt) is the test oracle problem and is irreducible here; §13 item 2
   says gate two cannot judge whether a qualitative summary fairly represents the nodes it cites.
   Every answer the walkthrough reads aloud passes through exactly that gate. T32 hardens it as far
   as a deterministic check can go; no task closes it, because none can. The mitigation is to say so
   in T40's writeup and in the walkthrough, which is what §13 exists for.
5. **T14's generator is the likeliest overrun and the most dangerous to under-build.** A generator
   that quietly preserves a signal the anchors use passes SC-05 while proving nothing — a false clean
   bill on the exact property R7 exists to establish. Sized at 2 h with its negative properties
   asserted directly and three negative controls, and written against R7.1's five perturbations
   verbatim rather than from memory.
6. **R6.7's 30-second budget is tight for an agentic query stage.** Stage 6 does multi-hop retrieval
   over frozen artifacts with adaptive thinking. T35 times every scenario; if it breaches, the lever
   is fewer tool hops, not a relaxed budget, because requirements §8 records that 60 s was explicitly
   rejected.
7. **T24 is the most requirement-dense task and the easiest to fail silently.** Six criteria, one
   confidently worded sentence, partly grep-based verification — which catches the phrasings
   anticipated and not the ones not. A second reader on T24's output text specifically is worth more
   than another automated check. That the "fifteen accounts" figure in **both** governing documents
   turned out to be 7 is the evidence for this risk, not a hypothetical.
8. **T38's identity check needs two model-backed builds**, which is API spend and wall clock at the
   tail where both are scarcest. It no longer depends on the handover report, so a P2 cut cannot
   strand it — but a budget cut can, and cut line 2 names exactly what is lost.
9. **A-04 and A-05 remain unverifiable from inside the data, and no task can change that.** T42
   carries both into the handover rather than leaving them in a spec, which is the only available
   mitigation.
10. **Two critic-named items are deliberately not their own tasks, recorded here per ground rule 4.**
    *Graph visualisation* (`st-link-analysis`): §10.1 leaves it a Could and §10.3 cuts it third; it
    would cost about 2 h and displace T44, and T13's `trace` CLI plus T37's expandable rows already
    serve R7.4/R7.5. Dropped. *Texture fill at 45°/135° for forced-colors and print* (§9.4): T07
    ships the print stylesheet and icon-plus-label, so state never rests on colour; the texture
    commitment itself is dropped, and requirements §7 excludes accessibility conformance. Both drops
    are recorded in design.md by T39 rather than taken silently. The **dark palette** is *not*
    dropped — it moved into T07, since §9.1 says dark mode is selected with its own steps rather than
    an automatic flip, and no candidate plan built it.


## Bounded correlation repair — 2026-09-24
- [ ] Complete event context and explicit interpretation abstention.
- [ ] Revalidate/consolidate final findings inside correlation; retain subject/context IDs.
- [ ] Correct SEEK role/time handling and precise process/session associations.
- [ ] Allow technique abstention and validate exactly selected evidence.
- [ ] Rebuild in isolation, inspect claims, test regressions and assignment questions.

## Action-preserving repair tasks (2026-09-24)
- [ ] Introduce grouped action contract, exact event partition validation and source-derived facts/times.
- [ ] Integrate case correlation and retain post-review hypothesis/seek.
- [ ] Enrich each atomic action, retain parent finding references and abstention.
- [ ] Expose actions, context and calculated chronology to timeline and chatbot.
- [ ] Run regression suite, live build, repeat correlation and assignment answer checks; document limits.


## Seek correctness repair

Implement hypothesis constraints and timestamp context; validate and match in Seek; test wrong destination, cross-event matches, boundaries and invalid windows; regenerate saved hypothesis and downstream projections; keep UI running.
