# Egress inventory

**What leaves this machine, from where, and carrying what.**

NFR-04 has two halves. The first is that the model sites are documented — that
is the table below. The second is that the documentation is *true*, which a
document cannot establish about itself. So the **exact serialised request body**
of every site is captured through a mock transport, committed as
`tests/fixtures/egress_request_bodies.json`, and checked against this file by
`tests/test_egress_inventory.py`: every field present maps to a category named
here, and nothing beyond it is sent. The inventory is checked, not described.

Three facts frame everything else:

- **The query plane has no path to the service.** `git grep anthropic -- app/`
  returns nothing, and a test asserts it. The app reads committed artifacts, so
  it starts with the credential unset and the network down.
- **Egress happens at exactly one place.** `agent/client.py` is the only module
  under `src/` that names a network client, and `tests/test_external_artifacts.py`
  asserts that the list of such modules is exactly `[agent/client.py]` — so
  there is exactly one function to capture in order to check this inventory.
- **Nothing fetches the ATT&CK catalogue at runtime.** D-03 retains the bundle
  locally, and no module under `src/` names `githubusercontent`,
  `attack-stix-data`, `taxii` or `urlretrieve`. The only code in the tree that
  fetches an external artifact is `scripts/fetch_external.py`, which is one-time
  provisioning and is not importable from `src/` or `app/`.

---

## The destinations

| Destination | Reached by | Carries | When |
|---|---|---|---|
| `api.anthropic.com` | `agent/client.py` only | see the site table below | during **build**, only with `ANTHROPIC_API_KEY` set |
| `raw.githubusercontent.com` | `scripts/fetch_external.py` | nothing — GET only | **once**, at provisioning; never at build or query time |

There is no third. Streamlit's usage telemetry is off in
`.streamlit/config.toml` (`gatherUsageStats = false`), there is no
`[[theme.fontFaces]]` table that would fetch a web font on first paint, and the
vendored Attack Flow `$ref` closure exists precisely so `jsonschema` does not
resolve references over the network at validation time — a real egress that the
`src/` grep cannot catch, because it happens inside the library's resolver.

---

## The model sites

Four contracts across **three stages**. Design §7 puts the model in exactly
three places; `interpret` and `hypothesise` are two contracts at one of them.
Everything else in the system is deterministic, and that is the stage-precise
answer to *"where AI was used and where it was deliberately not"*.

### 1 · `interpret` — stage 3, correlate

Proposes a candidate finding over a neighbourhood. The deterministic layer has
already computed every relation; this step interprets them and computes nothing.

| Category sent | Example |
|---|---|
| observation ids and their asserted normalised values | `obs_9a1b2c3d4e5f` → `jclark` |
| record ids, source types and recorded timestamps | `rec_…`, `endpoint`, `2026-06-12T09:07:30.394151Z` |
| relation names and their endpoint observation ids | `same_size(obs_a, obs_b)` |
| previously accepted finding statements and ids | so a proposal can build on one |

### 2 · `hypothesise` — stage 3, correlate

Predicts what record should exist if the findings so far are right, committed
*before* looking for it.

| Category sent | Example |
|---|---|
| accepted finding statements, stages and ids | `fnd_…`, `lateral-movement` |
| entity names as they appear in observations | `FILE-SRV-01`, `jclark` |
| source type coverage per entity | *"`endpoint` covers WKSTN-07; `cloud_storage` does not"* |

### 3 · `select_technique` — stage 4, enrich

Chooses one ATT&CK technique from a retrieved enum, quoting the values that
triggered the choice.

| Category sent | Example |
|---|---|
| one accepted finding statement and its stage | |
| the observations it cites, with their fields and values | `process_name` → `powershell.exe` |
| candidate ATT&CK technique ids, names and descriptions from the local catalogue | `T1059.001`, *PowerShell* |

The candidate list comes from `data/attack/catalogue_v19.2.json`, which is
derived from the committed bundle. Nothing is retrieved from MITRE at this step.

### 4 · `answer` — stage 6, answer

Answers an analyst question over the frozen artifacts.

| Category sent | Example |
|---|---|
| the analyst's question | as typed |
| accepted finding statements, stages and ids | |
| observation ids, fields and asserted values | |
| technique mappings and the local catalogue version | `19.2` |
| computed coverage gaps | *"no mail-gateway source is present"* |

---

## The request envelope

Every request carries exactly these six top-level fields. Only one of them
carries incident information; the other five are protocol. A field appearing
that is not in this table is unreviewed egress, and the captured-body test fails
on it.

| Body field | What it carries | Incident information |
|---|---|---|
| `model` | the model id, `claude-opus-5` | no |
| `max_tokens` | the response budget | no |
| `thinking` | `{"type": "adaptive"}` | no |
| `output_config` | the effort level, and the response contract as JSON schema — field names and their descriptions, derived from `agent/schemas.py` | no |
| `system` | the site's system prompt, verbatim from `agent/contracts.py` and hashed into the contract-set hash | no — authored text, committed and reviewable |
| `messages` | one user message, assembled from labelled blocks: the categories tabled above, and nothing else | **yes** |

The `system` row is the one worth arguing about. A system prompt is authored
text rather than incident data, but it is still text going out, so it is held to
the same standard a different way: it lives in `agent/contracts.py`, the capture
asserts the body carries it *verbatim*, and it is hashed into
`CONTRACT_SET_HASH`. A prompt cannot be edited for a demo without the hash
changing and the fixture diffing.

---

## What is never sent

Named explicitly, because "we only send what we need" is not a checkable claim.

| Not sent | Why it matters |
|---|---|
| **Raw record payloads in bulk** | The prompt carries the observations a step is reasoning over, not the 242-record dataset. Records reach the provider only as the specific cited fields and values. |
| **The `note` field** | Stripped at the parse boundary (T10), so no downstream stage — model or otherwise — can see it. It is the dataset's answer key, and a model that read it would score perfectly while demonstrating nothing. |
| **`tests/fixtures/ground_truth.json`** | Not reachable from `src/` or `app/` at all; a test enforces that with `git grep`. |
| **The credential** | Read from `ANTHROPIC_API_KEY` in the environment and stored nowhere in the tree (NFR-10). No key file, no `.streamlit/secrets.toml`. `.env` is gitignored and no module reads it. |
| **Class docstrings** | Pydantic uses `__doc__` as a schema's object `description`, so leaving them would send this codebase's design commentary to the provider on every call. `wire.wire_schema` strips it, at the root and inside `$defs`. Field descriptions stay — those are prompt content. |
| **Filesystem paths and machine identity** | Artifacts record repository-relative paths (`paths.relative`), so no absolute build-machine path becomes evidence or reaches a prompt. |

---

## How the check works

Three things have to agree, and none of them is allowed to be the sole authority:

| | Where it lives | What it says |
|---|---|---|
| the declaration | `egress_categories` on each `Site` in `agent/contracts.py` | what this site may send |
| the document | the tables above | what a reader is told |
| the evidence | `tests/fixtures/egress_request_bodies.json` | what was actually serialised |

`client.captured_request_body` builds the request through the same
`_request_kwargs` the live call uses, against an `httpx.MockTransport` that
records the body and answers `401`. Nothing leaves the process, no credential is
needed, and — critically — the capture cannot drift from the live request,
because building it twice is what would let the inventory describe a request the
system does not send.

It returns 401 rather than a synthetic success on purpose: a fabricated response
body is the one thing a probe must never manufacture, and the request is already
captured by the time the transport returns.

`scripts/regen_egress_fixture.py` writes the fixture; `--check` rebuilds it to
memory and diffs. The material in it is *derived* — record and observation ids
computed by `siem_investigator.ids` from real events, technique names and the
catalogue version read from the derived catalogue — and drawn only from the 220
**benign** events, because a committed, readable, prompt-shaped fixture
populated from the intrusion would be a hint sheet.

Then `tests/test_egress_inventory.py` asserts, per site: the top-level fields are
exactly the envelope table's; `system` is the committed prompt verbatim; the
user message decomposes into labelled blocks whose every label is a declared
category; every declared category is documented here and every category
documented here is declared in code; and the schema sent is exactly the
contract's, carrying no class docstrings.

### The part that is a mechanism rather than a test

A test over a fixture pins today's request. What keeps it true as the prompt
builders arrive is `contracts.render_payload`, which assembles a user payload
from `PayloadBlock(category, text)` and raises `UndeclaredEgress` for a category
the site does not declare. **Every prompt builder goes through it** — the
stage-3 loop, the stage-4 mapper, the stage-6 answerer — so sending something
new means declaring a category, and declaring one that is not in the tables
above fails the test that reads this file.

Stated plainly, because the limit matters: at T06 the envelope and the labelling
discipline are production code, and the payload blocks in the fixture stand in
for prompts that T22, T24 and T31 have yet to write.

### A second property the same capture proves

Measured on **anthropic 0.84.0**, the SDK's `transform_schema` discards `enum`
and `const`, folding them into each property's `description` as prose — so a
closed `Literal` would arrive as a *hint rather than a constraint*, and a
hallucinated technique id would be accepted by the API and rejected only on
parse. `agent/wire.py`'s `_restore_closed_values` repairs the schema and
`client._request_kwargs` sends it through `extra_body`. Without that, D-08's
"structurally unrepresentable" claim is false, and the captured body is where
that is verified rather than assumed.
