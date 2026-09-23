# The stage-6 answer payload

**Status:** contract. Produced by stage 6 (`T31`), consumed by
`app/components/citation.py`, enforced by `citation.validate_payload`.

This document exists because the renderer and the emitter are written at
different tasks — the layout landed at `T07`, the emitter arrives at `T31` — and
a layout constraint that lives only in the renderer's head is a constraint the
emitter will break. Design §9.4 is blunt about the cost: citations have to
render as **top-level siblings** of the answer body, and retrofitting that is a
rewrite of the render loop rather than an edit.

`validate_payload` checks **shape, not truth.** Whether the citations resolve is
settled by the render, which reports every one that did not. Whether the claims
are warranted is settled by the citation gate at stage 6. Neither is this
document's business.

---

## Shape

```json
{
  "answer_id": "ans_3f9c1a2b4d5e",
  "question": "How did the intruder obtain valid credentials?",
  "body": "…" ,
  "claims": [
    {
      "claim_id": "clm_01",
      "text": "The account jclark authenticated from WKSTN-07 at 09:07:30Z.",
      "kind": "observation",
      "support": { "label": "corroborated", "flags": [] },
      "basis": {
        "name": "cross_source_field_equality",
        "requires": "the same normalised value at a named field of two records from different source types",
        "applies_because": "username matches across auth and endpoint for this pair"
      },
      "citations": [
        {
          "node_id": "obs_9a1b2c3d4e5f",
          "layer": "observation",
          "record_id": "rec_1a2b3c4d5e6f",
          "event_id": "EVT-0231",
          "source_type": "endpoint",
          "timestamp": "2026-06-12T09:07:30.394151Z",
          "field": "username",
          "asserted_value": "jclark"
        }
      ]
    }
  ],
  "gaps": [
    { "statement": "No mail-gateway source is present.",
      "limits": "the delivery vector cannot be evidenced, only inferred from process lineage" }
  ],
  "provenance": {
    "model_id": "claude-opus-5",
    "attack_version": "19.2",
    "contract_set": "…",
    "validator_version": "…",
    "software_version": "0.1.0"
  }
}
```

## Required keys

`validate_payload` raises `PayloadError` naming the missing key. It does not
fill in defaults: a blank panel where a claim should be is worse than a stack
trace, because only one of the two gets fixed.

| Level | Required | Source of the requirement |
|---|---|---|
| payload | `answer_id` · `question` · `body` · `claims` | `REQUIRED_PAYLOAD_KEYS` |
| claim | `claim_id` · `text` · `kind` · `support` · `citations` | `REQUIRED_CLAIM_KEYS` |
| support | `label` | R3.2 — the structure of the support is stated, not shaded |
| citation | at least one per claim | **R2.2 / R2.3 — an uncited claim is a bug, not an empty state** |

`claims` must be a sequence, and a string is explicitly not one. A claim list
that arrived as a single string would otherwise iterate into characters and
render one empty claim per letter.

## Optional keys

| Key | Effect if absent | Requirement |
|---|---|---|
| `basis` | the basis caption is omitted | R2.3, R10.2 — what the basis requires and why it applies are inspectable rather than implied |
| `gaps` | no gaps block | R3.6 — absent sources are reported *without being asked*, so they belong in the answer rather than on a page the reader may never open |
| `provenance` | no version caption | R10.3 — the versions in use are retained with the answer |
| `support.flags` | no flag badges | the two flags from stage-5 close |

`body` accepts a string or a sequence of paragraphs. A sequence renders one
`st.markdown` per entry, which is how a multi-paragraph answer keeps its
spacing.

## Citation columns

The eight `CITATION_COLUMNS` are the citation table, in reading order — what was
cited, where it came from, when, and which value it carries:

`node_id` · `layer` · `record_id` · `event_id` · `source_type` · `timestamp` ·
`field` · `asserted_value`

A citation may omit any of them and the cell renders empty, with two
exceptions that are not cosmetic:

- **`record_id` must resolve** in the records authority. If it does not, the
  renderer emits an error in place of the record and adds it to
  `RenderReport.unresolved`. The component cannot withhold the answer — that is
  the gate's job at stage 6 — so it reports instead, and R2.9 requires the
  caller to act on it.
- **`timestamp` is shown exactly as recorded, with the zone named** (R7.5).
  Never reformatted. A reformatted timestamp is no longer the evidence.

## Layout constraints the emitter must respect

1. **Citations are siblings, not children.** Everything renders inside one
   `st.chat_message`; each citation is its own top-level expander. Streamlit
   raises `StreamlitAPIException` on an expander inside an expander, so nesting
   would cap the surface at one open citation. Three open at once is the case
   `T07` verifies, and `tests/test_ui_render.py` proves the shape statically by
   walking the AST of every module under `app/`.
2. **Expansion state is keyed in `st.session_state`**, under
   `{key_prefix}::{claim_id}::{node_id}`. So `claim_id` must be unique within a
   payload and `node_id` unique within a claim; duplicates would collapse two
   citations onto one toggle.
3. **A closed citation costs nothing.** The record body renders only when the
   expander is open, which is what keeps a long answer inside NFR-03's budget.
4. **Record lookup is cached on `(path, mtime)`.** The emitter must rewrite
   `01_records.jsonl` rather than mutating it in place, or the UI will serve a
   record that no longer exists under a citation that still points at it.

## What this contract deliberately does not carry

No probability, percentage or confidence value anywhere — R3.4. `support.label`
is one of four words, and the flags are words too. There is no field a number
could be put in, which is the point: the constraint is structural rather than
remembered.

Answer claims are also **not** nodes in the committed graph (§8.2). They live in
the per-question answer record with citations pointing *into* the graph.
Otherwise the graph would vary with whatever anyone happened to ask.
