# Requirements — Cyber Incident Investigation Intelligence

**Phase 1 of Spec → Design → Tasks → Implement → Validate.**
Status: **draft — blocked on 20 open questions (§12.1).** Date: 2026-09-22.
Incident under investigation: `INC-2026-0610-001`.

This document says *what* the system must do and *how we will know it did it*. It deliberately
contains no architecture, no technology choices, and no mechanism. Those belong in
[design.md](design.md).

Requirements use [EARS](https://alistairmavin.com/ears/) syntax — a fixed clause order and a
small keyword set (`WHEN`, `WHILE`, `WHERE`, `IF`/`THEN`, `SHALL`) chosen because it makes each
requirement independently testable. Requirement IDs are stable and are referenced by
`tasks.md` and by the validation harness.

**Nothing in this document is settled by assumption.** Where a value or a policy has not been
ratified, the requirement carries a proposed value *and* a pointer to an open question —
`→ Q-R-nn`. Those questions are listed in §12.1 and every one of them blocks Phase 1 sign-off.
Proposed values are written in full rather than left as `TBD` so that the requirement stays
testable while the number is being argued about.

---

## 1. Purpose

A healthcare organisation suffered a suspected intrusion. Their SIEM holds 72 hours of events
across endpoint, authentication, network and cloud storage. Reconstructing what happened
currently costs a senior analyst 6–8 hours of manual cross-source correlation.

This system reconstructs the attack from those logs and answers questions about scope and
impact, **with the specific log evidence behind every claim**, so that the output can be handed
to a board and a legal team.

A previous tool failed because it returned raw search results with no correlation, no timeline
and no ATT&CK linkage — "grep with a UI" — and missed a lateral movement event that was obvious
in hindsight. **Correlation and traceability are the product. Search is not a feature of it.**

### 1.1 Success criteria

The system succeeds when all of the following hold:

1. An analyst obtains the reconstructed attack chain in **minutes**, not hours.
2. Every claim in every output can be traced to specific log events by `event_id`.
3. The system's stated uncertainty matches reality — it does not overclaim where evidence is
   thin, and it does not withhold conclusions the evidence supports.
4. Where the logs cannot answer a question, the system says so and names what is missing.
5. A reader who distrusts the system can verify any single claim in under 30 seconds.

### 1.2 Anti-goal

The system must never produce a plausible, well-written, uncited conclusion. In an incident
investigation a fabricated finding is worse than no finding: it misdirects containment, and it
is discoverable in litigation. **A correct "I cannot confirm X because the relevant logs are
absent" is a successful output.**

---

## 2. Users

| User | Context | What they need |
|---|---|---|
| **SOC analyst** (primary) | Mid-investigation, under time pressure, will be challenged on conclusions | The chain, the pivots, the raw events behind each step, and an honest list of what is unknown |
| **CISO** (secondary) | Briefing a board and legal counsel | Blast radius, a defensible executive summary, and an explicit confidence statement |
| **IR responder** | Acting in the next two hours | Prioritised containment actions tied to specific evidenced compromise |

The analyst is the user the system is designed for. The CISO is a consumer of its output, not an
operator of it.

### 2.1 Non-user stakeholders

| Stakeholder | Interest |
|---|---|
| **Evaluating panel** | Not a user, but the audience for §3.8's deliverables. Judges applied reasoning, engineering judgment, agentic thinking, trust and traceability, communication and product intuition — explicitly **not** polish (C-07) |
| **Legal counsel** | Never operates the system. Consumes the handover report (`R-RPT`) and depends on the chain-of-custody record (R-NFR-12) being sufficient to show how a conclusion was reached |

Recorded because the panel's criteria and legal's evidentiary needs shape requirements that no
user would ask for — `R-ATK-07`, `R-NFR-12`, `R-NFR-18` and `R-RPT-02` exist for them.

---

## 3. Scope

### 3.1 System boundary

The system owns the reconstruction and the answering. It owns no collection, no enforcement and
no remediation.

```
   INPUTS (not owned)                SYSTEM UNDER SPECIFICATION           OUTPUTS (owned)

   data/raw/siem_logs.json  ──►  ┌──────────────────────────────┐
   fixed, read-only              │  ingest → correlate → enrich │ ──►  analyst Q&A with
                                 │       ↓                      │      citations  (R-QRY)
   ATT&CK Enterprise        ──►  │  evidence → answer → render  │
   catalogue, cached locally     │                              │ ──►  timeline / blast radius
                                 │  validation harness          │      / coverage gaps  (R-UI)
   Claude API               ──►  │  (reads ground truth)        │
   governed by Q-R-07            └──────────────────────────────┘ ──►  handover report  (R-RPT)

   OUTSIDE THE BOUNDARY: SIEM collection and retention · mail gateway, DNS and EDR telemetry
   that does not exist in this dataset · threat-intelligence services · containment execution ·
   ticketing and case management · identity and access systems
```

The last line is the one that matters analytically: several things the investigation *needs* sit
outside the boundary and are not merely unimplemented — they are absent from the dataset
(§7.2). The system's job is to say so, not to substitute for them.

### 3.2 Data scope

| Dimension | Extent |
|---|---|
| Dataset | `data/raw/siem_logs.json`, one file, treated as read-only (R-ING-09) |
| Incident | One: `INC-2026-0610-001` |
| Window | `2026-06-10T08:00:00Z` → `2026-06-13T08:00:00Z` (72 hours) |
| Volume | 242 events |
| Source types | 4 — `network` (84), `endpoint` (65), `auth` (62), `cloud_storage` (31) |
| Knowledge base | MITRE ATT&CK Enterprise, version recorded per R-ATK-07 |

All four source types are retained deliberately: dropping any one severs the chain. `network`
carries the only command-and-control evidence, `auth` carries the only lateral-movement
authentication evidence, and the exfiltration conclusion requires joining `endpoint` to
`cloud_storage`. This is a derivation from the data, not a preference — but it is still a scope
decision a reviewer should ratify (§14).

### 3.3 Functional scope

In scope, each expanded in §6:

1. Ingest and normalise all four source types, preserving originals (`R-ING`).
2. Resolve entities across sources, including honest handling of ambiguity (`R-ENT`).
3. Reconstruct the attack timeline by cross-source correlation (`R-COR`).
4. Map observed behaviour to ATT&CK techniques from the real catalogue (`R-ATK`).
5. Assess blast radius across hosts, accounts and data (`R-BLR`).
6. Identify and report coverage gaps unprompted (`R-GAP`).
7. Answer free-form analyst questions with enforced citations (`R-QRY`).
8. Present all of the above conversationally with expandable evidence (`R-UI`).
9. Produce a handover artifact for a non-operating audience (`R-RPT`) — subject to **Q-R-08**.
10. Score itself against ground truth and prove leak independence (`R-VAL`).

### 3.4 Out of scope

See §11 for each cut and its rationale, and §8.1 for the four quality characteristics
deliberately not covered.

### 3.5 Assumptions

These are beliefs about the data and the world that the requirements rest on. If one is false,
specific conclusions become unsafe — the third column says which.

| # | Assumption | If false |
|---|---|---|
| **A-01** | The dataset `metadata` accurately describes source types, schemas and internal subnets | R-ING-07 misclassifies internal/external, corrupting C2 and exfiltration reasoning |
| **A-02** | The `note` annotations are accurate and complete enough to serve as validation ground truth | The §9.1 metrics measure agreement with a flawed oracle rather than correctness |
| **A-03** | Exactly one intrusion is embedded; no second, unrelated attack chain is present | A second chain would be folded into the first. R-COR-09 conflict reporting is the only safeguard |
| **A-04** | Timestamps are accurate and consistently UTC, with no clock skew between source systems | Temporal-adjacency correlation (R-COR-03) becomes unreliable and the timeline order may be wrong |
| **A-05** | For the source types present, the export is complete — an absence is a collection gap, not an export failure | Gap analysis (`R-GAP`) would attribute a missing event to the environment when it is an artifact of the export |
| **A-06** | The ATT&CK Enterprise catalogue can be obtained once and cached, satisfying R-NFR-10 | R-ATK-03 cannot be met without live network access at demo time, breaking R-NFR-10 |
| **A-07** | A single analyst uses the system on one machine at a time | The authentication and multi-user cuts in §11 become invalid |

A-04 and A-05 are the two worth stating out loud in the walkthrough: both are standard
investigative assumptions that practitioners make silently, and both are unverifiable from
inside this dataset.

### 3.6 Dependencies

| # | Depends on | Owned by | Notes |
|---|---|---|---|
| **D-01** | The provided dataset | Assignment | Fixed; no further collection is possible |
| **D-02** | MITRE ATT&CK Enterprise catalogue | MITRE | External; cached locally per R-NFR-10. Access method is **Q-D-03** |
| **D-03** | Claude API | Anthropic | What content may be sent to it is **Q-R-07**; absence is handled by R-NFR-03 |
| **D-04** | Language runtime and libraries | Phase 2 | Selected in `design.md` after build-versus-adopt comparison |

### 3.7 Constraints

| # | Constraint | Source |
|---|---|---|
| **C-01** | 3–5 calendar days, one developer | Stated budget |
| **C-02** | The demonstrable path must not require network access to a third-party service | R-NFR-10 |
| **C-03** | The dataset is fixed and read-only; no additional telemetry can be collected | D-01, R-ING-09 |
| **C-04** | Development machine is Windows; the demonstration machine is not yet known | **Q-R-12** |
| **C-05** | Claude API access is available | Confirmed |
| **C-06** | The `note` field may not influence any behaviour outside the validation harness | R-UB-11, R-VAL-06 |
| **C-07** | Polish is explicitly not being evaluated; budget spent on appearance is budget lost | Assignment |

C-07 is a real constraint, not a note. The assignment says it is not grading on polish and
names applied reasoning, engineering judgment, agentic thinking, trust and traceability,
communication and product intuition as the criteria instead.

### 3.8 Deliverables

The assignment names three. Only the first is a software artifact.

| # | Deliverable | Where it lives |
|---|---|---|
| **1** | Tangible artifact — the running prototype | This repository |
| **2** | A 5–10 minute walkthrough: what was built, architectural decisions, where AI and agents were used **and where they were deliberately not**, shortcuts taken, what another day or week would add | **Q-R-18** |
| **3** | A short written or verbal discussion of trust and hallucination, agentic workflow design, and product thinking | **Q-R-18** |

Deliverables 2 and 3 are graded, and this document's §12.2 and §11 are most of their raw
material — the design questions and the declared cuts *are* the architectural-decisions
narrative. Whether they are produced as repository artifacts or prepared separately is **Q-R-18**.

---

## 4. Definitions

| Term | Meaning in this document |
|---|---|
| **Event** | One record in the `events` array, uniquely identified by `event_id` |
| **Entity** | An account, host, IP address, file, process or storage bucket referenced by an event |
| **Observation** | A statement directly recorded by ≥1 event (see §5.1) |
| **Inference** | A statement derived by correlating observations (see §5.1) |
| **Citation** | The triple (`event_id`, `source_type`, `timestamp`) identifying evidence |
| **Correlation rule** | A named, deterministic rule that derives an inference from observations |
| **Independent source types** | Two or more of `endpoint`/`auth`/`network`/`cloud_storage` |
| **Attack phase** | A stage of the intrusion: initial access, execution, C2, credential access, discovery, lateral movement, collection, exfiltration, defence evasion |
| **Attack-attributed** | An event the system has concluded is part of the intrusion, reached by applying correlation rules to observations — never by reading a leak field (§7.3) |
| **Coverage gap** | A question the ingested logs structurally cannot answer |
| **Leak field** | A dataset artifact that reveals the answer without investigative reasoning (§7.3) |
| **Answer record** | The persisted trace of one question, containing exactly: the question as asked, the answer as rendered, the software and ATT&CK catalogue versions, the ordered list of investigative steps taken, and every citation returned |
| **Temporal adjacency** | Two events falling within a defined correlation window of one another. The window value is not ratified — **Q-R-19** |
| **Contradicting evidence** | Two or more events asserting mutually exclusive facts about the same entity over overlapping time — an account authenticating interactively from two hosts at one moment, a file deleted before it was created, a process exiting before its child starts. Which contradictions are detectable is a design matter (**Q-D-07**); that they must be reported is R-COR-09 |
| **Citation support** | A citation supports a statement when the cited event contains the field values the statement asserts. A statement spanning several events is supported only when every asserted value appears in at least one cited event |
| **Ambiguous resolution** | An entity resolution returning more than one candidate (R-ENT-02) |

---

## 5. The output contract

This section defines the shape of everything the system asserts. It is a requirement, not a
design: the mechanism for producing and validating it belongs in `design.md`.

### 5.1 Claim taxonomy

Every statement the system makes is exactly one of two classes.

| Class | Definition | Must carry | Must not carry |
|---|---|---|---|
| **Observation** | Directly recorded in ≥1 event | ≥1 citation | Likelihood or confidence markers → **Q-R-02** |
| **Inference** | Derived by correlating ≥2 observations, or by reasoning over absence | ≥1 citation, a likelihood term, a confidence level, and the **name of the correlation rule applied** | — |

The proposal is that observations carry no estimative language, because they are not estimates:
"`EVT-0238` records a 2,473,829,122-byte upload to bucket `ext-drop-xf9q2`" is a line in a log,
not a judgement, and prefixing it with "almost certainly" would be false precision. **This is
not ratified — see Q-R-02.**

### 5.2 Two axes of uncertainty → **Q-R-01**, **Q-R-03**

The proposed model follows [ICD 203](https://github.com/wesinator/ICD203-intel-analysis):
likelihood and confidence are separate and are never combined in one sentence.

- **Likelihood** — how probable the proposition is. Controlled vocabulary:
  `almost no chance` (01–05%), `very unlikely` (05–20%), `unlikely` (20–45%),
  `roughly even chance` (45–55%), `likely` (55–80%), `very likely` (80–95%),
  `almost certainly` (95–99%).
- **Confidence** — how sound the evidence and reasoning are. Assigned **mechanically** from
  corroboration structure, never by a language model:

| Confidence | Assigned when |
|---|---|
| **High** | ≥2 independent source types corroborate, and no contradicting evidence (§4) exists |
| **Moderate** | A single source type (any number of events), or a required entity resolution had exactly one candidate |
| **Low** | The inference depends on absence of evidence, **or** on an entity resolution with >1 candidate, **or** on a single event |

The documented fallback, should this prove too much machinery for the schedule, is the same
two-class taxonomy with a three-tier scale (`Confirmed`/`Probable`/`Unconfirmed`) and no
percentage bands: the two-axis separation survives and the vocabulary simplifies. **Neither the
vocabulary (Q-R-01) nor the corroboration thresholds (Q-R-03) are ratified.**

### 5.3 Worked examples from this dataset

Normative once §5.2 is ratified: the system's output for these five claims is checked against
this table.

| Claim | Class | Corroborating source types | Likelihood | Confidence |
|---|---|---|---|---|
| Lateral movement to `FILE-SRV-02` | Inference | network + endpoint | `almost certainly` | **High** |
| C2 channel to `185.220.101.45` | Inference | network only | `very likely` | **Moderate** |
| 2.3 GB exfiltrated to an external bucket | Inference | cloud_storage only | `almost certainly` | **Moderate** (single-sourced) |
| Initial access via malicious document attachment | Inference | endpoint only; no mail source exists | `likely` | **Low** |
| Attacker evicted after 20:08:11 | Inference | absence of evidence | *not asserted* | **Low** — reported as undetermined |

The last two rows are the point of the whole scheme. A naive system states the phishing vector
flatly and declares the attack over at 20:08. Both are overclaims, and both are caught here by
rules that downgrade absence-based and single-source reasoning automatically rather than relying
on a model's modesty.

### 5.4 Contract enforcement — `R-CLM`

The sections above describe the contract; these requirements make it testable.

- **R-CLM-01** The system SHALL classify every statement it asserts as either an observation or an
  inference, per §5.1.
- **R-CLM-02** WHEN the system asserts an inference, it SHALL attach a likelihood term drawn from the
  controlled vocabulary in §5.2, a confidence level, and ≥1 citation.
- **R-CLM-03** WHEN the system asserts an inference, it SHALL name the correlation rule that produced
  it, so that the chain from raw event → rule → inference → rendered prose is inspectable at every
  link.
- **R-CLM-04** The system SHALL derive confidence levels mechanically from the corroboration rules in
  §5.2, and SHALL NOT permit a language model to assign or alter a confidence level.
- **R-CLM-05** IF the system asserts an observation, THEN it SHALL NOT attach a likelihood term or a
  confidence level to it. → **Q-R-02**

---

## 6. Functional requirements

### 6.1 Ingest and normalisation — `R-ING`

- **R-ING-01** The system SHALL load every event in the `events` array of the source dataset and
  SHALL report the count loaded per `source_type`.
- **R-ING-02** The system SHALL retain each source event verbatim and retrievable by `event_id`,
  so that any citation can be expanded to the original record.
- **R-ING-03** The system SHALL normalise every event to a common representation exposing at
  minimum: `event_id`, `source_type`, `event_name`, a UTC timestamp, and the set of entities the
  event references.
- **R-ING-04** WHEN normalising an event, the system SHALL preserve every source field, including
  fields with no place in the common representation.
- **R-ING-05** IF an event lacks a field expected for its `source_type`, THEN the system SHALL
  ingest the event, SHALL record which expected fields were absent, and SHALL NOT discard it.
- **R-ING-06** The system SHALL parse timestamps of differing precision into a single ordered
  time base.
- **R-ING-07** The system SHALL classify every IP address as internal or external using the
  subnets declared in the dataset `metadata`, and SHALL NOT hardcode a subnet list independently
  of that metadata.
- **R-ING-08** IF the source dataset cannot be parsed, or does not contain the expected top-level
  structure, THEN the system SHALL abort with a diagnostic naming the failure and SHALL NOT emit a
  partial reconstruction.
- **R-ING-09** The system SHALL treat the source dataset as read-only and SHALL NOT modify it.
- **R-ING-10** WHEN two events carry identical timestamps, the system SHALL apply a documented,
  deterministic tie-break that does not depend on `event_id` ordinal value (R-UB-13).

### 6.2 Entity resolution — `R-ENT`

- **R-ENT-01** The system SHALL derive an IP-to-hostname mapping from events that contain both an
  IP address and a hostname.
- **R-ENT-02** WHEN an IP address resolves to more than one hostname, the system SHALL return all
  candidates and SHALL mark the resolution **ambiguous**.
- **R-ENT-03** IF a network event's IP address cannot be resolved to any hostname, THEN the system
  SHALL retain the event with the IP as the entity identifier and SHALL NOT infer a hostname.
- **R-ENT-04** WHERE an inference depends on an ambiguous resolution, the system SHALL assign that
  inference **Low** confidence per §5.2.

> Rationale: 80 of 84 network events carry no `src_host` and 83 carry no `dst_host`, so
> network-to-host correlation must pass through this mapping — and the mapping is genuinely
> unreliable in this dataset (`10.0.3.78` resolves to two different workstations). A resolver
> that returns one confident answer would be lying.

### 6.3 Correlation and timeline reconstruction — `R-COR`

- **R-COR-01** The system SHALL produce a single timeline of attack-attributed activity ordered by
  timestamp ascending.
- **R-COR-02** Every timeline entry SHALL cite ≥1 `event_id`.
- **R-COR-03** The system SHALL correlate events across source types using at minimum: shared
  account, shared host, shared IP address (subject to R-ENT-02), process lineage
  (`parent_process` → `process_name`), exact equality of file name **and** file size, and
  temporal adjacency as defined in §4. → **Q-R-19** (correlation window unratified)
- **R-COR-04** WHEN an `endpoint` file-creation event and a `cloud_storage` upload event share both
  file name and file size exactly, the system SHALL emit a staged-then-exfiltrated correlation
  linking the two events.
- **R-COR-05** The system SHALL determine, for each attack phase defined in §4, whether it is
  observed, and SHALL cite the evidence where it is.
- **R-COR-06** IF no ingested event evidences a given attack phase, THEN the system SHALL report
  that phase as **not observed** rather than omitting it from the output.
- **R-COR-07** The system SHALL report the first and last observed attack-attributed activity with
  citations.
- **R-COR-08** WHEN privilege level changes across the timeline, the system SHALL attribute the
  change to the mechanism evidenced by events, and SHALL NOT assert an exploitation or bypass
  mechanism that no event evidences.
- **R-COR-09** IF two or more ingested events support mutually incompatible conclusions, THEN the
  system SHALL report the conflict, cite every event involved, and SHALL NOT silently prefer one.
  → **Q-R-17**
- **R-COR-10** The system SHALL record every event it evaluated as potentially attack-related and
  did not attribute to the attack, together with the reason for rejection. → **Q-R-16**

> R-COR-06 is what separates "not present in the environment" from "not looked for" — the
> distinction the previous tool collapsed when it missed lateral movement. R-COR-08 exists because
> this intrusion escalates `medium → high → SYSTEM` entirely through stolen credentials and service
> execution; there is no exploit event, and a system asked for "privilege escalation" will
> otherwise invent one. R-COR-10 exists because the dataset is deliberately baited — 14 scattered
> authentication failures, benign outbound SSH, benign file-sharing — and an analyst's trust
> depends on seeing what was dismissed, not only what was flagged.

### 6.4 MITRE ATT&CK enrichment — `R-ATK`

- **R-ATK-01** The system SHALL map each attack-attributed timeline entry to zero or more ATT&CK
  Enterprise techniques, each identified by **technique ID and official technique name**.
- **R-ATK-02** WHEN asserting a technique, the system SHALL cite the `event_id`(s) evidencing it and
  SHALL state the observable that triggered the mapping.
- **R-ATK-03** The system SHALL obtain technique IDs and names from the MITRE ATT&CK Enterprise
  catalogue, and SHALL NOT rely on a language model's recollection of them.
- **R-ATK-04** IF an asserted technique ID is absent from the catalogue, THEN the system SHALL reject
  the assertion and SHALL report a mapping failure.
- **R-ATK-05** IF an observed behaviour has no technique that its evidence supports, THEN the system
  SHALL report the behaviour as **unmapped** rather than assigning the nearest-matching technique.
- **R-ATK-06** The system SHALL associate each asserted technique with its ATT&CK tactic.
- **R-ATK-07** The system SHALL record the version of the ATT&CK catalogue in use and SHALL include
  it in every output that asserts techniques.

> R-ATK-07 is a traceability requirement, not bookkeeping: technique IDs are deprecated, renamed
> and re-parented between ATT&CK releases. A mapping handed to a legal team is meaningless without
> the catalogue version it was made against.

### 6.5 Blast radius — `R-BLR`

- **R-BLR-01** The system SHALL enumerate every host with ≥1 attack-attributed event, each with
  first-observed and last-observed timestamps and citations.
- **R-BLR-02** The system SHALL enumerate every account used in attack-attributed activity, with
  citations.
- **R-BLR-03** The system SHALL distinguish **confirmed compromised** from **involved but not
  confirmed**, and SHALL state the rule used to separate them.
- **R-BLR-04** The system SHALL report every data asset observed to be accessed, collected or
  exfiltrated, with volume where the logs record it, and citations.
- **R-BLR-05** The system SHALL report which hosts and accounts it **cannot rule out**, and why.

### 6.6 Coverage gap analysis — `R-GAP`

- **R-GAP-01** The system SHALL report which log source types would be required to answer questions
  it could not answer, and which of those are absent from the dataset.
- **R-GAP-02** WHEN a claim rests on a single source type, the system SHALL label it
  **single-sourced**.
- **R-GAP-03** The system SHALL report hosts that appear in the incident but have no endpoint
  telemetry.
- **R-GAP-04** The system SHALL state, for each identified gap, which specific conclusion it limits.
- **R-GAP-05** The system SHALL report coverage gaps **unprompted** as part of the reconstruction,
  not only when a user asks about them.

> R-GAP-05 matters: gaps that surface only on request are gaps the CISO will not know to ask about.

### 6.7 Question answering — `R-QRY`

- **R-QRY-01** The system SHALL accept free-form natural-language questions about the incident.
- **R-QRY-02** Every factual statement in an answer SHALL carry ≥1 citation.
- **R-QRY-03** IF a question cannot be answered from the ingested events, THEN the system SHALL state
  that it cannot, and SHALL name the data that would be required.
- **R-QRY-04** The system SHALL answer each of the ten queries in §9 to the acceptance criteria
  stated there.
- **R-QRY-05** WHEN asked what actions to take, the system SHALL tie each recommended action to
  specific evidenced compromise and SHALL label it as short-term containment, eradication or
  recovery, per NIST SP 800-61r3.
- **R-QRY-06** WHEN asked for an executive summary, the system SHALL produce one whose every
  assertion is traceable to the reconstruction, within the length the user requested.
- **R-QRY-07** The system SHALL answer a question about the incident within 60 seconds.
  → **Q-R-04** (threshold unratified)
- **R-QRY-08** WHEN asked about a specific entity — an account, host, IP address, file or bucket —
  the system SHALL return every attack-attributed event referencing that entity, with citations.
- **R-QRY-09** WHEN a question scopes a time range, the system SHALL restrict its answer to events
  within that range and SHALL state the range it applied.
- **R-QRY-10** WHEN a question refers to the preceding exchange, the system SHALL resolve the
  reference against the conversation and SHALL state what it resolved it to. → **Q-R-09**

> R-QRY-08 is the analyst's actual working motion: pivot on an entity, see everything touching it.
> R-QRY-10 is how follow-up questions work at all ("and what about that host?"), but whether
> conversational memory is in scope is unratified.

### 6.8 Interface — `R-UI`

- **R-UI-01** The system SHALL present a conversational interface in which a user asks questions and
  receives answers with their citations.
- **R-UI-02** WHEN a citation is displayed, the user SHALL be able to view the complete raw source
  event without leaving the interface.
- **R-UI-03** The system SHALL present the reconstructed timeline with per-entry techniques,
  citations and confidence.
- **R-UI-04** The system SHALL present the blast radius and the coverage gaps as first-class views,
  reachable without asking a question.
- **R-UI-05** WHILE an answer is being generated, the system SHALL display the investigative steps
  taken, including which tools were invoked.
- **R-UI-06** WHEN displaying any timestamp, the system SHALL include an explicit timezone
  designator. → **Q-R-13**

> R-UI-05 is a trust requirement, not a progress indicator: an analyst who can see the steps can
> judge whether the reasoning was sound.

### 6.9 Reporting and handover — `R-RPT` → **Q-R-08**

The assignment's framing is that the output goes to a board and a legal team. That implies a
handover artifact rather than a screen. Whether one is in scope, and in what form, is unratified.

- **R-RPT-01** The system SHALL produce a self-contained report of the reconstruction containing the
  timeline, the asserted techniques, the blast radius, the coverage gaps, and every citation.
- **R-RPT-02** The report SHALL state the dataset identifier, the ATT&CK catalogue version
  (R-ATK-07), the software version, and the time of generation.
- **R-RPT-03** The report SHALL be readable without access to the running system.

### 6.10 Validation harness — `R-VAL`

- **R-VAL-01** The harness SHALL score the system's attack-event identification against the dataset's
  `note` annotations as ground truth, reporting precision and recall overall and per attack phase.
- **R-VAL-02** The harness SHALL score asserted ATT&CK techniques against the ground-truth technique
  set, reporting which were missed and which were asserted without ground-truth support.
- **R-VAL-03** The harness SHALL verify that every citation in every generated answer resolves to an
  event present in the dataset.
- **R-VAL-04** The harness SHALL verify **leak independence**: given a dataset variant in which the
  `note` field is stripped, `event_id` values are reassigned in random order, and timestamp
  sub-second precision is randomised, the set of attack-attributed events, the order of the
  reconstructed timeline, and the set of asserted techniques SHALL all be unchanged.
- **R-VAL-05** The harness SHALL verify that no rendered sentence contains both a likelihood term
  and a confidence term (§5.2).
- **R-VAL-06** WHERE the `note` field is read, it SHALL be read only by the validation harness.
- **R-VAL-07** The harness SHALL verify that every requirement in §6 and §7 is exercised by at least
  one automated test or a documented manual procedure, and SHALL report any that is not.

> R-VAL-04 is the single most valuable test in this document. It is the only way to *prove* rather
> than assert that the reconstruction came from investigative reasoning.

---

## 7. Unwanted behaviour requirements

EARS Unwanted Behaviour clauses. These are the anti-fabrication requirements and they take
precedence over every requirement in §6: **a suppressed answer is preferable to an uncited one.**

### 7.1 Fabrication and citation integrity — `R-UB`

- **R-UB-01** IF a generated answer contains a factual statement with no citation, THEN the system
  SHALL withhold the answer and SHALL report which statement failed.
- **R-UB-02** IF a citation references an `event_id` not present in the dataset, THEN the system SHALL
  withhold the answer and SHALL report a citation-integrity failure.
- **R-UB-03** IF a citation references a real event that does not support the statement made, in the
  sense defined by **citation support** in §4, THEN the system SHALL treat this as a
  citation-integrity failure.
- **R-UB-04** IF the evidence required for a conclusion is absent, THEN the system SHALL state the
  limitation explicitly and SHALL NOT substitute inference for the missing evidence.
- **R-UB-05** IF a rendered sentence would contain both a likelihood term and a confidence level,
  THEN the system SHALL reject that rendering.

### 7.2 Dataset-specific honesty requirements — `R-UB`

Each of these encodes a known gap in this dataset where a fluent model will otherwise confabulate.

- **R-UB-06** IF asked about the phishing email itself — sender, subject, recipient or attachment name
  — THEN the system SHALL state that no email or mail-gateway source is present in the dataset, and
  SHALL NOT name any of them.
- **R-UB-07** IF asked to identify the command-and-control domain, THEN the system SHALL state that no
  DNS source is present and SHALL report only the IP address observed.
- **R-UB-08** IF asked whether the attacker was evicted or remains present, THEN the system SHALL
  report the last observed activity and state that eviction is **undetermined** from the available
  window.
- **R-UB-09** IF asked how the attacker's tooling reached a host where no file-creation event records
  it, THEN the system SHALL state that the transfer is inferred and name the event it is inferred
  from.
- **R-UB-10** IF asked whether dumped credentials were transmitted off the host, THEN the system SHALL
  state that no event records the dump being read or sent.

### 7.3 Leak prohibition — `R-UB`

The dataset reveals the answer three ways. Using any of them as detection signal invalidates the
prototype as a demonstration.

| Leak | Prohibition | Verified by |
|---|---|---|
| `note` field beginning `ATTACK:` | **R-UB-11** The system SHALL remove the `note` field from every event before that event is available to any ingest, correlation, enrichment or answer-generation step. | R-VAL-06 |
| Timestamp sub-second precision (all 22 attack events have whole-second timestamps; all 220 benign events carry microseconds) | **R-UB-12** The system SHALL NOT use timestamp sub-second precision as a discriminating feature. | R-VAL-04 |
| `event_id` ordinal value (attack events occupy the final 22 IDs, contiguously) | **R-UB-13** The system SHALL NOT use the ordinal value of `event_id` as a discriminating feature. | R-VAL-04, R-ING-10 |

---

## 8. Non-functional requirements — `R-NFR`

- **R-NFR-01 (Reproducibility)** Given identical input, the deterministic portion of the pipeline
  SHALL produce identical output across runs.
- **R-NFR-02 (Provenance)** Every derived artifact SHALL be traceable to the raw events it was
  derived from.
- **R-NFR-03 (Graceful degradation)** WHILE no language-model service is reachable, the system SHALL
  still produce the timeline, ATT&CK mapping, blast radius and coverage gaps.
- **R-NFR-04 (Latency — reconstruction)** The deterministic reconstruction SHALL complete within
  10 seconds on the provided dataset. → **Q-R-05** (threshold unratified)
- **R-NFR-05 (Inspectability)** Structured intermediate representations SHALL be persisted to disk in
  a human-readable form so that each pipeline stage can be examined independently.
- **R-NFR-06 (Bounded cost)** The number of language-model invocations per user question SHALL be
  bounded and reported.
- **R-NFR-07 (Reviewability)** Every source file SHALL stay within a stated line-count ceiling, and
  any file exceeding it SHALL be reported by the build. Proposed ceiling: 400 lines.
  → **Q-R-20** (ceiling unratified)
- **R-NFR-08 (Secrets)** Credentials SHALL be supplied by environment and SHALL NOT be committed.
- **R-NFR-09 (Startup)** The system SHALL start from a documented single command.
- **R-NFR-10 (Demo resilience)** The demonstrable path SHALL NOT depend on network access to any
  third-party service at demo time.
- **R-NFR-11 (Data egress)** The system SHALL document precisely what log content leaves the local
  machine, and SHALL NOT transmit log content to any third party other than as documented.
  → **Q-R-07**
- **R-NFR-12 (Chain of custody)** The system SHALL persist an answer record, containing every
  element enumerated in the §4 definition, for every answer it produces. → **Q-R-10**
- **R-NFR-13 (Testability)** Every requirement in §6 and §7 SHALL be verifiable by an automated test
  or a documented manual procedure (measured by R-VAL-07).
- **R-NFR-14 (Error transparency)** IF any pipeline stage fails, THEN the system SHALL report which
  stage failed and SHALL NOT present a partial reconstruction as though it were complete.
- **R-NFR-15 (Capacity)** The system's behaviour beyond the provided dataset size SHALL be stated:
  either a supported bound with evidence, or an explicit declaration that scale is untested.
  → **Q-R-11**
- **R-NFR-16 (Portability)** The platforms on which the system is supported SHALL be documented and
  verified on each. → **Q-R-12**
- **R-NFR-17 (Synthesis reproducibility)** The reproducibility expected of language-model-generated
  prose SHALL be stated, and the system SHALL meet whatever is stated. → **Q-R-14**
- **R-NFR-18 (Versioning)** Every output SHALL identify the software version that produced it.

### 8.1 Coverage against ISO/IEC 25010

Recorded so that the NFR set is demonstrably systematic rather than whatever came to mind.

| Quality characteristic | Covered by | Notes |
|---|---|---|
| Functional suitability | §6, §7, §9 | Acceptance suite is the measure |
| Performance efficiency — time behaviour | R-NFR-04, R-QRY-07 | Both thresholds unratified |
| Performance efficiency — capacity | R-NFR-15 | Scope of the claim is Q-R-11 |
| Performance efficiency — resource use | R-NFR-06 | Language-model cost only |
| Reliability — fault tolerance | R-NFR-03, R-NFR-14, R-ING-08 | |
| Reliability — maturity | R-NFR-01, R-NFR-17 | Deterministic core vs prose split |
| Reliability — recoverability | — | **Deliberate gap: §11, single-user prototype with no persistent state to recover** |
| Security — confidentiality | R-NFR-08, R-NFR-11 | Egress policy is Q-R-07 |
| Security — integrity | R-ING-09 | Source dataset is read-only |
| Security — accountability / non-repudiation | R-NFR-02, R-NFR-12, R-ATK-07, R-NFR-18 | The chain-of-custody group |
| Security — authenticity | — | **Deliberate cut: §11, no authentication** |
| Maintainability — modularity | R-NFR-07 | |
| Maintainability — analysability | R-NFR-05, R-CLM-03 | Rule naming is what makes reasoning analysable |
| Maintainability — testability | R-NFR-13, R-VAL-07 | |
| Portability — installability | R-NFR-09, R-NFR-16 | Platform set is Q-R-12 |
| Portability — adaptability | — | **Deferred: additional source types are a design property, Q-D-01, not a requirement here** |
| Usability — operability | R-UI-01..06 | |
| Usability — error protection | R-UB-01..05, R-NFR-14 | |
| Usability — accessibility | — | **Deliberate cut: §11** |
| Compatibility — interoperability | R-RPT-01..03, Q-D-04 | Handover format is Q-R-08 |

---

## 9. Acceptance criteria — the ten queries

The assignment supplies ten queries. They are adopted verbatim as the acceptance suite. Each must
pass **both** its specific criteria below **and** the universal criteria.

**Universal criteria (every query):** every factual statement carries ≥1 resolvable citation
(R-QRY-02, R-UB-01, R-UB-02); no leak field influenced the answer (R-UB-11..13); confidence and
likelihood are not mixed in a sentence (R-UB-05); the answer is produced within the R-QRY-07
threshold.

| # | Query | Specific acceptance criteria |
|---|---|---|
| **AC-01** | "Walk me through the full attack timeline from initial access to last observed activity." | Chronologically ordered; covers initial access, execution, C2, credential access, discovery, lateral movement, collection, exfiltration and defence evasion; identifies the correct first and last observed activity with citations; every entry cited |
| **AC-02** | "What was the initial access vector and what evidence supports that conclusion?" | Names the document-application-spawning-shell process lineage as the evidence, cites the event; **states that no email or mail-gateway source exists** and does not name a sender, subject or attachment (R-UB-06); assigns Low confidence per §5.3 |
| **AC-03** | "Which MITRE ATT&CK techniques did the attacker use? List them with technique IDs." | Each technique given as ID + official name + tactic + citation; catalogue version stated (R-ATK-07); recall ≥ 80% of the ground-truth technique set (R-VAL-02); **no privilege-escalation exploitation technique asserted** (R-COR-08); any unmapped behaviour reported as unmapped |
| **AC-04** | "Which user accounts were compromised or used by the attacker?" | Identifies the single compromised account with citations; separates confirmed-compromised from merely-observed (R-BLR-03); states that the account has no benign baseline activity in the window |
| **AC-05** | "Which internal hosts did the attacker move to after the initial foothold?" | Identifies both post-foothold hosts in order with citations; names the authentication event and the service-execution event that evidence the movement; **does not rely on the IP-to-host mapping without flagging it** where used (R-ENT-02) |
| **AC-06** | "Is there evidence of data exfiltration? If so, what was accessed and when?" | Answers yes; names file, exact byte count, destination bucket, external ownership, client, timestamp; **cites the two events that join on exact name-and-size equality** (R-COR-04); labels the claim single-sourced and states that no firewall record corroborates the egress (R-GAP-02) |
| **AC-07** | "What is the blast radius — list every affected host and account." | Complete host and account enumeration with first/last observed and citations; names the data asset and volume; states what cannot be ruled out (R-BLR-05), including hosts with no endpoint telemetry (R-GAP-03) |
| **AC-08** | "Where are the gaps in our log coverage that limit your confidence in this reconstruction?" | Reports the absence of a mail source and a DNS source; reports the uncorroborated egress; reports uneven endpoint coverage; reports the unobserved tool transfer and the unobserved credential exfiltration; ties each gap to the specific conclusion it limits (R-GAP-04) |
| **AC-09** | "Give me a 3-sentence executive summary suitable for a board briefing." | Exactly three sentences; every assertion traceable to the reconstruction; states residual uncertainty; contains no claim the evidence does not support |
| **AC-10** | "What should the incident response team do in the next 2 hours to contain this?" | Each action tied to specific evidenced compromise with citation; each labelled short-term containment / eradication / recovery (R-QRY-05); prioritised; includes at least one action addressing a coverage gap rather than only the confirmed chain |

### 9.1 Quantitative gates → **Q-R-06** (all thresholds unratified)

Measured by the harness (§6.10) against the `note` ground truth.

| Metric | Must | Should |
|---|---|---|
| Attack-event recall | ≥ 0.80 | 1.00 |
| Attack-event precision | ≥ 0.70 | ≥ 0.85 |
| ATT&CK technique recall | ≥ 0.80 | 1.00 |
| Citation resolution rate | 1.00 | 1.00 |
| Leak-independence (R-VAL-04) | pass | pass |
| Requirements exercised by a test (R-VAL-07) | 1.00 | 1.00 |

Citation resolution must be **exactly** 1.00. A single unresolvable citation is a correctness
failure, not a quality metric. The same applies to R-VAL-07: a requirement with no test is an
untested requirement, not a lower-quality one.

---

## 10. Priorities → **Q-R-15** (allocation unratified)

MoSCoW against the stated **3–5 day** budget with Claude API access available.

### Must

Claim contract enforcement (`R-CLM-01..05`) · ingest and normalisation (`R-ING-01..10`) · entity
resolution with ambiguity (`R-ENT-01..04`) · correlation and timeline (`R-COR-01..08`) · ATT&CK
mapping from the real catalogue (`R-ATK-01..07`) · blast radius (`R-BLR-01..05`) · gap analysis
(`R-GAP-01..05`) · question answering (`R-QRY-01..07`) · all unwanted behaviour requirements
(`R-UB-01..13`) · validation harness (`R-VAL-01..07`) · conversational interface with expandable
citations and timeline view (`R-UI-01..03`) · `R-NFR-01..05`, `R-NFR-08..11`, `R-NFR-13..14`,
`R-NFR-18`.

### Should

Blast radius and coverage gaps as first-class views (`R-UI-04`) · visible investigative steps
(`R-UI-05`) · explicit timezone display (`R-UI-06`) · entity pivot (`R-QRY-08`) · time-range
scoping (`R-QRY-09`) · conflicting-evidence reporting (`R-COR-09`) · handover report
(`R-RPT-01..03`) · chain of custody (`R-NFR-12`) · bounded-cost reporting (`R-NFR-06`) · stated
capacity and portability (`R-NFR-15..17`).

### Could

Considered-and-rejected event log (`R-COR-10`) · conversational memory (`R-QRY-10`) · export in
MITRE Attack Flow form · ATT&CK Navigator layer output · confidence calibration measured against
ground truth.

### Won't (this iteration)

See §11.

---

## 11. Explicit scope cuts

The assignment states that thoughtful cuts, declared plainly, beat silent incompleteness.

| Cut | Rationale |
|---|---|
| **No support for datasets other than the provided one** | Generality is untested and would be a claim we cannot back. Ingest extensibility is a design property to argue in `design.md` (Q-D-01), not a requirement to test here |
| **No real-time or streaming ingest** | The assignment provides a fixed 72-hour export. Streaming would consume the budget that correlation quality needs |
| **No multi-incident support** | One incident (`INC-2026-0610-001`). Incident scoping is a different product |
| **No authentication or multi-user state** | A prototype for one analyst at one desk. Covers the 25010 authenticity gap in §8.1 |
| **No recoverability guarantees** | No persistent mutable state exists to recover; the source dataset is read-only (R-ING-09) |
| **No accessibility conformance** | Not evaluated by the assignment, and a conformance claim would take budget from correlation quality. Stated rather than silently skipped |
| **No threat-intelligence enrichment of external indicators** | Reputation lookup for the C2 address would require a live third-party service, violating R-NFR-10, and the conclusion does not depend on it |
| **No detection-rule authoring or Sigma output** | Downstream of investigation; out of the assignment's stated scope |
| **No automated containment actions** | The system recommends; a human acts. Acting on a possibly-wrong reconstruction is the failure mode this whole document guards against |
| **No behavioural baselining or anomaly scoring** | The compromised account has zero benign activity in the window, so no baseline can be computed for it. Building the machinery would demonstrate nothing on this data |

---

## 12. Open questions

Nothing below has been decided. Requirements that depend on these carry a `→ Q-…` pointer.

### 12.1 Requirements-level — these block Phase 1 sign-off

| # | Question | Affects | Proposed |
|---|---|---|---|
| **Q-R-01** | Two-axis ICD 203 likelihood + confidence, or the three-tier `Confirmed`/`Probable`/`Unconfirmed` fallback? | §5.2, R-CLM-02, R-VAL-05 | Two-axis |
| **Q-R-02** | Do observations carry no uncertainty marker at all, or should every line carry one for visual consistency? | §5.1, R-CLM-05 | No marker on observations |
| **Q-R-03** | Are the High/Moderate/Low corroboration rules defensible as written? Specifically: is "single source type" always Moderate, even when it is a direct audit-log record of the act itself? | §5.2 | As written |
| **Q-R-04** | What is the acceptable ceiling on answering one question? | R-QRY-07 | 60 s |
| **Q-R-05** | What is the acceptable ceiling on the deterministic reconstruction? | R-NFR-04 | 10 s |
| **Q-R-06** | Are the quantitative gates set at defensible levels, and is precision ≥ 0.70 too lenient given a baited dataset? | §9.1 | recall ≥ 0.80, precision ≥ 0.70 |
| **Q-R-07** | May raw log content be transmitted to a third-party language-model API? The client is a healthcare organisation; the dataset is synthetic. Does the prototype need a redaction boundary, or is unredacted egress acceptable if documented? | R-NFR-11, and the whole trust discussion | Unresolved — has architectural consequences |
| **Q-R-08** | Is a handover report artifact in scope, and in what form? The assignment's framing is a board and a legal team, who do not operate a chat UI | §6.9 `R-RPT-01..03` | In scope, form undecided |
| **Q-R-09** | Does the interface need conversational memory for follow-up questions, or is each question standalone? | R-QRY-10 | Could-have |
| **Q-R-10** | Must the system persist a chain-of-custody record of its own reasoning, or is on-screen transparency (R-UI-05) sufficient? | R-NFR-12 | Should-have |
| **Q-R-11** | Is any behaviour beyond 242 events in scope, or is scale explicitly declared untested? | R-NFR-15 | Declare untested |
| **Q-R-12** | Which platforms must this run on? Windows is the development machine; the interviewer's is unknown | R-NFR-09, R-NFR-16 | Unresolved |
| **Q-R-13** | Display timestamps in UTC only, or offer local time? The dataset is entirely UTC | R-UI-06 | UTC with explicit designator |
| **Q-R-14** | Must language-model prose be reproducible run to run, or is variability acceptable provided the underlying claims are stable? | R-NFR-17, R-NFR-01 | Unresolved |
| **Q-R-15** | Is the MoSCoW allocation in §10 right? In particular: are `R-UI-04`, `R-UI-05` and `R-NFR-12` correctly Should rather than Must? | §10 | As written |
| **Q-R-16** | Should the system surface the suspicious-but-benign events it considered and dismissed? It builds analyst trust; it also adds noise | R-COR-10 | Could-have |
| **Q-R-17** | When two events support incompatible conclusions, report both with reduced confidence, or decline to conclude? | R-COR-09 | Report both |
| **Q-R-18** | Are assignment deliverables 2 (walkthrough) and 3 (trust / agentic-design / product discussion) produced as repository artifacts in `docs/writeup/` and `docs/architecture/`, or prepared separately outside this spec? Both are graded | §3.8 | Repository artifacts — they reuse §11 and §12.2 directly |
| **Q-R-19** | What correlation window defines temporal adjacency? Too wide and unrelated background events join the chain; too narrow and the 3-hour gap between staging and upload breaks the exfiltration correlation. The attack's own inter-event gaps range from 2 seconds to 2h27m | §4, R-COR-03 | Unresolved — needs a value, or a per-rule window rather than one global figure |
| **Q-R-20** | What per-file line-count ceiling, and is a build-time check worth the setup at this scale? | R-NFR-07 | 400 lines |

### 12.2 Design-level — deferred to Phase 2, not blocking

These are mechanism. Recorded here so they are not lost.

| # | Question |
|---|---|
| **Q-D-01** | Ingest generality: hand-written parsers for four known schemas, declarative field mapping, or mapping to OCSF or ECS classes |
| **Q-D-02** | Where reasoning lives — how much is deterministic code, how much is agent reasoning, and where the boundary sits. Relevant evidence: extractive question answering hallucinates on 3–8% of responses; multi-step agent tool-call chains on 20–40%. To be argued, not assumed |
| **Q-D-03** | ATT&CK catalogue access: full STIX feed, MITRE's `mitreattack-python`, or a curated locally-cached subset. Constrained by R-NFR-10 |
| **Q-D-04** | Timeline representation: adopt the MITRE Attack Flow object model internally, or only as an export format |
| **Q-D-05** | Correlation data structure: at 242 events a graph library may be over-engineering. To be decided explicitly rather than by reflex |
| **Q-D-06** | UI framework, constrained by R-UI-02 and R-UI-05 |
| **Q-D-07** | How citation validation is implemented, and at which layer it sits |
| **Q-D-08** | How the agent's tool surface is defined and bounded |

---

## 13. Traceability to the assignment

| Assignment requirement | Requirements satisfying it |
|---|---|
| Multi-source log correlation | `R-ING-01..10`, `R-ENT-01..04`, `R-COR-03..04` |
| Attack timeline reconstruction | `R-COR-01..10`, `R-UI-03`, `AC-01` |
| MITRE ATT&CK TTP mapping with cited technique IDs | `R-ATK-01..07`, `AC-03` |
| Blast radius assessment | `R-BLR-01..05`, `AC-07` |
| Flag gaps and uncertainty | `R-GAP-01..05`, `R-CLM-01..05`, `R-UB-04..10`, `AC-08` |
| Full traceability — cite source, timestamp, event ID | `R-ING-02`, `R-QRY-02`, `R-UB-01..03`, `R-VAL-03`, `R-UI-02`, `R-NFR-02` |
| Prefer honest non-confirmation over fabrication | §1.2, `R-UB-04..10`, `AC-02`, `AC-06` |
| Demonstrate an agentic workflow | `R-QRY-01`, `R-QRY-08..10`, `R-UI-05`, `R-NFR-05..06`, and `Q-D-02` |
| Structured intermediate representations | `R-NFR-05`, `R-ING-03..04` |
| Verification passes | `R-UB-01..05`, `R-VAL-01..07` |
| Hand output to a board and a legal team | `R-RPT-01..03`, `R-NFR-12`, `R-ATK-07`, `R-NFR-18`, `AC-09` |
| Explicit scope reductions | §11 |

---

## 14. Review

Phase 1 is complete when **all 20 questions in §12.1 are answered** and the reviewer confirms:

- [ ] The success criteria in §1.1 are the right criteria
- [ ] The system boundary in §3.1 draws the line in the right place
- [ ] Retaining all four source types (§3.2) is the right scope decision
- [ ] The seven assumptions in §3.5 are acceptable, particularly A-04 (no clock skew) and A-05 (the export is complete for the sources present) — both unverifiable from inside the dataset
- [ ] The constraints in §3.7 are complete and correct
- [ ] The claim taxonomy in §5.1 and the uncertainty model in §5.2 are ratified or corrected
- [ ] The acceptance criteria in §9 are what the system should be judged against
- [ ] The quantitative gates in §9.1 are set at defensible levels
- [ ] The MoSCoW allocation in §10 is right
- [ ] The scope cuts in §11 are the right cuts, including the four 25010 gaps in §8.1
- [ ] Nothing in §12.2 was decided here by accident
