# Design: Cyber Incident Investigation Intelligence

| | |
|---|---|
| **Phase** | 2 of Spec → Design → Tasks → Implement → Validate |
| **Status** | **Not started.** Blocked on Phase 1 sign-off — see [requirements.md §10](requirements.md) |
| **Created** | 2026-09-22 |

> **Nothing here is decided.** This file currently holds only the agenda: decisions that must be
> made in Phase 2, and the material carried over from Phase 1 that turned out to describe
> *mechanism* rather than requirement.
>
> Phase 2 may not begin until the 18 clarifications in `requirements.md` §10 are answered.
> Writing architecture before the requirements are ratified is the failure mode this process
> exists to prevent.

---

## 1. Agenda — decisions this document must make

Each carries the trade-off to argue, not a conclusion. Where research has already been done, it
is recorded so the argument starts from evidence.

### D-01 — How the four log formats are read

The four supplied source types share no common field naming and no join key. Options: parsers
written directly against the four known shapes; declarative field mapping expressed as
configuration; or mapping onto an industry schema such as the Open Cybersecurity Schema
Framework or the Elastic Common Schema.

Trade-off: the industry-schema route is defensible and standard, but spends the budget on
mapping tables rather than on the cross-referencing quality that is actually being evaluated.
Note also the documented failure mode of schema mapping — fields with no home in the target
schema get silently dropped — which is why `requirements.md` R2.3 requires original records to
survive unaltered.

Generality is explicitly *not* a requirement (`requirements.md` §9). If extensibility is argued
for here, it must be argued as a design property, not smuggled in as an obligation.

### D-02 — Where the reasoning lives

How much of the investigation is fixed logic and how much is model reasoning, and where the
boundary sits. This is the decision the evaluating panel will press hardest on, and the
assignment explicitly asks where AI was used **and where it was deliberately not**.

Evidence to argue from: published 2026 figures put hallucination at 3–8% of responses for
extractive question answering against supplied text, and 20–40% of chains for multi-step
agentic tool use. That asymmetry is an argument for keeping the investigative conclusions in
fixed logic and confining the model to rendering — but the assignment also asks for a
demonstrated agentic workflow, so a defensible split matters more than either extreme.

Constrained by `requirements.md` NFR-01 (same conclusions every run), NFR-02 (core findings
without any outside service), NFR-04 (what leaves the machine), NFR-12 (wording stability), and
by NC-09 and NC-12 once answered.

### D-03 — How the technique catalogue is obtained and retained

The published MITRE ATT&CK Enterprise catalogue is a large machine-readable graph. Options: the
full published feed; MITRE's own client library; or a locally retained subset covering the
techniques this intrusion evidences.

Constrained by NFR-02: the demonstrable path must not require an outside service to be
reachable. R4.4 requires the catalogue version to be reported, so whatever is chosen must
expose it.

### D-04 — How the reconstruction is represented internally

MITRE's Center for Threat-Informed Defense publishes **Attack Flow**, a data model for exactly
this output: an action representing a technique execution, an asset representing what it acted
on, a condition representing an outcome, and an operator joining alternative paths. Decision:
adopt it as the internal representation, adopt it only as an export format, or not at all.

Adopting it buys existing visualisation and a one-sentence answer to "why this representation".
It also imposes its vocabulary on everything upstream.

### D-05 — How activities are related to one another

At the volume of the supplied data, a graph library may be more machinery than the problem
needs. To be decided explicitly rather than by reflex.

**Carried over from Phase 1 as mechanism:** how close in time two activities must be before
proximity counts as evidence of relationship. This cannot be a single global figure — the
intrusion's own gaps between related activities range from **2 seconds** to **2 hours 27
minutes**. A window wide enough to relate the data staging to its removal will also pull in
unrelated background traffic; a window tight enough to be precise will break the single most
important relationship in the data. Per-relationship windows are the likely answer, and that is
a design decision, which is why it was removed from `requirements.md`.

### D-06 — How the analyst interacts with it

Constrained by `requirements.md` R2.2 (reach the underlying record without leaving what you are
reading) and R10.1 (see the steps while the answer is forming).

### D-07 — How a statement is checked against the records it cites

`requirements.md` R2.5 requires detecting that a cited record does not contain the values a
statement asserts. Mechanising that is the hardest single problem in this build. It also
governs R3.9 — which incompatibilities between records are detectable at all.

### D-08 — How the model's available actions are defined and bounded

Only relevant if D-02 places reasoning in a model with tools. Constrained by NFR-01 and R10.2
(a conclusion must identify the reasoning that produced it).

### D-09 — Source file size limit

**Carried over from Phase 1 as mechanism.** A per-file ceiling and whether a build-time check is
worth the setup at this scale. Was previously written as a requirement, which it is not: no user
or evaluator can observe it.

### D-10 — How structured intermediate results are made inspectable

`requirements.md` R7.4 requires the intermediate results of the investigation to be available
for inspection. The form — where they live, in what format, whether they persist between runs —
is a design decision.

---

## 2. What Phase 2 must produce

Per the process:

1. Two or three candidate architectures with their trade-offs argued, and a recommendation.
2. Component and data-flow diagrams, in `../architecture/`.
3. Resolution of every agenda item above, with reasoning recorded.
4. A build-versus-adopt comparison for each external capability, per the stated rule: identify
   the problem category, ask whether it is a solved problem, research what exists, compare
   building against adopting, and only then design something new.
5. Stress questions answered explicitly: what breaks at ten times the data volume, and where the
   single points of failure are.
6. The dependency list that `requirements.txt` will be regenerated from — it was deliberately
   removed in Phase 1 because an empty dependency file asserts nothing.

---

## 3. Traceability

Every design decision must name the requirement it serves. A decision serving no requirement is
either scope creep or a missing requirement — and if it is the latter, Phase 1 reopens rather
than the requirement being invented here.
