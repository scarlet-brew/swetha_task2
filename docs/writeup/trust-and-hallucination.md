# Trust and hallucination

*Written for: the Deloitte Cyber Engineering interview panel.*

The bar in the brief is a legal one: *can the CISO hand this to their board and
legal team with confidence?* That is not a question about accuracy. A document
can be accurate and still unusable in front of counsel if nobody can say where
each sentence came from. So the design target was never "make the model reliable"
— it was **make the system's conclusions checkable without trusting the model at
all.**

## The architecture, in one sentence

An untrusted generator proposes; a small deterministic kernel accepts or rejects;
nothing reaches an output that the kernel did not accept.

This is the LLM-Modulo pattern (Kambhampati et al., ICML 2024) and, older, the
de Bruijn criterion from proof assistants: an arbitrarily clever tactic over a
tiny trusted core. The generator supplies **completeness** — it finds
relationships a fixed rule set would not. The kernel supplies **soundness**. The
two properties are bought separately, which is what lets the generator be
replaced, retried or distrusted without weakening the guarantee.

## Where the model is, and where it deliberately is not

Four contracts across three stages. Everything else is deterministic code.

| Stage | Model? | Why |
|---|---|---|
| 1 Ingest | no | Loading records is not a judgement. |
| 2 Parse | no | Normalisation is a closed registry of six pure transforms. |
| 3 Correlate — factual layer | **no** | Ten atomic relations. This is the important one; see below. |
| 3 Correlate — interpretive layer | yes | `interpret`, `hypothesise`. |
| 4 Enrich | yes, constrained | Selection from a retrieved enum. |
| 5 Synthesise | no | Projections of a closed graph. |
| 6 Answer | yes, gated | Retrieval and rendering over frozen artifacts. |

**The boundary the whole design turns on:** the deterministic layer emits facts
and decides nothing; the model interprets facts and computes nothing.

The factual layer computes ten relations — `same_account`, `same_host`,
`same_address`, `same_file`, `same_size`, `process_parent`, `temporal_within`,
`flow_endpoint`, `session_bracket`, `address_resolves_to_host` — and **no
detection rules**. It links everything linkable, benign included. Two
consequences follow, and both matter:

- There is **no coverage ceiling**, because nothing is being detected. A rule
  engine can only find what someone encoded; this cannot miss a relationship for
  want of a rule.
- The model **cannot invent a relationship**. It can only interpret ones that
  factually hold. A fabricated link is not "caught" — it is unavailable.

There is deliberately no composite relation. `same_file ∧ same_size ∧ ordered`
is something the interpretive layer *observes*; bundling it into one relation
called `staged_then_uploaded` would both compute a link and call it
exfiltration. That is interpretation leaking into the deterministic layer, and it
is the reason an earlier design draft was discarded.

## What the kernel actually checks

Six checks, each producing a **specific diagnostic** rather than a boolean:

1. Every cited observation exists.
2. **Every cited edge re-evaluates to true** — recomputed from its relation
   function, never read from a cache of earlier conclusions.
3. **No invented identifier** — every identifier named in the statement appears
   in a cited observation. Cheap, total, and it catches the commonest
   fabrication mode.
4. The cited edges actually connect the cited observations, so a finding cannot
   cite five true edges about unrelated things.
5. Stage from a closed vocabulary; layer discipline; acyclicity; termination.
6. **At close only** — no two accepted findings mutually incompatible.

Check 6 is deferred on purpose: compatibility is a **set-level** property, so two
findings can each be individually valid and jointly inconsistent.

Plus five graph invariants, all machine-decidable: layer order, termination in
raw records, acyclicity, grounding, and normalisation reproducibility. The last
means re-applying a recorded transform to its recorded raw value must reproduce
the asserted value — so "this filename came from that path" is checkable rather
than trusted. All five hold on every build.

## Three places the design makes fabrication structurally impossible

Detection is weaker than impossibility, and where impossibility was available it
was taken.

**Technique ids.** Candidates are retrieved deterministically from the local
catalogue, and the model selects from a closed enum of exactly those ids. A
hallucinated technique is not representable in the request body. MITRE's own
TRAM needs no catalogue check at prediction time for the same reason — a
closed-label classifier cannot emit a label outside its set.

This one nearly failed silently, and finding out why was the single most
valuable measurement in the project. On `anthropic` 0.84.0 the SDK's schema
transform **discards `enum`**, folding it into the property description as
prose. A closed `Literal` therefore arrives at the API as a *hint*, the model
may emit anything, and validation raises only on the way back — which is
validate-then-reject, the posture this design explicitly rejects. The schema is
repaired and re-sent, and a test captures the real serialised request body to
prove the enum survives. Without that, the claim in the design document would
have been false rather than merely unproven.

**Confidence scores.** There is no field anywhere that a probability could go
in. R3.4 forbids them and the schemas have no slot; a scan over every emitted
contract checks for the shape of one. Support is instead **computed** from the
evidence structure — Corroborated / Single-sourced / Absence-based / Conflicted,
from the count of distinct source types behind a finding. A model-asserted
confidence would be an opinion wearing the clothes of a measurement.

**Answer-time invention.** No tool at stage 6 can create a node. The answer
stage retrieves, reasons and cites; every citation must resolve to a node that
already exists. And the pivot loophole is closed explicitly: **a claim that
attributes activity to the intrusion must cite at least one finding.**
Observation-only citations support facts — that a value appeared in a record —
not attributions. Without that rule, stage 6 could assemble an attribution from
raw observations and mint a conclusion the kernel never saw.

## What was tried and abandoned

**One large model call over all the observations, with a validator.** Discarded
because it undersells the problem. The brief's own list of the predecessor's
failures begins with *no correlation*, and correlation inside a single inference
has no answer to "how would you have caught the movement the last tool missed."

**Union of N independent proposal passes.** Discarded on a result rather than a
preference. Because the validator is deterministic, the
contract-satisfying-but-wrong region is a **fixed** subset of accept-space: it
does not average out and cannot be detected by cross-pass agreement. So expected
false positives are non-decreasing in N and **precision is monotone
non-increasing** (Stroebl, Kapoor & Narayanan, arXiv:2411.17501). The sharpest
way to put it: precision was being measured by the same artifact whose blind
spots define it. Replaced by **bounded back-prompt repair**, which uses the
rejection diagnostic instead of discarding it.

**Model-proposed correlation rules.** Discarded because it put interpretation
back inside the deterministic layer, reintroducing the coverage ceiling.

## A failure this design did not prevent, and what it teaches

Worth stating because it is the most instructive bug in the build, and none of
the six checks or five invariants would ever have caught it.

Asked whether data was exfiltrated, the system answered that a 2.47 GB archive
appeared in cloud storage with an identical byte count to a staged endpoint
file, and then added that *"neither record carries a username, hostname or
uploading principal"*. Both records carry `username: jdavis`. The upload record
also carries `source_host: FILE-SRV-02`, `bucket_owner: EXTERNAL` and
`user_agent: python-requests/2.28.1`. The answer was the opposite of the truth,
and it **understated** the strongest finding in the incident.

Nothing fabricated anything. Every claim cited a real observation, every edge
re-evaluated true, no identifier was invented. The finding cited the two
`file_size_bytes` observations that made `same_size` hold — correctly — and the
answer stage was shown only the cited fields. So it reasoned from *"this was not
cited"* to *"this is not in the data"*, which is invalid, and said so honestly.

The lesson generalises past this one bug: **a record is the atomic unit of
evidence.** Citing one of its fields does not make the others unknown. Any stage
that infers what exists from what was cited will produce confident, well-cited,
verifiable falsehoods — which is a more dangerous failure mode than an obvious
hallucination, because every mechanism designed to catch fabrication passes it.

The fix was to print the whole cited record wherever a stage reasons over
citations, and to offer the rest of a record alongside the relations in the
interpretive step. Both places had made the same mistake, and the class of error
is now visible in one place rather than two.

It is also a fair verdict on the test suite: 294 tests, and the bug was found by
a person reading the output and saying *"it is attributed to a user, right?"*

## The honest limits

**What none of this checks is whether an interpretation is apt.** A finding can
cite real observations, rest on real edges, name only real identifiers, pass
every check — and still conclude wrongly. That is the test oracle problem. It is
irreducible here, and it is stated rather than papered over.

**Reproducibility is replay reproducibility, not determinism.** Temperature 0 is
not determinism — batch invariance alone produces dozens of distinct outputs
from identical requests. So the claim made is narrower and actually true: *given
the committed trajectory, the contract-set hash and the validator version, every
validation verdict is bit-for-bit reproducible.* The interpretive step is an
untrusted, out-of-TCB component that affects **coverage only**. That is a
stronger guarantee than sampling control could give, and it is honest about
which part is not reproducible.

**The system is biased toward missing things.** Every design choice that
prevents fabrication also costs recall, and this is the error class the field is
criticised for not measuring. The rejection log and the unconfirmed-hypothesis
ledger are kept and surfaced precisely because they are the visible part of that
cost — a coverage backlog rather than noise.

**Single points of failure**, named: the relation set (a missing relation makes
links missing, and no downstream check can detect a link that was never
computed); the aptness of interpretation, unchecked by construction; and the
anchor set, mitigated by the fact that anchors order rather than filter.

## The leaks, and why they are refused

The dataset gives the answer away three times over, and each leak selects
*exactly* the 22 intrusion events:

| Leak | Measured |
|---|---|
| `note` field beginning `ATTACK:` | 22 of 242 records |
| whole-second timestamps | 22 of 242 — the other 220 carry microseconds |
| `event_id` ordering | `EVT-0221`–`EVT-0242`, the final 22, contiguous |

Any one of them scores 100% precision *and* 100% recall while demonstrating
nothing. `note` is stripped at the parse boundary, so no downstream stage can
read it — removal rather than a promise not to look. The other two cannot be
removed, so the anchors are tested against them: each leak's signal is destroyed
(timestamps flattened to whole seconds; ids reversed so the intrusion becomes the
*first* 22) and the review order recomputed. If the order is unchanged, the
anchors were not using it. That test runs on every build.

Anchors **order** the search and never filter it — the ranking is a permutation
of the input, never a subset, which is checked. R1.10 allows unusualness as
grounds for review and forbids it as evidence, and that distinction is
mechanical here rather than aspirational.
