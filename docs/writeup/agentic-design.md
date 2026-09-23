# Agentic workflow design

*Written for: the Deloitte Cyber Engineering interview panel.*

## Why this is agentic rather than one large prompt

The brief names six stages — ingest, parse, correlate, enrich, synthesise,
answer — and separately lists the predecessor tool's three failures: *no
correlation across sources, no timeline reconstruction, no connection to known
attack techniques*. Those are exactly stages 3, 5 and 4. **The pipeline in the
brief is an inventory of what the predecessor lacked**, so it became the
skeleton: six stages, six committed artifacts, six verification passes.

The first design draft was a single model call over all 242 records with a
validator on the output. It was discarded, and the reason is worth stating
plainly: correlation inside one opaque inference has no answer to *"how would
you have caught the lateral movement the last tool missed?"* You cannot point at
the step that would have found it, because there is only one step.

## The loop

Inside `correlate`, four layers with a hard boundary in the middle:

```
DIRECT OBSERVATIONS
        |
========v==================================================
FACTUAL CORRELATION LAYER    deterministic - total - decides nothing
  ten atomic relations, zero detection rules
========v==================================================
CORRELATION GRAPH            virtual; the traversed subgraph is committed
        |
========v==================================================
AI INVESTIGATION LAYER       non-deterministic - interpretive
  SELECT -> EXPAND -> INTERPRET -> HYPOTHESISE -> SEEK
========v==================================================
CANDIDATE FINDINGS -> VALIDATION (6 checks) -> INVESTIGATION GRAPH
```

- **SELECT** — which observation to look at next. Anchors *order* the queue and
  never filter it; the ranking is a permutation of the input, never a subset.
- **EXPAND** — query the relations around it. **Truncation is reported**: each
  relation returns up to *k* nearest by time *with its full total stated*. A
  1-hop expansion on a busy host returns 60+ observations through `same_host`
  alone, and without the total the model would reason over a partial view
  believing it complete.
- **INTERPRET** — propose a finding citing specific edges, or say nothing. On
  the measured run, "nothing here" was a frequent and useful answer.
- **HYPOTHESISE** — predict what should exist if the findings so far are right,
  **committed before looking**. A prediction written after the search is a
  description of what was found; written before, it is a test that can fail.
- **SEEK** — `found` / `not_found` / `not_covered`.

`not_covered` is the one that makes the other two mean anything. Without it,
"not found" conflates *absence from the estate* with *blindness of the source*,
and those are different findings with different consequences. On the measured
run: 7 found, 3 not found, **10 not covered** — which is to say two thirds of
the failed predictions failed because no source could have seen the answer, and
saying so is more useful than saying "not found".

## The graph is virtual

`same_account` alone is roughly 44,000 pairs across 12 accounts. Materialising
all-pairs would be wasteful and unreadable, so relations are **deterministic
functions the interpretive layer queries**, backed by value indexes. Sparse
relations are materialised because they are small; dense ones stay queries. What
gets committed is the **subgraph the investigation actually traversed** — 1,451
edges on the measured run — which is both smaller and a record of what was
examined.

This also strengthens validation: a cited edge is **re-evaluated from its
relation function**, not looked up in a stored list. The kernel verifies against
the data, never against a cache of earlier conclusions.

And it dissolved the one genuinely hard parameter. `temporal_within` **reports**
the interval rather than thresholding it, so no global time window has to be
chosen — which is fortunate, because this intrusion's own related activities are
separated by anything from 2 seconds to 1 h 27 m 41 s. Any fixed window would be
wrong in one direction or the other.

## Termination, and refusing to conclude

The loop stops when the frontier empties, when a full pass yields no accepted
finding, or when the step budget is exhausted. Budget exhaustion marks open
hypotheses `unconfirmed` with `INSUFFICIENT_EVIDENCE` rather than resolving
them. An agent that concludes because it ran out of time is worse than one that
says it ran out of time.

## Rejection as a first-class output

Every rejection carries a **specific diagnostic** — not "invalid" but *"PSEXESVC
is named in the statement but appears in no cited observation"*. Three
consequences:

1. The rejection log is a **coverage backlog**, not noise. It records what the
   interpretive layer tried to claim and exactly why the kernel refused.
2. A rejection can be **back-prompted** once, carrying the diagnostic. This
   replaced union-of-N sampling, which a published result rules out: because the
   validator is deterministic, the contract-satisfying-but-wrong region is a
   fixed subset of accept-space, so precision is monotone non-increasing in N.
   Repair uses the information the rejection produced; resampling discards it.
3. On the measured run, **2 proposals were rejected, both for invented
   identifiers** — the commonest fabrication mode, caught by the cheapest check.

## Build plane and query plane

Two commands, deliberately separate.

**The build** runs once, needs a credential, and writes 23 committed artifacts
under `data/derived/`. **The app** only reads them. Nothing is computed at
question time that could mint a claim, which is why the app starts with no
credential and no network — measured at 1.85 s to accept connections with a
*hanging* proxy and the key unset.

The measured build: 743 s, 22 findings accepted, 20 mapped to ATT&CK v19.2, all
five graph invariants holding. Twelve minutes is slow for an interactive tool
and completely acceptable for a step that runs once and commits its output.

With the credential unset the build still runs: the relationships, the scope of
compromise and the coverage report are all deterministic. Technique attribution
is then reported as **unmapped** rather than omitted — a visible absence rather
than a silent one.

## Where agency is deliberately withheld

The honest answer to *"where did you not use AI?"* is stage-precise: the model
appears at four contracts across three stages and nowhere else. Ingest, parse,
the factual correlation layer, and the whole of synthesise are deterministic
code.

Two of those are worth defending individually:

**The factual layer.** Giving the model the job of computing relationships would
have made every downstream check meaningless, because there would be no
independent fact to check against.

**Synthesise.** The timeline, the scope, the gap report and the privilege report
are pure projections of the closed graph. Letting a model write the timeline
would let it reorder the incident.

Absence-based conclusions are computed **only** at stage 5, after the graph
closes — never during the loop. A later iteration may find what an earlier one
declared unobserved, and closed-world claims are not monotone under a growing
accepted set.

## What the shape costs

The design is biased toward missing things, and the measured run shows it
honestly. Of 22 accepted findings, roughly half reconstruct the real intrusion —
the Word-to-PowerShell chain on WKSTN-07, the C2 channel, `net.exe` discovery,
the port-445-to-`psexesvc` lateral movement, and the 2,473,829,122-byte file
appearing in both endpoint and cloud storage. The rest are honest but
low-value observations about benign activity: Outlook spawning Word, SSH-port
flows with no resolvable endpoints. They are correctly labelled
**Single-sourced**, they cite real records, and they are not wrong — they are
just not interesting.

That is the direct consequence of anchors that order rather than filter. A filter
would have cut them, and would also have encoded the answer. Given the choice
between a precise system that cheats and a noisier one that does not, this
design takes the second and reports the noise.
