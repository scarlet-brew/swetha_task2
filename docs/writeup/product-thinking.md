# Product thinking

*Written for: the Deloitte Cyber Engineering interview panel.*

## Who this is for, and what they are actually doing

Two users, and they are not the same person.

**The SOC analyst** is mid-incident and time-poor. Today this correlation takes a
senior analyst 6–8 hours by hand. They need to know what happened, in order,
with the evidence to hand — and critically, they need to know **what the data
cannot tell them**, because that is what determines their next action.

**The CISO** is the one the brief names: *can they hand this to their board and
legal team with confidence?* They are not reading logs. They need a document
that survives someone hostile asking "how do you know that?" about any sentence
in it.

Those two needs converge on one property — **every claim traceable to a raw
record** — which is why the evidence layer is the product and search is not.

## The reference class is a case file, not a dashboard

This was the first real product decision, and it drove the whole UI.

A SOC dashboard optimises for *monitoring*: dense, dark, real-time, scanning for
anomalies. This tool is used once per incident, read in order, and handed to
people who do not use security software. So the model is a **forensic dossier**
— parchment, serif chrome, printable, evidence quoted inline.

It also differentiates. Every other candidate will ship dark-mode Grafana.

The palette is measured rather than asserted: 14.25:1 / 8.61:1 / 4.85:1 on
parchment, recomputed from the exact hex values in the config file by a test, so
the one place a colour is written is the place the contrast floor is checked.
Muted ink was darkened from its first candidate specifically to clear the 4.5:1
body-text floor rather than the easier 3:1 large-text one. Dark mode is
*selected* — its own steps against its own surface — not an automatic flip.

No web fonts anywhere. A Google Fonts request from the frontend would break the
offline guarantee on the first demo behind a corporate proxy.

## The decision I would defend hardest: no confidence scores

The obvious design puts a number on every finding. This deliberately does not,
and there is no field anywhere a number could go in.

A confidence score is a *product* failure before it is a technical one. "87%
confident" tells the CISO nothing they can act on, cannot be checked by anyone,
and — the real problem — **it launders a model's opinion into something that
looks like a measurement.** In front of counsel that is worse than useless.

What replaces it is the **structure of the support**, computed from the evidence:

| Label | What it means, mechanically |
|---|---|
| **Corroborated** | supporting observations draw on two or more distinct log sources |
| **Single-sourced** | they draw on one |
| **Absence-based** | the named basis reasons from records *not* being present |
| **Conflicted** | two cited observations within one support disagree |

These are countable facts about the evidence, not judgements. On the measured
run: 13 corroborated, 9 single-sourced. A reader can check every one.

Three of the four status colours measure below 3:1 against parchment, so **icon
plus word is mandatory on every badge** — colour never carries the state alone.
That is an accessibility requirement and it doubles as the product requirement
that support states are *words*.

## Reporting gaps is the feature, not a caveat

The brief says it outright: *a correct "I can see suspicious activity but cannot
confirm exfiltration because the relevant logs are absent" beats a fabricated
conclusion.* So the gap report is a first-class surface, not a footnote.

It is **derived, not written by hand**. The unconfirmed and uncoverable
hypothesis sets *are* the report — each gap appears beside the hypothesis that
went looking for it, so a reader sees what was predicted and what the search
returned. On the measured run, 13 of 20 hypotheses came back unconfirmed or
uncoverable, and 10 of those failed because **no source could have seen the
answer**.

The structural gaps are checked against what was actually ingested rather than
hard-coded as prose: no mail source (so the phishing email is unknowable — sender,
subject and attachment name are *not* invented), no DNS source (so C2 is an
address with no domain), and every one of the 84 firewall records is an `allow`,
so there is no block signal and no network record independently corroborates the
2.47 GB egress. That transfer is labelled what it is: corroborated by endpoint
and cloud storage, with the network path unevidenced.

The privilege report is the sharpest example. Integrity rises
medium → high → SYSTEM, and the tempting conclusion is an exploit. There is no
exploit record. So the report names the mechanisms that *are* evidenced —
stolen credentials and service execution — and states explicitly that
**T1068 is deliberately absent from every mapping**, with a test asserting it.
Inferring an exploit from rising integrity would be closing a gap with
inference, which is the exact failure the brief warns about.

## Scope cuts, stated plainly

The brief rewards explicit reductions over silent incompleteness.

**Cut, and why:**
- **Detection rule export.** Out of scope. Internal deterministic rule-like
  detections are in scope as part of reconstruction; shipping reusable Sigma or
  similar is a different product.
- **Baselining.** No behavioural baseline is built. `jdavis` has no ordinary
  activity in the 72-hour window, so there is nothing to compare against — and
  more importantly, *unusualness may prioritise review but must never attribute*.
  Building a baseline would invite exactly that.
- **Graph visualisation.** A node-link picture of 1,451 edges is decorative. The
  trace view answers the question a reader actually has ("how do you know that?")
  and a force-directed blob does not.
- **Real-time ingestion.** The build runs once per incident. Streaming is a
  different system.

**Kept despite cost:**
- **The pipeline surface**, showing all six stages with their artifacts and
  verification results. It is nearly free because every stage already writes a
  report, and it is the best available answer to "where did you use AI and where
  did you not."
- **The full 51 MiB ATT&CK bundle**, committed. A derived subset would be
  smaller and would make the version claim unverifiable.

## What another day, and another week, would buy

**Another day**, in priority order:

1. **Measure accuracy properly.** The ground-truth labels exist and are
   quarantined from the system. Recall and precision against them is one script,
   and it is the number I would most want before showing this to anyone.
2. **Cut the noise.** Of 22 findings, roughly half are honest but low-value
   observations about benign activity. They are correctly labelled
   Single-sourced, but a reader has to wade. A relevance pass at synthesise time
   — ordering, never filtering — would fix the reading experience without
   touching the evidence.
3. **Faster build.** 743 s is dominated by sequential model calls. Batching the
   independent ones is an easy 3–4×.

**Another week:**

1. **Second dataset.** The acceptance scenarios are a regression suite for *this*
   incident, and they are not proof of generalisation. I would want to know how
   much of the performance is the architecture and how much is this dataset.
2. **False-negative measurement.** This architecture is structurally biased
   toward missing things, and that is the error class the field is criticised for
   not measuring. Perturbation harnesses — the R7.1 generator is specified for
   exactly this.
3. **Analyst feedback into the rejection log.** The log already records what the
   kernel refused. An analyst marking "this rejection was wrong" turns it into
   training signal for the prompts.
4. **The handover document** as a self-contained Markdown export — the thing the
   CISO actually forwards.

## The honest summary

What works: the correlation is real and cross-source, every claim traces to a raw
record, the gaps are reported without being asked, and three separate mechanisms
make fabrication structurally impossible rather than merely detected.

What does not: about half the findings are noise, the build takes twelve minutes,
and nothing here establishes that it generalises beyond this dataset. Aptness of
interpretation is unchecked by construction and named as such.

The thing I would want a reviewer to take away is the trade this makes. It is
biased toward missing things rather than inventing them, it says so, and it
surfaces the cost. For a document that goes to a board and a legal team, that is
the right direction to be wrong in.
