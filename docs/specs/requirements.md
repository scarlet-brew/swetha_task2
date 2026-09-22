# Requirements: Cyber Incident Investigation Intelligence

| | |
|---|---|
| **Phase** | 1 of Spec → Design → Tasks → Implement → Validate |
| **Status** | Draft — 18 clarifications outstanding (§10) |
| **Created** | 2026-09-22 |
| **Incident** | `INC-2026-0610-001` |

> **Scope of this document.** What the system must do and how we will know it did it, written so
> that a non-engineer stakeholder can review it. **No architecture, no technology, no mechanism.**
> Anything that describes *how* belongs in [design.md](design.md).
>
> Ambiguity is marked inline as `[NEEDS CLARIFICATION: NC-nn]` and collected in §10. Every marker
> blocks Phase 1 sign-off.

---

## 1. Introduction

A healthcare organisation has suffered a suspected intrusion. Three days of security logs exist
across endpoints, authentication, network and cloud storage. Establishing what happened
currently takes a senior analyst six to eight hours of manual cross-referencing before a
timeline can even begin to form.

This system reconstructs the intrusion from those logs and answers questions about its scope and
impact, with the specific log records behind every statement.

An earlier attempt failed. It returned raw search results with no cross-referencing, no
timeline, and no link to known adversary behaviour, and it missed a host-to-host movement that
was obvious in hindsight. **Cross-referencing and verifiability are the product. Search is not.**

### 1.1 The governing principle

A plausible, fluent, unsupported conclusion is the worst possible output. It misdirects
containment and it is discoverable in litigation.

> A correct *"I can see suspicious activity but cannot confirm data was removed, because the
> relevant logs are absent"* is a **successful** answer.

### 1.2 Who this is for

| Role | Situation | What they need |
|---|---|---|
| **SOC analyst** — primary | Mid-incident, time-pressured, will be challenged on conclusions | The sequence, the pivots, the underlying records, and an honest list of unknowns |
| **CISO** — consumer | Briefing a board and legal counsel | Scope of compromise, a defensible summary, explicit uncertainty |
| **Incident responder** | Acting within two hours | Prioritised actions tied to specific evidence |
| **Evaluator** | Judging whether the approach is sound | Proof that conclusions came from investigation, not from answers embedded in the data |

---

## 2. Key entities

Concepts the system reasons about. Named here so the requirements can refer to them; no
structure or storage is implied.

| Entity | Description |
|---|---|
| **Log record** | One entry from one source, with a source, a time, an identifier, and the details of what was observed |
| **Log source** | A system that produced records: endpoint activity, authentication, network traffic, cloud storage activity |
| **Actor** | An account observed acting |
| **Host** | A machine observed acting or being acted upon |
| **Asset** | Data observed being read, collected or removed |
| **Activity** | Something that happened, evidenced by one or more log records |
| **Intrusion stage** | A phase of the intrusion: gaining access, running code, remote control, credential theft, reconnaissance, movement between hosts, data collection, data removal, covering tracks |
| **Technique** | A published MITRE ATT&CK adversary technique, identified by its catalogue identifier and official name |
| **Finding** | A statement the system makes, with the records supporting it |
| **Absent source** | A log source that would answer a question but which the available data does not include |
| **Developer annotation** | A field present in the supplied data that labels which records belong to the intrusion. Available for measuring accuracy only |

---

## 3. Requirements

Each requirement is independently testable. Priority: **P1** is the minimum viable
investigation — without any one of these there is no product. **P2** makes it usable by the
other roles. **P3** is desirable.

### Requirement 1 — Reconstruct the intrusion as a sequence  `P1`

**User story.** As a SOC analyst, I want the intrusion presented as one chronological sequence
assembled from every available log source, so that I can see what happened without manually
cross-referencing thousands of lines across separate systems.

**Acceptance criteria**

1. WHEN the analyst requests the reconstruction THEN THE SYSTEM SHALL present the
   intrusion-related activity as one sequence ordered by time of occurrence.
2. WHEN presenting a step THEN THE SYSTEM SHALL identify the actor, the host and what was done.
3. THE SYSTEM SHALL assemble the sequence from activity recorded by more than one log source
   wherever such activity exists.
4. WHEN two records from different log sources describe the same underlying activity THEN THE
   SYSTEM SHALL present them as one step and identify every source that observed it.
5. WHEN the sequence is presented THEN THE SYSTEM SHALL state the earliest and latest
   intrusion-related activity found.
6. WHERE the data evidences an intrusion stage THE SYSTEM SHALL identify that stage in the
   sequence.
7. IF no record evidences a given intrusion stage THEN THE SYSTEM SHALL report that stage as not
   observed, rather than omitting it.
8. IF no activity in the data evidences an intrusion THEN THE SYSTEM SHALL state that none is
   evidenced and SHALL NOT present a sequence.

### Requirement 2 — Show the evidence for every statement  `P1`

**User story.** As a SOC analyst, I want every statement to point at the log records behind it,
so that I can verify any conclusion myself and defend it when challenged.

**Acceptance criteria**

1. WHEN THE SYSTEM states a fact about the incident THEN THE SYSTEM SHALL identify each
   supporting log record by its source, its time and its identifier.
   `[NEEDS CLARIFICATION: NC-17 — how times are presented]`
2. WHEN a supporting record is identified THEN THE SYSTEM SHALL make the complete original
   record available to the analyst without requiring them to leave what they are reading.
3. THE SYSTEM SHALL present original records unaltered.
4. IF a statement has no supporting record THEN THE SYSTEM SHALL withhold the statement and
   report which statement was withheld.
5. IF a cited record does not contain the values the statement asserts THEN THE SYSTEM SHALL
   treat that statement as unsupported under criterion 4.
6. IF a cited identifier does not exist in the data THEN THE SYSTEM SHALL withhold the answer and
   report the failure.

### Requirement 3 — State what cannot be determined  `P1`

**User story.** As a CISO briefing a board and legal counsel, I want the system to say plainly
what it cannot establish, so that I never repeat a conclusion the evidence does not support.

**Acceptance criteria**

1. IF the available data cannot answer a question THEN THE SYSTEM SHALL state that it cannot and
   SHALL name the information that would be required.
2. WHEN THE SYSTEM states a conclusion that no single record directly records THEN THE SYSTEM
   SHALL indicate how strongly the evidence supports it.
   `[NEEDS CLARIFICATION: NC-01 — what vocabulary expresses evidential strength]`
3. WHEN a conclusion is supported by records from only one log source THEN THE SYSTEM SHALL say
   so.
   `[NEEDS CLARIFICATION: NC-14 — is such a conclusion weakly or strongly supported when that
   single source records the act itself]`
4. WHEN a conclusion rests on the absence of records THEN THE SYSTEM SHALL say so and SHALL NOT
   present it as observed fact.
5. THE SYSTEM SHALL report, without being asked, which log sources are absent and which
   conclusions their absence limits.
6. WHEN asked for information that an absent source would hold THEN THE SYSTEM SHALL state that
   the source is absent and SHALL NOT supply the information on any other basis.
7. WHEN asked whether the intrusion has ended THEN THE SYSTEM SHALL report the last observed
   activity and state that continuation cannot be determined from the available period.
8. THE SYSTEM SHALL identify hosts and accounts involved in the incident that no relevant log
   source covers.
9. IF records support mutually incompatible conclusions THEN THE SYSTEM SHALL report the
   incompatibility and cite every record involved.
   `[NEEDS CLARIFICATION: NC-02 — report both, or decline to conclude]`

> Criterion 6 is the assignment's own worked example. The supplied data contains no mail records,
> so the phishing message itself — sender, subject, attachment — is unknowable. Naming any of
> them would be fabrication.

### Requirement 4 — Name the adversary techniques used  `P1`

**User story.** As a SOC analyst, I want observed behaviour mapped to published MITRE ATT&CK
techniques with their identifiers, so that I can compare this intrusion to known adversary
behaviour and describe it in a vocabulary others already use.

**Acceptance criteria**

1. WHEN THE SYSTEM attributes a technique to an activity THEN THE SYSTEM SHALL state the
   technique identifier, its official name and its tactic.
2. WHEN THE SYSTEM attributes a technique THEN THE SYSTEM SHALL cite the supporting records and
   state the observation that led to the attribution.
3. THE SYSTEM SHALL name only techniques that exist in the published catalogue.
4. WHEN THE SYSTEM reports techniques THEN THE SYSTEM SHALL state which published version of the
   catalogue it used.
5. IF an observed behaviour matches no technique that the evidence supports THEN THE SYSTEM SHALL
   report the behaviour as unmapped, rather than naming the closest available technique.
6. IF a change in privilege level is observed THEN THE SYSTEM SHALL attribute it only to a
   mechanism that the records evidence.

> Criterion 6 matters on this data: privilege rises to the highest level, but by credential theft
> and remote service creation — not by any exploitation. Asked about "privilege escalation", an
> unconstrained system will name an exploitation technique that no record supports.

### Requirement 5 — Establish the scope of compromise  `P1`

**User story.** As a CISO, I want a complete list of affected hosts, accounts and data, so that I
can scope containment, notification and legal obligations.

**Acceptance criteria**

1. THE SYSTEM SHALL list every host involved in intrusion-related activity, each with when it
   was first and last involved, and the supporting records.
2. THE SYSTEM SHALL list every account used in intrusion-related activity, with supporting
   records.
3. WHEN listing hosts and accounts THEN THE SYSTEM SHALL distinguish those confirmed compromised
   from those merely observed, and SHALL state the basis for that distinction.
4. THE SYSTEM SHALL identify data observed to be read, collected or removed, with the volume
   where records state it.
5. THE SYSTEM SHALL state which hosts and accounts it cannot rule out, and why.

### Requirement 6 — Ask questions in plain language  `P1`

**User story.** As a SOC analyst working under pressure, I want to ask questions in my own words,
so that I do not have to learn a query language during an incident.

**Acceptance criteria**

1. THE SYSTEM SHALL accept questions expressed in plain language.
2. WHEN asked any of the ten evaluation questions in §7 THEN THE SYSTEM SHALL answer to the
   criteria stated there.
3. WHEN a question names a particular account, host, address, file or storage location THEN THE
   SYSTEM SHALL report every intrusion-related activity involving it.
4. WHEN a question restricts the period of interest THEN THE SYSTEM SHALL restrict its answer to
   that period and SHALL state the period applied.
5. WHEN a question asks for a summary of a stated length THEN THE SYSTEM SHALL respect that
   length.
6. WHEN a question is asked THEN THE SYSTEM SHALL produce its answer within a stated time.
   `[NEEDS CLARIFICATION: NC-03 — acceptable answer time]`

### Requirement 7 — Demonstrate that conclusions came from investigation  `P1`

**User story.** As an evaluator, I want to confirm the system reached its conclusions by
examining the records rather than by reading answers embedded in the supplied data, so that I can
believe the approach would work on real logs.

**Acceptance criteria**

1. WHEN given the same data with developer annotations removed, record identifiers renumbered in
   a different order, and the precision of recorded times altered THEN THE SYSTEM SHALL produce
   the same set of intrusion-related activity, the same sequence order, and the same set of
   techniques.
2. THE SYSTEM SHALL use developer annotations for no purpose other than measuring its own
   accuracy.
3. THE SYSTEM SHALL report its own accuracy against those annotations, stating what it found,
   what it missed, and what it wrongly included.
4. THE SYSTEM SHALL make the intermediate results of its investigation available for inspection.

> This is the only requirement that can *prove* rather than assert that the reconstruction was
> earned. The supplied data reveals the answer three separate ways, and criterion 1 is a
> black-box test that all three were ignored.

### Requirement 8 — Produce something that can be handed over  `P2`

**User story.** As a CISO, I want a short summary and a self-contained written record, so that I
can brief a board and give something to legal counsel who will never operate this system.

`[NEEDS CLARIFICATION: NC-04 — is a handover record in scope, and in what form]`

**Acceptance criteria**

1. WHEN asked for a summary of a stated length THEN THE SYSTEM SHALL produce one in which every
   assertion traces to the reconstruction and residual uncertainty is stated.
2. THE SYSTEM SHALL produce a self-contained record containing the sequence, the techniques, the
   affected hosts, accounts and data, the absent sources, and every citation.
3. WHEN producing that record THEN THE SYSTEM SHALL state the data it was built from, the
   catalogue version used, the version of the system, and when it was produced.
4. THE SYSTEM SHALL make that record readable without access to the running system.

### Requirement 9 — Recommend what to do next  `P2`

**User story.** As an incident responder, I want prioritised actions each tied to specific
evidence, so that I can begin containing this before the investigation is complete.

**Acceptance criteria**

1. WHEN asked what should be done THEN THE SYSTEM SHALL propose actions, each tied to a specific
   evidenced compromise and citing it.
2. WHEN proposing an action THEN THE SYSTEM SHALL classify it as limiting further damage,
   removing the adversary's access, or restoring normal operation.
3. WHEN proposing actions THEN THE SYSTEM SHALL order them.
4. THE SYSTEM SHALL include at least one action that addresses an absent log source, rather than
   only the confirmed activity.
5. THE SYSTEM SHALL NOT carry out any such action itself.

### Requirement 10 — Show the working  `P2`

**User story.** As a SOC analyst, I want to see what the system did to reach an answer, so that I
can judge whether the reasoning was sound instead of trusting the output.

**Acceptance criteria**

1. WHILE an answer is being produced THE SYSTEM SHALL show the steps it is taking.
2. WHEN a conclusion is presented THEN THE SYSTEM SHALL identify which reasoning produced it.
3. WHEN an answer is complete THEN THE SYSTEM SHALL retain a record of the question, the steps
   taken, the citations returned, and the versions in use, such that another person can establish
   how the conclusion was reached.
   `[NEEDS CLARIFICATION: NC-05 — is a retained record required, or is on-screen visibility enough]`

### Requirement 11 — Ask follow-up questions  `P3`

**User story.** As a SOC analyst, I want to ask follow-up questions that refer back to what we
were just discussing, so that I can explore a thread without restating context each time.

`[NEEDS CLARIFICATION: NC-06 — in scope, or is each question standalone]`

**Acceptance criteria**

1. WHEN a question refers to the preceding exchange THEN THE SYSTEM SHALL resolve the reference
   and SHALL state what it resolved it to.

### Requirement 12 — Show what was ruled out  `P3`

**User story.** As a SOC analyst, I want to see the suspicious activity the system examined and
dismissed, so that I can judge whether it overlooked something.

`[NEEDS CLARIFICATION: NC-07 — worth the additional noise]`

**Acceptance criteria**

1. WHEN THE SYSTEM has examined an activity as potentially intrusion-related and has not
   attributed it to the intrusion THEN THE SYSTEM SHALL make that decision and its reason
   available on request.

---

## 4. Non-functional requirements

Observable qualities only. Where these once described mechanism, they have been reduced to what
a user or evaluator can witness.

| # | Requirement |
|---|---|
| **NFR-01** | Given the same data and the same question, THE SYSTEM SHALL reach the same conclusions on every run. |
| **NFR-02** | WHILE any service outside the analyst's machine is unavailable, THE SYSTEM SHALL still produce the sequence, the techniques, the scope of compromise and the absent-source report. |
| **NFR-03** | THE SYSTEM SHALL complete a reconstruction of the supplied data within a stated time. `[NEEDS CLARIFICATION: NC-08]` |
| **NFR-04** | THE SYSTEM SHALL state what information about the incident leaves the analyst's machine, and SHALL send nothing beyond what is stated. `[NEEDS CLARIFICATION: NC-09 — the client is a healthcare organisation; is unrestricted transmission of log content to an outside service acceptable]` |
| **NFR-05** | THE SYSTEM SHALL leave the supplied data unmodified. |
| **NFR-06** | IF any part of the investigation fails THEN THE SYSTEM SHALL report what failed and SHALL NOT present an incomplete reconstruction as complete. |
| **NFR-07** | IF the supplied data cannot be read or is not in the expected form THEN THE SYSTEM SHALL say so and SHALL produce no reconstruction. |
| **NFR-08** | Every output THE SYSTEM produces SHALL identify the version of the system that produced it. |
| **NFR-09** | THE SYSTEM SHALL be startable by following written instructions, without modifying it. |
| **NFR-10** | THE SYSTEM SHALL state the environments in which it has been verified to run. `[NEEDS CLARIFICATION: NC-10 — which environments must be supported]` |
| **NFR-11** | THE SYSTEM SHALL state the volume of data at which its behaviour has been established, or state that this has not been established. `[NEEDS CLARIFICATION: NC-11]` |
| **NFR-12** | THE SYSTEM SHALL state whether repeated answers to the same question are identical in wording, and SHALL meet whatever it states. `[NEEDS CLARIFICATION: NC-12 — is identical wording required, or only identical conclusions]` |
| **NFR-13** | Credentials required to operate THE SYSTEM SHALL NOT be stored alongside it. |
| **NFR-14** | Every requirement in §3 and §4 SHALL be verifiable by a repeatable procedure, and any that is not SHALL be reported. |

---

## 5. Success criteria

Measurable, and stated without reference to how the system is built.

| # | Criterion |
|---|---|
| **SC-01** | An analyst obtains the complete reconstruction in minutes rather than the six to eight hours the manual process takes. |
| **SC-02** | 100% of factual statements in outputs resolve to a log record that contains the asserted values. A single failure is a defect, not a lower score. |
| **SC-03** | The reconstruction identifies at least a stated proportion of the activity belonging to the intrusion, and wrongly includes no more than a stated proportion of unrelated activity. `[NEEDS CLARIFICATION: NC-13 — the two proportions]` |
| **SC-04** | Across a fixed set of questions about information the data does not contain, the system fabricates nothing and names the absent source every time. |
| **SC-05** | Findings are unchanged when developer annotations, record identifiers and time precision are altered (Requirement 7). |
| **SC-06** | A reader who distrusts a given statement can reach the record behind it in under 30 seconds. |
| **SC-07** | All ten evaluation questions in §7 are answered to their stated criteria. |
| **SC-08** | Every absent log source that limits a conclusion is reported without the user asking. |

---

## 6. Assumptions

Beliefs about the data and the world that these requirements rest on. If one is false, the third
column says what becomes unsafe.

| # | Assumption | If false |
|---|---|---|
| **A-01** | The data's own description of its sources, formats and internal address ranges is accurate | Internal and external activity are misclassified, corrupting the remote-control and data-removal reasoning |
| **A-02** | Developer annotations are accurate and complete enough to measure accuracy against | SC-03 measures agreement with a flawed answer key rather than correctness |
| **A-03** | Exactly one intrusion is present; there is no second, unrelated one | A second would be folded into the first. Requirement 3 criterion 9 is the only safeguard |
| **A-04** | Recorded times are accurate and consistently expressed, with no drift between source systems | Sequence order may be wrong, and any conclusion drawn from two activities being close in time becomes unreliable |
| **A-05** | For the sources present, the data is complete — a missing record reflects what was collected, not what was exported | An absent-source report would blame the environment for what is an artifact of how the data was supplied |
| **A-06** | The published technique catalogue can be obtained once and retained, so that NFR-02 holds | Requirement 4 criterion 3 cannot be met without an outside service being reachable |
| **A-07** | One analyst uses the system at a time | The exclusions in §9 covering identity and concurrent use become invalid |

> A-04 and A-05 are unverifiable from inside the supplied data, and both are assumptions
> practitioners normally make in silence.

---

## 7. Acceptance scenarios — the ten evaluation questions

The assignment supplies ten questions. They are adopted verbatim as the acceptance suite.

**Every scenario additionally requires:** every factual statement resolves to a record
containing the asserted values (R2); no developer annotation, identifier ordering or time
precision influenced the answer (R7); the answer arrives within NC-03.

| # | Given the supplied data is loaded, when the analyst asks… | Then the system must… |
|---|---|---|
| **AS-01** | "Walk me through the full attack timeline from initial access to last observed activity." | Present one time-ordered sequence covering every intrusion stage the data evidences, naming those it does not; state the earliest and latest activity; cite every step |
| **AS-02** | "What was the initial access vector and what evidence supports that conclusion?" | Name the evidence of a document application starting a command interpreter, and cite it; **state that no mail records exist**; name no sender, subject or attachment; indicate that this conclusion is weakly supported |
| **AS-03** | "Which MITRE ATT&CK techniques did the attacker use? List them with technique IDs." | Give identifier, official name, tactic and citation for each; state the catalogue version; assert no exploitation-based privilege escalation; report any behaviour it could not map |
| **AS-04** | "Which user accounts were compromised or used by the attacker?" | Identify the account with citations; separate confirmed compromise from mere observation; state that this account has no ordinary activity in the period against which to compare |
| **AS-05** | "Which internal hosts did the attacker move to after the initial foothold?" | Identify both subsequent hosts in order with citations; name the authentication and the remote-service-creation activity that evidence the movement; flag any host identification that rested on an ambiguous address-to-host association |
| **AS-06** | "Is there evidence of data exfiltration? If so, what was accessed and when?" | Answer yes; name the file, the exact size, the destination, its external ownership, the client used and the time; cite the two records that match on file name and exact size; state that only one log source evidences this and that no network record corroborates it |
| **AS-07** | "What is the blast radius — list every affected host and account." | Enumerate all hosts and accounts with first and last involvement and citations; name the data and volume; state what cannot be ruled out, including hosts no source covers |
| **AS-08** | "Where are the gaps in our log coverage that limit your confidence in this reconstruction?" | Report the absent mail and name-resolution sources, the uncorroborated data removal, the uneven endpoint coverage, the unobserved tool transfer and the unobserved credential removal — each tied to the specific conclusion it limits |
| **AS-09** | "Give me a 3-sentence executive summary suitable for a board briefing." | Produce exactly three sentences, every assertion traceable, residual uncertainty stated, nothing asserted beyond the evidence |
| **AS-10** | "What should the incident response team do in the next 2 hours to contain this?" | Propose ordered actions, each citing the evidence that motivates it and classified as limiting damage, removing access or restoring operation; include at least one addressing an absent source |

---

## 8. Edge cases

| Situation | Required behaviour |
|---|---|
| A network address is associated with more than one host across the data | Report every candidate and mark the association uncertain; treat any conclusion depending on it as weakly supported (R3.2) |
| A network address is associated with no host | Retain the activity identified by address alone; infer no host (R3.4) |
| Two records carry identical times | Order them by a stated, repeatable rule that does not depend on record identifiers (R7.1) |
| Records support incompatible conclusions | R3.9 |
| An entire log source is absent | R3.5, R3.6 |
| A behaviour matches no catalogue technique | R4.5 |
| An intrusion stage has no evidence | R1.7 |
| No intrusion is present in the data at all | R1.8 — state that none is evidenced; invent none |
| A question concerns a period outside the data | State the period covered and that the question falls outside it |
| A question cannot be answered from the data | R3.1 |
| The data is unreadable or malformed | NFR-07 |
| A question asks the system to act rather than advise | R9.5 |

---

## 9. Out of scope

Declared rather than silently omitted; the assignment rewards explicit reductions.

| Excluded | Reason |
|---|---|
| Data other than the supplied set | Generality would be an untested claim |
| Continuous or live collection | The supplied data is a fixed three-day export |
| More than one incident | Incident scoping is a different product |
| Identity, access control and concurrent use | One analyst, one machine (A-07) |
| Recovery of system state after failure | No lasting state exists to recover; the supplied data is never modified (NFR-05) |
| Accessibility conformance | Not evaluated here, and a conformance claim would consume the budget that investigation quality needs |
| Reputation or intelligence lookup for external addresses | Requires an outside service, conflicting with NFR-02; no conclusion depends on it |
| Producing reusable detection rules | Downstream of investigation |
| Carrying out containment | The system advises; a person acts. Acting on a possibly-wrong reconstruction is the failure this document exists to prevent |
| Comparing behaviour against a normal baseline | The compromised account has no ordinary activity in the period, so no baseline can be formed |

---

## 10. Clarifications needed

Every item blocks Phase 1 sign-off. A proposal is offered where one exists; none has been
adopted.

| # | Question | Blocks | Proposal |
|---|---|---|---|
| **NC-01** | What vocabulary expresses evidential strength? Options include the intelligence community's estimative-probability terms paired with a separate confidence statement, or a simpler three-tier scale | R3.2 | Separate the likelihood of the claim from the strength of the evidence, and never combine them in one sentence |
| **NC-02** | Should directly-recorded facts also carry a strength marker, for visual consistency, or would that be false precision? | R3.2 | No marker on directly-recorded facts |
| **NC-03** | What is the acceptable time to answer one question? | R6.6 | 60 seconds |
| **NC-04** | Is a handover record in scope, and in what form? Legal counsel will never operate the system | Requirement 8 | In scope; form undecided |
| **NC-05** | Must the working be retained after the answer, or is on-screen visibility sufficient? | R10.3 | Retained |
| **NC-06** | Are follow-up questions that refer back in scope? | Requirement 11 | Desirable, not required |
| **NC-07** | Is showing dismissed activity worth the noise it adds? | Requirement 12 | Desirable, not required |
| **NC-08** | What is the acceptable time to reconstruct the supplied data? | NFR-03 | 10 seconds |
| **NC-09** | The client is a healthcare organisation. Is unrestricted transmission of log content to a service outside the analyst's machine acceptable, or must content be restricted or reduced first? | NFR-04 | **Unresolved — the answer shapes the whole design** |
| **NC-10** | Which environments must the system be verified in? | NFR-10 | **Unresolved** |
| **NC-11** | Must behaviour beyond the supplied volume be established, or is it acceptable to state that it has not been? | NFR-11 | State that it has not been |
| **NC-12** | Must repeated answers be identical in wording, or only in their conclusions? | NFR-12 | **Unresolved** |
| **NC-13** | What proportion of intrusion activity must be found, and what proportion of unrelated activity may be wrongly included? The data is deliberately seeded with misleading but benign activity | SC-03 | Find ≥ 80%; wrongly include ≤ 30% |
| **NC-14** | Is a conclusion supported by a single log source that directly records the act itself weakly or strongly supported? The data-removal finding turns on this | R3.3 | **Unresolved — currently the weakest point in the specification** |
| **NC-15** | Are the P1 / P2 / P3 priorities in §3 right? | §3 | As written |
| **NC-16** | Are the exclusions in §9 the right ones? | §9 | As written |
| **NC-17** | How should times be presented — as recorded, or converted to the reader's local time? | R1.1, R2.1 | As recorded, with the zone stated |
| **NC-18** | Are the walkthrough and the written discussion of trust, workflow design and product thinking — both graded — produced as artifacts in this repository, or prepared separately? | Deliverables | In this repository |

Two questions raised during Phase 1 turned out to describe *mechanism* and have been moved to
[design.md](design.md): how close in time two activities must be to be considered related, and
what limit applies to the size of a source file.

---

## 11. Review and acceptance checklist

**Content quality**

- [ ] No implementation detail: no architecture, no components, no technology, no data formats
- [ ] Written for a stakeholder who does not build software
- [ ] Every requirement expresses a user-visible outcome, not an internal behaviour
- [ ] All mandatory sections present

**Requirement quality**

- [ ] No `[NEEDS CLARIFICATION]` markers remain
- [ ] Every acceptance criterion is testable and unambiguous
- [ ] Success criteria are measurable and free of technology references
- [ ] Each requirement is independently testable
- [ ] Edge cases identified with required behaviour for each
- [ ] Scope boundaries are explicit
- [ ] Assumptions and their consequences are recorded

**Content sign-off**

- [ ] §1.1 is the right governing principle
- [ ] §1.2 names the right roles
- [ ] The twelve requirements in §3 are the right ones, at the right priorities
- [ ] The success criteria in §5 are the right measures
- [ ] The assumptions in §6 are acceptable, in particular A-04 and A-05
- [ ] The ten acceptance scenarios in §7 are what the system should be judged against
- [ ] The exclusions in §9 are the right exclusions
