# Requirements: Cyber Incident Investigation Intelligence

**Phase 1 of** Spec → Design → Tasks → Implement → Validate  ·  **Status:** draft, 3 open questions (§8)  ·  **Incident:** `INC-2026-0610-001`  ·  **2026-09-22**

What the system must do and how we will know it did it. No architecture, no technology, no
mechanism — those belong in [design.md](design.md).

---

## 1. Overview

A healthcare organisation has suffered a suspected intrusion. Three days of security logs exist
across endpoints, authentication, network traffic and cloud storage. Establishing what happened
currently costs a senior analyst six to eight hours of manual cross-referencing.

This system reconstructs the intrusion from those logs and answers questions about its scope,
citing the specific log records behind every statement.

An earlier attempt failed: raw search results, no cross-referencing, no timeline, no link to
known adversary behaviour. It missed a host-to-host movement that was obvious in hindsight.
**Cross-referencing and verifiability are the product. Search is not.**

**The governing principle.** A fluent, plausible, unsupported conclusion is the worst possible
output — it misdirects containment and it is discoverable in litigation. A correct *"I can see
suspicious activity but cannot confirm data was removed, because the relevant logs are absent"*
is a **successful** answer.

**Users.** A **SOC analyst** works the incident and will be challenged on every conclusion. A
**CISO** consumes the result to brief a board and legal counsel. An **incident responder** needs
to act within two hours. An **evaluator** needs to see that the conclusions were earned.

---

## 2. Requirements

**Priority.** **P1** — the deliverable fails without it. **P2** — needed by a role other than
the analyst. Each requirement is independently testable.

### Requirement 1 — Reconstruct the intrusion as a sequence `P1`

**As a** SOC analyst, **I want** the intrusion presented as one chronological sequence drawn
from every available log source, **so that** I can see what happened without manually
cross-referencing thousands of lines across separate systems.

1. WHEN the analyst requests the reconstruction THEN THE SYSTEM SHALL present the
   intrusion-related activity as one sequence ordered by time of occurrence.
2. WHEN presenting a step THEN THE SYSTEM SHALL identify the account, the host, what was done,
   and which log source recorded it.
3. THE SYSTEM SHALL include intrusion-related activity from every log source that records any.
4. WHEN activities recorded by different log sources are related to one another THEN THE SYSTEM
   SHALL present that relationship and cite the records on both sides of it.
5. WHEN the sequence is presented THEN THE SYSTEM SHALL state the first and last intrusion-related
   activity found, and the period of data examined.
6. IF the data evidences a stage of the intrusion — gaining access, running code, remote control,
   credential theft, reconnaissance, movement between hosts, data collection, data removal,
   covering tracks — THEN THE SYSTEM SHALL identify that stage in the sequence.
7. IF no record evidences a given stage THEN THE SYSTEM SHALL report that stage as not observed,
   rather than omitting it.
8. IF no activity evidences an intrusion at all THEN THE SYSTEM SHALL say so and SHALL NOT present
   a sequence.
9. THE SYSTEM SHALL attribute activity to the intrusion only on the basis of observed behaviour
   evidenced by cited records.
10. IF an account, host or address is notable only for having little or no other recorded activity,
    or for lacking the variation its peers show, THEN THE SYSTEM SHALL treat that as grounds for
    review and SHALL NOT treat it as evidence of intrusion.

*Criterion 4 is the point. No two records in this data describe the same action, so there is
nothing to merge — the value is in showing that activity in one source is related to activity in
another.*

*Criterion 10 exists because unusualness in this data is a shortcut to the right answer for the
wrong reason. One account has no ordinary activity in the whole period and it is the compromised
one; the only three hosts with a single network address are exactly the three compromised hosts,
while every other host shows four to nine. Both would score perfectly here and fail on real logs.*

### Requirement 2 — Show the evidence for every statement `P1`

**As a** SOC analyst, **I want** every statement to point at the log records behind it, **so
that** I can verify any conclusion myself and defend it when challenged.

Statements come in two classes, and they carry different obligations:

- an **atomic observation** asserts values that appear directly in one or more records;
- a **derived finding** — movement between hosts, credential theft, data removal — asserts
  something no single record contains, and exists only by connecting records together.

1. WHEN THE SYSTEM makes a statement about the incident THEN THE SYSTEM SHALL classify it as an
   atomic observation or a derived finding.
2. WHEN THE SYSTEM states an atomic observation THEN THE SYSTEM SHALL cite each record whose
   values it asserts, identified by source, recorded time and identifier.
3. WHEN THE SYSTEM states a derived finding THEN THE SYSTEM SHALL cite the complete set of records
   the finding rests on, and SHALL name the correlation or inference rule that connects them.
4. WHEN a record is cited THEN THE SYSTEM SHALL make the complete original record available,
   unaltered, without the analyst leaving what they are reading.
5. IF an atomic observation asserts a value that appears in no cited record THEN THE SYSTEM SHALL
   withhold the statement and report which value failed.
6. IF a derived finding names no rule, omits a record its named rule requires, or cites a record
   that does not fulfil the role the rule assigns it, THEN THE SYSTEM SHALL withhold the finding
   and report which of those failed.
7. THE SYSTEM SHALL NOT withhold a derived finding on the ground that no individual record
   contains it in full.
8. IF a cited identifier does not exist in the data THEN THE SYSTEM SHALL withhold the answer and
   report the failure.

*Criterion 7 is why the split exists. "The attacker moved from one server to the next" appears in
no record: it rests on a network flow between the two hosts, a service created on the second, and
a process whose parent is that service — three records joined by a named rule. Checking a derived
finding value-by-value against single records would withhold the system's primary output. The
check that replaces it is stronger, not weaker: the rule is named, so a reviewer can ask whether
the rule is sound and whether each cited record really plays the part the rule assigns it.*

### Requirement 3 — State what cannot be determined `P1`

**As a** CISO briefing a board and legal counsel, **I want** the system to say plainly what it
cannot establish, **so that** I never repeat a conclusion the evidence does not support.

1. IF the data cannot answer a question THEN THE SYSTEM SHALL say so and SHALL name the
   information that would be required.
2. WHEN THE SYSTEM states a derived finding THEN THE SYSTEM SHALL indicate how strongly its
   evidence set supports it.
   `[NEEDS CLARIFICATION: Q1]`
3. WHEN a conclusion rests on records from a single log source, or on the absence of records, THEN
   THE SYSTEM SHALL say so and SHALL NOT present it as observed fact.
4. THE SYSTEM SHALL report, without being asked, which log sources are absent and which
   conclusions their absence limits.
5. WHEN asked for information that an absent source would hold THEN THE SYSTEM SHALL state that
   the source is absent and SHALL NOT supply the information on any other basis.
6. WHEN asked whether the intrusion has ended THEN THE SYSTEM SHALL report the last observed
   activity and state that continuation cannot be determined from the available period.
7. IF a network address is associated with more than one host across the data THEN THE SYSTEM
   SHALL report every candidate, mark the association uncertain, and treat any conclusion
   depending on it as weakly supported.
8. IF a network address is associated with no host THEN THE SYSTEM SHALL identify the activity by
   address alone and SHALL NOT infer a host.
9. IF records support mutually incompatible conclusions THEN THE SYSTEM SHALL report the
   incompatibility and cite every record involved.
10. THE SYSTEM SHALL identify hosts and accounts that appear in the incident but about which one
    or more relevant log sources record nothing.

*Criterion 5 is the assignment's own example: this data contains no mail records, so the phishing
message — sender, subject, attachment — is unknowable. Naming any of them is fabrication.*

### Requirement 4 — Name the adversary techniques used `P1`

**As a** SOC analyst, **I want** observed behaviour mapped to published MITRE ATT&CK techniques
with their identifiers, **so that** I can compare this intrusion to known adversary behaviour and
describe it in a vocabulary others already use.

1. WHEN THE SYSTEM attributes a technique THEN THE SYSTEM SHALL state its identifier, its official
   name and its tactic, cite the supporting records, and state the observation that led to the
   attribution.
2. THE SYSTEM SHALL name only techniques that exist in the published catalogue, and SHALL state
   which version of that catalogue it used.
3. IF an observed behaviour matches no technique the evidence supports THEN THE SYSTEM SHALL report
   it as unmapped rather than naming the closest available technique.
4. WHEN activity is observed running at a higher privilege than activity seen earlier THEN THE
   SYSTEM SHALL name the mechanism the records evidence, and SHALL NOT assert an exploitation,
   elevation-bypass or token-manipulation mechanism that no record evidences.
5. WHEN comparing privilege levels THEN THE SYSTEM SHALL compare only activity on the same host,
   and SHALL state that privilege observed on one host is not evidence of a rise relative to
   another.
6. IF records show privileged activity with no preceding record of that privilege being acquired
   THEN THE SYSTEM SHALL report that the account appears to have already held it, and SHALL cite
   both the authentication and the privileged activity.
7. IF no available source is capable of recording a change of privilege THEN THE SYSTEM SHALL say
   so, and SHALL NOT report the absence of an escalation mechanism as evidence that none occurred.
8. THE SYSTEM SHALL distinguish the privilege-escalation **tactic** from the **mechanism class**
   that achieved it, and SHALL NOT present a technique as absent from the reconstruction merely
   because it is more commonly cited under a different tactic.

*Criteria 4–8 together prevent a specific and tempting error. In this data privilege appears to
rise `medium → high → SYSTEM`, but the three readings are on three different hosts, so no
within-host rise is evidenced at all (criterion 5). Nothing records privilege being acquired: the
account is already executing at high integrity 54 seconds after authenticating, with no
intervening record (criterion 6) — which is a finding about standing privilege, not about the
adversary. And no event type in this data could record a privilege change even if one had
happened, so "no escalation mechanism observed" is guaranteed regardless of the facts and is a
statement about coverage (criterion 7).*

*Criterion 8 exists because the obvious wording of this is wrong. ATT&CK maps **T1078 Valid
Accounts** to the Privilege Escalation tactic among others, so valid-account use is **not** an
alternative to privilege escalation — it is one of its named forms. **T1569.002 Service
Execution** maps to Execution only, so a SYSTEM-level shell obtained through a remote service is
not itself an escalation technique. The accurate statement is therefore not "no
privilege-escalation mechanism observed" but: no exploitation, elevation-bypass or
token-manipulation mechanism is evidenced; privileged access was obtained through valid-account
use, which ATT&CK itself classifies under Privilege Escalation; and no source here could have
recorded an escalation event in any case.*

### Requirement 5 — Establish the scope of compromise `P1`

**As a** CISO, **I want** a complete list of affected hosts, accounts and data, **so that** I can
scope containment, notification and legal obligations.

1. THE SYSTEM SHALL list every host and every account involved in intrusion-related activity, each
   with when it was first and last involved, and the supporting records.
2. WHEN listing them THEN THE SYSTEM SHALL distinguish those confirmed compromised from those
   merely observed, and SHALL state the basis for the distinction.
3. THE SYSTEM SHALL identify every asset observed to be read, collected or removed, with the volume
   where records state it.
4. THE SYSTEM SHALL state which hosts and accounts it cannot rule out, and why.

### Requirement 6 — Ask questions in plain language `P1`

**As a** SOC analyst working under pressure, **I want** to ask questions in my own words, **so
that** I do not have to learn a query language during an incident.

1. THE SYSTEM SHALL accept questions expressed in plain language.
2. WHEN asked any of the ten evaluation questions in §6 THEN THE SYSTEM SHALL answer to the
   criteria stated there.
3. WHEN a question names a particular account, host, address, file or storage location THEN THE
   SYSTEM SHALL report every intrusion-related activity involving it.
4. WHEN a question restricts the period of interest THEN THE SYSTEM SHALL restrict its answer to
   that period and SHALL state the period applied.
5. IF a question concerns a period the data does not cover THEN THE SYSTEM SHALL state the period
   covered and that the question falls outside it.
6. WHEN a question asks for a summary of a stated length THEN THE SYSTEM SHALL respect that length.
7. WHEN a question is asked THEN THE SYSTEM SHALL answer within a stated time.
   `[NEEDS CLARIFICATION: Q2]`

### Requirement 7 — Demonstrate the conclusions were earned `P1`

**As an** evaluator, **I want** to confirm the system reached its conclusions by examining the
records rather than by reading answers embedded in the supplied data, **so that** I can believe
the approach would work on real logs.

1. WHEN given the same data with developer annotations removed, record identifiers reassigned in a
   different order, sub-second time precision replaced in a way that leaves the true order of
   events unchanged, ordinary activity added for accounts that have none, and the number of
   distinct network addresses per host equalised, THEN THE SYSTEM SHALL produce the same
   intrusion-related activity, the same sequence order, the same relationships and the same
   techniques.
2. THE SYSTEM SHALL use developer annotations for no purpose other than measuring its own accuracy.
3. THE SYSTEM SHALL report its own accuracy against those annotations: what it found, what it
   missed, and what it wrongly included.
4. THE SYSTEM SHALL make the intermediate results of its investigation available for inspection.

*The supplied data reveals the answer five separate ways: an annotation field naming the intrusion
records; record identifiers in which the intrusion occupies the last contiguous block; a
difference in recorded time precision between intrusion and background records; exactly one
account with no ordinary activity, which is the compromised one; and exactly three hosts with a
single network address, which are the three compromised hosts. Each of the five would score
perfectly on this data and teach nothing. Criterion 1 is a black-box test that none was used.*

### Requirement 8 — Produce something that can be handed over `P2`

**As a** CISO, **I want** a short summary and a self-contained written record, **so that** I can
brief a board and give something to legal counsel who will never operate this system.

1. WHEN asked for a summary of a stated length THEN THE SYSTEM SHALL produce one in which every
   assertion traces to the reconstruction and residual uncertainty is stated.
2. THE SYSTEM SHALL produce a self-contained Markdown document containing the sequence, the
   relationships between activities, the techniques, the affected hosts, accounts and assets, the
   absent sources, and every citation.
3. WHEN producing that record THEN THE SYSTEM SHALL state the data it was built from, the catalogue
   version, the version of the system, and when it was produced.
4. THE SYSTEM SHALL make that record readable without access to the running system.

### Requirement 9 — Recommend what to do next `P2`

**As an** incident responder, **I want** prioritised actions each tied to specific evidence, **so
that** I can begin containing this before the investigation is complete.

1. WHEN asked what should be done THEN THE SYSTEM SHALL propose ordered actions, each tied to a
   specific evidenced compromise and citing it.
2. WHEN proposing an action THEN THE SYSTEM SHALL classify it as limiting further damage, removing
   the adversary's access, or restoring normal operation.
3. THE SYSTEM SHALL include at least one action addressing an absent log source, rather than only
   the confirmed activity.
4. THE SYSTEM SHALL NOT carry out any such action itself.

### Requirement 10 — Show the working `P2`

**As a** SOC analyst, **I want** to see what the system did to reach an answer, **so that** I can
judge whether the reasoning was sound instead of trusting the output.

1. WHILE an answer is being produced THE SYSTEM SHALL show the steps it is taking.
2. WHEN a derived finding is presented THEN THE SYSTEM SHALL make the rule named under R2.3
   inspectable, including what the rule requires and why it applies to the cited records.
3. WHEN an answer is complete THEN THE SYSTEM SHALL retain the question, the steps taken, the
   citations returned and the versions in use, so that another person can establish how the
   conclusion was reached.

---

## 3. Non-functional requirements

| # | Requirement |
|---|---|
| **NFR-01** | Given the same data and the same question, THE SYSTEM SHALL return the same conclusions and the same citations on every run. |
| **NFR-02** | THE SYSTEM SHALL determine every factual conclusion on the analyst's machine. A service outside that machine MAY be used only to choose the words in which an already-determined conclusion is expressed. WHILE such a service is unavailable, THE SYSTEM SHALL still present every conclusion, in a plainly-rendered form. See §3.1 for the definition of that distinction and the rationale. |
| **NFR-03** | THE SYSTEM SHALL complete a reconstruction of the supplied data within a stated time. `[NEEDS CLARIFICATION: Q2]` |
| **NFR-04** | THE SYSTEM SHALL state what information about the incident leaves the analyst's machine, and SHALL send nothing beyond what is stated. `[NEEDS CLARIFICATION: Q4]` |
| **NFR-05** | THE SYSTEM SHALL leave the supplied data unmodified. |
| **NFR-06** | IF any part of the investigation fails, or the data cannot be read, THEN THE SYSTEM SHALL report what failed and SHALL NOT present an incomplete reconstruction as complete. |
| **NFR-07** | Every output THE SYSTEM produces SHALL identify the version of the system and the period of data behind it. |
| **NFR-08** | THE SYSTEM SHALL be startable by following written instructions, without modification, on the machine used to demonstrate it. |
| **NFR-09** | THE SYSTEM SHALL display recorded times as they appear in the data, with the time zone stated. |
| **NFR-10** | Credentials required to operate THE SYSTEM SHALL NOT be stored alongside it. |

Behaviour beyond the supplied volume of data is not established and will be stated as such.

### 3.1 Conclusion and wording — the NFR-02 boundary

NFR-02 turns entirely on this distinction, so it is defined here rather than left to judgement.

A statement is a **factual conclusion** if altering it would change **which records are cited**,
**what is asserted about them**, **which rule is named** as connecting them, or **which
qualifications accompany the assertion**. Factual conclusions are subject to R2 and R1.9.

Everything else is **wording**: word choice, ordering, length and tone. The test is operational —
if an edit cannot change a citation, an assertion, or a qualification, it is wording.

The third clause is not decoration. A board summary that quietly omits *uncorroborated* contains
no false sentence and is still misleading, so dropping a qualification is a change to the
conclusion, not to its wording. It follows that for the summary in R8.1 and the recommendations
in R9, **which** findings appear, **which** evidence each rests on and **what** qualifications
travel with them are all determined on the analyst's machine; only their phrasing may not be.

**Why NFR-02 exists.** Three reasons, in increasing order of importance:

1. The walkthrough happens in a room. No conclusion may be hostage to network access.
2. NFR-01 requires the same conclusions on every run. A conclusion produced off-machine cannot be
   guaranteed reproducible, so pinning conclusions to local work is what makes NFR-01 achievable
   at all.
3. This document's premise is that a fluent, unsupported conclusion is the primary risk (§1). An
   off-machine generative service is precisely what produces fluent, wrong output. Confining it to
   wording means the worst consequence of a bad generation is an awkward sentence rather than a
   false finding.

A service *running on* the analyst's machine is not outside it, and NFR-02 does not restrict one.
NFR-02 also makes NFR-04 inexpensive: if only wording crosses the boundary, identifiers need not.

---

## 4. Success criteria

| # | Criterion |
|---|---|
| **SC-01** | An analyst with no prior knowledge of the incident can state the initial access, every affected host and account, and whether data was removed, within ten minutes of first use — against six to eight hours manually. |
| **SC-02** | Citation integrity is **100%**, measured separately by class: every value asserted by an atomic observation appears in a cited record, **and** every derived finding names a rule and cites a complete evidence set in which each record fulfils the role that rule assigns it. A single failure of either kind is a defect, not a lower score. |
| **SC-03** | Against the intrusion activity, recall is at least **80%** and precision is at least **70%**, measured as required by Requirement 7 criterion 3. |
| **SC-04** | Across a fixed set of questions about information the data does not contain, the system fabricates nothing and names the absent source every time. |
| **SC-05** | Findings are unchanged under the perturbation in Requirement 7. |

---

## 5. Assumptions

| # | Assumption | If false |
|---|---|---|
| **A-01** | The data's own description of its sources and internal address ranges is accurate | Internal and external activity are misclassified, corrupting the remote-control and data-removal reasoning |
| **A-02** | Developer annotations are accurate enough to measure accuracy against | SC-03 measures agreement with a flawed answer key rather than correctness |
| **A-03** | Exactly one intrusion is present | A second would be folded into the first; R3.9 is the only safeguard |
| **A-04** | Recorded times are accurate, with no drift between source systems | Sequence order may be wrong, and any conclusion drawn from two activities being close in time becomes unreliable |
| **A-05** | For the sources present, the data is complete — a missing record reflects what was collected, not what was exported | The absent-source report blames the environment for an artifact of how the data was supplied |

A-04 and A-05 are unverifiable from inside the data, and both are assumptions practitioners
normally make in silence.

---

## 6. Acceptance scenarios — the ten evaluation questions

Adopted verbatim from the assignment. **Every scenario also requires:** every atomic observation
cites records containing the values it asserts, and every derived finding names its rule and
cites a complete evidence set (R2); no annotation, identifier ordering or time precision
influenced the answer (R7).

| # | The analyst asks… | The system must… |
|---|---|---|
| **AS-01** | "Walk me through the full attack timeline from initial access to last observed activity." | Present one time-ordered sequence covering every stage the data evidences, name those it does not, state the first and last activity, cite every step |
| **AS-02** | "What was the initial access vector and what evidence supports that conclusion?" | Name and cite the evidence of a document application starting a command interpreter; **state that no mail records exist**; name no sender, subject or attachment; state that a single log source supports this |
| **AS-03** | "Which MITRE ATT&CK techniques did the attacker use? List them with technique IDs." | Give identifier, official name, tactic and citation for each; state the catalogue version; report anything it could not map. On privilege: assert **no** exploitation, elevation-bypass or token-manipulation technique; do **not** deny the privilege-escalation tactic, since valid-account use is one of its forms; state that the privilege readings are on different hosts, that the account already held it, and that no source here records privilege changes (R4.4–R4.8) |
| **AS-04** | "Which user accounts were compromised or used by the attacker?" | Identify every such account with citations, each resting on evidenced behaviour; separate confirmed compromise from mere observation; note where an account has no ordinary activity to compare against **as a limitation on the assessment, never as grounds for it** (R1.10) |
| **AS-05** | "Which internal hosts did the attacker move to after the initial foothold?" | Identify every subsequent host in the order reached, with citations; name the authentication and the remote-service-creation activity evidencing the movement; flag any host identification resting on an uncertain address association |
| **AS-06** | "Is there evidence of data exfiltration? If so, what was accessed and when?" | Answer yes; name the file, exact size, destination, its external ownership, the client used and the time; establish the link between the archive staged on the host and the upload to the external destination, citing the record on each side; then separate the three levels of support — the **upload itself** is recorded by cloud storage alone; the **staging-to-upload link** is corroborated by endpoint and cloud storage together; and **no network record independently corroborates the transfer path** |
| **AS-07** | "What is the blast radius — list every affected host and account." | Enumerate every host and account with first and last involvement and citations; name the assets and volume; state what cannot be ruled out, including hosts that appear in the incident but about which a relevant source records nothing |
| **AS-08** | "Where are the gaps in our log coverage that limit your confidence in this reconstruction?" | Report the absent mail and name-resolution sources, the absence of any event type able to record a privilege change, the uncorroborated transfer path, the uneven endpoint coverage, the unobserved tool transfer and the unobserved credential removal — each tied to the conclusion it limits |
| **AS-09** | "Give me a 3-sentence executive summary suitable for a board briefing." | Exactly three sentences, every assertion traceable, residual uncertainty stated, nothing beyond the evidence |
| **AS-10** | "What should the incident response team do in the next 2 hours to contain this?" | Ordered actions, each citing the evidence that motivates it and classified as limiting damage, removing access or restoring operation; at least one addressing an absent source |

**What this suite is and is not.** These ten scenarios are a **regression suite for this one
supplied incident**. They were written after reading the developer annotations, so they encode
its known answer. Passing them shows the system reproduces this incident correctly; it is **not**
evidence that the system generalises to an incident it has not seen, and no claim of
generalisation follows from it. Requirement 7 is the only check that constrains *how* the answer
was reached rather than what it is.

---

## 7. Out of scope

| Excluded | Reason |
|---|---|
| Data other than the supplied set | Generality would be an untested claim |
| Continuous or live collection | The supplied data is a fixed three-day export |
| More than one incident | Incident scoping is a different product |
| Identity, access control and concurrent use | One analyst, one machine |
| Accessibility conformance | Not evaluated here; a conformance claim would cost budget that investigation quality needs |
| Reputation lookup for external addresses | Requires an outside service, conflicting with NFR-02; no conclusion depends on it |
| Exporting detection rules for other tools to run | The repeatable reasoning that attributes activity to the intrusion is **in scope** — it is how attribution happens, and every conclusion names the reasoning behind it (R1.9, R10.2). What is excluded is publishing that reasoning in a portable form for other systems to consume |
| Carrying out containment | The system advises; a person acts. Acting on a possibly-wrong reconstruction is the failure this document exists to prevent |
| Comparing behaviour against a normal baseline | Attribution may never rest on behaviour being unusual (R1.10), so a baseline cannot serve the purpose one is normally built for. Using it to prioritise what an analyst reviews first is *permitted* by R1.10 but is not built in this iteration: three days is too short to establish a norm, and no P1 outcome depends on it |
| Follow-up questions that refer back to earlier ones; showing the activity examined and dismissed | Both considered and deferred — useful, but not needed for any P1 outcome |

---

## 8. Open questions

| # | Question | Blocks | Proposal |
|---|---|---|---|
| **Q1** | What vocabulary expresses evidential strength — the intelligence community's estimative terms with a separate confidence statement, or a simpler three-tier scale? And is a conclusion resting on a single source **weakly** supported even when that source directly records the act? The upload record is the case in point: one source records the act itself, while the staging-to-upload link beside it carries two | R3.2, R3.3 | Separate the likelihood of a claim from the strength of its evidence; never combine them in one sentence. Second half unresolved |
| **Q2** | How long may the system take to reconstruct the data, and to answer one question? | NFR-03, R6.7 | 10 seconds; 60 seconds |
| **Q4** | The client is a healthcare organisation. May log content be sent unrestricted to a service outside the analyst's machine, or must it be reduced first? | NFR-04 | **Unresolved — shapes the whole design** |

---

## 9. Review checklist

- [ ] No implementation detail: no architecture, no components, no technology
- [ ] Every acceptance criterion is testable and unambiguous
- [ ] No `[NEEDS CLARIFICATION]` markers remain
- [ ] The ten requirements in §2 are the right ones, at the right priorities
- [ ] The success criteria in §4 are the right measures
- [ ] The assumptions in §5 are acceptable, in particular A-04 and A-05
- [ ] The acceptance scenarios in §6 are what the system should be judged against
- [ ] The exclusions in §7 are the right exclusions
