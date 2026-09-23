# Architecture diagrams

Four views of the design in [../specs/design.md](../specs/design.md). Mermaid renders on GitHub
and in most Markdown viewers.

---

## 1 · The six-stage pipeline

The assignment names these six stages, and describes the predecessor tool as having had *"no
correlation across sources, no timeline reconstruction, and no connection to known attack
techniques."* Those are exactly stages 3, 5 and 4 — so the pipeline in the brief is an inventory of
what the predecessor lacked.

Every model step is followed by a deterministic gate it cannot bypass.

```mermaid
flowchart TB
    RAW[("data/raw/siem_logs.json
    242 records · 4 source types · read-only")]
    CAT[("data/attack/
    official ATT&CK v19.2 STIX bundle
    + derived flat catalogue")]

    subgraph BUILD["BUILD — run once · artifacts committed · credential required"]
        direction TB
        ING["1 · INGEST — deterministic
        records loaded verbatim
        note stripped at the parse boundary"]
        PAR["2 · PARSE — deterministic
        role-tagged entities · normalisation provenance
        address to host candidates with ambiguity"]
        COR["3 · CORRELATE — four layers
        facts (code) to interpretation (model) to validation"]
        ENR["4 · ENRICH WITH ATT&CK
        technique selected from a retrieved enum, then validated"]
        SYN["5 · SYNTHESISE — deterministic
        timeline · scope · gaps · Attack Flow · Navigator"]
        ING --> PAR --> COR --> ENR --> SYN
    end

    DER[("data/derived/
    sorted JSONL — the committed audit representation")]

    subgraph QUERY["QUERY — live · no credential present"]
        direction TB
        ANS["6 · ANSWER — model + read-only tools
        retrieve, reason, cite existing nodes"]
        CHK{"citation gate
        deterministic"}
        ANS --> CHK
    end

    OUT["analyst
    chat · timeline · impact · pipeline"]
    REP["handover report
    self-contained Markdown"]
    WH["withheld
    + which check failed"]

    RAW --> ING
    CAT -.-> ENR
    CAT -.-> ANS
    SYN --> DER
    DER --> ANS
    DER --> OUT
    DER --> REP
    CHK -->|all citations resolve| OUT
    CHK -->|any check fails| WH

    classDef model fill:#4a3f6b,stroke:#8b7fb8,color:#fff
    classDef gate fill:#6b3f3f,stroke:#b88b8b,color:#fff
    classDef store fill:#3f4a6b,stroke:#7f8bb8,color:#fff
    class COR,ENR,ANS model
    class CHK gate
    class RAW,CAT,DER store
```

Note what this makes visible: **`data/attack/` feeds both planes, but the credential exists only in
the build plane.** The app reads committed artifacts and has no path to an outside service, which
is why it runs with the key unset and the network down.

---

## 2 · Inside `correlate` — four layers

The boundary that the whole design turns on: **the deterministic layer emits facts and decides
nothing; the model interprets facts and computes nothing.**

```mermaid
flowchart TB
    OBS["DIRECT OBSERVATIONS
    values present at named fields of records
    + normalisation provenance"]

    subgraph FACT["FACTUAL CORRELATION LAYER — deterministic · total · decides nothing"]
        direction TB
        REL["ten atomic relations, zero detection rules
        same_account · same_host · same_address · same_file · same_size
        process_parent · temporal_within (Δ reported) · flow_endpoint
        session_bracket · address_resolves_to_host"]
    end

    GRAPH["CORRELATION / EVIDENCE GRAPH
    virtual — relations are queried, not materialised
    the traversed subgraph is what gets committed"]

    subgraph AI["AI INVESTIGATION LAYER — non-deterministic · interpretive"]
        direction TB
        SEL["SELECT — anchors first, then the frontier"]
        EXP["EXPAND — neighbourhood, with truncation reported"]
        INT["INTERPRET — propose a finding citing specific edges"]
        HYP["HYPOTHESISE — what should exist, committed before looking"]
        SEK["SEEK — FOUND | NOT_FOUND | NOT_COVERED"]
        SEL --> EXP --> INT --> HYP --> SEK
        SEK -.->|new observations| SEL
    end

    CAND["CANDIDATE FINDINGS
    statement · stage · cites_obs · cites_edges · rationale"]
    VAL{"VALIDATION — six deterministic checks"}
    INV["INVESTIGATION GRAPH"]
    REJ["rejection log
    the coverage backlog"]

    OBS --> REL --> GRAPH --> SEL
    INT --> CAND --> VAL
    VAL -->|accept| INV
    VAL -->|reject with diagnostic| REJ
    REJ -.->|back-prompt, bounded| INT

    classDef det fill:#3f5a4a,stroke:#7fb894,color:#fff
    classDef model fill:#4a3f6b,stroke:#8b7fb8,color:#fff
    classDef gate fill:#6b3f3f,stroke:#b88b8b,color:#fff
    class REL,GRAPH det
    class SEL,EXP,INT,HYP,SEK model
    class VAL gate
```

Two consequences worth stating: there is **no coverage ceiling** in the factual layer because
nothing is being detected, and the model **cannot invent a relationship** — only interpret ones
that factually exist.

`temporal_within` **reports** Δ rather than thresholding it, which is why no global time window has
to be chosen. The intrusion's own gaps between related activities span 2 seconds to 2 h 27 min.

---

## 3 · The provenance model

```mermaid
classDiagram
    direction TB

    class RawLogRecord {
        id : rec_ + sha256 prefix
        source_type
        recorded_time
        payload : byte-identical
    }
    class DirectObservation {
        id : obs_
        field
        raw_value
        transform
        normalised_value
    }
    class FactualEdge {
        id : edg_
        relation
        ordered endpoints
        params : reported, not identity
    }
    class DerivedFinding {
        id : fnd_
        statement : NOT part of identity
        stage
        support_label
        flags
    }
    class TechniqueMapping {
        id : map_
        technique_id
        technique_ref
        tactic
        quoted_values
        catalogue_version
    }
    class Hypothesis {
        id : hyp_
        predicted entity/role/kind/source/window
        status : proposed|confirmed|unconfirmed|uncoverable
    }
    class AnswerClaim {
        text
        question
        NOT in the committed graph
    }

    DirectObservation --> "1..*" RawLogRecord : cites at named field
    FactualEdge --> "2" DirectObservation : relates
    DerivedFinding --> "1..*" DirectObservation : cites
    DerivedFinding --> "1..*" FactualEdge : cites
    DerivedFinding --> "0..*" DerivedFinding : cites
    TechniqueMapping --> "1" DerivedFinding : attaches to
    TechniqueMapping --> "1..*" DirectObservation : cites
    Hypothesis --> "1..*" DerivedFinding : premised on
    AnswerClaim --> "1..*" DerivedFinding : cites
    AnswerClaim --> "0..*" DirectObservation : cites

    note for RawLogRecord "cites nothing — every chain terminates here"
    note for AnswerClaim "attribution requires at least one finding citation"
```

**Five invariants, all machine-decidable — this is the trust story:**

1. **Layer order** — a record cites nothing; an observation cites only records; a finding cites
   observations, findings and edges; a claim cites findings, mappings or observations
2. **Termination** — every chain bottoms out in raw records
3. **Acyclicity** — no node transitively supports itself
4. **Grounding** — every asserted value appears at a named field of a cited record
5. **Normalisation reproducibility** — re-applying a recorded transform to its recorded raw value
   yields the asserted value

---

## 4 · The validation gates

```mermaid
flowchart LR
    P["candidate finding"] --> C1{"cited observations
    all exist?"}
    C1 -->|no| R1["REJECT
    O7 does not exist"]
    C1 -->|yes| C2{"every cited edge
    re-evaluates true?"}
    C2 -->|no| R2["REJECT
    same_size(O7,O9) does not hold"]
    C2 -->|yes| C3{"every identifier in the
    statement appears in a
    cited observation?"}
    C3 -->|no| R3["REJECT
    PSEXESVC not in any cited observation"]
    C3 -->|yes| C4{"stage in the
    closed vocabulary?"}
    C4 -->|no| R4["REJECT
    unknown stage"]
    C4 -->|yes| C5{"layer order · acyclic ·
    terminates in records?"}
    C5 -->|no| R5["REJECT
    cycle, with the path"]
    C5 -->|yes| A["ACCEPT
    into the graph"]
    A --> C6{"AT CLOSE ONLY
    no two accepted findings
    mutually incompatible?"}
    C6 -->|conflict| R6["REPORT the incompatibility
    cite every record involved"]
    C6 -->|consistent| DONE["INVESTIGATION GRAPH"]

    classDef reject fill:#6b3f3f,stroke:#b88b8b,color:#fff
    classDef accept fill:#3f6b4a,stroke:#7fb88b,color:#fff
    class R1,R2,R3,R4,R5,R6 reject
    class A,DONE accept
```

Check 3 does the most work in practice, and it is cheap and total. Check 6 is deferred to close
deliberately: acyclicity and mutual compatibility are **set-level** properties, so two findings can
each be individually valid and jointly inconsistent.

Every rejection carries a **specific** diagnostic, not a boolean — which is what makes the
rejection log a coverage backlog rather than noise, and what the bounded back-prompt feeds on.

---

## What these diagrams deliberately do not claim

The gates validate citations, edges, identifiers, vocabulary and structure. **They do not validate
whether an interpretation is apt.** A finding can cite real observations and real edges, name only
real identifiers, and still conclude wrongly — the test oracle problem, irreducible here. See
§13 of [design.md](../specs/design.md) for the full unsoundness statement.
