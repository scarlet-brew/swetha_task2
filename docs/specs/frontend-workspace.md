# Approved incident workspace implementation

This specification implements the user-approved design study 05. It supersedes the previous Streamlit presentation decisions for the primary analyst interface. The original Streamlit pages remain available as a legacy diagnostic surface. The investigation engine, evidence graph, model contract and stored artifacts remain unchanged.

## Requirements and design

- Brief, Timeline, Systems & accounts, Evidence and How it works appear in horizontal navigation. The assistant is available from every page.
- Use the approved narrow chat panel, original welcome layout, readable answers and visible source buttons. Return from a source to the preserved conversation; support expanded reading and mobile full-screen chat.
- All displayed findings come from the saved pipeline artifacts. No scripted answers, hardcoded attack path, curated sample host lists or inferred compromise labels ship in the application.
- Every answer goes through the existing `answer.ask` and its citation gate. Withheld answers remain withheld. The UI expands backend citation nodes to all underlying records and shows individual claim-to-source relationships.
- Original source records show event ID, source and timestamp. Development annotations are excluded. Model and log text is escaped before rendering.
- Recognize missing artifacts, changing builds, mismatched build contracts, absent credentials, service errors and citation-gate rejection. Do not silently substitute preview answers.
- The frontend shares one snapshot revision. If artifacts change during an answer, withhold it and request a refresh. Refreshing to a new snapshot clears the old conversation.
- Export an evidence-linked plain-text brief from the same snapshot. Read-only API; no rebuild or containment buttons.

## Implementation choice

Use the existing approved HTML/CSS with browser JavaScript and a small standard-library Python HTTP server. This avoids an additional React/Node build chain and preserves the side-panel interaction without Streamlit DOM workarounds. No Python dependency changes are needed. `workspace_service.py` adapts the current artifact and answer contracts; it does not create findings or bypass backend validation.

The server is intentionally a local interview prototype: loopback binding, host validation, a per-process request token, same-origin checks and no remote assets. Production deployment would require an appropriate application server, authentication, authorization, durable sessions and access controls. The UI does not claim production readiness.

## Tasks and acceptance

1. Build the read-only snapshot and gated answer adapter.
2. Implement all five approved views against that adapter.
3. Implement pending/error/withheld states, source inspection, claim-level references, follow-up context and export.
4. Test source resolution, refresh/revision guards, HTML escaping, browser flows and responsive layout.
5. Supply a launcher and operational notes. Validate with current artifacts without rewriting the backend.

Follow-up context currently includes the preceding four user questions, not previous AI prose. This avoids promoting generated statements to evidence; specific references to prior answer paragraphs may need a self-contained question.
