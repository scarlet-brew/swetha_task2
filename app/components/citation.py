"""The answer body and its citations, rendered as top-level siblings.

This is the layout design SS9.4 calls a day-one constraint, and the reason it
is one:

    The natural layout for cited prose is an expander per claim with an
    expander per citation inside it. Streamlit's historical answer to that was
    `StreamlitAPIException: Expanders may not be nested inside other
    expanders`, and retrofitting the flat layout later is a rewrite of the
    render loop rather than a local change.

So every expander this module emits is a direct child of the `st.chat_message`
container: the answer body, then each claim's support line, then that claim's
citation expanders, all at one level. Grouping is carried by order and by
headings, never by nesting. The second drill-down -- citation to raw record --
is `st.json(body, expanded=2)` inside the citation, which needs no second
expander.

Measured at T07 on streamlit 1.64.0, and recorded because it changes what the
check means: 1.64 raises *no* exception for nested expanders; the backend guard
is gone. The sibling layout is therefore no longer forced by the engine on this
version. It is kept anyway, and `tests/test_ui_sibling_render.py` asserts the
structural property against the *rendered* tree -- no expander has an expander
ancestor -- rather than only the absence of an exception, which is an assertion
that cannot quietly become vacuous the way "no exception was raised" just did.

Expansion state is keyed in `st.session_state` through each expander's `key`
plus `on_change="rerun"`. Without `on_change="rerun"` an expander does not
track state at all: `.open` returns None and the key never appears in session
state, so a rerun would silently collapse every citation the reader had opened.

Record lookup sits behind `@st.cache_data`, keyed on the records file's path
and mtime, so a rebuild of `01_records.jsonl` invalidates it rather than
serving a stale record under a citation.
"""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import streamlit as st

from app.components import evidence_table, support_badge

#: Columns of the per-claim citation table, in reading order: what was cited,
#: where it came from, when, and which value it carries. R2.2 requires source,
#: recorded time and identifier on a cited record; the rest is what makes the
#: table scannable.
CITATION_COLUMNS = (
    "node_id",
    "layer",
    "record_id",
    "event_id",
    "source_type",
    "timestamp",
    "field",
    "asserted_value",
)

#: Keys the payload must carry. Checked rather than assumed: the emitter lands
#: at T31 and this layout is its contract (docs/specs/answer_payload.md), so a
#: missing key has to fail by name here rather than render as a blank panel.
REQUIRED_PAYLOAD_KEYS = ("answer_id", "question", "body", "claims")
REQUIRED_CLAIM_KEYS = ("claim_id", "text", "kind", "support", "citations")


@dataclass
class RenderReport:
    """What the render found, for the caller and for the tests.

    `unresolved` is the load-bearing field. R2.9 says an answer citing an
    identifier that does not exist must be withheld and the failure reported;
    this module cannot withhold an answer on its own -- that is the gate's job
    at stage 6 -- so it reports every citation it could not resolve, renders an
    error in place of the record, and lets the caller decide.
    """

    answer_id: str
    claims: int = 0
    citations: int = 0
    expanded: list[str] = field(default_factory=list)
    unresolved: list[str] = field(default_factory=list)


class PayloadError(ValueError):
    """The answer payload does not match the contract this layout requires."""


def _require(obj: Mapping[str, Any], keys: Sequence[str], what: str) -> None:
    missing = [key for key in keys if key not in obj]
    if missing:
        raise PayloadError(
            f"{what} is missing {missing}; see docs/specs/answer_payload.md"
        )


def validate_payload(payload: Mapping[str, Any]) -> None:
    """Check a payload against the contract without rendering it.

    Separate from `render_answer` so stage 6 can validate what it is about to
    emit, and so a test can assert the contract without a script run. It checks
    *shape*, not truth: whether the citations resolve is a question for the
    render, and whether the claims are warranted is the gate's.
    """
    _require(payload, REQUIRED_PAYLOAD_KEYS, "answer payload")
    claims = payload["claims"]
    if not isinstance(claims, Sequence) or isinstance(claims, (str, bytes)):
        raise PayloadError("answer payload `claims` must be a sequence")
    for index, claim in enumerate(claims, start=1):
        _require(claim, REQUIRED_CLAIM_KEYS, f"claim {index}")
        _require(claim["support"], ("label",), f"claim {index} support")
        if not claim["citations"]:
            # R2.2 and R2.3: an uncited claim is a bug, not an empty state.
            raise PayloadError(f"claim {index} cites nothing")


@st.cache_data(show_spinner=False)
def load_records(path: str, mtime: float) -> dict[str, dict]:
    """`01_records.jsonl` as `{record id: record}`.

    `mtime` is part of the cache key and is otherwise unused: it is what makes
    a rebuilt records file invalidate the cache instead of the UI serving a
    record that no longer exists under a citation that still points at it.

    D-10 fixes the committed representation as one JSON object per line keyed
    by `id` (`jsonl.write(..., id_key="id")`). A line without an id is skipped
    rather than guessed at, because a record the UI cannot address by id is
    indistinguishable from an absent one and R2.9 wants that said, not patched.
    """
    records: dict[str, dict] = {}
    file = Path(path)
    if not file.is_file():
        return records
    with file.open("r", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            obj = json.loads(line)
            record_id = obj.get("id")
            if isinstance(record_id, str):
                records[record_id] = obj
    return records


def records_from_file(path: str | Path) -> dict[str, dict]:
    """`load_records` with the mtime read for you, or `{}` if absent."""
    file = Path(path)
    if not file.is_file():
        return {}
    return load_records(str(file), file.stat().st_mtime)


def _citation_rows(citations: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    return [{key: citation.get(key) for key in CITATION_COLUMNS} for citation in citations]


def _citation_label(citation: Mapping[str, Any]) -> str:
    """The expander header: what, from where, when.

    R2.2 asks for source, recorded time and identifier on every cited record,
    and this is the line a reader scans before deciding to open anything, so
    all three are in the header rather than inside it. Times are shown exactly
    as recorded with the zone named (R7.5) -- never reformatted, because a
    reformatted timestamp is no longer the evidence.
    """
    parts = [
        str(citation.get("node_id") or citation.get("record_id") or "?"),
        str(citation.get("source_type") or "unknown source"),
        str(citation.get("timestamp") or "no recorded time"),
    ]
    zone = citation.get("zone")
    if zone:
        parts[-1] = f"{parts[-1]} {zone}"
    return "  ·  ".join(parts)


def _render_citation(
    citation: Mapping[str, Any],
    *,
    records: Mapping[str, Mapping[str, Any]],
    key: str,
    report: RenderReport,
) -> None:
    """One citation, as a top-level sibling expander.

    Called from the chat-message container directly and never from inside
    another expander -- that placement is the whole point of the module, and
    the render test asserts it structurally.
    """
    default_open = bool(citation.get("open_by_default", False))
    box = st.expander(
        _citation_label(citation),
        expanded=default_open,
        key=key,
        on_change="rerun",
    )
    is_open = st.session_state.get(key, default_open)
    if is_open:
        report.expanded.append(key)

    with box:
        layer = citation.get("layer", "unknown layer")
        st.caption(f"{layer} · cites record `{citation.get('record_id', '?')}`")
        if citation.get("field") is not None:
            st.markdown(
                f"asserts `{citation.get('field')}` = `{citation.get('asserted_value')}`"
            )

        record_id = citation.get("record_id")
        body = records.get(record_id) if isinstance(record_id, str) else None
        if body is None:
            report.unresolved.append(str(record_id))
            st.error(
                f"Cited record `{record_id}` does not resolve in the records "
                "authority. Under R2.9 an answer resting on it must be withheld "
                "rather than shown without it.",
                icon=":material/link_off:",
            )
            return

        # Only render the record when the expander is open. With
        # on_change="rerun" the container reports its own state, so a closed
        # citation costs nothing -- which is what keeps a long answer inside
        # NFR-03's render budget.
        if is_open:
            st.json(body, expanded=2)


def render_claim(
    claim: Mapping[str, Any],
    *,
    records: Mapping[str, Mapping[str, Any]],
    key_prefix: str,
    report: RenderReport,
    index: int,
) -> None:
    """One claim: the statement, its support, its basis, its citations.

    Order is deliberate. R2.1 classifies the statement, R3.2 labels the
    structure of its support, R2.3 names the basis, and only then come the
    citations -- so a reader who stops reading after three lines has still been
    told what kind of claim it is and how strong the support is.
    """
    _require(claim, REQUIRED_CLAIM_KEYS, f"claim {index}")
    report.claims += 1

    support = claim["support"]
    st.markdown(f"**C{index}.** {claim['text']}")
    st.markdown(
        f"`{claim['kind']}`  "
        + support_badge.support_markup(support["label"], support.get("flags", ()))
    )

    basis = claim.get("basis")
    if basis:
        # R2.3 and R10.2: the basis is named, and what it requires and why it
        # applies are inspectable rather than implied.
        st.caption(
            f"Basis **{basis.get('name', 'unnamed')}** — requires "
            f"{basis.get('requires', 'unstated')}; applies because "
            f"{basis.get('applies_because', 'unstated')}"
        )

    citations = list(claim["citations"])
    report.citations += len(citations)
    evidence_table.render_table(
        _citation_rows(citations),
        columns=CITATION_COLUMNS,
        empty_message=(
            "No citations on this claim — under R2.2 and R2.3 that is a bug, "
            "not an empty state."
        ),
    )

    for citation in citations:
        _render_citation(
            citation,
            records=records,
            key=f"{key_prefix}::{claim['claim_id']}::{citation.get('node_id')}",
            report=report,
        )


def render_answer(
    payload: Mapping[str, Any],
    *,
    records: Mapping[str, Mapping[str, Any]] | None = None,
    key_prefix: str | None = None,
) -> RenderReport:
    """Render one answer inside `st.chat_message`, citations as siblings.

    `records` is injected rather than looked up here so that the same component
    renders a real answer over `01_records.jsonl` and the layout specimen over
    its own bundled records, with no branch inside the render path and no test
    hook in production code.
    """
    validate_payload(payload)
    prefix = key_prefix or f"cite::{payload['answer_id']}"
    report = RenderReport(answer_id=str(payload["answer_id"]))
    resolved = records or {}

    with st.chat_message("assistant"):
        body = payload["body"]
        for paragraph in [body] if isinstance(body, str) else list(body):
            st.markdown(paragraph)

        for index, claim in enumerate(payload["claims"], start=1):
            render_claim(
                claim,
                records=resolved,
                key_prefix=prefix,
                report=report,
                index=index,
            )

        gaps = payload.get("gaps") or []
        if gaps:
            # R3.6: the absent sources and what their absence limits are
            # reported without being asked, so they are part of the answer
            # rather than a separate page the reader might not visit.
            st.markdown("**Gaps limiting this answer**")
            for gap in gaps:
                if isinstance(gap, Mapping):
                    line = str(gap.get("statement", ""))
                    if gap.get("limits"):
                        line += f" — limits: {gap['limits']}"
                else:
                    # A bare string is a gap with no stated limit. Accepted
                    # rather than rejected: R3.6 asks for the absence to be
                    # reported, and refusing to render it would suppress it.
                    line = str(gap)
                st.markdown(f"- {line}")

        provenance = payload.get("provenance")
        if provenance:
            # R10.3: the versions in use, retained with the answer.
            st.caption(
                " · ".join(f"{key} {value}" for key, value in sorted(provenance.items()))
            )

    return report
