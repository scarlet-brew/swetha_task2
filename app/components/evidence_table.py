"""Tables, via pyarrow rather than pandas.

This module settles the last unmeasured assumption in design SS10.1. That
section dropped `pandera` and `streamlit-aggrid` on measured grounds -- both
reach `pandas._libs.join`, which this machine's Application Control policy
blocks -- and asserted without measuring that `st.dataframe` over
`pyarrow.Table.from_pylist` "covers the need via narwhals".

Measured at T07: it does, and more cleanly than SS10.1 hoped. With every
`pandas` import blocked by a `sys.meta_path` hook, `st.dataframe` given a
`pyarrow.Table` still renders -- Streamlit serialises Arrow to Arrow IPC and
never constructs a DataFrame. See `tests/test_ui_render.py`, which runs that
blocked render in a subprocess so the hook cannot leak into the rest of the
suite.

One caveat worth recording, because it will bite the next person: the
*inspection* helper `AppTest.dataframe[i].value` does convert to pandas, via
`pyarrow.Table.to_pandas`. That is test scaffolding, not a render path. Tests
read `proto.arrow_data.data` back with `pyarrow.ipc` instead.

Every table surface in the app goes through here, so there is exactly one place
where a DataFrame could creep back in.
"""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence

import pyarrow as pa
import streamlit as st

#: Types Arrow infers cleanly and a reader can sort on. Anything else in a
#: column, or any mixture, is rendered as text -- see `_coerce_column`.
_SCALAR_TYPES = (str, int, float, bool)


class EmptyTable(ValueError):
    """No rows to build a table from.

    Raised rather than rendering an empty frame, because an empty table and an
    absent table look identical on screen and mean very different things in a
    system whose job is to distinguish "nothing happened" from "nothing was
    recorded". Callers decide which message to show.
    """


def _as_text(value: object) -> str:
    """One cell as a string a reader can compare by eye.

    Containers go through `json.dumps(sort_keys=True)` rather than `str`, so a
    dict cell reads as JSON -- the same notation as the raw record under the
    citation it sits beside -- instead of as Python repr with single quotes.
    """
    if isinstance(value, str):
        return value
    if isinstance(value, (Mapping, list, tuple)):
        return json.dumps(value, sort_keys=True, ensure_ascii=False, default=str)
    return str(value)


def _coerce_column(values: list[object]) -> list[object]:
    """Keep a homogeneous scalar column typed; render anything else as text.

    Measured at T07, and the one real difference from the pandas route SS10.1
    dropped: Arrow has no `object` dtype. `pa.Table.from_pylist` infers a
    column type from the values and raises `ArrowTypeError` on a mixture, where
    pandas would have silently produced an object column.

    That matters because a citation table is heterogeneous by nature --
    `asserted_value` holds a process name on one row and a byte count on the
    next -- so the mixture is the normal case, not an edge case. Coercing the
    whole table to text would be the easy fix and the wrong one: it would cost
    numeric sorting and right alignment on `bytes` and `ratio` columns, which
    are the columns a reader scans. So the choice is per column.
    """
    present = [value for value in values if value is not None]
    if not present:
        return values
    kinds = {type(value) for value in present}
    if len(kinds) == 1 and next(iter(kinds)) in _SCALAR_TYPES:
        return values
    return [None if value is None else _as_text(value) for value in values]


def arrow_table(
    rows: Sequence[Mapping[str, object]], *, columns: Sequence[str] | None = None
) -> pa.Table:
    """`rows` as a `pyarrow.Table`, with a stable column order.

    `columns` fixes the order and the projection. Without it, column order
    would follow whichever key order the first row happened to have, which
    makes a table's layout depend on dict construction order somewhere
    upstream.

    Missing keys become nulls rather than an error: a citation list where one
    row lacks `field` is a real shape in this data (SS3.2's resolution rows
    carry different keys), and dropping the row would hide evidence to keep a
    table rectangular.
    """
    if not rows:
        raise EmptyTable("no rows")
    order = list(columns) if columns is not None else list(dict.fromkeys(
        key for row in rows for key in row
    ))
    coerced = {key: _coerce_column([row.get(key) for row in rows]) for key in order}
    # Rebuilt row-wise and handed to `from_pylist` rather than to
    # `from_pydict`. The app's data is row-oriented -- a list of citation dicts,
    # a list of artifact dicts -- and SS10.1's open question was specifically
    # whether `from_pylist` covers the need, so this keeps the measured path
    # and the shipped path the same one. The coercion above is a pre-pass over
    # the same rows, not a change of representation.
    normalised = [
        {key: coerced[key][index] for key in order} for index in range(len(rows))
    ]
    return pa.Table.from_pylist(normalised)


def render_table(
    rows: Sequence[Mapping[str, object]],
    *,
    columns: Sequence[str] | None = None,
    empty_message: str = "No rows.",
    height: int | str = "auto",
) -> pa.Table | None:
    """Render `rows` as a real table, or the empty message. Returns the table.

    `hide_index` is on because an Arrow table has no index to show and a row
    number implies an ordering the data may not have. Returning the table lets
    a test assert the Arrow schema that was rendered without re-deriving it.
    """
    try:
        table = arrow_table(rows, columns=columns)
    except EmptyTable:
        st.caption(empty_message)
        return None
    st.dataframe(table, hide_index=True, width="stretch", height=height)
    return table
