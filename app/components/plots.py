"""The only two charts in the application (design SS9.3, T43).

Most of this system is not a chart. A timeline whose job is to be *read* in
order with the evidence opened beside it is a table; an enumeration of affected
hosts is a table. Two things genuinely are charts, because both answer a
question about *shape* that a table cannot:

* **Source-type lanes** -- where the activity sits in the 72-hour window. This
  is what makes "twelve hours of intrusion inside a three-day window" legible
  at a glance.
* **Coverage matrix** -- which hosts are visible to which sources. A grid of
  presence and absence, which is a status question.

**The key decision: position carries identity, colour carries state.** One lane
per source type means the lane *is* the label, so colour is free to say
intrusion-attributed versus background. The consequence is that there are **zero
categorical series anywhere in this application**, which sidesteps the
colourblind-safety ceiling on multi-series palettes entirely rather than working
around it.

Rendered through `st.vega_lite_chart` with the data inline in the spec.

One honest note: **this is not a pandas-free path.** Measured by blocking every
`pandas` import and rendering, `st.vega_lite_chart` reaches pandas through
Streamlit's Vega integration even when handed a plain dict. The *table* path
does avoid it, and `tests/test_ui_sibling_render.py` proves that; the chart path
does not, and saying otherwise would be a claim the code does not support.
Colours come from `theme.palette()`, which reads the same measured hex values
`config.toml` holds and the contrast test checks. The chart font is the app's
system sans, so nothing is fetched to render one.
"""

from __future__ import annotations

from typing import Any

import streamlit as st

from app import theme

#: Every mark is at least this many pixels, per the mark specs.
MARK_SIZE = 70


def _colours(mode: str = "light") -> dict[str, str]:
    palette = theme.palette(mode)
    return {
        "attributed": palette["ink"],
        "background": palette["ink_muted"],
        "surface": palette["panel"],
        "rule": palette["rule"],
        "baseline": palette["baseline"],
        "text": palette["ink"],
        "muted": palette["ink_muted"],
    }


def source_type_lanes(
    records: list[dict], attributed_events: set[str], *, height: int = 260
) -> None:
    """One lane per source type across the collection window.

    Two colours, both from the measured palette: ink for a record an accepted
    finding cites, muted ink for everything else. A legend is present because
    there are two series, and the lane labels carry identity independently, so
    the encoding never rests on colour alone.
    """
    colours = _colours()
    values = [
        {
            "recorded_time": record["recorded_time"],
            "source_type": record["source_type"],
            "state": "cited by a finding"
            if record["event_id"] in attributed_events
            else "not cited",
            "event_id": record["event_id"],
            "event_name": record["event_name"],
        }
        for record in records
    ]

    spec: dict[str, Any] = {
        "$schema": "https://vega.github.io/schema/vega-lite/v5.json",
        "background": colours["surface"],
        "height": height,
        "autosize": {"type": "fit", "contains": "padding"},
        "mark": {"type": "circle", "size": MARK_SIZE, "opacity": 0.85},
        "encoding": {
            "x": {
                "field": "recorded_time",
                "type": "temporal",
                "title": "recorded time (UTC)",
                "axis": {
                    "grid": True,
                    "gridColor": colours["rule"],
                    "domainColor": colours["baseline"],
                    "tickColor": colours["baseline"],
                    "labelColor": colours["muted"],
                    "titleColor": colours["muted"],
                },
            },
            "y": {
                "field": "source_type",
                "type": "nominal",
                "title": None,
                "sort": ["endpoint", "auth", "network", "cloud_storage"],
                "axis": {
                    "grid": True,
                    "gridColor": colours["rule"],
                    "domainColor": colours["baseline"],
                    "labelColor": colours["text"],
                    "tickColor": colours["baseline"],
                },
            },
            "color": {
                "field": "state",
                "type": "nominal",
                "scale": {
                    "domain": ["cited by a finding", "not cited"],
                    "range": [colours["attributed"], colours["background"]],
                },
                "legend": {
                    "orient": "top",
                    "title": None,
                    "labelColor": colours["text"],
                },
            },
            # Hover by default: an HTML chart is interactive, so it ships with
            # a per-mark tooltip rather than needing one asked for.
            "tooltip": [
                {"field": "event_id", "title": "event"},
                {"field": "source_type", "title": "source"},
                {"field": "event_name", "title": "kind"},
                {"field": "recorded_time", "type": "temporal", "title": "recorded"},
                {"field": "state", "title": "status"},
            ],
        },
        "config": {
            "view": {"stroke": None},
            # Matches the app: system sans, no web font, nothing fetched.
            "font": "system-ui, -apple-system, Segoe UI, Roboto, Helvetica Neue, Arial, sans-serif",
        },
    }
    spec["data"] = {"values": values}
    st.vega_lite_chart(spec=spec, width="stretch")


def coverage_matrix(entities: list[dict], source_types: list[str], *, height: int = 300) -> None:
    """Hosts against source types: covered, mentioned only, or absent.

    Three states, not two, and the distinction is load-bearing. A host that only
    ever appears as the far end of a network flow is *mentioned* by that source,
    not *covered* by it -- and "no record exists" means something quite different
    in those two cases. This grid is where an absence-based claim gets its
    warrant or loses it.
    """
    colours = _colours()
    values = []
    for entity in entities:
        if entity["entity_type"] != "host":
            continue
        coverage = entity["coverage"]
        for source in source_types:
            if source in coverage["observed_on_in"]:
                state = "covered"
            elif source in coverage["mentioned_in"]:
                state = "mentioned only"
            else:
                state = "absent"
            values.append(
                {
                    "host": entity["value"],
                    "source_type": source,
                    "state": state,
                }
            )

    if not values:
        st.caption("No host entities to chart.")
        return

    palette = theme.palette()
    spec: dict[str, Any] = {
        "$schema": "https://vega.github.io/schema/vega-lite/v5.json",
        "background": colours["surface"],
        "height": height,
        "autosize": {"type": "fit", "contains": "padding"},
        # A 2px surface gap between adjacent cells, so the grid reads as cells
        # rather than as a continuous wash.
        "mark": {"type": "rect", "stroke": colours["surface"], "strokeWidth": 2},
        "encoding": {
            "x": {
                "field": "source_type",
                "type": "nominal",
                "title": None,
                "axis": {
                    "orient": "top",
                    "labelAngle": 0,
                    "labelColor": colours["text"],
                    "domainColor": colours["baseline"],
                    "tickColor": colours["baseline"],
                },
            },
            "y": {
                "field": "host",
                "type": "nominal",
                "title": None,
                "axis": {
                    "labelColor": colours["text"],
                    "domainColor": colours["baseline"],
                    "tickColor": colours["baseline"],
                },
            },
            "color": {
                "field": "state",
                "type": "nominal",
                "scale": {
                    "domain": ["covered", "mentioned only", "absent"],
                    # A one-hue ramp, light to dark, because the three states are
                    # ordered by how much the source actually tells you. Not a
                    # categorical palette: these are steps on one scale.
                    "range": [palette["ink"], palette["ink_muted"], palette["rule"]],
                },
                "legend": {"orient": "bottom", "title": None, "labelColor": colours["text"]},
            },
            "tooltip": [
                {"field": "host", "title": "host"},
                {"field": "source_type", "title": "source"},
                {"field": "state", "title": "coverage"},
            ],
        },
        "config": {
            "view": {"stroke": None},
            # Matches the app: system sans, no web font, nothing fetched.
            "font": "system-ui, -apple-system, Segoe UI, Roboto, Helvetica Neue, Arial, sans-serif",
        },
    }
    spec["data"] = {"values": values}
    st.vega_lite_chart(spec=spec, width="stretch")
