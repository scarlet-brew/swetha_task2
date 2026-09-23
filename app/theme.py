"""The palette, read back out of `.streamlit/config.toml` rather than restated.

Design SS9.1 measured seven steps against the surface they sit on, and SS9.2
forbids a web font. Both facts live in `.streamlit/config.toml`, because that is
the file Streamlit itself consumes -- so a second copy here would be a second
thing to get wrong, and the copy that drifted would be the one nobody renders.

So this module reads that file and hands the same strings to the app. Two things
depend on it: the Pipeline surface shows the palette audit as a table (SS9.4
item 4 -- a stage is expandable to its verification result, and the
accessibility claim is a claim like any other), and the tests recompute every
contrast ratio from these exact strings -- `tests/test_ui_render.py` from the
palette directly, `tests/test_ui_sibling_render.py` from the Arrow bytes the
audit table actually sent. Nothing hardcodes a hex next to the ratio it is
supposed to produce.

The WCAG 2.x arithmetic lives here rather than in the test for the same reason:
the audit table and the test assertion have to be one computation, or the table
could report a number the test never checked.
"""

from __future__ import annotations

import tomllib
from functools import lru_cache
from pathlib import Path
from typing import Literal

import streamlit as st

#: app/theme.py -> app -> repository root
ROOT = Path(__file__).resolve().parents[1]
CONFIG_TOML = ROOT / ".streamlit" / "config.toml"
STATIC = Path(__file__).resolve().parent / "static"

Mode = Literal["light", "dark"]

#: SS9.1's role names mapped onto the Streamlit theme keys that carry them.
#:
#: The mapping is the interesting part of this module. Streamlit's vocabulary is
#: about widgets (codeTextColor, dataframeBorderColor); SS9.1's is about a
#: printed page (secondary ink, baseline). Recording the correspondence once,
#: here, is what lets the audit table and the contrast test speak SS9.1's
#: language while config.toml stays valid Streamlit configuration -- an invented
#: key there earns a startup warning and is then ignored.
PALETTE_ROLES: dict[str, str] = {
    "page": "backgroundColor",
    "panel": "secondaryBackgroundColor",
    "ink": "textColor",
    "ink_secondary": "codeTextColor",
    "ink_muted": "grayTextColor",
    "rule": "borderColor",
    "baseline": "dataframeBorderColor",
}

#: The role the others are measured against. SS9.1's column says "vs surface",
#: and the surface text sits on is the panel, not the page plane.
SURFACE_ROLE = "panel"

#: SS9.1's status palette: support state -> the Streamlit colour family carrying
#: it. The families are set in `[theme]` and deliberately not in `[theme.dark]`,
#: which is how "unthemed" is expressed mechanically: an unset section inherits
#: from `[theme]`.
STATUS_FAMILIES: dict[str, str] = {
    "corroborated": "green",
    "single_sourced": "yellow",
    "absence_based": "orange",
    "conflicted": "red",
}

#: WCAG 2.x thresholds, named so an audit row can say which floor it clears
#: instead of printing a bare number.
BODY_TEXT_FLOOR = 4.5
LARGE_TEXT_FLOOR = 3.0


@lru_cache(maxsize=1)
def read_config() -> dict:
    """`.streamlit/config.toml`, parsed. Cached: it cannot change mid-session."""
    return tomllib.loads(CONFIG_TOML.read_text(encoding="utf-8"))


def theme_table(mode: Mode = "light") -> dict[str, str]:
    """The `[theme]` string values for `mode`, with `[theme.dark]` applied over.

    Streamlit's own resolution rule, reproduced: a key unset in `[theme.dark]`
    inherits from `[theme]`. Reproducing it is what makes the audit honest --
    auditing only the keys spelled out under `[theme.dark]` would silently skip
    every inherited one.
    """
    theme = read_config().get("theme", {})
    resolved = {key: value for key, value in theme.items() if isinstance(value, str)}
    if mode == "dark":
        resolved.update(
            {
                key: value
                for key, value in theme.get("dark", {}).items()
                if isinstance(value, str)
            }
        )
    return resolved


def palette(mode: Mode = "light") -> dict[str, str]:
    """SS9.1's seven steps for `mode`, keyed by role name."""
    table = theme_table(mode)
    missing = [key for key in PALETTE_ROLES.values() if key not in table]
    if missing:
        section = "theme.dark" if mode == "dark" else "theme"
        raise KeyError(
            f"{CONFIG_TOML.name} [{section}] is missing {missing}; SS9.1 requires "
            "every step to be declared, not defaulted"
        )
    return {role: table[key] for role, key in PALETTE_ROLES.items()}


def status_palette() -> dict[str, str]:
    """Support state -> the hex drawn for it. Unthemed by design (SS9.1)."""
    table = theme_table("light")
    return {
        state: table[f"{family}TextColor"]
        for state, family in STATUS_FAMILIES.items()
    }


# --------------------------------------------------------------------------
# WCAG 2.x relative luminance and contrast ratio
# --------------------------------------------------------------------------


def _srgb_channels(colour: str) -> tuple[float, float, float]:
    """`#rgb` or `#rrggbb` as three floats in 0-1. Raises on anything else.

    Strict on purpose: a silently accepted rgb() or named colour would produce
    a luminance from nothing, and the audit would then report a ratio for a
    colour the browser never draws.
    """
    text = colour.strip().lstrip("#")
    if len(text) == 3:
        text = "".join(char * 2 for char in text)
    if len(text) != 6 or any(char not in "0123456789abcdefABCDEF" for char in text):
        raise ValueError(f"{colour!r} is not a #rgb or #rrggbb hex colour")
    channels = tuple(int(text[index : index + 2], 16) / 255 for index in (0, 2, 4))
    return channels  # type: ignore[return-value]


def relative_luminance(colour: str) -> float:
    """WCAG 2.x relative luminance of an sRGB hex colour."""

    def linear(value: float) -> float:
        return value / 12.92 if value <= 0.04045 else ((value + 0.055) / 1.055) ** 2.4

    red, green, blue = (linear(channel) for channel in _srgb_channels(colour))
    return 0.2126 * red + 0.7152 * green + 0.0722 * blue


def contrast_ratio(first: str, second: str) -> float:
    """WCAG 2.x contrast ratio between two hex colours, in [1, 21]."""
    lighter, darker = sorted(
        (relative_luminance(first), relative_luminance(second)), reverse=True
    )
    return (lighter + 0.05) / (darker + 0.05)


def audit(mode: Mode = "light") -> list[dict[str, object]]:
    """One row per SS9.1 step: role, hex, ratio against the surface, floor met.

    The surface reports 1.0 against itself rather than being dropped, so the
    table shows the whole palette and a reader can see what the other ratios
    are measured against.
    """
    steps = palette(mode)
    surface = steps[SURFACE_ROLE]
    rows: list[dict[str, object]] = []
    for role, hex_value in steps.items():
        ratio = contrast_ratio(hex_value, surface)
        rows.append(
            {
                "role": role,
                "hex": hex_value,
                "config_key": PALETTE_ROLES[role],
                "ratio_vs_panel": round(ratio, 2),
                "clears": (
                    "body text 4.5:1"
                    if ratio >= BODY_TEXT_FLOOR
                    else "large text 3:1"
                    if ratio >= LARGE_TEXT_FLOOR
                    else "non-text only"
                ),
            }
        )
    return rows


def status_audit() -> list[dict[str, object]]:
    """One row per support state, measured against the parchment panel surface.

    Three of the four sit below 3:1, which is *why* SS9.1 mandates icon plus
    word. The table states the reason rather than leaving it in a comment.

    Measured against the panel for the same reason `audit` is: it is the
    surface a badge is actually drawn on. Recomputing SS9.1's status column
    against the panel reproduces its Corroborated 2.71 and Conflicted 3.88
    exactly; its Single-sourced and Absence-based figures do not reproduce
    against either the panel or the page plane. The structural claim the
    icon-plus-word rule rests on -- three of four below 3:1 -- holds on both
    surfaces, so the rule is unaffected either way.
    """
    surface = palette("light")[SURFACE_ROLE]
    rows: list[dict[str, object]] = []
    for state, hex_value in status_palette().items():
        ratio = contrast_ratio(hex_value, surface)
        rows.append(
            {
                "support_state": state,
                "hex": hex_value,
                "colour_family": STATUS_FAMILIES[state],
                "ratio_vs_panel": round(ratio, 2),
                "colour_alone_sufficient": bool(ratio >= LARGE_TEXT_FLOOR),
            }
        )
    return rows


def inject_chrome() -> None:
    """Load the two stylesheets config.toml cannot express.

    `st.html` given a `Path` to a `.css` file wraps it in style tags and routes
    it away from the main container, so neither sheet takes up layout space.
    Nothing in either sets a colour -- the palette belongs to config.toml, and
    duplicating it into CSS is the drift this module exists to prevent.
    """
    for sheet in ("chrome.css", "print.css"):
        path = STATIC / sheet
        if path.is_file():
            st.html(path)
