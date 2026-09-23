"""Support-state badges: icon plus word, always, on every state.

Two independent requirements meet here and say the same thing.

R3.2-R3.5 want the *structure* of a finding's support named in words --
Corroborated, Single-sourced, Absence-based, with R3.3's resolution-dependent
and conflicted flags on top -- and explicitly forbid substituting a probability
or a belief for them.

Design SS9.1 measured the four status colours against the parchment surface and
three of them land below 3:1. So colour cannot carry a state on its own even if
the requirements had allowed it.

The consequence is one rule, enforced by construction rather than by review:
every badge this module emits is `<icon> <word>`, and colour is a decoration
applied around text that already reads correctly without it. `badge_markup(...,
colour=False)` returns exactly the same icon and word with no colour markup at
all, which is what the render test asserts.

Icons are typographic marks, not emoji: an emoji is a colour image in most
fonts, which would put the state back into colour by another route, and it
prints as a grey blob.
"""

from __future__ import annotations

from dataclasses import dataclass

import streamlit as st

from app.theme import STATUS_FAMILIES


@dataclass(frozen=True)
class BadgeSpec:
    """One support state or flag as it renders.

    `family` is the Streamlit colour family that carries the SS9.1 hex (set in
    `.streamlit/config.toml`), or None for a state SS9.1 gives no colour --
    which renders in muted ink and loses nothing, because the word is the
    signal.
    """

    icon: str
    word: str
    family: str | None
    meaning: str


#: R3.2's three support labels plus R3.3's conflicted, which SS9.1's status
#: table also colours. Keys are the labels the answer payload carries.
SUPPORT_STATES: dict[str, BadgeSpec] = {
    "corroborated": BadgeSpec(
        icon="✓",  # CHECK MARK -- two or more sources agree
        word="Corroborated",
        family=STATUS_FAMILIES["corroborated"],
        meaning="supporting observations draw on two or more distinct log sources",
    ),
    "single_sourced": BadgeSpec(
        icon="▲",  # BLACK UP-POINTING TRIANGLE -- one leg to stand on
        word="Single-sourced",
        family=STATUS_FAMILIES["single_sourced"],
        meaning="supporting observations draw on one log source",
    ),
    "absence_based": BadgeSpec(
        icon="◌",  # DOTTED CIRCLE -- an outline around nothing recorded
        word="Absence-based",
        family=STATUS_FAMILIES["absence_based"],
        meaning="the named basis reasons from records not being present",
    ),
    "conflicted": BadgeSpec(
        icon="⇄",  # RIGHTWARDS ARROW OVER LEFTWARDS ARROW -- two ways at once
        word="Conflicted",
        family=STATUS_FAMILIES["conflicted"],
        meaning="a cited observation is inconsistent with another in the same support",
    ),
}

#: R3.3's two additive flags. `conflicted` is deliberately the same spec object
#: as the state above: it is one condition, whether it arrives as a label or as
#: a flag on another label, and two spellings of it would eventually diverge.
SUPPORT_FLAGS: dict[str, BadgeSpec] = {
    "resolution_dependent": BadgeSpec(
        icon="◐",  # CIRCLE WITH LEFT HALF BLACK -- partially determined
        word="Resolution-dependent",
        family=None,  # SS9.1 gives it no status colour; muted ink and the word
        meaning="rests on an entity association with more than one candidate",
    ),
    "conflicted": SUPPORT_STATES["conflicted"],
}


class UnknownSupportState(KeyError):
    """A payload named a support state or flag this module does not render.

    Raised rather than defaulted. A badge that silently fell back to a generic
    label would misreport the structure of a finding's support, which is the
    one thing R3.4 says must come from the structure alone.
    """


def spec(name: str) -> BadgeSpec:
    """The spec for a support label or flag name."""
    if name in SUPPORT_STATES:
        return SUPPORT_STATES[name]
    if name in SUPPORT_FLAGS:
        return SUPPORT_FLAGS[name]
    raise UnknownSupportState(
        f"{name!r} is not a support state or flag; expected one of "
        f"{sorted(set(SUPPORT_STATES) | set(SUPPORT_FLAGS))}"
    )


def badge_text(name: str) -> str:
    """`<icon> <word>` -- the colourless form, and the whole signal.

    Every other function here decorates this string. If the decoration is
    stripped, dropped by a print driver or unavailable in forced-colors mode,
    this is what remains, and it is complete.
    """
    found = spec(name)
    return f"{found.icon} {found.word}"


def badge_markup(name: str, *, colour: bool = True) -> str:
    """One badge as Streamlit markdown.

    Uses Streamlit's `:family-badge[...]` syntax rather than a styled HTML
    span, so the hex comes from `.streamlit/config.toml` at render time and
    this module never holds a copy of it. `colour=False` returns
    `badge_text(name)` unchanged -- not a greyed-out badge, no colour markup at
    all -- which is the state the render test inspects.
    """
    text = badge_text(name)
    if not colour:
        return text
    found = spec(name)
    family = found.family or "gray"
    return f":{family}-badge[{text}]"


def support_markup(
    label: str, flags: object = (), *, colour: bool = True
) -> str:
    """A support label followed by its R3.3 flags, in one markdown line.

    Flags are additive, never substitutes: R3.3 says a resolution-dependent
    finding is *additionally* flagged, so the label it qualifies stays visible
    beside it.
    """
    parts = [badge_markup(label, colour=colour)]
    parts.extend(badge_markup(flag, colour=colour) for flag in tuple(flags))  # type: ignore[arg-type]
    return "  ".join(parts)


def render(label: str, flags: object = (), *, colour: bool = True) -> str:
    """Emit the support line and return the markup that was emitted.

    Returning the markup keeps the pure function and the side effect in step:
    the test asserts on the returned string knowing it is the string that was
    rendered, rather than on a second construction of it.
    """
    markup = support_markup(label, flags, colour=colour)
    st.markdown(markup)
    return markup


def legend_rows() -> list[dict[str, str]]:
    """Every state and flag as table rows: icon, word, what it means.

    R3.2-R3.5 make these labels the system's substitute for a confidence
    score, so the app has to be able to say what each one means without the
    reader consulting the spec.
    """
    rows: list[dict[str, str]] = []
    for kind, table in (("support state", SUPPORT_STATES), ("flag", SUPPORT_FLAGS)):
        for name, found in table.items():
            if kind == "flag" and name in SUPPORT_STATES:
                continue  # conflicted is listed once, as a state
            rows.append(
                {
                    "kind": kind,
                    "badge": badge_text(name),
                    "name": name,
                    "means": found.meaning,
                }
            )
    return rows
