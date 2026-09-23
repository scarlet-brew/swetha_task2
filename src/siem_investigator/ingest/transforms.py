"""Stage 2a -- the closed transform registry, and invariant 5 (T11).

Every asserted value records how it was produced:
`record_id | field | raw_value | transform | normalised_value`. Invariant 5 says
**re-applying the recorded transform to the recorded raw value must reproduce
the asserted value**, which makes normalisation checkable rather than trusted.

`identity` is recorded explicitly even though it changes nothing. A missing
provenance entry is then a bug rather than an ambiguity -- there is no "it must
have been unchanged" case to argue about.

Transforms are pure and total. One that cannot normalise a value says so by
returning `None`, and the observation is withheld rather than guessed at.
"""

from __future__ import annotations

import datetime as dt
from collections.abc import Callable

BACKSLASH = chr(92)


def identity(value: object) -> object | None:
    """Recorded explicitly, so absence of provenance is always a bug."""
    return value


def lower(value: object) -> str | None:
    return str(value).lower() if isinstance(value, str) else None


def basename(value: object) -> str | None:
    r"""Last path segment, lowercased. Handles `C:\Temp\x.zip` and bare names.

    This is what lets an endpoint `file_path` and a cloud `file_name` be
    compared at all -- the strongest cross-source join in the dataset runs
    through it.
    """
    if not isinstance(value, str) or not value:
        return None
    # A trailing separator ("C:\\") leaves nothing after the split. That is not a
    # basename, so the observation is withheld rather than asserting an empty value.
    trimmed = value.replace(BACKSLASH, "/").rstrip("/")
    tail = trimmed.rsplit("/", 1)[-1].lower()
    return tail or None


def ipv4_canonical(value: object) -> str | None:
    """A dotted-quad with no leading zeros, or None if it is not one.

    Returning None rather than raising is the point: a malformed address is
    data about the source, not a crash.
    """
    if not isinstance(value, str):
        return None
    parts = value.strip().split(".")
    if len(parts) != 4:
        return None
    try:
        octets = [int(part) for part in parts]
    except ValueError:
        return None
    if any(octet < 0 or octet > 255 for octet in octets):
        return None
    return ".".join(str(octet) for octet in octets)


def utc_instant(value: object) -> str | None:
    """Normalised ISO-8601 UTC with exactly six fractional digits.

    The dataset mixes precisions -- 220 records carry microseconds, 22 are
    written to whole seconds -- so this is what puts both on one comparable
    scale. Sub-second precision is preserved because R7.1's perturbation test
    alters it deliberately.
    """
    if not isinstance(value, str):
        return None
    try:
        parsed = dt.datetime.fromisoformat(value)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=dt.timezone.utc)
    utc = parsed.astimezone(dt.timezone.utc)
    return f"{utc.strftime('%Y-%m-%dT%H:%M:%S')}.{utc.microsecond:06d}Z"


def integer(value: object) -> int | None:
    """A byte count as an exact integer. SS8.2 requires integers for byte counts."""
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, float) and value.is_integer():
        return int(value)
    if isinstance(value, str):
        try:
            return int(value.strip())
        except ValueError:
            return None
    return None


#: The closed registry. A transform not named here cannot be recorded, so the
#: set of ways a value may change is fixed and reviewable.
REGISTRY: dict[str, Callable[[object], object | None]] = {
    "identity": identity,
    "lower": lower,
    "basename": basename,
    "ipv4_canonical": ipv4_canonical,
    "utc_instant": utc_instant,
    "integer": integer,
}


class UnregisteredTransform(KeyError):
    """A provenance entry names a transform that does not exist."""


def apply(name: str, raw_value: object) -> object | None:
    if name not in REGISTRY:
        raise UnregisteredTransform(f"{name!r} is not in the closed transform registry")
    return REGISTRY[name](raw_value)


def reproduces(entry: dict) -> bool:
    """Invariant 5 for one provenance entry."""
    return apply(entry["transform"], entry["raw_value"]) == entry["normalised_value"]


def check_all(entries: list[dict]) -> list[str]:
    """Every provenance entry that fails invariant 5, named."""
    failures = []
    for entry in entries:
        try:
            if not reproduces(entry):
                failures.append(
                    f"{entry.get('record')}.{entry.get('field')}: "
                    f"{entry['transform']}({entry['raw_value']!r}) != {entry['normalised_value']!r}"
                )
        except UnregisteredTransform as exc:
            failures.append(f"{entry.get('record')}.{entry.get('field')}: {exc}")
    return failures
