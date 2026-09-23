"""The committed audit representation, implementing D-10.

Deterministic sorted JSONL: one object per line, lines sorted by id, keys
sorted within each object, LF endings. The point is that `git diff` between two
builds shows exactly which nodes changed and nothing else -- which is why
pretty-printed JSON was rejected (inserting one node shifts every bracket
after it) along with YAML (quoting footguns), TOML (no stdlib writer) and
SQLite (opaque to review).

D-10 fixes the serialisation as `json.dumps(sort_keys=True, ensure_ascii=False)`
with *default* separators, deliberately unlike `ids.canonical_json`: this
representation exists to be read by a reviewer, so it keeps the space after
each comma and colon. The canonical form exists only to be hashed, so it drops
them. The two must not be conflated -- hashing this form would give different
ids.

`write` refuses two different objects claiming one id. Under SS8.2 an id *is* a
digest of the node's structural identity, so that situation means either a real
sha256 collision or an excluded field leaking into a digest. Both are bugs that
must not reach a committed artifact, and the same mechanism gives deduplication
for free: two identical objects collapse to one line.
"""

from __future__ import annotations

import json
import os
from collections.abc import Iterable, Mapping
from pathlib import Path
from typing import Any

#: Written explicitly rather than left to the platform. `.gitattributes` marks
#: these files `-text` so git never rewrites them, which means the bytes this
#: module emits are the bytes that get committed and hashed -- on Windows, where
#: text mode would otherwise translate every newline to CRLF.
NEWLINE = "\n"


class IdConflict(ValueError):
    """Two structurally different objects claim the same id."""


def _line(obj: Mapping[str, Any]) -> str:
    return json.dumps(obj, sort_keys=True, ensure_ascii=False, allow_nan=False)


def write(path: str | os.PathLike[str], objects: Iterable[Mapping[str, Any]], *, id_key: str = "id") -> int:
    """Write `objects` as sorted JSONL. Returns the number of lines written.

    Deduplicates by id; raises `IdConflict` if one id carries two different
    payloads. Sorting is by the serialised line, not by insertion order, so the
    file is a function of its contents alone.
    """
    path = Path(path)
    by_id: dict[str, str] = {}

    for index, obj in enumerate(objects):
        if not isinstance(obj, Mapping):
            raise TypeError(f"{path.name} item {index}: expected a mapping, got {type(obj).__name__}")
        node_id = obj.get(id_key)
        if not isinstance(node_id, str) or not node_id:
            raise ValueError(f"{path.name} item {index}: missing or empty {id_key!r}")
        line = _line(obj)
        existing = by_id.get(node_id)
        if existing is None:
            by_id[node_id] = line
        elif existing != line:
            raise IdConflict(
                f"{path.name}: id {node_id!r} claimed by two different objects.\n"
                f"  first: {existing}\n"
                f"  again: {line}\n"
                "Under SS8.2 an id is a digest of structural identity, so this means a "
                "field excluded from identity is being varied, or the identity fields "
                "supplied do not match SS8.2's table for this node kind."
            )

    path.parent.mkdir(parents=True, exist_ok=True)
    # newline="" stops the io layer translating; we emit LF ourselves.
    with path.open("w", encoding="utf-8", newline="") as handle:
        for node_id in sorted(by_id):
            handle.write(by_id[node_id])
            handle.write(NEWLINE)
    return len(by_id)


def read(path: str | os.PathLike[str]) -> list[dict[str, Any]]:
    """Read a JSONL file into a list, preserving file order (so: id order)."""
    path = Path(path)
    out: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8", newline="") as handle:
        for lineno, line in enumerate(handle, start=1):
            stripped = line.strip()
            if not stripped:
                continue
            try:
                out.append(json.loads(stripped))
            except json.JSONDecodeError as exc:
                raise ValueError(f"{path.name}:{lineno}: {exc}") from exc
    return out


def index_by_id(objects: Iterable[Mapping[str, Any]], *, id_key: str = "id") -> dict[str, dict[str, Any]]:
    """`{id: object}`, for the by-id retrieval R2.5's citations depend on."""
    return {obj[id_key]: dict(obj) for obj in objects}


def write_json(path: str | os.PathLike[str], obj: Any) -> None:
    """Write a single committed JSON artifact -- the per-stage reports and SS5 projections.

    Indented and key-sorted: these are read whole rather than diffed line by
    line, so readability wins over minimal diffs. LF and a trailing newline,
    for the same reason as above.
    """
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    text = json.dumps(obj, sort_keys=True, ensure_ascii=False, allow_nan=False, indent=2)
    with path.open("w", encoding="utf-8", newline="") as handle:
        handle.write(text)
        handle.write(NEWLINE)


def read_json(path: str | os.PathLike[str]) -> Any:
    with Path(path).open("r", encoding="utf-8") as handle:
        return json.load(handle)
