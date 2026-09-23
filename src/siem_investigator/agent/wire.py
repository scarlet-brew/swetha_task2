"""Turning a Pydantic contract into the JSON schema that actually goes out.

Separated from `client.py` because it is the part worth reading on its own: it
exists entirely to work around one measured SDK behaviour, and NFR-07 asks that
no component be so large a reviewer cannot follow it. The transport, the
provenance and the live call are a different concern and live next door.

**The behaviour.** Measured on anthropic 0.84.0: `transform_schema` -- what
`messages.parse` runs over an `output_format` type -- keeps a fixed keyword set
and folds the rest into each property's `description` as prose. **`enum` and
`const` are discarded.** So a closed `Literal` arrives at the API as
`{"type": "string", "description": "...{enum: ['T1059.001', ...]}"}`: a hint,
not a constraint. The model may emit `T1068`, the API accepts it, and
`TypeAdapter.validate_json` raises on the way back -- validate-then-reject,
which is the posture D-08 explicitly rejects.

`_restore_closed_values` puts them back. `client._request_kwargs` then sends the
repaired schema via `extra_body`, which the base client shallow-merges over the
body with the extra winning, while `output_format` still drives the typed parse
on the way back -- so both halves hold at once. Without this, D-08's and T05's
"structurally unrepresentable" claim is simply false.
"""

from __future__ import annotations

from typing import Any

from anthropic.lib._parse._transform import transform_schema
from pydantic import BaseModel

#: Substrings that would indicate a probability, percentage or confidence value
#: reaching a contract. R3.4 forbids them, and the way that rots is a
#: harmless-looking field added later -- so the schema is scanned, not trusted.
_BELIEF_TOKENS = (
    "probability",
    "confidence",
    "percent",
    "likelihood",
    "certainty",
    "score",
    "weight",
)


def _restore_closed_values(pydantic_schema: Any, wire: Any) -> Any:
    """Put `enum`/`const` back into `wire`, taken from `pydantic_schema`.

    See the module docstring: the SDK's transform drops them, which silently
    turns a constraint into a hint.
    """
    if not isinstance(pydantic_schema, dict) or not isinstance(wire, dict):
        return wire
    repaired = dict(wire)
    for keyword in ("enum", "const"):
        if keyword not in pydantic_schema:
            continue
        repaired[keyword] = pydantic_schema[keyword]
        # Drop the demoted copy folded into the description: a second statement
        # of one constraint can only drift from the first. Any real description
        # survives -- the transform appends after a blank line, so this is exact.
        kept = repaired.get("description", "").split("{%s: " % keyword)[0].rstrip()
        repaired["description"] = kept
        if not kept:
            repaired.pop("description")
    for container in ("properties", "$defs"):
        if container in repaired and container in pydantic_schema:
            repaired[container] = {
                name: _restore_closed_values(pydantic_schema[container].get(name), sub)
                for name, sub in repaired[container].items()
            }
    if "items" in repaired and "items" in pydantic_schema:
        repaired["items"] = _restore_closed_values(pydantic_schema["items"], repaired["items"])
    return repaired


def wire_schema(model: type[BaseModel]) -> dict[str, Any]:
    """The JSON schema actually put on the wire for `model`.

    The SDK's transform runs first, so we inherit what it considers well-formed
    -- including the `additionalProperties: false` it injects at every object
    level -- and then the dropped closed values are repaired.

    Class docstrings are stripped, at the root **and inside `$defs`**. Pydantic
    uses `__doc__` as an object's schema `description`, so leaving them would
    send this codebase's design commentary to the provider on every call --
    egress no category in `docs/egress.md` could honestly cover.

    The nested case is not hypothetical: it was caught by a test that failed
    because `CitedEdge`'s own docstring, which happens to mention `prefixItems`,
    was arriving at the API. Stripping only the root looked correct and was not.

    Only *object-level* descriptions go. Field descriptions stay -- those are
    prompt content, and they are what tells the model what each field means.
    """
    schema = _restore_closed_values(model.model_json_schema(), transform_schema(model))
    return _strip_object_descriptions(schema)


def _strip_object_descriptions(schema: dict[str, Any]) -> dict[str, Any]:
    """Drop the `description` Pydantic derived from each class docstring.

    An object schema's own `description` comes from `__doc__`; a field's comes
    from its `Field(description=...)`. So this removes `description` from the
    root and from every `$defs` entry, and touches nothing under `properties`.
    """
    cleaned = dict(schema)
    cleaned.pop("description", None)
    definitions = cleaned.get("$defs")
    if isinstance(definitions, dict):
        cleaned["$defs"] = {
            name: _strip_object_descriptions(entry) if isinstance(entry, dict) else entry
            for name, entry in definitions.items()
        }
    return cleaned


def schema_defects(schema: dict[str, Any]) -> list[str]:
    """Ways `schema` fails what D-08 and R3.4 require, each named with its path.

    Three properties, all structural:

    1. `additionalProperties: false` on **every** object level, not just the
       root -- a nested object left open is a place for an unmodelled field.
    2. Every object states `required`, or every field is omittable and the
       contract says nothing.
    3. No field name or description suggests a probability, percentage or
       confidence value (R3.4).
    """
    defects: list[str] = []

    def walk(node: Any, path: str) -> None:
        if not isinstance(node, dict):
            return
        if node.get("type") == "object" or "properties" in node:
            if node.get("additionalProperties") is not False:
                defects.append(f"{path}: additionalProperties is not false")
            if "properties" in node and "required" not in node:
                defects.append(f"{path}: no required list -- every field is omittable")
        for name, sub in (node.get("properties") or {}).items():
            lowered = name.lower()
            for token in _BELIEF_TOKENS:
                if token in lowered:
                    defects.append(f"{path}.{name}: field name suggests a belief value (R3.4)")
            description = (sub or {}).get("description", "") if isinstance(sub, dict) else ""
            for token in _BELIEF_TOKENS:
                if token in description.lower():
                    defects.append(
                        f"{path}.{name}: description mentions {token!r} (R3.4)"
                    )
            walk(sub, f"{path}.{name}")
        for name, sub in (node.get("$defs") or {}).items():
            walk(sub, f"{path}.$defs.{name}")
        if "items" in node:
            walk(node["items"], f"{path}[]")
        for keyword in ("anyOf", "oneOf", "allOf"):
            for index, sub in enumerate(node.get(keyword) or []):
                walk(sub, f"{path}.{keyword}[{index}]")

    walk(schema, "$")
    return defects
