"""Content-derived identity, implementing design SS8.2.

    id = <prefix>_ + sha256(canonical_json(identity_fields))[:12]

Two properties are bought here, and both are load-bearing later.

**Diffability across runs.** Prose is excluded from identity, so re-running the
build with a different model gives structurally identical findings identical
ids. A diff between two runs then shows which findings changed *structurally*,
not which sentences got reworded.

**One mechanism instead of two.** Because the id is a hash of the structural
identity, the dedup key and the id are the same thing: two proposals citing the
same observations and edges at the same stage collide by construction, whatever
words they arrived in. `jsonl.write` relies on exactly that.

The six `*_id` builders below are the reason this module is worth its length.
SS8.2 excludes specific fields from specific node kinds -- `statement` from
`fnd_`, `status` from `hyp_`, catalogue version from `map_` -- and a generic
`node_id(prefix, dict)` cannot enforce any of it: one stray key and every
committed artifact's ids shift. The builders take only the fields SS8.2 admits,
so an excluded field has nowhere to go. That is the same constrain-don't-
validate move the ATT&CK enum makes at stage 4, applied to identity.

`node_id` stays public because SS8.2 names it and tests exercise the primitive
directly, but production code should reach for a builder.
"""

from __future__ import annotations

import datetime as _dt
import hashlib
import json
from collections.abc import Iterable, Mapping, Sequence

#: Length of the hex digest suffix. 12 hex chars = 48 bits. At the scale this
#: system works on -- a few thousand nodes -- collision probability is around
#: 1e-9, and a collision would surface as `jsonl.write` refusing two different
#: objects that claim one id, not as silent corruption.
_DIGEST_CHARS = 12

#: Node prefixes from SS8.1/SS8.2. `node_id` rejects anything else, so a typo in a
#: prefix fails at the call rather than producing a plausible-looking id.
PREFIXES = frozenset({"rec", "obs", "edg", "fnd", "map", "hyp"})


class IdentityError(TypeError):
    """An identity field cannot be canonicalised deterministically."""


def _canonicalise(value: object, path: str = "$") -> object:
    """Reduce `value` to JSON types whose serialisation is fully determined.

    `json.dumps` is deterministic for a *given* Python object, but several
    Python values serialise in ways that are stable only by accident. This walk
    removes each of those hazards, naming the offending path when it cannot.
    """
    if value is None or isinstance(value, str):
        return value

    # bool before int: bool is a subclass of int, and `True` must stay `true`
    # rather than becoming `1`, which is a different JSON document.
    if isinstance(value, bool):
        return value

    if isinstance(value, int):
        return value

    if isinstance(value, float):
        # SS8.2 says "integers for byte counts". Floats are the classic
        # determinism hazard in JSON -- repr differs across platforms and
        # round-trips are lossy -- and nothing in this data model needs one.
        # An integral float is almost always a byte count that took a detour
        # through arithmetic, so narrow it; anything else is a bug worth
        # hearing about at the call site.
        if value != value or value in (float("inf"), float("-inf")):
            raise IdentityError(f"{path}: NaN/Infinity cannot be an identity field")
        if value.is_integer():
            return int(value)
        raise IdentityError(
            f"{path}: non-integral float {value!r} cannot be an identity field; "
            "identity fields are exact by construction"
        )

    if isinstance(value, _dt.datetime):
        return canonical_instant(value, path=path)

    if isinstance(value, _dt.date):
        raise IdentityError(
            f"{path}: bare date {value!r} is not an instant; supply a datetime or a string"
        )

    if isinstance(value, Mapping):
        out: dict[str, object] = {}
        for key, item in value.items():
            if not isinstance(key, str):
                # `sort_keys=True` raises on mixed key types, and an int key
                # would sort by a different rule than its string form.
                raise IdentityError(f"{path}: mapping key {key!r} is not a string")
            out[key] = _canonicalise(item, f"{path}.{key}")
        return out

    # str is a Sequence, and is handled above.
    if isinstance(value, (list, tuple)) or (
        isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray))
    ):
        return [_canonicalise(item, f"{path}[{i}]") for i, item in enumerate(value)]

    if isinstance(value, (set, frozenset)):
        # A set has no order, so its serialisation would depend on hash
        # randomisation. Where SS8.2 wants an unordered field it says "sorted",
        # and the builders below do the sorting explicitly and visibly.
        raise IdentityError(
            f"{path}: sets have no deterministic order; pass a sorted sequence"
        )

    raise IdentityError(f"{path}: {type(value).__name__} is not a JSON type")


def canonical_instant(value: _dt.datetime, *, path: str = "$") -> str:
    """A datetime as normalised ISO-8601 UTC: `YYYY-MM-DDTHH:MM:SS.ffffffZ`.

    Exactly six fractional digits, always. Sub-second precision has to survive
    because R7.1's perturbation test alters it deliberately, and a variable
    number of digits would make two spellings of one instant hash differently.

    This is the form the supplied dataset uses where it records sub-second
    precision at all, so such a record's raw timestamp string and its
    canonicalised datetime agree character for character. A timestamp written to
    whole-second precision gains `.000000` -- one instant, one spelling, whatever
    precision it arrived in.

    A naive datetime is refused: its instant depends on the reader's zone, and
    an ambiguous instant inside an identity field churns ids for no reason.
    """
    if value.tzinfo is None or value.tzinfo.utcoffset(value) is None:
        raise IdentityError(
            f"{path}: naive datetime {value!r} has no instant; attach a timezone"
        )
    utc = value.astimezone(_dt.timezone.utc)
    return f"{utc.strftime('%Y-%m-%dT%H:%M:%S')}.{utc.microsecond:06d}Z"


def canonical_json(value: object) -> str:
    """SS8.2's canonical form: sorted keys, no whitespace, `ensure_ascii=False`.

    Distinct from the committed JSONL form, which D-10 fixes as plain
    `json.dumps(sort_keys=True, ensure_ascii=False)` with default separators
    because that representation exists to be *read* in review. This one exists
    only to be hashed, so it drops every byte it can.
    """
    return json.dumps(
        _canonicalise(value),
        sort_keys=True,
        ensure_ascii=False,
        separators=(",", ":"),
        allow_nan=False,
    )


def content_digest(value: object) -> str:
    """Full sha256 hex digest of `value`'s canonical form.

    Used where a whole digest is wanted rather than an id -- the prompt hash,
    the contract-set hash, artifact manifests.
    """
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def node_id(prefix: str, identity_fields: Mapping[str, object]) -> str:
    """SS8.2's primitive. Prefer a typed builder below.

    Raises on an unknown prefix and on an empty identity: an id derived from
    nothing would be the same id for every node of that kind.
    """
    if prefix not in PREFIXES:
        raise IdentityError(f"unknown node prefix {prefix!r}; expected one of {sorted(PREFIXES)}")
    if not isinstance(identity_fields, Mapping):
        raise IdentityError(f"identity_fields must be a mapping, got {type(identity_fields).__name__}")
    if not identity_fields:
        raise IdentityError(f"{prefix}_: empty identity would collide with every other {prefix}_ node")
    return f"{prefix}_{content_digest(identity_fields)[:_DIGEST_CHARS]}"


def _sorted_ids(ids: Iterable[str], *, field: str) -> list[str]:
    """Deduplicated, sorted ids.

    Deduplication matters as much as sorting: citing one observation twice is
    the same claim as citing it once, so the two spellings must not produce
    two findings.
    """
    out = set()
    for value in ids:
        if not isinstance(value, str) or not value:
            raise IdentityError(f"{field}: {value!r} is not an id")
        out.add(value)
    if not out:
        raise IdentityError(f"{field}: must cite at least one id")
    return sorted(out)


# --------------------------------------------------------------------------
# The six builders. Each admits exactly the fields SS8.2's table lists, which is
# what keeps an excluded field from reaching a digest.
# --------------------------------------------------------------------------


def record_id(*, source_type: str, event_id: str, payload: Mapping[str, object]) -> str:
    """`rec_` -- source type, event id, canonical payload. Nothing excluded."""
    return node_id(
        "rec",
        {"source_type": source_type, "event_id": event_id, "payload": payload},
    )


def observation_id(
    *, record: str, field: str, normalised_value: object, transform: str
) -> str:
    """`obs_` -- record id, field, normalised value, transform name.

    Excluded: created-at, trajectory step. Two runs observing the same field of
    the same record must agree on the id even if they looked at different
    times, or the graph would differ between runs for no factual reason.
    """
    return node_id(
        "obs",
        {
            "record": record,
            "field": field,
            "normalised_value": normalised_value,
            "transform": transform,
        },
    )


def edge_id(*, relation: str, endpoints: Sequence[str]) -> str:
    """`edg_` -- relation name and *ordered* endpoint ids.

    Order is preserved, never sorted: several relations are directional
    (`process_parent` names parent then child, `temporal_within` names earlier
    then later), so reversing the endpoints states something different.

    Excluded: computed params. A reported delta-t is derivable from the
    endpoints, so including it adds nothing and churns the id if the time base
    shifts.
    """
    if len(endpoints) != 2:
        raise IdentityError(f"edg_: expected 2 endpoints, got {len(endpoints)}")
    for endpoint in endpoints:
        if not isinstance(endpoint, str) or not endpoint:
            raise IdentityError(f"edg_: endpoint {endpoint!r} is not an id")
    return node_id("edg", {"relation": relation, "endpoints": list(endpoints)})


def finding_id(
    *, cited_observations: Iterable[str], cited_edges: Iterable[str], stage: str
) -> str:
    """`fnd_` -- sorted cited observation ids, sorted cited edge ids, stage.

    Excluded, and this is the load-bearing exclusion: `statement` and
    `rationale` (rendered prose), `proposed_at`, model id, prompt hash,
    provider version. There is no parameter for any of them.

    `cited_edges` may be empty: a finding can rest on observations alone.
    `cited_observations` may not -- a finding citing nothing is ungrounded, and
    invariant 2 (termination in raw records) would have nothing to terminate.
    """
    edges = sorted(set(cited_edges))
    for edge in edges:
        if not isinstance(edge, str) or not edge:
            raise IdentityError(f"fnd_: cited edge {edge!r} is not an id")
    return node_id(
        "fnd",
        {
            "cited_observations": _sorted_ids(cited_observations, field="fnd_.cited_observations"),
            "cited_edges": edges,
            "stage": stage,
        },
    )


def mapping_id(
    *,
    technique_id: str,
    finding: str,
    cited_observations: Iterable[str],
    quoted_values: Iterable[str],
) -> str:
    """`map_` -- technique id, target finding id, sorted cited observations, quoted values.

    Excluded: catalogue version. It is recorded as provenance on the node, but
    the assertion *"this is T1059.001"* is unchanged by a catalogue bump, so
    bumping the catalogue must not rewrite every mapping id in the tree.

    `quoted_values` are sorted and deduplicated: they are the field values that
    triggered the selection, and the order they were quoted in is presentation.
    """
    values = sorted(set(quoted_values))
    for value in values:
        if not isinstance(value, str):
            raise IdentityError(f"map_: quoted value {value!r} is not a string")
    return node_id(
        "map",
        {
            "technique_id": technique_id,
            "finding": finding,
            "cited_observations": _sorted_ids(cited_observations, field="map_.cited_observations"),
            "quoted_values": values,
        },
    )


def hypothesis_id(*, premises: Iterable[str], prediction: Mapping[str, object]) -> str:
    """`hyp_` -- premise ids and the predicted entity/role/event-kind/source/window.

    Excluded: rationale prose, and `status`. Status *changes* -- proposed to
    confirmed, unconfirmed or uncoverable -- and an identity that changed with
    it would make the hypothesis ledger unjoinable to itself, which is exactly
    what the coverage-gap report (T27) reads.
    """
    if not isinstance(prediction, Mapping) or not prediction:
        raise IdentityError("hyp_: prediction must be a non-empty mapping")
    for excluded in ("status", "rationale", "outcome"):
        if excluded in prediction:
            raise IdentityError(
                f"hyp_: {excluded!r} is excluded from hypothesis identity by SS8.2; "
                "record it on the node, not in the prediction"
            )
    return node_id(
        "hyp",
        {
            "premises": _sorted_ids(premises, field="hyp_.premises"),
            "prediction": prediction,
        },
    )
