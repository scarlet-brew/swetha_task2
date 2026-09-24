"""Querying the virtual correlation graph (T17).

Split from `relations.py` because the two halves answer different questions.
`relations.py` says *what a relation is* -- eleven pure predicates, each an
exact statement about two observations. This says *how the graph is searched*:
value indexes, re-evaluation, sparse materialisation, and the neighbourhood the
interpretive layer reads.

`evaluate` recomputes a relation from its predicate rather than reading a stored
list, which is what makes validation check 2 mean anything: a cited edge is
verified against the data, never against a cache of earlier conclusions.
"""

from __future__ import annotations

from collections import defaultdict
from typing import Any

from .. import ids
from .relations import (
    ALL_RELATIONS,
    DENSE,
    PREDICATES,
    SPARSE,
    interval_seconds,
)

class RelationIndex:
    """Queries over the virtual graph, backed by value indexes.

    `evaluate` re-computes a relation from its predicate rather than looking it
    up in a stored list, which is what makes validation check 2 meaningful: a
    cited edge is verified against the data, not against a cache of earlier
    conclusions.
    """

    def __init__(self, observations: list[dict], resolution: list[dict] | None = None):
        self.observations = observations
        self.by_id = {observation["id"]: observation for observation in observations}
        self.by_value: dict[tuple[str, Any], list[dict]] = defaultdict(list)
        self.by_record: dict[str, list[dict]] = defaultdict(list)
        for observation in observations:
            if observation["entity_type"] is not None:
                self.by_value[(observation["entity_type"], observation["normalised_value"])].append(
                    observation
                )
            self.by_record[observation["record"]].append(observation)
        # address -> host candidates, from stage 2. Kept as candidates.
        self.resolution = {row["address"]: row for row in (resolution or [])}

    # ---- the tenth relation, which is not a pairwise predicate -------------

    def address_resolves_to_host(self, address_observation: dict, host_observation: dict) -> bool:
        """Whether the resolution table admits this host for this address.

        Deliberately admits **every** candidate. Only three hosts in this
        dataset have a single stable address, and those are the compromised
        ones -- so a resolver that preferred unambiguous mappings would
        rediscover the intrusion by construction.
        """
        if address_observation["entity_type"] != "address" or host_observation["entity_type"] != "host":
            return False
        row = self.resolution.get(address_observation["normalised_value"])
        if row is None:
            return False
        return any(
            candidate["host"] == host_observation["normalised_value"]
            for candidate in row["candidates"]
        )

    def is_ambiguous(self, address_value: str) -> bool:
        row = self.resolution.get(address_value)
        return bool(row and row["ambiguous"])

    # ---- evaluation -------------------------------------------------------

    def evaluate(self, relation: str, left_id: str, right_id: str) -> tuple[bool, dict]:
        """`(holds, reported parameters)`, recomputed from the data."""
        left, right = self.by_id.get(left_id), self.by_id.get(right_id)
        if left is None or right is None:
            return False, {"error": "endpoint does not exist"}
        if relation == "address_resolves_to_host":
            holds = self.address_resolves_to_host(left, right)
            params: dict[str, Any] = {}
            if holds:
                row = self.resolution[left["normalised_value"]]
                params = {"candidates": row["candidate_count"], "ambiguous": row["ambiguous"]}
            return holds, params
        predicate = PREDICATES.get(relation)
        if predicate is None:
            return False, {"error": f"unknown relation {relation!r}"}
        holds = predicate(left, right)
        params = {}
        if holds and relation in ("temporal_within", "session_bracket"):
            params = {"interval_seconds": interval_seconds(left, right)}
        return holds, params

    # ---- materialisation of the sparse relations --------------------------

    def _pairs_by_shared_value(self, entity_type: str, *, cross_source_only: bool = False):
        for (kind, _value), group in self.by_value.items():
            if kind != entity_type:
                continue
            for index, left in enumerate(group):
                for right in group[index + 1 :]:
                    if left["record"] == right["record"]:
                        continue
                    if cross_source_only and left["source_type"] == right["source_type"]:
                        continue
                    yield left, right

    def materialise_sparse(self) -> list[dict]:
        """The five sparse relations, as edge nodes.

        Sparse on measurement, not assumption: these are the relations whose
        full extension is small enough to be read by a person.
        """
        edges: list[dict] = []

        def add(relation: str, left: dict, right: dict) -> None:
            holds, params = self.evaluate(relation, left["id"], right["id"])
            if not holds:
                return
            edges.append(
                {
                    "id": ids.edge_id(relation=relation, endpoints=[left["id"], right["id"]]),
                    "layer": "edge",
                    "relation": relation,
                    "from_observation": left["id"],
                    "to_observation": right["id"],
                    "from_event": left["event_id"],
                    "to_event": right["event_id"],
                    # Reported, never part of identity.
                    "params": params,
                }
            )

        for left, right in self._pairs_by_shared_value("file"):
            add("same_file", left, right)
        for left, right in self._pairs_by_shared_value("size"):
            add("same_size", left, right)
        for left, right in self._pairs_by_shared_value("pid"):
            add("process_pid", left, right)

        for observations in self.by_record.values():
            parents = [o for o in observations if o["field"] == "parent_process"]
            children = [o for o in observations if o["field"] == "process_name"]
            for parent in parents:
                for child in children:
                    add("process_parent", parent, child)

            origins = [o for o in observations if o["entity_type"] == "address" and o["role"] == "origin"]
            targets = [o for o in observations if o["entity_type"] == "address" and o["role"] == "target"]
            for origin in origins:
                for target in targets:
                    add("flow_endpoint", origin, target)

        hosts = [o for o in self.observations if o["entity_type"] == "host"]
        addresses = [o for o in self.observations if o["entity_type"] == "address"]
        seen: set[tuple[str, str]] = set()
        for address in addresses:
            row = self.resolution.get(address["normalised_value"])
            if not row:
                continue
            names = {candidate["host"] for candidate in row["candidates"]}
            for host in hosts:
                if host["normalised_value"] not in names:
                    continue
                key = (address["id"], host["id"])
                if key in seen:
                    continue
                seen.add(key)
                add("address_resolves_to_host", address, host)

        return edges

    # ---- the query the interpretive layer uses ----------------------------

    #: Relations that link two records by something real -- a shared account, a
    #: shared file, a parent process. These get the window.
    LINKING = (
        "same_account",
        "same_host",
        "same_address",
        "same_file",
        "same_size",
        "process_pid",
        "process_parent",
        "flow_endpoint",
        "address_resolves_to_host",
    )

    #: Relations that describe *ordering* rather than linkage. Reported as
    #: annotations on the neighbours above, never as lists of their own.
    ORDERING = ("temporal_within", "session_bracket")

    #: Relations queryable through the value index rather than by scanning.
    BY_VALUE = (
        "same_account",
        "same_host",
        "same_address",
        "same_file",
        "same_size",
        "process_pid",
    )

    def neighbourhood(self, observation_id: str, *, k: int = 12) -> dict:
        """Observations related to this one, **with truncation reported**.

        Two things the shape of this function decides, both learned the hard
        way.

        **Truncation is always stated.** Each relation reports its full total
        beside what it shows, because a model reasoning over a partial view
        believing it complete is worse than one told the view is partial. A
        1-hop expansion on a busy host returns 60+ observations through
        `same_host` alone.

        **Ordering relations are annotations, not lists.** `temporal_within`
        held 1,782 candidates and was given eight slots of the window, while
        `same_account` -- which carried the actual intrusion chain -- got the
        same eight. Time now annotates the neighbours that a linking relation
        surfaced, so the window is spent on records connected by something real.
        """
        anchor = self.by_id.get(observation_id)
        if anchor is None:
            return {"observation": observation_id, "error": "does not exist"}

        found: dict[str, Any] = {}
        surfaced: dict[str, dict] = {}

        for relation in self.LINKING:
            matches = []
            if relation in self.BY_VALUE:
                if anchor["entity_type"] is None:
                    continue
                candidates = self.by_value.get(
                    (anchor["entity_type"], anchor["normalised_value"]), []
                )
            else:
                candidates = self.observations

            for candidate in candidates:
                if candidate["id"] == anchor["id"]:
                    continue
                holds, params = self.evaluate(relation, anchor["id"], candidate["id"])
                if holds:
                    matches.append((candidate, params))

            if not matches:
                continue
            matches.sort(key=lambda pair: abs(interval_seconds(anchor, pair[0])))
            shown = matches[:k]
            for candidate, _ in shown:
                surfaced[candidate["id"]] = candidate

            found[relation] = {
                "total": len(matches),
                "showing": len(shown),
                "truncated": len(matches) > k,
                "observations": [
                    {
                        "id": candidate["id"],
                        "event_id": candidate["event_id"],
                        "source_type": candidate["source_type"],
                        "field": candidate["field"],
                        "value": candidate["normalised_value"],
                        "params": params,
                    }
                    for candidate, params in shown
                ],
            }

        # Ordering, over what the linking relations surfaced. This is the chain:
        # the same neighbours, placed in time relative to the anchor.
        ordering: dict[str, list[dict]] = {}
        for relation in self.ORDERING:
            rows = []
            for candidate in surfaced.values():
                holds, params = self.evaluate(relation, anchor["id"], candidate["id"])
                reverse, _ = self.evaluate(relation, candidate["id"], anchor["id"])
                if not (holds or reverse):
                    continue
                delta = interval_seconds(anchor, candidate)
                rows.append(
                    {
                        "id": candidate["id"],
                        "event_id": candidate["event_id"],
                        "interval_seconds": delta,
                        "direction": "after the anchor" if delta > 0 else "before the anchor",
                    }
                )
            if rows:
                rows.sort(key=lambda row: row["interval_seconds"])
                ordering[relation] = rows

        same_record = [
            {
                "id": sibling["id"],
                "field": sibling["field"],
                "value": sibling["normalised_value"],
                "entity_type": sibling["entity_type"],
                "role": sibling["role"],
            }
            for sibling in self.by_record.get(anchor["record"], [])
            if sibling["id"] != anchor["id"]
        ]

        return {
            "observation": anchor["id"],
            "event_id": anchor["event_id"],
            "source_type": anchor["source_type"],
            "field": anchor["field"],
            "value": anchor["normalised_value"],
            "recorded_time": anchor["recorded_time"],
            "record_context": same_record,
            "relations": found,
            "ordering": ordering,
        }
