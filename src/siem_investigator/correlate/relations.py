"""The factual correlation layer -- ten atomic relations (T16, T17).

**Deterministic, total, and it decides nothing.** Ten relation *types*, zero
detection rules. There is deliberately no composite: `same_file AND same_size
AND ordered` is something the interpretive layer *observes*, and bundling it
into one relation called `staged_then_uploaded` is exactly how interpretation
leaks into the deterministic layer -- the failure that killed design draft 3.
Such a rule would both compute a link and call it exfiltration.

Two consequences worth stating. There is **no coverage ceiling**, because
nothing is being detected. And the model **cannot invent a relationship** --
only interpret ones that factually exist.

**The graph is virtual.** `same_account` alone is ~44,000 pairs across 12
accounts; materialising all-pairs would be wasteful and unreadable. Sparse
relations (`same_file`, `same_size`, `process_parent`, `flow_endpoint`,
`address_resolves_to_host`) are materialised because they are small; dense ones
(`same_account`, `same_host`, `same_address`, `temporal_within`,
`session_bracket`) stay indexed queries. What gets committed is the subgraph the
investigation actually traversed.

**`temporal_within` reports the interval rather than thresholding it.** No
global time window has to be chosen, which dissolves the one genuinely hard
parameter in the design: this intrusion's own related activities are separated
by anything from 2 seconds to over an hour and a half, so any fixed window
would be wrong in one direction or the other.
"""

from __future__ import annotations

import datetime as dt
from collections import defaultdict
from typing import Any, Callable

from .. import ids

#: Relations small enough to materialise. Measured, not guessed: the whole
#: dataset yields a handful of each.
SPARSE = ("same_file", "same_size", "process_parent", "flow_endpoint", "address_resolves_to_host")

#: Relations left as indexed queries because all-pairs would be unreadable.
DENSE = ("same_account", "same_host", "same_address", "temporal_within", "session_bracket")

ALL_RELATIONS = tuple(sorted(SPARSE + DENSE))


def _instant(observation: dict) -> dt.datetime:
    return dt.datetime.fromisoformat(observation["recorded_time"].replace("Z", "+00:00"))


def interval_seconds(left: dict, right: dict) -> float:
    """Signed seconds from `left` to `right`. **Reported, never thresholded.**"""
    return (_instant(right) - _instant(left)).total_seconds()


# --------------------------------------------------------------------------
# The ten predicates. Each takes two observations and returns a bool, plus
# optional reported parameters. None of them decides anything.
# --------------------------------------------------------------------------


def _same_entity(entity_type: str) -> Callable[[dict, dict], bool]:
    def predicate(left: dict, right: dict) -> bool:
        return (
            left["entity_type"] == entity_type
            and right["entity_type"] == entity_type
            and left["normalised_value"] == right["normalised_value"]
            and left["record"] != right["record"]
        )

    return predicate


same_account = _same_entity("account")
same_host = _same_entity("host")
same_address = _same_entity("address")
same_file = _same_entity("file")


def same_size(left: dict, right: dict) -> bool:
    """Exact byte equality, and **both sides must carry a size**.

    Absent is not zero and not equal. A deletion record naming a file it does
    not size must not match the upload of that file -- which is precisely the
    false positive this relation removes. Measured on this dataset: basename
    alone gives 2 cross-source file pairs, one of them wrong; basename plus
    exact size gives 1, the right one.
    """
    return (
        left["entity_type"] == "size"
        and right["entity_type"] == "size"
        and left["normalised_value"] == right["normalised_value"]
        and left["record"] != right["record"]
    )


def process_parent(parent: dict, child: dict) -> bool:
    """`parent_process` of one record matching `process_name` of the same record.

    Directional and within a single record, which is what the endpoint source
    actually gives: a `process_create` event names both the process and its
    parent. Ordering the endpoints matters -- reversing them states that the
    child spawned the parent.
    """
    return (
        parent["field"] == "parent_process"
        and child["field"] == "process_name"
        and parent["record"] == child["record"]
    )


def flow_endpoint(origin: dict, target: dict) -> bool:
    """The two ends of one network flow, in direction order."""
    return (
        origin["record"] == target["record"]
        and origin["entity_type"] == "address"
        and target["entity_type"] == "address"
        and origin["role"] == "origin"
        and target["role"] == "target"
    )


def session_bracket(opening: dict, closing: dict) -> bool:
    """A logon and a logoff for one account on one host, in time order.

    Brackets an interval during which the account held a session, which is what
    lets activity be placed inside or outside one.
    """
    if opening["entity_type"] != "account" or closing["entity_type"] != "account":
        return False
    if opening["normalised_value"] != closing["normalised_value"]:
        return False
    if opening["event_name"] != "user_logon" or closing["event_name"] != "user_logoff":
        return False
    return interval_seconds(opening, closing) > 0


def temporal_within(earlier: dict, later: dict) -> bool:
    """Ordered in time. The interval is **reported** as a parameter, not tested."""
    return earlier["record"] != later["record"] and interval_seconds(earlier, later) > 0


PREDICATES: dict[str, Callable[[dict, dict], bool]] = {
    "same_account": same_account,
    "same_host": same_host,
    "same_address": same_address,
    "same_file": same_file,
    "same_size": same_size,
    "process_parent": process_parent,
    "flow_endpoint": flow_endpoint,
    "session_bracket": session_bracket,
    "temporal_within": temporal_within,
}


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

    def neighbourhood(self, observation_id: str, *, k: int = 8) -> dict:
        """Observations related to this one, **with truncation reported**.

        Each relation returns up to `k` nearest by time *with its full total
        stated*. Without the total the model reasons over a partial view
        believing it complete -- a 1-hop expansion on a busy host returns 60+
        observations through `same_host` alone.
        """
        anchor = self.by_id.get(observation_id)
        if anchor is None:
            return {"observation": observation_id, "error": "does not exist"}

        found: dict[str, list[dict]] = {}
        for relation in ALL_RELATIONS:
            matches = []
            if relation in ("same_account", "same_host", "same_address", "same_file", "same_size"):
                if anchor["entity_type"] is None:
                    continue
                for candidate in self.by_value.get(
                    (anchor["entity_type"], anchor["normalised_value"]), []
                ):
                    holds, params = self.evaluate(relation, anchor["id"], candidate["id"])
                    if holds:
                        matches.append((candidate, params))
            else:
                for candidate in self.observations:
                    if candidate["id"] == anchor["id"]:
                        continue
                    holds, params = self.evaluate(relation, anchor["id"], candidate["id"])
                    if holds:
                        matches.append((candidate, params))

            if not matches:
                continue
            matches.sort(key=lambda pair: abs(interval_seconds(anchor, pair[0])))
            found[relation] = {
                "total": len(matches),
                "showing": min(k, len(matches)),
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
                    for candidate, params in matches[:k]
                ],
            }

        return {
            "observation": anchor["id"],
            "event_id": anchor["event_id"],
            "source_type": anchor["source_type"],
            "field": anchor["field"],
            "value": anchor["normalised_value"],
            "relations": found,
        }
