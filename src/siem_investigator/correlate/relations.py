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
SPARSE = (
    "same_file",
    "same_size",
    "process_parent",
    "process_pid",
    "flow_endpoint",
    "address_resolves_to_host",
)

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


def process_pid(creation: dict, access: dict) -> bool:
    """A process id in one record matching a pid or target pid in another.

    The eleventh relation, and the reason it exists is concrete. EVT-0222
    records the creation of PowerShell pid 5104; EVT-0226 records pid 5104
    reading LSASS memory. The pid is the only thing joining them, and with the
    original ten relations there was **no path at all** between the credential
    theft and the shell that performed it.

    Atomic and decides nothing, like every other relation here: it asserts that
    two records name the same process id, not that one caused the other.
    Directional only in the sense that the endpoints are ordered.
    """
    return (
        creation["entity_type"] == "pid"
        and access["entity_type"] == "pid"
        and creation["normalised_value"] == access["normalised_value"]
        and creation["record"] != access["record"]
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
    "process_pid": process_pid,
    "flow_endpoint": flow_endpoint,
    "session_bracket": session_bracket,
    "temporal_within": temporal_within,
}


# The query side lives in `index.py`: what a relation *is* and how the graph is
# *searched* are different concerns. Re-exported so callers need one import.
from .index import RelationIndex  # noqa: E402

__all__ = [
    "ALL_RELATIONS",
    "DENSE",
    "PREDICATES",
    "RelationIndex",
    "SPARSE",
    "interval_seconds",
]
