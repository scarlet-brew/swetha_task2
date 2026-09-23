"""A scripted interpreter, so the loop mechanism is testable without a credential (T21).

This is not a fallback for the model and is not a rule registry -- design draft
3 died for putting interpretation into deterministic rules. It exists so a loop
failure is diagnosable as **mechanism or prompt**: if the loop works with the
stub and fails with the model, the fault is the prompt; if it fails with both,
it is the machinery.

It proposes only what the factual layer already makes obvious, in flat prose,
and it declines far more often than it proposes. That keeps the offline build
honest about what it is: the relationships and the scope are real, the
*interpretation* is a placeholder.
"""

from __future__ import annotations

from typing import Any

#: Relation sets that justify a placeholder statement, and the stage to file it
#: under. Deliberately thin -- three shapes, all of them directly readable off
#: the edges rather than inferred.
_SHAPES = (
    # One relation each. An earlier version required `same_file` and `same_size`
    # together, which no single observation can satisfy: an observation carries
    # one entity type, so it is either the name or the size, never both.
    ({"same_size"}, "exfiltration", "a file of identical exact byte count appears in two sources"),
    ({"same_file"}, "collection", "a file of the same name appears in more than one record"),
    ({"process_parent"}, "execution", "one process was created by another on the same host"),
    ({"flow_endpoint"}, "command-and-control", "a network flow connects two addresses"),
)


class StubInterpreter:
    def __init__(self, index):
        self.index = index
        self.proposed: set[tuple[str, ...]] = set()

    def interpret(self, neighbourhood: dict, context: dict) -> dict | None:
        present = set(neighbourhood.get("relations", {}))
        for required, stage, phrasing in _SHAPES:
            if not required <= present:
                continue

            cited = [neighbourhood["observation"]]
            edges = []
            for relation in sorted(required):
                data = neighbourhood["relations"][relation]
                for row in data["observations"][:1]:
                    cited.append(row["id"])
                    edges.append(
                        {
                            "relation": relation,
                            "from_observation": neighbourhood["observation"],
                            "to_observation": row["id"],
                        }
                    )

            key = tuple(sorted(set(cited))) + (stage,)
            if key in self.proposed:
                return None
            self.proposed.add(key)

            events = sorted({neighbourhood["event_id"]} | {
                self.index.by_id[obs]["event_id"] for obs in cited if obs in self.index.by_id
            })
            return {
                # Names only event ids, which are grounded by construction --
                # the invented-identifier check is not being dodged, there is
                # simply nothing here that could be invented.
                "statement": f"Across {', '.join(events)}, {phrasing}.",
                "stage": stage,
                "rationale": (
                    "Placeholder interpretation from the scripted stub: the relations "
                    f"{sorted(required)} hold between the cited observations."
                ),
                "cites_observations": sorted(set(cited)),
                "cites_edges": edges,
            }
        return None

    def hypothesise(self, findings: list[dict], context: dict) -> dict | None:
        """One hypothesis per exfiltration finding, and only that.

        Predicts the network record that *would* corroborate a transfer. In this
        dataset no firewall record corroborates the egress, so the prediction is
        expected to come back unconfirmed -- which is the honest outcome and
        exactly what the coverage-gap report should carry.
        """
        latest = findings[-1]
        if latest["stage"] != "exfiltration":
            return None
        return {
            "premises": [latest["id"]],
            "predicted_entity": "185.220.101.45",
            "predicted_role": "target",
            "predicted_event_kind": "network/network_connection",
            "predicted_source_type": "network",
            "window_start": "2026-06-10T08:00:00.000000Z",
            "window_end": "2026-06-13T08:00:00.000000Z",
            "rationale": (
                "If a file left the estate, a perimeter flow record of comparable volume "
                "should exist. Committed before looking."
            ),
        }
