"""The investigation graph, the five invariants, and `trace` (T13).

Dataclasses and `dict` adjacency rather than a graph library (D-05). The reason
is not size -- it is that every check here has to produce a **specific
diagnostic**: not "there is a cycle" but the path, not "invalid" but which
identifier was invented. A generic library has no node schemas, no layer
typing, and no way to generate those messages, so it would sit beside a second
source of truth rather than replacing one.

The five invariants, all machine-decidable -- this is the trust story:

1. **Layer order** -- a record cites nothing; an observation cites only records;
   a finding cites observations, findings and edges; a claim cites findings,
   mappings or observations.
2. **Termination** -- every chain bottoms out in raw records.
3. **Acyclicity** -- no node transitively supports itself.
4. **Grounding** -- every asserted value appears at a named field of a cited
   record.
5. **Normalisation reproducibility** -- re-applying a recorded transform to its
   recorded raw value yields the asserted value.

Invariants 1-3 live here; 4 is in `observations.py` and 5 in `transforms.py`,
each next to the data it checks.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

#: What each layer is allowed to cite. Invariant 1, as data.
CITES_ALLOWED: dict[str, frozenset[str]] = {
    "record": frozenset(),
    "observation": frozenset({"record"}),
    "edge": frozenset({"observation"}),
    "finding": frozenset({"observation", "edge", "finding"}),
    "mapping": frozenset({"finding", "observation"}),
    "hypothesis": frozenset({"finding"}),
    "claim": frozenset({"finding", "mapping", "observation"}),
}


@dataclass
class Graph:
    """Nodes by id, plus the citation adjacency between them."""

    nodes: dict[str, dict] = field(default_factory=dict)
    cites: dict[str, list[str]] = field(default_factory=dict)

    def add(self, node: dict, *, layer: str, cites: list[str] | None = None) -> str:
        node_id = node["id"]
        stored = dict(node)
        stored["layer"] = layer
        self.nodes[node_id] = stored
        self.cites[node_id] = list(cites or [])
        return node_id

    def layer_of(self, node_id: str) -> str | None:
        node = self.nodes.get(node_id)
        return node["layer"] if node else None

    # ---- invariant 1 -------------------------------------------------------

    def layer_violations(self) -> list[str]:
        problems = []
        for node_id, targets in self.cites.items():
            layer = self.layer_of(node_id)
            if layer is None:
                continue
            allowed = CITES_ALLOWED.get(layer)
            if allowed is None:
                problems.append(f"{node_id}: unknown layer {layer!r}")
                continue
            for target in targets:
                target_layer = self.layer_of(target)
                if target_layer is None:
                    problems.append(f"{node_id} ({layer}) cites {target}, which does not exist")
                elif target_layer not in allowed:
                    problems.append(
                        f"{node_id} ({layer}) cites {target} ({target_layer}); a {layer} may cite "
                        f"only {sorted(allowed) or 'nothing'}"
                    )
        return problems

    # ---- invariant 2 -------------------------------------------------------

    def termination_failures(self) -> list[str]:
        """Every chain must bottom out in a record.

        A node whose transitive citations reach no record is ungrounded even if
        every individual citation resolves.
        """
        failures = []
        for node_id, layer in ((n, self.layer_of(n)) for n in self.nodes):
            if layer == "record":
                continue
            seen: set[str] = set()
            stack = [node_id]
            reached_record = False
            while stack:
                current = stack.pop()
                if current in seen:
                    continue
                seen.add(current)
                if self.layer_of(current) == "record":
                    reached_record = True
                    break
                stack.extend(self.cites.get(current, []))
            if not reached_record:
                failures.append(f"{node_id} ({layer}) reaches no raw record")
        return failures

    # ---- invariant 3 -------------------------------------------------------

    def find_cycle(self) -> list[str] | None:
        """The first cycle found, **as its path**, or None.

        Iterative three-colour DFS. Returning the path rather than a boolean is
        the whole reason this is hand-written: a reviewer needs to see which
        chain supports itself.
        """
        WHITE, GREY, BLACK = 0, 1, 2
        colour: dict[str, int] = {node: WHITE for node in self.nodes}

        for root in self.nodes:
            if colour[root] != WHITE:
                continue
            stack: list[tuple[str, int]] = [(root, 0)]
            path: list[str] = []
            colour[root] = GREY
            path.append(root)
            while stack:
                node, index = stack[-1]
                targets = self.cites.get(node, [])
                if index < len(targets):
                    stack[-1] = (node, index + 1)
                    target = targets[index]
                    if colour.get(target, WHITE) == GREY:
                        start = path.index(target)
                        return path[start:] + [target]
                    if colour.get(target, WHITE) == WHITE:
                        colour[target] = GREY
                        path.append(target)
                        stack.append((target, 0))
                else:
                    colour[node] = BLACK
                    stack.pop()
                    if path and path[-1] == node:
                        path.pop()
        return None

    # ---- tracing -----------------------------------------------------------

    def trace(self, node_id: str, *, depth: int = 0) -> dict:
        """The full support chain beneath `node_id`, down to records.

        This is R2.4 made operational: any node, traced to the raw evidence,
        with nothing in between hidden.
        """
        node = self.nodes.get(node_id)
        if node is None:
            return {"id": node_id, "error": "does not exist"}
        return {
            "id": node_id,
            "layer": node["layer"],
            "summary": summarise(node),
            "cites": [self.trace(target, depth=depth + 1) for target in self.cites.get(node_id, [])],
        }

    def check_all(self) -> dict[str, Any]:
        cycle = self.find_cycle()
        layer = self.layer_violations()
        termination = self.termination_failures()
        return {
            "invariant_1_layer_order": {"violations": layer, "holds": not layer},
            "invariant_2_termination": {"failures": termination, "holds": not termination},
            "invariant_3_acyclicity": {"cycle_path": cycle, "holds": cycle is None},
            "nodes": len(self.nodes),
            "citations": sum(len(targets) for targets in self.cites.values()),
            "by_layer": {
                layer_name: sum(1 for node in self.nodes.values() if node["layer"] == layer_name)
                for layer_name in sorted({node["layer"] for node in self.nodes.values()})
            },
        }


def summarise(node: dict) -> str:
    """One line describing a node, for a trace or a diagnostic."""
    layer = node.get("layer")
    if layer == "record":
        return f"{node['event_id']} {node['kind']} at {node['recorded_time']}"
    if layer == "observation":
        return (
            f"{node['event_id']}.{node['field']} = {node['normalised_value']!r} "
            f"via {node['transform']}"
        )
    if layer == "edge":
        return f"{node['relation']}({node['from_event']}, {node['to_event']})"
    if layer == "finding":
        return f"[{node.get('stage')}] {node.get('statement', '')}"
    if layer == "mapping":
        return f"{node.get('technique_id')} {node.get('technique_name')}"
    if layer == "hypothesis":
        return f"{node.get('status')}: {node.get('predicted_event_kind')} for {node.get('predicted_entity')}"
    return node.get("id", "?")


def render_trace(tree: dict, *, indent: int = 0) -> str:
    """A trace as indented text, for the `trace` CLI and the pipeline surface."""
    pad = "  " * indent
    if "error" in tree:
        return f"{pad}{tree['id']}: {tree['error']}"
    lines = [f"{pad}{tree['layer']:<12} {tree['id']}  {tree['summary']}"]
    for child in tree["cites"]:
        lines.append(render_trace(child, indent=indent + 1))
    return "\n".join(lines)
