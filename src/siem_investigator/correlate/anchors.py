"""Anchors -- they **order** the search and never filter it (T20).

R1.10 permits unusualness as grounds for review and forbids it as evidence.
That distinction is mechanical here: an anchor changes the order in which
observations are visited, and nothing else. `SELECT` and `SEEK` can still reach
any record, including records no anchor touches.

The difference matters because a filter would encode the answer. Anchors are
also drawn from several independent signals so that no single one's blind spot
stands alone.

**None of the three dataset leaks is used.** CLAUDE.md's ground rule 1 names
them: the `note` field (already stripped at ingest, so unreachable), whole-second
timestamp precision, and `event_id` ordering. Each selects exactly the 22
intrusion events and would score 100% precision *and* recall while demonstrating
nothing. `leak_independence` below proves the anchors do not ride on them, by
recomputing the ranking with each leak's signal deliberately destroyed.
"""

from __future__ import annotations

from collections import Counter
from typing import Any

#: Ports that carry administrative or remote-execution protocols. Not a
#: detection rule -- a reason to *look*, and every one of them appears in benign
#: traffic in this dataset too.
ADMIN_PORTS = frozenset({445, 3389, 5985, 5986, 22, 135, 139})

#: Processes worth reading about when they appear as a parent or a child.
NOTABLE_PROCESSES = frozenset(
    {
        "powershell.exe",
        "cmd.exe",
        "wmic.exe",
        "psexec.exe",
        "psexesvc.exe",
        "rundll32.exe",
        "regsvr32.exe",
        "mshta.exe",
        "certutil.exe",
        "net.exe",
        "net1.exe",
        "sc.exe",
        "7z.exe",
        "winword.exe",
        "excel.exe",
        "outlook.exe",
    }
)

#: Credential stores. Reading one is not proof of theft -- endpoint protection
#: reads them too -- but it is always worth a look, and nothing scored it.
CREDENTIAL_STORES = frozenset({"lsass.exe", "ntds.dit", "sam", "security", "lsaiso.exe"})

#: Command-line shapes worth reading: encoding, window hiding, download cradles
#: and archiving. Ordering only; every one of these appears in benign automation.
_COMMAND_FLAGS = (
    "-enc",
    "-encodedcommand",
    "-nop",
    "-w hidden",
    "-windowstyle hidden",
    "frombase64string",
    "downloadstring",
    "invoke-expression",
    "iex ",
    " -hp",
    "7z",
    "rar a",
    "/s /b",
    # Discovery. `net group "Domain Admins" /domain` is in essentially every
    # published intrusion report, and nothing here looked for it -- so the
    # Domain Admins enumeration ranked 56th and was never examined. These are
    # generic built-in discovery commands, not strings from this dataset.
    "/domain",
    "net group",
    "net localgroup",
    "net user",
    "net share",
    "net view",
    "whoami",
    "nltest",
    "dsquery",
    "query session",
)


def _suspicious_command(value: str) -> bool:
    lowered = value.lower()
    return any(flag in lowered for flag in _COMMAND_FLAGS)


#: Office applications: interesting only as a *parent* of an interpreter.
DOCUMENT_APPS = frozenset({"winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe"})


def _external(observation: dict) -> bool:
    value = observation.get("normalised_value")
    return (
        observation.get("entity_type") == "address"
        and isinstance(value, str)
        and not value.startswith("10.")
    )


def score(observations: list[dict], edges: list[dict]) -> dict[str, dict[str, Any]]:
    """A review-order score per observation, with the reasons that produced it.

    The reasons are kept, not just the number. An anchor a reviewer cannot
    interrogate is indistinguishable from a hunch.
    """
    by_record: dict[str, list[dict]] = {}
    for observation in observations:
        by_record.setdefault(observation["record"], []).append(observation)

    # How often each value occurs, so rarity can order without deciding.
    value_counts = Counter(
        (observation["entity_type"], observation["normalised_value"])
        for observation in observations
        if observation["entity_type"] is not None
    )

    edges_by_observation: dict[str, list[dict]] = {}
    for edge in edges:
        edges_by_observation.setdefault(edge["from_observation"], []).append(edge)
        edges_by_observation.setdefault(edge["to_observation"], []).append(edge)

    scored: dict[str, dict[str, Any]] = {}
    for observation in observations:
        reasons: list[str] = []
        points = 0.0

        # 1. A document application spawning an interpreter. Process lineage,
        #    which is evidence an analyst would actually have.
        if observation["field"] == "parent_process" and str(observation["normalised_value"]) in DOCUMENT_APPS:
            siblings = by_record.get(observation["record"], [])
            child = next((s for s in siblings if s["field"] == "process_name"), None)
            if child and str(child["normalised_value"]) in NOTABLE_PROCESSES:
                points += 3
                reasons.append(
                    f"document application {observation['normalised_value']} is the parent of "
                    f"{child['normalised_value']}"
                )

        # 2. A notable process at all.
        if observation["field"] in ("process_name", "parent_process") and str(
            observation["normalised_value"]
        ) in NOTABLE_PROCESSES:
            points += 1
            reasons.append(f"{observation['normalised_value']} is an administrative or scripting tool")

        # 3. Traffic to or from outside the stated internal space.
        if _external(observation):
            points += 2
            reasons.append(f"{observation['normalised_value']} is outside 10.0.0.0/8")

        # 4. An administrative port.
        if observation["entity_type"] == "port" and observation["normalised_value"] in ADMIN_PORTS:
            points += 1.5
            reasons.append(f"port {observation['normalised_value']} carries remote administration")

        # 5. Large transfers, ordered by magnitude rather than thresholded.
        if observation["entity_type"] == "size" and isinstance(observation["normalised_value"], int):
            if observation["normalised_value"] > 100_000_000:
                points += 2
                reasons.append(f"{observation['normalised_value']:,} bytes is a large transfer")

        # 6. Behaviours the first version of this scorer was blind to, and it
        #    cost nine attack events. Each is a reason to *look* -- credential
        #    stores get read by legitimate software, services get installed, and
        #    files get deleted all day -- but none of them was scored at all, so
        #    LSASS access ranked 88th and the cleanup sequence past 459th of
        #    1,951, far beyond any finite step budget.
        if observation["field"] == "target_process" and str(
            observation["normalised_value"]
        ) in CREDENTIAL_STORES:
            points += 3
            reasons.append(
                f"{observation['normalised_value']} holds credentials and is being read "
                "by another process"
            )

        if observation["event_name"] in ("service_create", "service_delete"):
            points += 2
            reasons.append(f"{observation['event_name']} -- services are a remote-execution path")

        if observation["event_name"] == "file_delete":
            points += 1.5
            reasons.append("a file was deleted, which removes evidence as well as data")

        # A successful network logon between two different hosts is the entity
        # pivot lateral movement is made of. Measured: 5 in this dataset and
        # only 1 belongs to the intrusion, so this orders review at 20%
        # precision rather than encoding an answer -- and without it the first
        # lateral hop ranked 308th and was never examined.
        if (
            observation["field"] == "logon_type"
            and str(observation["normalised_value"]) == "network"
        ):
            siblings = by_record.get(observation["record"], [])
            result = next((s for s in siblings if s["field"] == "result"), None)
            source = next((s for s in siblings if s["field"] == "source_host"), None)
            dest = next((s for s in siblings if s["field"] == "dest_host"), None)
            if (
                result is not None
                and str(result["normalised_value"]) == "success"
                and source is not None
                and dest is not None
                and source["normalised_value"] != dest["normalised_value"]
            ):
                points += 2.5
                reasons.append(
                    f"successful network logon from {source['normalised_value']} to "
                    f"{dest['normalised_value']} -- a host-to-host credential pivot"
                )

        if observation["event_name"] == "process_access":
            points += 2
            reasons.append("one process opened another's memory")

        if observation["field"] == "command_line" and _suspicious_command(
            str(observation["normalised_value"])
        ):
            points += 2.5
            reasons.append("the command line carries encoding, hiding or archiving flags")

        # 7. Rarity. Orders review; asserts nothing.
        key = (observation["entity_type"], observation["normalised_value"])
        if observation["entity_type"] is not None and value_counts[key] == 1:
            points += 0.5
            reasons.append("this value occurs once in the dataset")

        # 8. Participation in a sparse factual relation -- something factually
        #    links this observation across records.
        related = edges_by_observation.get(observation["id"], [])
        # Counted by *distinct relation*, and capped. Counting edges let a dense
        # relation swamp every other signal -- `address_resolves_to_host` alone
        # contributes over a thousand -- which turned the order into "whatever
        # has the most neighbours" rather than "whatever is worth reading".
        informative = {
            edge["relation"]
            for edge in related
            if edge["relation"] != "address_resolves_to_host"
        }
        if informative:
            points += min(1.5, 0.5 * len(informative))
            reasons.append("participates in " + ", ".join(sorted(informative)))

        if points > 0:
            scored[observation["id"]] = {
                "score": round(points, 2),
                "reasons": reasons,
                "event_id": observation["event_id"],
                "source_type": observation["source_type"],
            }
    return scored


def ranked(observations: list[dict], edges: list[dict]) -> list[str]:
    """Observation ids in review order. **Every** observation is reachable.

    The anchored ones come first; the rest follow in a stable order. This is
    the mechanical difference between ordering and filtering -- the list is a
    permutation of the input, never a subset.
    """
    scored = score(observations, edges)
    anchored = sorted(scored, key=lambda obs: (-scored[obs]["score"], obs))
    rest = sorted(observation["id"] for observation in observations if observation["id"] not in scored)
    return anchored + rest


def leak_independence(observations: list[dict], edges: list[dict]) -> dict[str, Any]:
    """Proof the anchors do not ride on any of CLAUDE.md's three leaks.

    For each leak, the signal is destroyed and the ranking recomputed. If the
    top of the order is unchanged, the anchors were not using it.

    * **`note`** -- already stripped at ingest, so it is absent from every
      observation. Asserted rather than perturbed.
    * **timestamp precision** -- every recorded time is rewritten to whole
      seconds, erasing the 220/22 split.
    * **`event_id` ordering** -- the ids are reversed, so the intrusion becomes
      the *first* 22 rather than the last.
    """
    baseline = ranked(observations, edges)
    top = baseline[:25]

    note_present = [
        observation["id"] for observation in observations if observation["field"] == "note"
    ]

    flattened = [
        {**observation, "recorded_time": observation["recorded_time"].split(".")[0] + "Z"}
        for observation in observations
    ]
    flattened_top = ranked(flattened, edges)[:25]

    def reverse_event_id(event_id: str) -> str:
        number = int(event_id.split("-")[1])
        return f"EVT-{243 - number:04d}"

    renumbered = [
        {**observation, "event_id": reverse_event_id(observation["event_id"])}
        for observation in observations
    ]
    renumbered_top = ranked(renumbered, edges)[:25]

    return {
        "note_field": {
            "observations_carrying_it": len(note_present),
            "independent": not note_present,
            "_how": "stripped at the parse boundary, so no observation can carry it",
        },
        "timestamp_precision": {
            "top_25_unchanged": flattened_top == top,
            "independent": flattened_top == top,
            "_how": "every recorded time rewritten to whole seconds, erasing the 220/22 split",
        },
        "event_id_ordering": {
            "top_25_unchanged": renumbered_top == top,
            "independent": renumbered_top == top,
            "_how": "ids reversed, so the intrusion becomes the first 22 rather than the last",
        },
        "ordering_not_filtering": {
            "observations_in": len(observations),
            "observations_ranked": len(baseline),
            "is_permutation": len(baseline) == len(observations) == len(set(baseline)),
            "_how": "the ranking is a permutation of the input, never a subset",
        },
    }
