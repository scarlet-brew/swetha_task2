"""Regenerate the committed egress fixture: what each model site actually sends (T06).

NFR-04 has two halves. The first is that every category of incident information
leaving the machine is documented -- `docs/egress.md`. The second is that the
documentation is *true*, which a document cannot establish about itself. So this
script captures the **exact serialised request body** for each of the four
contracts through a mock transport, labels every piece of the user payload with
the documented category it instantiates, and commits the result.
`tests/test_egress_inventory.py` then checks the three against each other: the
captured body, the categories declared in `agent/contracts.py`, and the table in
`docs/egress.md`.

    python scripts/regen_egress_fixture.py           # rewrite the fixture
    python scripts/regen_egress_fixture.py --check   # rebuild to memory and diff

Nothing leaves the process and no credential is needed: `httpx.MockTransport`
answers `401` before a socket is opened, and the request is already captured by
then. Running this with the network down produces the same file.

**Two deliberate properties of the material in it.**

*Derived, not invented.* The record and observation ids are computed by
`siem_investigator.ids` from real events in `data/raw/siem_logs.json`, and the
technique names and catalogue version come from the derived catalogue. A
hand-typed `obs_deadbeef` would make the fixture a drawing of a request rather
than a request.

*Benign events only.* Every event quoted here is one of the 220 ordinary ones.
The fixture is committed, readable, and shows the shape of a prompt -- so
populating it from the intrusion would turn a test fixture into a hint sheet,
and R7.2 confines the answer key to accuracy measurement.

**What this pins, and what it cannot yet.** The envelope is production code:
`client._request_kwargs` builds it, so the six top-level fields, the system
prompts and the emitted schemas are the real ones. The *user payload* is
assembled here from labelled blocks through `contracts.render_payload`, which
refuses an undeclared category -- so when T22, T24 and T31 build their real
payloads through that same function, the check extends to them by construction.
Until then this fixture pins the envelope and the labelling discipline, not the
final prompt text.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT / "src") not in sys.path:
    sys.path.insert(0, str(ROOT / "src"))

import anthropic  # noqa: E402

from siem_investigator import ids  # noqa: E402
from siem_investigator.agent import client, contracts, schemas  # noqa: E402
from siem_investigator.agent.contracts import PayloadBlock, Site  # noqa: E402
from siem_investigator.enrich.catalogue import Catalogue  # noqa: E402

RAW = ROOT / "data" / "raw" / "siem_logs.json"
FIXTURE = ROOT / "tests" / "fixtures" / "egress_request_bodies.json"

#: Benign events the blocks are built from, chosen one per source type so the
#: fixture exercises a cross-source payload rather than four rows of endpoint.
SAMPLE_EVENT_IDS = ("EVT-0141", "EVT-0046", "EVT-0114", "EVT-0199")

#: Candidates for the stage-4 enum. Real ids, and deliberately *not* T1068:
#: nothing in this dataset evidences exploitation for privilege escalation, and
#: a fixture is a place a wrong id would sit unread for weeks.
CANDIDATE_TECHNIQUE_IDS = ("T1059.001", "T1078", "T1569.002")


def load_events() -> dict[str, dict[str, Any]]:
    payload = json.loads(RAW.read_text(encoding="utf-8"))
    return {event["event_id"]: event for event in payload["events"]}


def record_of(event: dict[str, Any]) -> tuple[str, dict[str, Any]]:
    """A record id and the payload it was computed from.

    `note` is dropped because the parse boundary drops it (T10) and nothing
    downstream may see it. The rest of the payload shape is T10's business; this
    fixture needs only *a* real record id, computed the way the system computes
    one.
    """
    payload = {key: value for key, value in event.items() if key != "note"}
    return ids.record_id(
        source_type=event["source_type"], event_id=event["event_id"], payload=payload
    ), payload


def observation_of(event: dict[str, Any], field: str) -> tuple[str, str]:
    """An observation id for one field of one event, and the value it asserts."""
    record, _ = record_of(event)
    value = str(event[field])
    return (
        ids.observation_id(
            record=record, field=field, normalised_value=value, transform="verbatim"
        ),
        value,
    )


def payload_blocks(
    events: dict[str, dict[str, Any]], catalogue: Catalogue
) -> dict[str, tuple[PayloadBlock, ...]]:
    """One labelled block per declared category, for all four sites.

    Every category each site declares appears exactly once, so the fixture
    exercises the whole declared surface rather than the convenient part of it.
    """
    endpoint, auth, network, cloud = (events[event_id] for event_id in SAMPLE_EVENT_IDS)

    process_obs, process_value = observation_of(endpoint, "process_name")
    parent_obs, parent_value = observation_of(endpoint, "parent_process")
    account_obs, account_value = observation_of(auth, "username")
    host_obs, host_value = observation_of(endpoint, "hostname")
    auth_record, _ = record_of(auth)
    endpoint_record, _ = record_of(endpoint)

    # A finding statement over benign records. It reads like the real thing,
    # because a prompt-shaped fixture is only useful if it is prompt-shaped.
    finding = ids.finding_id(
        cited_observations=[process_obs, parent_obs], cited_edges=[], stage="execution"
    )
    statement = (
        f"{process_value} was created by {parent_value} on {host_value}, "
        f"recorded at {endpoint['timestamp']}."
    )
    mapping = ids.mapping_id(
        technique_id="T1059.001",
        finding=finding,
        cited_observations=[process_obs],
        quoted_values=[process_value],
    )

    def candidates() -> str:
        lines = []
        for technique_id in CANDIDATE_TECHNIQUE_IDS:
            technique = catalogue.technique(technique_id)
            first_sentence = technique.description.split(". ")[0][:160]
            lines.append(
                f"  {technique.technique_id}  {technique.name}  "
                f"[{', '.join(technique.tactics)}]  {first_sentence}."
            )
        return "CANDIDATE TECHNIQUES\n" + "\n".join(lines)

    interpret = (
        PayloadBlock(
            "observation ids and their asserted normalised values",
            f"OBSERVATIONS\n  {process_obs}  process_name  {process_value}\n"
            f"  {parent_obs}  parent_process  {parent_value}\n"
            f"  {account_obs}  username  {account_value}",
        ),
        PayloadBlock(
            "record ids, source types and recorded timestamps",
            f"RECORDS\n  {endpoint_record}  {endpoint['source_type']}  {endpoint['timestamp']}\n"
            f"  {auth_record}  {auth['source_type']}  {auth['timestamp']}",
        ),
        PayloadBlock(
            "relation names and their endpoint observation ids",
            f"EDGES\n  process_parent({parent_obs}, {process_obs})\n"
            f"  same_host({host_obs}, {process_obs})",
        ),
        PayloadBlock(
            "previously accepted finding statements and ids",
            f"ACCEPTED SO FAR\n  {finding}  (execution)  {statement}",
        ),
    )

    hypothesise = (
        PayloadBlock(
            "accepted finding statements, stages and ids",
            f"FINDINGS\n  {finding}  (execution)  {statement}",
        ),
        PayloadBlock(
            "entity names as they appear in observations",
            f"ENTITIES\n  host {host_value}\n  account {account_value}\n"
            f"  address {network['src_ip']}",
        ),
        PayloadBlock(
            "source type coverage per entity",
            f"COVERAGE\n  {host_value}: endpoint yes, auth yes, cloud_storage no\n"
            f"  {account_value}: auth yes, endpoint no",
        ),
    )

    select_technique = (
        PayloadBlock(
            "one accepted finding statement and its stage",
            f"FINDING\n  {finding}  (execution)  {statement}",
        ),
        PayloadBlock(
            "the observations it cites, with their fields and values",
            f"CITED OBSERVATIONS\n  {process_obs}  process_name  {process_value}\n"
            f"  {parent_obs}  parent_process  {parent_value}",
        ),
        PayloadBlock(
            "candidate ATT&CK technique ids, names and descriptions from the local catalogue",
            candidates(),
        ),
    )

    answer = (
        PayloadBlock(
            "the analyst's question",
            f"QUESTION\n  Which accounts appear on {host_value} during the period examined?",
        ),
        PayloadBlock(
            "accepted finding statements, stages and ids",
            f"FINDINGS\n  {finding}  (execution)  {statement}",
        ),
        PayloadBlock(
            "observation ids, fields and asserted values",
            f"OBSERVATIONS\n  {host_obs}  hostname  {host_value}\n"
            f"  {account_obs}  username  {account_value}\n"
            f"  {cloud['event_id']} bucket  {cloud['bucket']}",
        ),
        PayloadBlock(
            "technique mappings and the local catalogue version",
            f"MAPPINGS\n  {mapping}  T1059.001  ->  {finding}\n"
            f"  catalogue version {catalogue.attack_version}",
        ),
        PayloadBlock(
            "computed coverage gaps",
            "GAPS\n  no mail-gateway source is present, so a delivery vector cannot be "
            "evidenced\n  no DNS source is present, so an address cannot be resolved to a name",
        ),
    )

    return {
        contracts.INTERPRET.name: interpret,
        contracts.HYPOTHESISE.name: hypothesise,
        contracts.SELECT_TECHNIQUE.name: select_technique,
        contracts.ANSWER.name: answer,
    }


def model_type_for(site: Site) -> type[schemas.BaseModel]:
    """The type a site sends.

    Stage 4 sends the *constrained* selection model, whose `technique_id` enum
    is the retrieved candidate set. Capturing the open base class would capture
    a request the system never makes, and would miss the one property the
    capture exists to prove.
    """
    if site is contracts.SELECT_TECHNIQUE:
        return schemas.technique_selection_model(CANDIDATE_TECHNIQUE_IDS)
    return site.model_type


def build() -> dict[str, Any]:
    events = load_events()
    catalogue = Catalogue.load()
    blocks = payload_blocks(events, catalogue)

    sites: dict[str, Any] = {}
    for site in contracts.SITES:
        site_blocks = blocks[site.name]
        user = contracts.render_payload(site, site_blocks)
        sites[site.name] = {
            "stage": site.stage,
            "payload_blocks": [
                {"category": block.category, "text": block.text} for block in site_blocks
            ],
            "prompt_hash": client.prompt_hash(site.system, user),
            "request_body": client.captured_request_body(
                model_type=model_type_for(site), system=site.system, user=user
            ),
        }

    return {
        "_note": (
            "The exact serialised request body of every model site, captured through a mock "
            "transport by scripts/regen_egress_fixture.py. Nothing was sent. Checked against "
            "docs/egress.md by tests/test_egress_inventory.py."
        ),
        "contract_set_hash": contracts.CONTRACT_SET_HASH,
        "validator_version": contracts.VALIDATOR_VERSION,
        "provider_sdk_version": anthropic.__version__,
        "sample_event_ids": list(SAMPLE_EVENT_IDS),
        "sites": sites,
    }


def render(payload: dict[str, Any]) -> str:
    return json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Regenerate the egress fixture.")
    parser.add_argument("--check", action="store_true", help="diff instead of writing")
    args = parser.parse_args(argv)

    text = render(build())
    label = FIXTURE.relative_to(ROOT).as_posix()
    if args.check:
        current = FIXTURE.read_text(encoding="utf-8") if FIXTURE.exists() else None
        if current == text:
            print(f"ok       {label}")
            return 0
        print(f"DIFFERS  {label}; run without --check.", file=sys.stderr)
        return 1

    FIXTURE.parent.mkdir(parents=True, exist_ok=True)
    FIXTURE.write_text(text, encoding="utf-8", newline="")
    print(f"wrote    {label}  {len(text):,} bytes")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
