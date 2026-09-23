"""T06's one verification that needs a credential: each contract really round-trips.

Everything else about the four model sites is checked offline -- the emitted
schema, the closed vocabularies, the exact serialised request body, the hashes.
Only one claim cannot be: that a live call against each contract comes back as a
**populated instance** of it. That claim is not stubbed anywhere in the test
suite, because a mock that returns a canned response and asserts the canned
response arrived proves the mock and nothing else.

So it lives here, as a command to run the moment a key exists:

    ANTHROPIC_API_KEY=... python scripts/live_round_trip.py
    python scripts/live_round_trip.py --dry-run    # no credential, no network

The payloads are the ones `scripts/regen_egress_fixture.py` commits, so this
sends exactly the request the fixture documents -- the same `client.call` path
stages 3, 4 and 6 use, with no special case for being a script.

`--dry-run` runs every step up to the credential gate: it builds each request
and reports what would be sent. It is how you check this script still works
while there is no key, which is the state the repository was written in.

Exits `2` with one line and no traceback when the credential is unset (NFR-02:
the deterministic stages run without it), `1` if any site fails to return a
populated instance, `0` when all four do.
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
for extra in (ROOT / "src", ROOT / "scripts"):
    if str(extra) not in sys.path:
        sys.path.insert(0, str(extra))

from siem_investigator.agent import client, contracts  # noqa: E402

import regen_egress_fixture as fixture  # noqa: E402


def payload_for(site: contracts.Site) -> str:
    """The user payload the committed fixture documents for this site."""
    return fixture.build()["sites"][site.name]["request_body"]["messages"][0]["content"]


def dry_run() -> int:
    """Everything up to the call, so the script is testable with no credential."""
    for site in contracts.SITES:
        body = client.captured_request_body(
            model_type=fixture.model_type_for(site),
            system=site.system,
            user=payload_for(site),
        )
        defects = client.request_defects(body)
        print(
            f"{site.name:17} would send {len(body['system']):,}-char system, "
            f"{len(body['messages'][0]['content']):,}-char payload, "
            f"contract {fixture.model_type_for(site).__name__}; "
            f"defects={defects or 'none'}"
        )
        if defects:
            return 1
    print()
    print(
        f"contract set {contracts.CONTRACT_SET_HASH[:12]}  "
        f"validator {contracts.VALIDATOR_VERSION}"
    )
    return 0


def round_trip() -> int:
    failures = 0
    for site in contracts.SITES:
        model_type = fixture.model_type_for(site)
        try:
            call = client.call(
                site=site.name,
                model_type=model_type,
                system=site.system,
                user=payload_for(site),
            )
        except client.ModelCallFailed as failure:
            # A refusal or a truncation is a handled outcome, not a crash: report
            # it against the site and keep going, so one bad contract does not
            # hide the state of the other three.
            print(f"{site.name:17} FAILED  {failure}", file=sys.stderr)
            failures += 1
            continue

        populated = {
            name: value
            for name, value in call.parsed.model_dump().items()
            if value not in (None, "", [], {})
        }
        print(
            f"{site.name:17} {type(call.parsed).__name__} with "
            f"{len(populated)}/{len(call.parsed.model_dump())} field(s) populated  "
            f"stop={call.stop_reason}  in={call.input_tokens} out={call.output_tokens}"
        )
        print(f"                  {call.provenance.as_dict()}")
        if not populated:
            print(f"{site.name:17} FAILED  the instance came back empty", file=sys.stderr)
            failures += 1
    return 1 if failures else 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="T06: one live round-trip per contract.")
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="build each request and report it; needs no credential and opens no socket",
    )
    args = parser.parse_args(argv)

    if args.dry_run:
        return dry_run()

    # Checked before anything is printed, so this path emits exactly one line.
    if not (os.environ.get("ANTHROPIC_API_KEY") or os.environ.get("ANTHROPIC_AUTH_TOKEN")):
        print(
            "ANTHROPIC_API_KEY is not set; the live round-trip cannot be run "
            "(--dry-run covers everything up to the call).",
            file=sys.stderr,
        )
        return 2

    return round_trip()


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
