"""T05 -- the model-plane probe. One strict round-trip, and clean behaviour with no credential.

Three model sites in design SS7 depend on native structured outputs, and D-08
commits to `client.messages.parse` with Pydantic, `additionalProperties: false`
and `thinking={"type": "adaptive"}`. There is **no deterministic fallback** --
the rule registry that would have been one died as draft 3 (SS11) -- so if that
surface does not behave as D-08 assumes, D-02 must be reopened before any
stage-3 code exists. This finds that out in half an hour, not on day four.

Two questions, usually conflated, kept apart here:

1.  *Is the closed enum a constraint or a validation?* D-08's argument, and
    MITRE's TRAM lesson quoted in SS4, is that a hallucinated technique id must
    be **structurally unrepresentable**, not caught afterwards. That is a claim
    about the request body, so `--structure-only` asserts it against the request
    body -- no credential, no network. See `_restore_closed_values`: what it
    found is not what D-08 assumed.
2.  *Does one real call come back parsed?* Needs a credential, and is the only
    part of this script that does.

Not here, deliberately: prompt text worth keeping, the contract-set hash, the
egress inventory, a reusable client. Those are T06.

    python scripts/probe_model.py --structure-only     # offline, no credential
    python scripts/probe_model.py                      # one live round-trip
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
from pathlib import Path
from typing import Any, Literal

import anthropic
import httpx
import pydantic
from anthropic.lib._parse._transform import transform_schema
from pydantic import BaseModel, ConfigDict, Field

# `httpx` arrives with `anthropic` and adds nothing to SS10.1's frozen set, the
# way pyarrow arrives with Streamlit. Measured: anthropic 0.84.0 sits on httpx
# 0.28.1, not the httpx2 the 1.x line moved to, so the mock transport below is
# version-coupled to the SDK and fails loudly, not silently, on an upgrade.
#
# The package is never installed (SS10.1 keeps setuptools out of the frozen set),
# so the version NFR-07 stamps on every output is imported by path, as in
# tests/_env.py.
_SRC = Path(__file__).resolve().parents[1] / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

from siem_investigator import __version__ as SOFTWARE_VERSION  # noqa: E402

#: Stands in for SS4's technique selection, whose real enum is *retrieved* per
#: finding (T23) from the catalogue T04 derives. Three entries suffice to test
#: whether a closed enum is structural, and using the three techniques SS4 names
#: keeps the probe honest about the dataset rather than inventing ids.
TechniqueId = Literal["T1059.001", "T1078", "T1569.002"]

#: The out-of-enum probe value, chosen deliberately: T1068 is in the catalogue
#: (T04 asserts that), and CLAUDE.md forbids mapping it here because this
#: dataset's integrity rise runs through stolen credentials and service
#: execution, not exploitation. Exactly the plausible-but-wrong id a generator
#: reaches for, so exactly the right thing to prove unrepresentable.
OUT_OF_ENUM = "T1068"

MODEL_ID = "claude-opus-5"

#: What the SDK pins as `anthropic-version` on every request. The answer record
#: carries it as the provider version: "which version of the provider's API
#: produced this claim" is not answerable from the model id alone.
PROVIDER_API_VERSION = "2023-06-01"

MAX_TOKENS = 16_000

SYSTEM_PROMPT = (
    "You select one ATT&CK technique for an observed behaviour. Choose only from "
    "the retrieved enum, quote the record field values that drove the choice, and "
    "cite the event_id of every record you relied on. Assign no confidence, score "
    "or probability of any kind."
)

USER_PROMPT = (
    "Endpoint record EVT-0231 on host WKSTN-07: process_create, "
    'process_name "powershell.exe", parent_process "cmd.exe", '
    'command_line "powershell.exe -nop -w hidden -enc <base64>", '
    "integrity_level medium.\n\n"
    "Retrieved enum: T1059.001 (PowerShell), T1078 (Valid Accounts), "
    "T1569.002 (Service Execution)."
)


class ProbeSelection(BaseModel):
    """The smallest model exercising every property D-08 depends on.

    `extra="forbid"` is the Pydantic half of `additionalProperties: false`; the
    wire half is asserted separately, because the two can disagree and only the
    wire half constrains generation.
    """

    model_config = ConfigDict(extra="forbid")

    technique_id: TechniqueId = Field(description="The selected ATT&CK technique id.")
    technique_name: str = Field(description="The technique's official name, as retrieved.")
    quoted_values: list[str] = Field(
        description="Field values from the cited record that triggered the choice (R4.1)."
    )
    cited_event_ids: list[str] = Field(
        description="The event_id of every record this selection rests on (R2.x)."
    )


# --- the request body, and whether it actually constrains ---------------------


def _restore_closed_values(pydantic_schema: Any, wire: Any) -> Any:
    """Put `enum`/`const` back into `wire`, taken from `pydantic_schema`.

    **Measured on anthropic 0.84.0, and it contradicts what D-08 assumed.**
    `transform_schema` -- what `messages.parse` runs over an `output_format`
    type -- keeps a fixed keyword set and folds the rest into the property's
    `description` as prose. `enum` and `const` are discarded, so a closed
    `Literal` reaches the API as `{"type": "string", "description": "...{enum:
    ['T1059.001', ...]}"}`: a hint, not a constraint. The model may emit T1068,
    the API accepts it, and `TypeAdapter.validate_json` raises on the way back
    -- validate-then-reject, the posture D-08 rejects. Restoring them here is
    what makes T05's claim true; without it the claim is false.
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


def wire_schema(model: type[BaseModel] = ProbeSelection) -> dict[str, Any]:
    """The JSON schema this probe puts on the wire.

    The SDK's transform runs first, so the probe inherits what the SDK considers
    well-formed -- including the `additionalProperties: false` it injects at
    every object level -- then the dropped closed values are repaired.

    The class docstring is stripped: Pydantic uses `__doc__` as the object's
    schema `description`, so leaving it sends this file's design commentary to
    the provider on every call -- egress no category in T06's NFR-04 inventory
    could honestly cover. Field descriptions stay; those are prompt content.
    """
    schema = _restore_closed_values(model.model_json_schema(), transform_schema(model))
    schema.pop("description", None)
    return schema


def enum_defects(schema: dict[str, Any]) -> list[str]:
    """Ways `schema` fails to make an out-of-enum technique id unrepresentable.

    Returned, not raised, so a caller can print them all at once. Empty is the
    T05 property holding.
    """
    defects: list[str] = []

    def walk(node: Any, path: str) -> None:
        if not isinstance(node, dict):
            return
        if node.get("type") == "object":
            if node.get("additionalProperties") is not False:
                defects.append(f"{path}: additionalProperties is not false")
            for name, sub in node.get("properties", {}).items():
                walk(sub, f"{path}.{name}")
        for sub in node.get("$defs", {}).values():
            walk(sub, path)
        if "items" in node:
            walk(node["items"], f"{path}[]")

    walk(schema, "$")
    allowed = schema.get("properties", {}).get("technique_id", {}).get("enum")
    if allowed is None:
        defects.append("$.technique_id: no enum -- any string is representable")
    elif OUT_OF_ENUM in allowed:
        defects.append(f"$.technique_id: enum contains the probe value {OUT_OF_ENUM}")
    elif sorted(allowed) != sorted(TechniqueId.__args__):
        defects.append(f"$.technique_id: enum is {allowed}, not the declared Literal")
    if "required" not in schema:
        defects.append("$: no required list -- every field is omittable")
    return defects


def _issue_probe_request(
    *, client: anthropic.Anthropic, model: str, extra_headers: dict[str, Any] | None = None
) -> Any:
    """The one `messages.parse` call, in one place.

    The live round-trip and the offline capture both go through here; building
    the request twice would have the capture asserting a request the probe does
    not send. `extra_headers` is the only difference and touches authentication
    alone, never the body.

    `output_format` alone would send the enum-less schema, and `parse` merges it
    over `output_config["format"]`. So the repaired schema goes via
    `extra_body`, which the base client shallow-merges over the body with the
    extra winning, replacing `output_config` outright -- while `output_format`
    still drives the typed parse back, so both halves hold at once.
    """
    return client.messages.parse(
        model=model,
        max_tokens=MAX_TOKENS,
        system=SYSTEM_PROMPT,
        messages=[{"role": "user", "content": USER_PROMPT}],
        output_format=ProbeSelection,
        thinking={"type": "adaptive"},
        extra_headers=extra_headers,
        extra_body={
            "output_config": {
                "effort": "low",
                "format": {"type": "json_schema", "schema": wire_schema()},
            }
        },
    )


def captured_request_body(*, model: str = MODEL_ID) -> dict[str, Any]:
    """The body `round_trip` would send, captured without sending it.

    `wire_schema` says what the probe intends to send; this says what the SDK
    does. They agree only because of an argument that could quietly stop
    holding -- deep-merge `extra_body`, or move the key, and the enum-less
    schema goes out with nothing downstream noticing: the call still succeeds
    and still parses. The mock transport answers before anything leaves the
    process, so this needs no credential and no network.
    """
    captured: dict[str, Any] = {}

    def handler(request: Any) -> Any:
        captured["body"] = json.loads(request.content)
        # 401, not a synthetic success: a fabricated response body is the one
        # thing a probe must never manufacture, and the request is already
        # captured by the time this returns.
        return httpx.Response(401, json={"type": "error", "error": {"type": "authentication_error"}})

    # No credential at all, deliberately: NFR-10 keeps key material out of the
    # tree, a placeholder literal here is indistinguishable from a real one to
    # the scan enforcing that (tests/test_environment.py), and the capture then
    # behaves identically whether or not a credential exists. Omitting
    # `X-Api-Key` per request is the only way the SDK builds a request with no
    # auth resolved; `default_headers` is not consulted.
    client = anthropic.Anthropic(
        max_retries=0,
        http_client=anthropic.DefaultHttpxClient(transport=httpx.MockTransport(handler)),
    )
    try:
        _issue_probe_request(client=client, model=model, extra_headers={"X-Api-Key": anthropic.Omit()})
    except anthropic.AuthenticationError:
        pass
    if "body" not in captured:
        raise RuntimeError("the request was never built; the transport saw nothing")
    return captured["body"]


def request_defects(body: dict[str, Any]) -> list[str]:
    """Ways the captured request body fails to carry what D-08 requires."""
    output_config = body.get("output_config")
    if not isinstance(output_config, dict):
        return ["output_config absent from the request body"]
    fmt = output_config.get("format")
    if not isinstance(fmt, dict):
        return ["output_config.format absent"]
    defects: list[str] = []
    if fmt.get("type") != "json_schema":
        defects.append(f"output_config.format.type is {fmt.get('type')!r}, not 'json_schema'")
    schema = fmt.get("schema")
    if not isinstance(schema, dict):
        defects.append("output_config.format.schema absent")
    else:
        defects.extend(f"sent schema: {defect}" for defect in enum_defects(schema))
    if body.get("thinking") != {"type": "adaptive"}:
        defects.append(f"thinking is {body.get('thinking')!r}, not {{'type': 'adaptive'}}")
    return defects


def post_hoc_rejects_out_of_enum() -> bool:
    """Whether Pydantic also rejects `OUT_OF_ENUM` on the way back.

    Reported because it is the check that is *not* sufficient alone: the wire
    schema constrains generation, this only catches it afterwards. Both should
    hold, in that order.
    """
    try:
        ProbeSelection.model_validate(
            {
                "technique_id": OUT_OF_ENUM,
                "technique_name": "Exploitation for Privilege Escalation",
                "quoted_values": [],
                "cited_event_ids": [],
            }
        )
    except pydantic.ValidationError:
        return True
    return False


# --- the provenance the answer record will carry ------------------------------


def prompt_hash(system: str = SYSTEM_PROMPT, user: str = USER_PROMPT) -> str:
    """SHA-256 over the exact prompt pair, so two runs of one prompt agree.

    T06 owns the real contract-set hash; this is the same idea at probe scale.
    """
    digest = hashlib.sha256()
    digest.update(system.encode("utf-8"))
    digest.update(b"\x00")
    digest.update(user.encode("utf-8"))
    return digest.hexdigest()


def provenance(*, requested_model: str, resolved_model: str | None) -> dict[str, Any]:
    """Design SS6's answer-record provenance block, as far as a probe can fill it.

    Requested and resolved model are separate fields because an alias can
    resolve to a dated snapshot, and the record must say which produced the
    claim. `catalogue_version` is absent rather than guessed -- T04 copies it
    verbatim from the bundle's `x-mitre-collection` object, and inventing a
    provenance value is the exact failure this design exists to prevent.
    """
    return {
        "model_id_requested": requested_model,
        "model_id_resolved": resolved_model,
        "provider": "anthropic",
        "provider_api_version": PROVIDER_API_VERSION,
        "provider_sdk_version": anthropic.__version__,
        "prompt_hash": prompt_hash(),
        "software_version": SOFTWARE_VERSION,
    }


# --- the two things the script does -------------------------------------------


def check_structure(*, verbose: bool = True) -> int:
    """Assert the constrain-don't-validate property against the request body."""
    body = captured_request_body()
    sent = body["output_config"]["format"]["schema"]
    defects = request_defects(body)
    post_hoc = post_hoc_rejects_out_of_enum()
    allowed = sent.get("properties", {}).get("technique_id", {}).get("enum")

    if verbose:
        print("T05 structure check -- no credential, no network")
        print(f"  anthropic {anthropic.__version__} / pydantic {pydantic.VERSION}")
        print(f"  provider api version  {PROVIDER_API_VERSION}\n")
        print("  captured request body, output_config.format.schema:")
        print(json.dumps(sent, indent=4, sort_keys=True), "\n")
        for label, value in (
            ("thinking", body.get("thinking")),
            ("technique_id enum", allowed),
            (f"{OUT_OF_ENUM} in enum", OUT_OF_ENUM in (allowed or [])),
            ("structural defects", defects or "none"),
            ("post-hoc also rejects", post_hoc),
        ):
            print(f"  {label:<21} {value}")
        print("\n  provenance block the answer record will carry:")
        print(json.dumps(provenance(requested_model=MODEL_ID, resolved_model=None), indent=4), "\n")

    if defects:
        for defect in defects:
            print(f"FAIL {defect}", file=sys.stderr)
        return 1
    if not post_hoc:
        print(f"FAIL ProbeSelection accepted {OUT_OF_ENUM}; the Literal is not closed", file=sys.stderr)
        return 1
    if verbose:
        print(
            f"PASS {OUT_OF_ENUM} is unrepresentable in the request body, and rejected "
            "on return. Constrained, then validated -- in that order."
        )
    return 0


#: Failure shapes of the live call, each with its own exit status. NFR-06 says a
#: failure must be reported as one, and none of these announces itself: a refusal
#: and a truncation both arrive as HTTP 200, and a truncated body reaches us as a
#: Pydantic error raised inside the SDK's post-parser, not as an API error.
_CALL_FAILURES: tuple[tuple[type[Exception], int, str], ...] = (
    (anthropic.AuthenticationError, 3, "credential rejected by the provider"),
    (anthropic.BadRequestError, 4, "request rejected by the provider"),
    (anthropic.RateLimitError, 5, "rate limited; no measurement taken"),
    (anthropic.APIConnectionError, 6, "could not reach the provider"),
    (anthropic.APIStatusError, 7, "provider returned an error status"),
    (pydantic.ValidationError, 8, "response did not validate against ProbeSelection"),
)


def round_trip(*, model: str) -> int:
    """One live `messages.parse`, with every documented failure shape handled."""
    try:
        response = _issue_probe_request(client=anthropic.Anthropic(), model=model)
    except tuple(kind for kind, _, _ in _CALL_FAILURES) as error:
        status, message = next(
            (s, m) for kind, s, m in _CALL_FAILURES if isinstance(error, kind)
        )
        print(f"FAIL {message}: {error}", file=sys.stderr)
        return status

    if response.stop_reason == "refusal":
        print("FAIL provider refused the request; no selection returned", file=sys.stderr)
        return 9
    if response.stop_reason == "max_tokens":
        print(f"FAIL response truncated at max_tokens={MAX_TOKENS}", file=sys.stderr)
        return 10

    # Measured on 0.84.0: `parsed_output` is a field of the *text block*
    # (`ParsedTextBlock`), not of `ParsedMessage`; with thinking on it is not
    # content[0].
    parsed = next((b.parsed_output for b in response.content if b.type == "text"), None)
    if parsed is None:
        print("FAIL no parsed text block in the response", file=sys.stderr)
        return 11

    print("T05 live round-trip")
    for label, value in (
        ("stop_reason", response.stop_reason),
        ("parsed instance", type(parsed).__name__),
        ("technique_id", parsed.technique_id),
        ("technique_name", parsed.technique_name),
        ("quoted_values", parsed.quoted_values),
        ("cited_event_ids", parsed.cited_event_ids),
        ("usage", f"in={response.usage.input_tokens} out={response.usage.output_tokens}"),
    ):
        print(f"  {label:<21} {value}")
    print("\n  provenance block the answer record will carry:")
    print(json.dumps(provenance(requested_model=model, resolved_model=response.model), indent=4))
    print("\nPASS one strict round-trip returned a parsed instance.")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="T05 model-plane probe: one strict round-trip, and the structure behind it.",
    )
    parser.add_argument(
        "--structure-only",
        action="store_true",
        help="assert the constraint against the request body and stop; needs no credential",
    )
    parser.add_argument("--model", default=MODEL_ID, help=f"model id to probe (default {MODEL_ID})")
    args = parser.parse_args(argv)

    if args.structure_only:
        return check_structure()

    # Checked before anything is printed, so this path emits exactly one line.
    # NFR-10 keeps the credential in the environment, never in the tree. The SDK
    # would also accept an `ant auth login` profile; both environment forms are
    # honoured here, but .env.example documents ANTHROPIC_API_KEY as the one the
    # system reads, so that is the one the message names.
    if not (os.environ.get("ANTHROPIC_API_KEY") or os.environ.get("ANTHROPIC_AUTH_TOKEN")):
        print(
            "ANTHROPIC_API_KEY is not set; the model plane cannot be probed "
            "(run with --structure-only for the offline checks).",
            file=sys.stderr,
        )
        return 2

    status = check_structure()
    return status if status != 0 else round_trip(model=args.model)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
