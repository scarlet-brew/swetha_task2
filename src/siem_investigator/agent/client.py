"""The one place a request reaches the model service (T06).

Every call from every one of design SS7's three model sites goes through
`call`. That is what makes `docs/egress.md` a checkable inventory rather than a
description: there is a single function to capture, and
`tests/test_egress_inventory.py` captures the real serialised body for each site
and asserts nothing outside the inventory leaves the process.

The schema a contract is sent as is built in `wire.py`, which exists to work
around one measured SDK behaviour and is worth reading on its own. This module
is the transport: how a request is assembled, how it is captured without being
sent, and what provenance a completed call carries.

**This is the only code under `src/` that names a network client**, and that is
the point -- `docs/egress.md` inventories what each site sends, and there is one
function to capture in order to check it. `tests/test_external_artifacts.py`
asserts that no *other* module under `src/` reaches the network.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from typing import Any, TypeVar

import anthropic
import httpx
from pydantic import BaseModel

from .. import __version__, ids
from .wire import schema_defects, wire_schema

#: Design SS10.1's model. Opus 5, with adaptive thinking.
MODEL_ID = "claude-opus-5"

#: The wire API version the SDK pins. Recorded on every answer record (R10.3),
#: because "which model" is not the same question as "which API".
PROVIDER_API_VERSION = "2023-06-01"

#: Adaptive, never a token budget: `budget_tokens` is rejected outright by
#: Opus 5.
THINKING: dict[str, str] = {"type": "adaptive"}

#: The credential is read from the environment and from nowhere else (NFR-10).
CREDENTIAL_VARIABLE = "ANTHROPIC_API_KEY"

ModelT = TypeVar("ModelT", bound=BaseModel)


def prompt_hash(system: str, user: str) -> str:
    """A stable digest of one prompt pair.

    Part of SS11.1's replay reproducibility: a validation verdict is reproducible
    *given the committed trajectory, the contract-set hash and the validator
    version*, and this is how the trajectory records which prompt produced a
    proposal. Stable across processes -- it hashes bytes, not object identity.

    Through `ids.content_digest`, so the system has exactly one canonical form
    (SS8.2) and one hash discipline. A second, locally reasonable `json.dumps`
    here would be a second answer to "what is this the hash of", and the
    contract-set hash already uses the first.
    """
    return ids.content_digest({"system": system, "user": user})


@dataclass(frozen=True)
class Provenance:
    """What every artifact and answer record carries about the call (R10.3)."""

    site: str
    model_id_requested: str
    model_id_resolved: str | None
    provider: str
    provider_api_version: str
    provider_sdk_version: str
    prompt_hash: str
    software_version: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "site": self.site,
            "model_id_requested": self.model_id_requested,
            "model_id_resolved": self.model_id_resolved,
            "provider": self.provider,
            "provider_api_version": self.provider_api_version,
            "provider_sdk_version": self.provider_sdk_version,
            "prompt_hash": self.prompt_hash,
            "software_version": self.software_version,
        }


def provenance(
    *, site: str, system: str, user: str, resolved_model: str | None, requested_model: str = MODEL_ID
) -> Provenance:
    return Provenance(
        site=site,
        model_id_requested=requested_model,
        model_id_resolved=resolved_model,
        provider="anthropic",
        provider_api_version=PROVIDER_API_VERSION,
        provider_sdk_version=anthropic.__version__,
        prompt_hash=prompt_hash(system, user),
        software_version=__version__,
    )


def credential_present() -> bool:
    return bool(os.environ.get(CREDENTIAL_VARIABLE))


def _request_kwargs(
    *, model_type: type[BaseModel], system: str, user: str, max_tokens: int, effort: str
) -> dict[str, Any]:
    """The request, built once.

    The live call and the offline capture both go through here. Building it
    twice would have the capture asserting a request the system does not send,
    which is the failure mode that makes an egress inventory worthless.
    """
    return {
        "model": MODEL_ID,
        "max_tokens": max_tokens,
        "system": system,
        "messages": [{"role": "user", "content": user}],
        "output_format": model_type,
        "thinking": THINKING,
        # `output_format` alone would send the enum-less schema. `parse` merges
        # this over `output_config["format"]`, and the base client shallow-merges
        # `extra_body` with the extra winning -- replacing `output_config`
        # outright -- while `output_format` still drives the typed parse back.
        "extra_body": {
            "output_config": {
                "effort": effort,
                "format": {"type": "json_schema", "schema": wire_schema(model_type)},
            }
        },
    }


def captured_request_body(
    *,
    model_type: type[BaseModel],
    system: str,
    user: str,
    max_tokens: int = 2048,
    effort: str = "medium",
) -> dict[str, Any]:
    """The exact body `call` would send, captured without sending it.

    `wire_schema` says what we intend to send; this says what the SDK does.
    They agree only because of an argument that could quietly stop holding --
    deep-merge `extra_body`, or move the key, and the enum-less schema goes out
    with nothing downstream noticing, because the call still succeeds and still
    parses.

    Needs no credential and no network: a mock transport answers before
    anything leaves the process. It returns 401 rather than a synthetic success,
    because a fabricated response body is the one thing this must never
    manufacture -- and the request is already captured by the time it returns.
    """
    captured: dict[str, Any] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["body"] = json.loads(request.content)
        return httpx.Response(
            401, json={"type": "error", "error": {"type": "authentication_error"}}
        )

    # No credential at all, deliberately. NFR-10 keeps key material out of the
    # tree, and a placeholder literal here is indistinguishable from a real one
    # to the scan that enforces it. Omitting `X-Api-Key` per request is the only
    # way to make the SDK build a request with no auth resolved.
    client = anthropic.Anthropic(
        max_retries=0,
        http_client=anthropic.DefaultHttpxClient(transport=httpx.MockTransport(handler)),
    )
    try:
        client.messages.parse(
            extra_headers={"X-Api-Key": anthropic.Omit()},
            **_request_kwargs(
                model_type=model_type, system=system, user=user, max_tokens=max_tokens, effort=effort
            ),
        )
    except anthropic.AuthenticationError:
        pass
    if "body" not in captured:
        raise RuntimeError("the request was never built; the transport saw nothing")
    return captured["body"]


def request_defects(body: dict[str, Any]) -> list[str]:
    """Ways a captured request body fails to carry what D-08 requires."""
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
        defects.extend(f"sent schema: {defect}" for defect in schema_defects(schema))
    if body.get("thinking") != THINKING:
        defects.append(f"thinking is {body.get('thinking')!r}, not {THINKING}")
    return defects


@dataclass(frozen=True)
class Call:
    """One completed model call: what came back, and everything about the call."""

    parsed: BaseModel
    provenance: Provenance
    stop_reason: str | None
    input_tokens: int
    output_tokens: int


def call(
    *,
    site: str,
    model_type: type[ModelT],
    system: str,
    user: str,
    max_tokens: int = 2048,
    effort: str = "medium",
    client: anthropic.Anthropic | None = None,
) -> Call:
    """Issue one strict, constrained call and return the parsed instance.

    Raises `CredentialMissing` with a one-line message rather than a traceback
    when the variable is unset: NFR-02 requires the deterministic stages to run
    without it, so this failing cleanly is part of the design rather than an
    error path.
    """
    if client is None:
        if not credential_present():
            raise CredentialMissing(
                f"{CREDENTIAL_VARIABLE} is not set; the deterministic stages still run, "
                "and affected behaviour is reported as unmapped rather than omitted"
            )
        client = anthropic.Anthropic()

    message = client.messages.parse(
        **_request_kwargs(
            model_type=model_type, system=system, user=user, max_tokens=max_tokens, effort=effort
        )
    )

    _check_stop_reason(message, max_tokens)
    parsed = _parsed_of(message, model_type)
    return Call(
        parsed=parsed,
        provenance=provenance(
            site=site, system=system, user=user, resolved_model=getattr(message, "model", None)
        ),
        stop_reason=getattr(message, "stop_reason", None),
        input_tokens=getattr(message.usage, "input_tokens", 0),
        output_tokens=getattr(message.usage, "output_tokens", 0),
    )


class CredentialMissing(RuntimeError):
    """`ANTHROPIC_API_KEY` is not set.

    A distinct type, and raised rather than returned, because NFR-02 makes this
    an ordinary operating state rather than an error: the deterministic stages
    run without a credential, and affected behaviour is reported as unmapped
    rather than omitted. The caller needs to tell it apart from a call that was
    attempted and failed.
    """


class ModelCallFailed(RuntimeError):
    """The call completed but returned no usable parsed instance."""


def _parsed_of(message: Any, model_type: type[ModelT]) -> ModelT:
    """Pull the parsed instance off a `ParsedMessage`.

    Two measured details on anthropic 0.84.0, both easy to get wrong:

    * the attribute is **`parsed_output`**, not `parsed`;
    * it is a field of the *text block* (`ParsedTextBlock`), not of
      `ParsedMessage`, and with thinking enabled the first block is a thinking
      block -- so `content[0]` works only by accident and only with thinking
      off. The blocks are searched by type instead.
    """
    for block in getattr(message, "content", ()):
        if getattr(block, "type", None) != "text":
            continue
        parsed = getattr(block, "parsed_output", None)
        if isinstance(parsed, model_type):
            return parsed
    raise ModelCallFailed(
        f"no parsed {model_type.__name__} in the response; stop_reason="
        f"{getattr(message, 'stop_reason', None)!r}"
    )


def _check_stop_reason(message: Any, max_tokens: int) -> None:
    """Surface the two documented non-answers as handled errors.

    Both are ordinary outcomes rather than exceptions in the transport, so
    without this they would arrive as "no parsed instance" and be
    indistinguishable from a contract bug.
    """
    stop_reason = getattr(message, "stop_reason", None)
    if stop_reason == "refusal":
        raise ModelCallFailed("the provider refused the request; no instance was returned")
    if stop_reason == "max_tokens":
        raise ModelCallFailed(
            f"the response was truncated at max_tokens={max_tokens}; raise the budget "
            "rather than accepting a partial contract"
        )
