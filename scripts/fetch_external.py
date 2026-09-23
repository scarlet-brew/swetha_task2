"""One-time provisioning: fetch the two external artifacts and record provenance.

This is the *only* code in the repository that opens a network connection, and
it deliberately lives in `scripts/` rather than `src/`. D-03 retains the ATT&CK
catalogue locally precisely so the build and the app never reach outside, and
T03 verifies that by grepping `src/` for `requests|urllib|httpx|taxii` and
expecting nothing. A fetcher inside the package would pass every functional
test and still break NFR-02 the first time someone ran the demo on a locked-down
network.

Two artifacts, one network window:

* the official ATT&CK Enterprise STIX 2.1 bundle (~51 MiB) plus the collection
  index that names its version -- the *authority* under D-03, from which the
  ~200 KB flat catalogue is derived at build time as a projection;
* the Attack Flow 2.0.0 JSON schema, which D-04 vendors so the stage-5 export
  can be validated against it offline.

The Attack Flow schema is the plan's second hard network dependency, and three
separate verifications elsewhere say "validates against the vendored schema" --
a file no earlier plan actually fetched. Both are pulled here so the discipline
is applied once rather than discovered at the last task.

Provenance is the point, not a courtesy. R4.2 requires the system to state
which catalogue version it mapped against, and that claim is only checkable if
the source URL, the retrieval date and the sha256 of the exact bytes are
recorded beside the file. `scripts/verify_external.py` re-hashes and compares.

    python scripts/fetch_external.py            # fetch anything missing
    python scripts/fetch_external.py --force    # re-fetch everything
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import sys
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

USER_AGENT = "siem-investigator/0.1 (assignment prototype; one-time provisioning)"
TIMEOUT_SECONDS = 180


@dataclass(frozen=True)
class Artifact:
    url: str
    destination: Path
    why: str


ARTIFACTS = (
    Artifact(
        url="https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/index.json",
        destination=ROOT / "data" / "attack" / "index.json",
        why=(
            "The collection index. Names the available Enterprise bundles and their "
            "versions, so the version claim in every artifact can be traced to MITRE's "
            "own listing rather than to a filename we chose."
        ),
    ),
    Artifact(
        url=(
            "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/"
            "enterprise-attack/enterprise-attack-19.2.json"
        ),
        destination=ROOT / "data" / "attack" / "enterprise-attack-19.2.json",
        why=(
            "The authority under D-03: official ATT&CK Enterprise v19.2 as STIX 2.1. "
            "Committed whole rather than as the derived subset, because a subset would "
            "make the derivation unreproducible and R4.2's version claim unverifiable. "
            "Three slices are used -- the collection object, the tactics and the "
            "techniques; the relationship objects are not."
        ),
    ),
    Artifact(
        # Upstream keeps it under stix/, not schema/ -- recorded here as found, since
        # the provenance claim is about the URL these bytes actually came from.
        url=(
            "https://raw.githubusercontent.com/center-for-threat-informed-defense/"
            "attack-flow/main/stix/attack-flow-schema-2.0.0.json"
        ),
        destination=ROOT / "data" / "schema" / "attack-flow-2.0.0.json",
        why=(
            "Vendored so D-04's Attack Flow export can be validated offline. Attack "
            "Flow is a projection here, never the internal model: 3 of 5 node kinds "
            "and all 10 factual relations have no equivalent in it."
        ),
    ),
)


def sha256_of(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def fetch(artifact: Artifact, *, force: bool) -> tuple[bool, str]:
    """Download `artifact` unless it is already present. Returns (fetched, sha256)."""
    if artifact.destination.exists() and not force:
        return False, sha256_of(artifact.destination)

    artifact.destination.parent.mkdir(parents=True, exist_ok=True)
    request = urllib.request.Request(artifact.url, headers={"User-Agent": USER_AGENT})

    # Written to a sibling first, then moved. A half-downloaded 51 MiB bundle
    # that still parses as truncated JSON would be a miserable thing to debug,
    # and provenance would record a digest of something nobody meant to keep.
    staging = artifact.destination.with_suffix(artifact.destination.suffix + ".partial")
    try:
        with urllib.request.urlopen(request, timeout=TIMEOUT_SECONDS) as response:
            if response.status != 200:
                raise RuntimeError(f"HTTP {response.status} for {artifact.url}")
            with staging.open("wb") as handle:
                while block := response.read(1 << 20):
                    handle.write(block)
    except (urllib.error.URLError, TimeoutError) as exc:
        staging.unlink(missing_ok=True)
        raise RuntimeError(f"could not fetch {artifact.url}: {exc}") from exc

    staging.replace(artifact.destination)
    return True, sha256_of(artifact.destination)


PROVENANCE_HEADER = """# Provenance

Retrieved once, by `scripts/fetch_external.py`, and committed. Nothing in
`src/` or `app/` opens a network connection -- D-03 retains the catalogue
locally so the build and the app run offline, and T03 verifies that by grepping
`src/` for `requests|urllib|httpx|taxii`.

The digests below are what make the version claim in every emitted artifact
checkable: re-hash these files and compare. `scripts/verify_external.py` does
exactly that, and `tests/test_external_provenance.py` runs it.

*Not* a licence grant. ATT&CK is (c) The MITRE Corporation, redistributed under
the ATT&CK Terms of Use; Attack Flow is published by the Center for Threat-
Informed Defense under Apache 2.0.
"""


def write_provenance(directory: Path, rows: list[tuple[Artifact, str, int]], retrieved: str) -> None:
    lines = [PROVENANCE_HEADER]
    for artifact, digest, size in rows:
        lines.append(f"\n## `{artifact.destination.name}`\n")
        lines.append(f"- **source** <{artifact.url}>")
        lines.append(f"- **retrieved** {retrieved}")
        lines.append(f"- **bytes** {size:,}")
        lines.append(f"- **sha256** `{digest}`")
        lines.append(f"\n{artifact.why}\n")
    (directory / "PROVENANCE.md").write_text("\n".join(lines), encoding="utf-8", newline="\n")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--force", action="store_true", help="re-fetch even if present")
    args = parser.parse_args(argv)

    retrieved = dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%d")
    by_directory: dict[Path, list[tuple[Artifact, str, int]]] = {}

    for artifact in ARTIFACTS:
        try:
            fetched, digest = fetch(artifact, force=args.force)
        except RuntimeError as exc:
            # T03 stops here rather than substituting a hand-authored subset:
            # CLAUDE.md ground rule 4 requires amending design.md first, and a
            # quiet substitution would leave R4.2's version claim unverifiable.
            print(f"FAILED  {exc}", file=sys.stderr)
            print(
                "\nD-03 depends on retaining the official bundle. Stop here and amend "
                "design.md before substituting anything hand-authored.",
                file=sys.stderr,
            )
            return 1
        size = artifact.destination.stat().st_size
        print(f"{'fetched' if fetched else 'present'}  {size:>11,}  {digest[:16]}...  {artifact.destination.name}")
        by_directory.setdefault(artifact.destination.parent, []).append((artifact, digest, size))

    for directory, rows in by_directory.items():
        write_provenance(directory, rows, retrieved)
        print(f"wrote    {directory.relative_to(ROOT).as_posix()}/PROVENANCE.md")

    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
