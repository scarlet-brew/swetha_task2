"""One-time provisioning: fetch every external artifact, with its `$ref` closure.

This is the only code in the repository that opens a socket, and it lives in
`scripts/` rather than `src/` on purpose. D-03 retains the ATT&CK catalogue
locally precisely so the build and the app never reach outside, and T03 verifies
that by scanning every file under `src/` for `requests|urllib|httpx|taxii` and
expecting nothing. A fetcher inside the package would pass every functional test
and still break NFR-02 the first time the demo ran on a locked-down network.

Three roots, and then a transitive closure:

* the official ATT&CK Enterprise v19.2 STIX 2.1 bundle plus the collection index
  that names its version -- the authority under D-03, from which the flat
  catalogue is derived at build time as a projection;
* the Attack Flow 2.0.0 JSON schema, vendored so D-04's stage-5 export can be
  validated offline;
* **everything the Attack Flow schema `$ref`s out to.** The published schema is
  *not* self-contained: it carries three remote references into the OASIS STIX
  2.1 common schemas, which fan out to a closure of 13 documents. Measured with
  `jsonschema 4.26.0`, validating against it without a preloaded registry
  succeeds -- *by fetching those schemas over the network at validation time*,
  with a `DeprecationWarning` about remote retrieval being a security
  vulnerability. Under NFR-02 that is a stage-5 failure on an offline machine,
  discovered at the last task rather than this one. Hence `refs/`.

**What this script owns, and what it does not.** It owns `ref_index.json`, the
machine-readable map a validator builds its `referencing.Registry` from. It does
*not* rewrite the two `PROVENANCE.md` files: those carry the hand-written D-03
and D-04 rationale, and a provisioning script that regenerated them would
quietly delete the reasoning while keeping the digests. Instead it *checks* them
and prints the rows to paste when they disagree, so the two records cannot drift
without something saying so.

    python scripts/fetch_external.py              # fetch anything missing, check provenance
    python scripts/fetch_external.py --force      # re-fetch everything
    python scripts/fetch_external.py --check      # no network; just verify what is here
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urljoin, urlparse

ROOT = Path(__file__).resolve().parents[1]
ATTACK_DIR = ROOT / "data" / "attack"
SCHEMA_DIR = ROOT / "data" / "schema"
REF_INDEX = SCHEMA_DIR / "ref_index.json"

USER_AGENT = "siem-investigator/0.1 (assignment prototype; one-time provisioning)"
TIMEOUT_SECONDS = 180

#: The row format both PROVENANCE.md tables use, and that
#: `tests/test_external_artifacts.py` parses.
PROVENANCE_HEADER = "| File | Bytes | sha256 | Source URL |"


@dataclass(frozen=True)
class Root:
    url: str
    destination: Path


ROOTS = (
    Root(
        "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/index.json",
        ATTACK_DIR / "index.json",
    ),
    Root(
        "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/"
        "enterprise-attack/enterprise-attack-19.2.json",
        ATTACK_DIR / "enterprise-attack-19.2.json",
    ),
    # Upstream names this `attack-flow-schema-2.0.0.json`; stored under the name
    # `paths.py` already fixed. The `$id` inside is untouched, so `$ref`
    # resolution is unaffected by the rename.
    Root(
        "https://raw.githubusercontent.com/center-for-threat-informed-defense/"
        "attack-flow/main/stix/attack-flow-schema-2.0.0.json",
        SCHEMA_DIR / "attack-flow-2.0.0.json",
    ),
)

#: Where the root of the `$ref` walk starts.
FLOW_SCHEMA = SCHEMA_DIR / "attack-flow-2.0.0.json"


def sha256_of(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def download(url: str, destination: Path) -> None:
    """Fetch `url` to `destination`, via a staging file.

    A half-written 51 MiB bundle that still parses as truncated JSON would be a
    miserable thing to debug, and provenance would record the digest of
    something nobody meant to keep.
    """
    destination.parent.mkdir(parents=True, exist_ok=True)
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    staging = destination.with_suffix(destination.suffix + ".partial")
    try:
        with urllib.request.urlopen(request, timeout=TIMEOUT_SECONDS) as response:
            if response.status != 200:
                raise RuntimeError(f"HTTP {response.status} for {url}")
            with staging.open("wb") as handle:
                while block := response.read(1 << 20):
                    handle.write(block)
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        staging.unlink(missing_ok=True)
        raise RuntimeError(f"could not fetch {url}: {exc}") from exc
    staging.replace(destination)


def ref_destination(url: str) -> Path:
    """Where a referenced OASIS schema is vendored.

    `.../cti-stix2-json-schemas/<branch>/schemas/common/<name>.json` becomes
    `data/schema/refs/<branch>/<name>.json`. The branch is kept in the path
    because the Attack Flow schema references *two* branches -- `stix2.1` for
    most of the closure and `master` for `timestamp.json` -- and the two files
    are not guaranteed to be identical, so collapsing them would be a guess.
    """
    parts = [part for part in urlparse(url).path.split("/") if part]
    try:
        branch = parts[parts.index("schemas") - 1]
    except ValueError:
        branch = "unversioned"
    return SCHEMA_DIR / "refs" / branch / parts[-1]


def every_ref(node: object):
    """Every `$ref` string anywhere in a JSON document."""
    if isinstance(node, dict):
        for key, value in node.items():
            if key == "$ref" and isinstance(value, str):
                yield value
            else:
                yield from every_ref(value)
    elif isinstance(node, list):
        for value in node:
            yield from every_ref(value)


def walk_closure(*, fetch: bool) -> list[tuple[str, Path]]:
    """Resolve the Attack Flow schema's remote `$ref` closure.

    Returns `(uri, vendored path)` for every referenced document, sorted by uri.

    References resolve against the *base URI of the document they appear in* --
    its `$id` where it declares one, else the URL it came from. The OASIS
    documents cite each other relatively (`../common/hex.json`), so resolving
    against anything else produces URIs that exist nowhere.
    """
    root_uri = json.loads(FLOW_SCHEMA.read_bytes()).get("$id") or ROOTS[2].url
    pending: list[tuple[str, Path]] = [(root_uri, FLOW_SCHEMA)]
    seen: dict[str, Path] = {}

    while pending:
        uri, path = pending.pop()
        document = json.loads(path.read_bytes())
        base = document.get("$id") or uri
        for reference in every_ref(document):
            if reference.startswith("#"):
                continue
            absolute = urljoin(base, reference).split("#", 1)[0]
            if absolute in seen or absolute == root_uri:
                continue
            destination = ref_destination(absolute)
            if not destination.exists():
                if not fetch:
                    raise RuntimeError(
                        f"{absolute} is referenced but not vendored at "
                        f"{destination.relative_to(ROOT).as_posix()}; run without --check"
                    )
                download(absolute, destination)
                print(f"fetched  {destination.stat().st_size:>11,}  {destination.relative_to(ROOT).as_posix()}")
            seen[absolute] = destination
            pending.append((absolute, destination))

    return sorted(seen.items())


def write_ref_index(closure: list[tuple[str, Path]], retrieved: str) -> None:
    root_uri = json.loads(FLOW_SCHEMA.read_bytes()).get("$id") or ROOTS[2].url
    payload = {
        "_note": (
            "Offline resolution map for the Attack Flow schema's remote $ref closure. "
            "jsonschema 4.26.0 fetches an unregistered remote $ref over the network, so a "
            "validator built without this map egresses at validation time (NFR-02). Build a "
            "referencing.Registry from these entries, keyed by 'uri', and pass it to the "
            "validator."
        ),
        "retrieved": retrieved,
        "root": {
            "uri": root_uri,
            "path": FLOW_SCHEMA.relative_to(ROOT).as_posix(),
            "sha256": sha256_of(FLOW_SCHEMA),
        },
        "refs": [
            {
                "uri": uri,
                "path": path.relative_to(ROOT).as_posix(),
                "sha256": sha256_of(path),
            }
            for uri, path in closure
        ],
    }
    REF_INDEX.write_text(
        json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8", newline=""
    )


def provenance_rows(provenance: Path) -> dict[str, tuple[int, str, str]]:
    """Parse a PROVENANCE.md table into `{file: (bytes, sha256, url)}`."""
    rows: dict[str, tuple[int, str, str]] = {}
    inside = False
    for line in provenance.read_text(encoding="utf-8").splitlines():
        if line.startswith(PROVENANCE_HEADER):
            inside = True
            continue
        if inside:
            if not line.startswith("|"):
                break
            cells = [cell.strip() for cell in line.strip().strip("|").split("|")]
            if len(cells) != 4 or set(cells[0]) <= {"-", ":"}:
                continue
            name, size, digest, url = cells
            rows[name.strip("`")] = (int(size), digest.strip("`"), url)
    return rows


def expected_rows(directory: Path, urls: dict[Path, str]) -> list[str]:
    out = []
    for path in sorted(urls):
        if not path.is_relative_to(directory):
            continue
        name = path.relative_to(directory).as_posix()
        out.append(f"| `{name}` | {path.stat().st_size} | `{sha256_of(path)}` | {urls[path]} |")
    return out


def check_provenance(directory: Path, urls: dict[Path, str]) -> int:
    """Compare PROVENANCE.md's table against the files on disk. Returns failures."""
    provenance = directory / "PROVENANCE.md"
    label = directory.relative_to(ROOT).as_posix()
    if not provenance.exists():
        print(f"MISSING  {label}/PROVENANCE.md", file=sys.stderr)
        return 1

    recorded = provenance_rows(provenance)
    failures = 0
    expected: dict[str, tuple[int, str, str]] = {}
    for path, url in urls.items():
        if path.is_relative_to(directory):
            expected[path.relative_to(directory).as_posix()] = (
                path.stat().st_size,
                sha256_of(path),
                url,
            )

    for name, (size, digest, url) in sorted(expected.items()):
        if name not in recorded:
            print(f"UNRECORDED {label}/{name}", file=sys.stderr)
            failures += 1
        elif recorded[name][:2] != (size, digest):
            print(
                f"MISMATCH {label}/{name}\n"
                f"         recorded {recorded[name][0]:,} bytes {recorded[name][1]}\n"
                f"         actual   {size:,} bytes {digest}",
                file=sys.stderr,
            )
            failures += 1

    for name in sorted(set(recorded) - set(expected)):
        print(f"STALE ROW {label}/{name} is recorded but not vendored", file=sys.stderr)
        failures += 1

    if failures:
        print(f"\nRows for {label}/PROVENANCE.md:\n", file=sys.stderr)
        for row in expected_rows(directory, urls):
            print(row, file=sys.stderr)
    else:
        print(f"ok       {label}/PROVENANCE.md  {len(recorded)} row(s) reproduce")
    return failures


def existing_retrieved() -> str | None:
    if REF_INDEX.exists():
        return json.loads(REF_INDEX.read_bytes()).get("retrieved")
    return None


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Fetch and verify the external artifacts.")
    parser.add_argument("--force", action="store_true", help="re-fetch even if present")
    parser.add_argument("--check", action="store_true", help="never fetch; verify what is present")
    args = parser.parse_args(argv)

    urls: dict[Path, str] = {}

    for root in ROOTS:
        if args.force or not root.destination.exists():
            if args.check:
                print(f"MISSING  {root.destination.relative_to(ROOT).as_posix()}", file=sys.stderr)
                return 1
            try:
                download(root.url, root.destination)
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
            print(f"fetched  {root.destination.stat().st_size:>11,}  {root.destination.relative_to(ROOT).as_posix()}")
        else:
            print(f"present  {root.destination.stat().st_size:>11,}  {root.destination.relative_to(ROOT).as_posix()}")
        urls[root.destination] = root.url

    try:
        closure = walk_closure(fetch=not args.check)
    except RuntimeError as exc:
        print(f"FAILED  {exc}", file=sys.stderr)
        return 1

    total = sum(path.stat().st_size for _, path in closure)
    print(f"closure  {len(closure)} document(s), {total:,} bytes under data/schema/refs/")
    for uri, path in closure:
        urls[path] = uri

    if not args.check:
        write_ref_index(closure, existing_retrieved() or "unrecorded")
        print(f"wrote    {REF_INDEX.relative_to(ROOT).as_posix()}")

    failures = check_provenance(ATTACK_DIR, urls) + check_provenance(SCHEMA_DIR, urls)
    if failures:
        print(f"\n{failures} provenance problem(s).", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
