"""Re-hash the vendored external artifacts and compare against PROVENANCE.md.

R4.2 requires the system to state which ATT&CK version it mapped against. That
claim is only worth anything if the bytes it was derived from are the bytes
MITRE published, so the digest recorded at fetch time has to be re-checkable
without a network. This script is that check, and
`tests/test_external_provenance.py` runs it as part of the suite.

It also catches the failure D-03 exists to prevent. Before `.gitattributes`
marked `*.json` as `-text`, `* text=auto eol=lf` resolved the bundle to
`eol: lf`, so git would have rewritten line endings on checkout and every
digest here would have failed against a file that still parsed perfectly. A
sha256 in a document proves nothing; a sha256 that something re-computes does.

    python scripts/verify_external.py
"""

from __future__ import annotations

import hashlib
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

PROVENANCE_FILES = (
    ROOT / "data" / "attack" / "PROVENANCE.md",
    ROOT / "data" / "schema" / "PROVENANCE.md",
)

_SECTION = re.compile(r"^## `(?P<name>[^`]+)`\s*$", re.MULTILINE)
_SHA256 = re.compile(r"^- \*\*sha256\*\* `(?P<digest>[0-9a-f]{64})`\s*$", re.MULTILINE)
_BYTES = re.compile(r"^- \*\*bytes\*\* (?P<size>[\d,]+)\s*$", re.MULTILINE)


def sha256_of(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def claims(provenance: Path) -> list[tuple[str, str, int]]:
    """`(filename, recorded sha256, recorded byte count)` per section."""
    text = provenance.read_text(encoding="utf-8")
    sections = list(_SECTION.finditer(text))
    out = []
    for index, section in enumerate(sections):
        end = sections[index + 1].start() if index + 1 < len(sections) else len(text)
        body = text[section.start():end]
        digest = _SHA256.search(body)
        size = _BYTES.search(body)
        if not digest or not size:
            raise ValueError(
                f"{provenance.name}: section for {section['name']!r} is missing a sha256 or byte count"
            )
        out.append((section["name"], digest["digest"], int(size["size"].replace(",", ""))))
    if not out:
        raise ValueError(f"{provenance.name}: no artifact sections found")
    return out


def main(argv: list[str] | None = None) -> int:
    failures = 0
    checked = 0

    for provenance in PROVENANCE_FILES:
        if not provenance.exists():
            print(f"MISSING  {provenance.relative_to(ROOT).as_posix()}", file=sys.stderr)
            failures += 1
            continue

        for name, recorded_digest, recorded_size in claims(provenance):
            path = provenance.parent / name
            label = path.relative_to(ROOT).as_posix()
            if not path.exists():
                print(f"MISSING  {label}", file=sys.stderr)
                failures += 1
                continue

            checked += 1
            actual_size = path.stat().st_size
            actual_digest = sha256_of(path)

            if actual_digest != recorded_digest:
                print(
                    f"MISMATCH {label}\n"
                    f"         recorded {recorded_digest}\n"
                    f"         actual   {actual_digest}\n"
                    f"         The committed bytes are not the bytes that were fetched. If the\n"
                    f"         file still parses, suspect EOL translation: `git check-attr text --"
                    f" {label}`\n"
                    f"         must report `text: unset`.",
                    file=sys.stderr,
                )
                failures += 1
            elif actual_size != recorded_size:
                # Cannot really happen once the digest matches; kept because a
                # size mismatch alongside a matching digest would mean the
                # provenance file itself was edited by hand.
                print(f"MISMATCH {label}: recorded {recorded_size:,} bytes, found {actual_size:,}", file=sys.stderr)
                failures += 1
            else:
                print(f"ok       {label}  {actual_size:>11,} bytes  {actual_digest[:16]}...")

    if failures:
        print(f"\n{failures} problem(s) across {checked} artifact(s).", file=sys.stderr)
        return 1
    print(f"\n{checked} artifact(s) match their recorded provenance.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
