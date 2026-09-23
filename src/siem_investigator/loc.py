"""The D-09 line reporter: a 400-line soft ceiling, reported and never enforced.

D-09 chose reporting over a build gate for one reason. The ceiling exists
because NFR-07 asks that no component be so large a reviewer cannot follow it,
and that is a judgement about a specific file. A gate turns it into an
arithmetic constraint, and the cheapest way to satisfy an arithmetic constraint
is to split a coherent module into two incoherent halves -- which makes the
review worse while making the number better.

So this prints a number and exits 0. Crossing the line is a prompt to look, not
a failure.

Physical lines, not statements: a reviewer scrolls past blanks and comments
too, and "how much is there to read" is the question being asked.

    python -m siem_investigator.loc              measure src/ app/ scripts/ tests/
    python -m siem_investigator.loc src/ app/    measure only what is named
"""

from __future__ import annotations

import sys
from collections.abc import Sequence
from pathlib import Path
from typing import NamedTuple

from . import paths

#: D-09's soft ceiling. A file is flagged only when it exceeds this, so 400 is
#: silent and 401 is reported.
CEILING = 400

#: Roots the ceiling governs: the system itself.
#:
#: `report()` measures `scripts/` and `tests/` too, so nothing is hidden, but the
#: ceiling is not applied to them. A long test module is a flat list of short
#: independent assertions -- "how much is there to follow" is small however many
#: lines it runs to, and splitting it by line count would scatter the evidence
#: across files while improving the number. That is precisely the failure mode
#: D-09 chose reporting over enforcement to avoid, so applying the ceiling there
#: would reintroduce it.
GOVERNED_ROOTS = (paths.ROOT / "src", paths.ROOT / "app")


def _display(path: str | Path) -> str:
    """Repository-relative where possible, absolute otherwise.

    `paths.relative` refuses a path outside the tree, which is right for
    artifacts -- an absolute build-machine path must never become evidence -- but
    this reporter is also pointed at scratch directories by its own tests.
    """
    try:
        return paths.relative(Path(path))
    except ValueError:
        return Path(path).as_posix()


def _governed(path: str | Path) -> bool:
    resolved = Path(path).resolve()
    return any(resolved.is_relative_to(root) for root in GOVERNED_ROOTS)


def count_lines(path: str | Path) -> int:
    """Physical lines in `path`.

    A file with no trailing newline still has a final line, and an empty file
    has none -- which is what `splitlines` gives.
    """
    return len(Path(path).read_text(encoding="utf-8").splitlines())


def python_files(roots=paths.CODE_ROOTS) -> list[Path]:
    """Every `.py` file under `roots`, sorted, skipping caches and virtualenvs."""
    skip = {"__pycache__", ".venv", "venv", ".git", "node_modules"}
    found: list[Path] = []
    for root in roots:
        root = Path(root)
        if not root.exists():
            continue
        for candidate in root.rglob("*.py"):
            if skip.isdisjoint(candidate.parts):
                found.append(candidate)
    return sorted(found)


def report(roots=paths.CODE_ROOTS) -> list[tuple[str, int]]:
    """`(display path, lines)` for every file, longest first."""
    measured = [(_display(path), count_lines(path)) for path in python_files(roots)]
    return sorted(measured, key=lambda row: (-row[1], row[0]))


def over_ceiling(roots=paths.CODE_ROOTS) -> list[tuple[str, int]]:
    """Files that exceed `CEILING`.

    When called with the default roots, only `GOVERNED_ROOTS` are eligible. When
    pointed at an explicit root -- as its own tests do -- everything under it is,
    since the caller has said what to measure.
    """
    explicit = roots is not paths.CODE_ROOTS
    flagged = []
    for path in python_files(roots):
        count = count_lines(path)
        if count > CEILING and (explicit or _governed(path)):
            flagged.append((_display(path), count))
    flagged.sort(key=lambda row: (-row[1], row[0]))
    return flagged


def main(argv: list[str] | None = None) -> int:
    measured = [(path, _display(path), count_lines(path)) for path in python_files()]
    measured.sort(key=lambda row: (-row[2], row[1]))
    total = sum(count for _, _, count in measured)
    flagged = [(name, count) for path, name, count in measured if count > CEILING and _governed(path)]

    print(f"{len(measured)} Python files, {total} lines, D-09 soft ceiling {CEILING}")
    print("  (the ceiling governs src/ and app/; scripts/ and tests/ are measured, not governed)\n")
    for path, name, count in measured:
        if count <= CEILING:
            marker = "      "
        elif _governed(path):
            marker = "  OVER"
        else:
            marker = "     ~"
        print(f"{count:6d}{marker}  {name}")

    if flagged:
        print(
            f"\n{len(flagged)} governed file(s) over the soft ceiling. D-09 reports and does "
            "not enforce: read them and decide whether the size is earned."
        )
    else:
        print(f"\nNo governed file over {CEILING} lines.")
    # Always 0. A soft ceiling that failed the build would be a hard one.
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
