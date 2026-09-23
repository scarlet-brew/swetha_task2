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


def _display(path: str | Path, roots: Sequence[str | Path] = ()) -> str:
    """Repository-relative where possible, else relative to the root it was found
    under, else absolute.

    `paths.relative` refuses a path outside the tree, which is right for
    artifacts -- an absolute build-machine path must never become evidence -- but
    this reporter is also pointed at directories outside it, by its own tests and
    by anyone who names a root on the command line. A listing of absolute paths
    is unreadable, so out of tree it falls back to the named root.
    """
    resolved = Path(path).resolve()
    try:
        return paths.relative(resolved)
    except ValueError:
        pass
    for root in roots:
        root_path = Path(root).resolve()
        if resolved.is_relative_to(root_path):
            return resolved.relative_to(root_path).as_posix()
    return resolved.as_posix()


def _governed(path: str | Path) -> bool:
    resolved = Path(path).resolve()
    return any(resolved.is_relative_to(root) for root in GOVERNED_ROOTS)


def count_lines(path: str | Path) -> int:
    """Physical lines in `path`.

    A file with no trailing newline still has a final line, and an empty file
    has none -- which is what `splitlines` gives.
    """
    return len(Path(path).read_text(encoding="utf-8").splitlines())


def python_files(roots: Sequence[str | Path] = paths.CODE_ROOTS) -> list[Path]:
    """Every `.py` file under `roots`, sorted, skipping caches and virtualenvs."""
    skip = {"__pycache__", ".venv", "venv", ".git", "node_modules"}
    found: list[Path] = []
    for root in roots:
        root_path = Path(root)
        if not root_path.exists():
            continue
        for candidate in root_path.rglob("*.py"):
            if skip.isdisjoint(candidate.parts):
                found.append(candidate)
    return sorted(found)


class Measurement(NamedTuple):
    """One row of the report: where the file is, how it reads in the listing,
    how long it is, and whether the ceiling applies to it."""

    path: Path
    display: str
    lines: int
    governed: bool


def measure(roots: Sequence[str | Path] = paths.CODE_ROOTS) -> list[Measurement]:
    """Every file under `roots`, longest first.

    One function decides whether the ceiling applies, so the CLI and
    `over_ceiling` cannot drift into disagreeing about which files it governs.

    An *explicit* root makes everything under it governed: `GOVERNED_ROOTS` is a
    statement about this repository's layout, and it says nothing about a
    directory the caller named instead. That is also what makes the ceiling
    behaviour itself testable -- point the reporter at a scratch directory and
    the flagging path runs for real.
    """
    explicit = roots is not paths.CODE_ROOTS
    rows = [
        Measurement(path, _display(path, roots), count_lines(path), explicit or _governed(path))
        for path in python_files(roots)
    ]
    return sorted(rows, key=lambda row: (-row.lines, row.display))


def report(roots: Sequence[str | Path] = paths.CODE_ROOTS) -> list[tuple[str, int]]:
    """`(display path, lines)` for every file, longest first."""
    return [(row.display, row.lines) for row in measure(roots)]


def over_ceiling(roots: Sequence[str | Path] = paths.CODE_ROOTS) -> list[tuple[str, int]]:
    """Governed files that exceed `CEILING`, longest first."""
    return [(row.display, row.lines) for row in measure(roots) if row.lines > CEILING and row.governed]


def main(argv: list[str] | None = None) -> int:
    """Print the measurement. Arguments, if given, are roots to measure instead
    of `paths.CODE_ROOTS`."""
    named = list(argv or [])
    rows = measure(tuple(named)) if named else measure()
    total = sum(row.lines for row in rows)
    flagged = [row for row in rows if row.lines > CEILING and row.governed]

    print(f"{len(rows)} Python files, {total} lines, D-09 soft ceiling {CEILING}")
    if not named:
        print("  (the ceiling governs src/ and app/; scripts/ and tests/ are measured, not governed)")
    print()
    for row in rows:
        if row.lines <= CEILING:
            marker = "      "
        elif row.governed:
            marker = "  OVER"
        else:
            marker = "     ~"
        print(f"{row.lines:6d}{marker}  {row.display}")

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
