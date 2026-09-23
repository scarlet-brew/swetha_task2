"""Which pipeline artifacts exist, read from the one place that names them.

The surfaces render from the committed artifacts, and at T07 none of them has
been produced yet. Rather than each page inventing its own empty state, this
module answers one question -- does this stage's output exist on disk -- and the
pages report the answer.

It reads `siem_investigator.paths`, the module design SS8.3 makes the single
place every artifact path is spelled. A second list of filenames in the UI would
drift from the pipeline's, and the failure would be a page confidently showing
nothing while the file sat there under a slightly different name.

Nothing here reads a file's contents. Existence and size are facts about the
tree; what an artifact *says* is the surfaces' business.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from siem_investigator import paths


@dataclass(frozen=True)
class Stage:
    """One of design SS2's six stages and the artifacts it publishes."""

    number: int
    name: str
    determinism: str
    artifacts: tuple[Path, ...]
    #: True for a stage that runs at question time rather than at build time.
    #: Without this, stage 6 publishes no build artifact and so reported "not
    #: built" while being perfectly alive -- a wrong answer that looked like a
    #: right one.
    live: bool = False

    @property
    def present(self) -> tuple[Path, ...]:
        return tuple(path for path in self.artifacts if path.is_file())

    @property
    def missing(self) -> tuple[Path, ...]:
        return tuple(path for path in self.artifacts if not path.is_file())

    @property
    def state(self) -> str:
        """`complete`, `partial` or `not built` -- the three honest answers.

        `partial` is separate from `not built` deliberately: a stage that wrote
        two of its three artifacts is a different situation from one that never
        ran, and collapsing them would hide a half-finished build.
        """
        if self.live:
            return "live at query time"
        if not self.present:
            return "not built"
        return "complete" if not self.missing else "partial"


#: The six stages of design SS2, with the artifacts each publishes. The
#: determinism column is SS2's own label and is the answer to "where is the
#: model" -- stages 1, 2 and 5 cannot involve one at all.
STAGES: tuple[Stage, ...] = (
    Stage(1, "INGEST", "deterministic", (paths.RECORDS, paths.INGEST_REPORT)),
    Stage(
        2,
        "PARSE",
        "deterministic",
        (paths.EVENTS, paths.ENTITIES, paths.RESOLUTION, paths.PARSE_REPORT),
    ),
    Stage(
        3,
        "CORRELATE",
        "deterministic facts + interpretive layer",
        (
            paths.OBSERVATIONS,
            paths.EDGES,
            paths.HYPOTHESES,
            paths.FINDINGS,
            paths.TRAJECTORY,
            paths.REJECTIONS,
            paths.CORRELATE_REPORT,
        ),
    ),
    Stage(
        4,
        "ENRICH WITH ATT&CK",
        "model selects from a retrieved enum",
        (paths.MAPPINGS, paths.UNMAPPED, paths.ENRICH_REPORT),
    ),
    Stage(
        5,
        "SYNTHESISE",
        "deterministic",
        (
            paths.TIMELINE,
            paths.SCOPE,
            paths.GAPS,
            paths.PRIVILEGE,
            paths.ATTACK_FLOW,
            paths.NAVIGATOR_LAYER,
            paths.SYNTHESISE_REPORT,
        ),
    ),
    Stage(
        6,
        "ANSWER",
        "model + read-only tools + gate",
        (),  # answers are per-question records under outputs/, not a build artifact
        live=True,
    ),
)


def stage_rows() -> list[dict[str, object]]:
    """The six stages as table rows: number, name, determinism, state, counts."""
    return [
        {
            "stage": stage.number,
            "name": stage.name,
            "determinism": stage.determinism,
            "state": stage.state,
            "artifacts_present": len(stage.present),
            "artifacts_expected": len(stage.artifacts),
        }
        for stage in STAGES
    ]


def artifact_rows(stage: Stage) -> list[dict[str, object]]:
    """One row per artifact of `stage`: path, present, bytes.

    Paths are repository-relative through `paths.relative`, because an absolute
    build-machine path on screen would become part of the evidence a reader
    copies out of the app.
    """
    return [
        {
            "artifact": paths.relative(path),
            "present": path.is_file(),
            "bytes": path.stat().st_size if path.is_file() else 0,
        }
        for path in stage.artifacts
    ]


def absent_notice(*required: Path) -> str | None:
    """A message naming every missing artifact, or None if all are present."""
    missing = [paths.relative(path) for path in required if not path.is_file()]
    if not missing:
        return None
    return (
        "This surface renders from committed artifacts that do not exist yet: "
        + ", ".join(f"`{name}`" for name in missing)
        + ". Nothing is shown in their place — an invented row here would be "
        "indistinguishable from a finding."
    )
