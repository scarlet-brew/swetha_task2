"""Derive the flat ATT&CK catalogue from the retained STIX bundle (D-03, T04).

Three slices of the 26,086-object bundle are used: the one `x-mitre-collection`
object (for the version), the 15 `x-mitre-tactic` objects, and the 858
`attack-pattern` objects. The 21,262 `relationship` objects are not -- nothing
here needs to know which group uses which technique.

**Authority and projection.** The bundle is the authority; this derived file is
a projection under SS8.3 -- regenerable, never authoritative, and covered by the
byte-identical invariant. That is why the bundle is committed whole rather than
as this subset: a subset alone would make the derivation unreproducible and
leave R4.2's version claim unverifiable.

**stdlib `json` only.** D-03 rejected `mitreattack-python` (pandas + numpy +
pillow + drawsvg to turn an id into a name, 150-300 MB installed, and its
`MitreAttackData` is typed against STIX *2.0* while the committed bundle is
2.1). Measured on this machine, the stdlib parse of the 51.3 MiB bundle takes
0.30-0.45 s and peaks at a 274 MiB working set -- 259 MiB above a bare
interpreter, and 257 MiB of it accounted for by `tracemalloc`. Affordable for a
build step that runs once, which is the whole reason the catalogue is derived at
build time rather than at query time. SS10.2 carries the measured row.

**Size.** Design D-03 estimated ~200 KB for this file. Measured, it is
1,475,013 bytes. The gap is descriptions: the 858 of them are 1,185,188
characters between them, and without them the projection is 262,248 bytes --
about what the estimate described. Truncating would shrink the file by degrading
the only thing it exists for, since stage 4 retrieves candidate techniques by
matching against names *and* descriptions. Still a 36x reduction from the
bundle, and committing 1.4 MiB costs nothing. SS10.2 records the correction.

    python -m siem_investigator.enrich.catalogue          # regenerate
    python -m siem_investigator.enrich.catalogue --check   # regenerate and diff
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from dataclasses import dataclass
from pathlib import Path

from .. import __version__, jsonl, paths

#: The STIX `source_name` that carries ATT&CK's own identifiers. A technique
#: also carries references to CAPEC and to published reporting; only this one
#: gives `T1059.001`.
ATTACK_SOURCE = "mitre-attack"

#: `kill_chain_phases` can name other kill chains. Only ATT&CK's own phases are
#: tactics.
ATTACK_KILL_CHAIN = "mitre-attack"


@dataclass(frozen=True)
class Technique:
    technique_id: str
    technique_ref: str
    name: str
    tactics: tuple[str, ...]
    is_subtechnique: bool
    revoked: bool
    deprecated: bool
    description: str

    @property
    def selectable(self) -> bool:
        """Whether stage 4 may offer this technique as a candidate.

        149 of the 858 techniques are revoked and 12 more deprecated in v19.2.
        They stay in the catalogue so an id found in older reporting can still
        be *resolved* to a name, but mapping a finding to a revoked technique
        would be a defect, so retrieval draws only from the selectable set.
        """
        return not (self.revoked or self.deprecated)


@dataclass(frozen=True)
class Tactic:
    tactic_id: str
    shortname: str
    name: str


def _attack_id(obj: dict) -> str | None:
    for reference in obj.get("external_references", ()):
        if reference.get("source_name") == ATTACK_SOURCE:
            return reference.get("external_id")
    return None


def _tactics_of(obj: dict) -> tuple[str, ...]:
    return tuple(
        phase["phase_name"]
        for phase in obj.get("kill_chain_phases", ())
        if phase.get("kill_chain_name") == ATTACK_KILL_CHAIN
    )


def sha256_of(path: Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for block in iter(lambda: handle.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def derive(bundle_path: Path | None = None) -> dict:
    """Read the bundle and return the flat catalogue as a plain dict.

    Deterministic by construction: techniques and tactics are sorted by their
    ATT&CK ids, and every value is copied rather than computed, so regenerating
    from the same bundle yields the same bytes.

    Tactic *order within a technique* is left as the bundle gives it, which is
    ATT&CK's own matrix order -- more informative than alphabetical, and stable
    because JSON preserves array order.
    """
    bundle_path = Path(bundle_path or paths.ATTACK_BUNDLE)
    with bundle_path.open(encoding="utf-8") as handle:
        bundle = json.load(handle)

    objects = bundle["objects"]

    collections = [obj for obj in objects if obj["type"] == "x-mitre-collection"]
    if len(collections) != 1:
        raise ValueError(
            f"{bundle_path.name}: expected exactly 1 x-mitre-collection object, found "
            f"{len(collections)}; the version claim in every artifact comes from it"
        )
    collection = collections[0]
    # Verbatim, not parsed or reformatted: R4.2's claim is about what MITRE
    # published, so re-deriving "19.2" from a filename would defeat the point.
    attack_version = collection["x_mitre_version"]

    tactics: list[Tactic] = []
    for obj in objects:
        if obj["type"] != "x-mitre-tactic":
            continue
        tactic_id = _attack_id(obj)
        if tactic_id is None:
            continue
        tactics.append(Tactic(tactic_id, obj["x_mitre_shortname"], obj["name"]))

    techniques: list[Technique] = []
    for obj in objects:
        if obj["type"] != "attack-pattern":
            continue
        technique_id = _attack_id(obj)
        if technique_id is None:
            # An attack-pattern with no ATT&CK id could not be cited by id, so
            # it could not appear in a mapping. None exist in v19.2; skipped
            # rather than asserted, since a future bundle is not this task's
            # problem.
            continue
        techniques.append(
            Technique(
                technique_id=technique_id,
                # D-04 borrows exactly one idea back from Attack Flow: carrying
                # the id and the STIX ref *as a pair* makes them checkable
                # against each other. The documented LLM failure mode is a right
                # name with a wrong id, which mere existence-checking passes.
                technique_ref=obj["id"],
                name=obj["name"],
                tactics=_tactics_of(obj),
                is_subtechnique=bool(obj.get("x_mitre_is_subtechnique", False)),
                revoked=bool(obj.get("revoked", False)),
                deprecated=bool(obj.get("x_mitre_deprecated", False)),
                description=obj.get("description", ""),
            )
        )

    techniques.sort(key=lambda technique: technique.technique_id)
    tactics.sort(key=lambda tactic: tactic.tactic_id)

    return {
        "attack_version": attack_version,
        "attack_spec_version": collection["x_mitre_attack_spec_version"],
        "stix_spec_version": collection["spec_version"],
        "collection_modified": collection["modified"],
        "source": {
            "file": paths.relative(bundle_path),
            "bundle_id": bundle["id"],
            "sha256": sha256_of(bundle_path),
            "objects": len(objects),
        },
        "derived_by": f"siem_investigator.enrich.catalogue @ {__version__}",
        "counts": {
            "tactics": len(tactics),
            "techniques": len(techniques),
            "selectable": sum(1 for technique in techniques if technique.selectable),
            "revoked": sum(1 for technique in techniques if technique.revoked),
            "deprecated": sum(1 for technique in techniques if technique.deprecated),
        },
        "tactics": [
            {"tactic_id": tactic.tactic_id, "shortname": tactic.shortname, "name": tactic.name}
            for tactic in tactics
        ],
        "techniques": [
            {
                "technique_id": technique.technique_id,
                "technique_ref": technique.technique_ref,
                "name": technique.name,
                "tactics": list(technique.tactics),
                "is_subtechnique": technique.is_subtechnique,
                "revoked": technique.revoked,
                "deprecated": technique.deprecated,
                "description": technique.description,
            }
            for technique in techniques
        ],
    }


class Catalogue:
    """Read side: the derived file, with the lookups stage 4 needs."""

    def __init__(self, payload: dict):
        self.payload = payload
        self.attack_version: str = payload["attack_version"]
        self.techniques: dict[str, Technique] = {
            row["technique_id"]: Technique(
                technique_id=row["technique_id"],
                technique_ref=row["technique_ref"],
                name=row["name"],
                tactics=tuple(row["tactics"]),
                is_subtechnique=row["is_subtechnique"],
                revoked=row["revoked"],
                deprecated=row["deprecated"],
                description=row["description"],
            )
            for row in payload["techniques"]
        }
        self.tactics: dict[str, Tactic] = {
            row["shortname"]: Tactic(row["tactic_id"], row["shortname"], row["name"])
            for row in payload["tactics"]
        }

    @classmethod
    def load(cls, path: Path | None = None) -> Catalogue:
        return cls(jsonl.read_json(path or paths.ATTACK_CATALOGUE))

    def technique(self, technique_id: str) -> Technique | None:
        return self.techniques.get(technique_id)

    def selectable_ids(self) -> tuple[str, ...]:
        """The closed enum stage 4 selects from, sorted.

        Returning this rather than a free-text field is what makes a
        hallucinated technique id *structurally unrepresentable* instead of
        merely detectable -- MITRE's own TRAM needs no catalogue check at
        prediction time for the same reason.
        """
        return tuple(sorted(tid for tid, t in self.techniques.items() if t.selectable))

    def tactic_name(self, shortname: str) -> str | None:
        tactic = self.tactics.get(shortname)
        return tactic.name if tactic else None

    def name_matches_id(self, technique_id: str, name: str) -> bool:
        """Whether `name` is the official name for `technique_id`.

        Stage 4's id/name consistency gate. The documented model failure is a
        plausible name paired with the wrong id, which an existence check on
        the id alone passes cleanly.
        """
        technique = self.techniques.get(technique_id)
        return technique is not None and technique.name == name


def write(destination: Path | None = None, bundle_path: Path | None = None) -> Path:
    destination = Path(destination or paths.ATTACK_CATALOGUE)
    jsonl.write_json(destination, derive(bundle_path))
    return destination


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Derive the flat ATT&CK catalogue.")
    parser.add_argument(
        "--check",
        action="store_true",
        help="regenerate to a temporary file and report whether it matches the committed one",
    )
    args = parser.parse_args(argv)

    if args.check:
        if not paths.ATTACK_CATALOGUE.exists():
            print("no committed catalogue to compare against", file=sys.stderr)
            return 1
        committed = paths.ATTACK_CATALOGUE.read_bytes()
        scratch = paths.ATTACK_CATALOGUE.with_suffix(".check.json")
        try:
            jsonl.write_json(scratch, derive())
            regenerated = scratch.read_bytes()
        finally:
            scratch.unlink(missing_ok=True)
        if committed == regenerated:
            print(f"byte-identical  {len(committed):,} bytes")
            return 0
        print(
            f"DIFFERS  committed {len(committed):,} bytes, regenerated {len(regenerated):,} bytes",
            file=sys.stderr,
        )
        return 1

    destination = write()
    catalogue = Catalogue.load(destination)
    counts = catalogue.payload["counts"]
    print(f"{paths.relative(destination)}  {destination.stat().st_size:,} bytes")
    print(f"  attack_version   {catalogue.attack_version}  (verbatim from x-mitre-collection)")
    print(f"  tactics          {counts['tactics']}")
    print(
        f"  techniques       {counts['techniques']}  "
        f"({counts['selectable']} selectable, {counts['revoked']} revoked, "
        f"{counts['deprecated']} deprecated)"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
