# Provenance — MITRE ATT&CK catalogue (authority 2)

Design `D-03` retains the official ATT&CK bundle locally rather than adopting
`mitreattack-python` (which pulls pandas, and whose `MitreAttackData` is typed against STIX 2.0
while this bundle is 2.1) and rather than keeping only a derived subset (which would make the
derivation unreproducible and requirement `R4.2`'s version claim unverifiable).

Retaining the bundle only works as an authority if the bytes can be shown to be the bytes MITRE
published. Hence this file, and hence `.gitattributes` marking `*.json -text`: end-of-line
normalisation on a committed external artifact would silently change the file and make every
sha256 below wrong on a fresh checkout.

**Nothing in `src/` fetches any of this.** The retrieval was a one-off, recorded here.

## Retrieved

`2026-09-23T21:01:12+00:00` (UTC), over HTTPS from `raw.githubusercontent.com`.

| File | Bytes | sha256 | Source URL |
|---|---|---|---|
| `enterprise-attack-19.2.json` | 53835637 | `dc1639caa5501d720e280cf1cbd8fbe009884a0c9b3e6e9ed9d0c25166c3d8f4` | https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack-19.2.json |
| `index.json` | 32340 | `470688307ba183e4f8a5031faa43a59eb7a84507d621bc7b0c3192e6875c1c04` | https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/index.json |

`index.json` is MITRE's collection index — the file that names the v19.2 bundle and its URL. It is
committed alongside the bundle because it is the upstream evidence that `enterprise-attack-19.2.json`
is the published v19.2 artifact and not a file someone assembled and named that way. The entry it
carries for this bundle:

```json
{
  "version": "19.2",
  "url": "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack-19.2.json",
  "modified": "2026-08-05T21:33:58.496Z"
}
```

## What the bundle actually contains — measured, not assumed

| Property | Measured value |
|---|---|
| Top-level keys | `id`, `objects`, `type` — `type` is `bundle` |
| Objects | 26086 |
| `spec_version` per object | `"2.1"` on all 26086 objects |
| `spec_version` at bundle level | **absent**, which is what STIX 2.1 requires (it was mandatory in 2.0) |
| `x-mitre-collection` objects | exactly 1 |
| Version field on that object | `x_mitre_version` = `"19.2"` (a string) |
| ATT&CK spec version | `x_mitre_attack_spec_version` = `"3.3.0"` |
| Largest object types | `relationship` 21262, `x-mitre-analytic` 1758, `attack-pattern` 858, `malware` 733 |

The STIX 2.1 claim in `D-03` therefore rests on the per-object `spec_version` and the absent
bundle-level one, not on the filename.

`attack_version` for `R4.2`/`NFR-07` is `x_mitre_version` on the single `x-mitre-collection`
object — the field T04 copies verbatim. It is `"19.2"`, matching the `index.json` entry above.

## The bundle is the authority; the flat catalogue is a projection

`catalogue_v19.2.json` in this directory is derived from the bundle by
`src/siem_investigator/enrich/catalogue.py` (T04) with stdlib `json` only. Delete it and it
regenerates byte-identically. It is never edited by hand and never the thing a version claim
points at.

## Re-verifying

Re-hash every artifact and compare against the table above. Both of these read the table and
recompute; neither reaches the network:

```
.venv/Scripts/python.exe scripts/fetch_external.py --check
.venv/Scripts/python.exe -m unittest tests.test_external_artifacts
```

Or by hand, one file:

```
.venv/Scripts/python.exe -c "import hashlib,pathlib; print(hashlib.sha256(pathlib.Path('data/attack/enterprise-attack-19.2.json').read_bytes()).hexdigest())"
```

Confirm git will not rewrite the bytes on checkout (`text: unset` is the required answer):

```
git check-attr text -- data/attack/enterprise-attack-19.2.json
```

## Re-fetching

Only needed if the files are lost, or to confirm upstream has not moved. A changed digest means
MITRE republished under the same version, which is a finding, not a routine update — the bundle is
pinned deliberately.

`scripts/fetch_external.py` is the only code in the repository that opens a socket, and it lives
outside `src/` for exactly that reason. It fetches anything missing and leaves present files alone;
`--force` re-fetches everything.

```
.venv/Scripts/python.exe scripts/fetch_external.py
```

## Licence

ATT&CK is (c) The MITRE Corporation, provided under the ATT&CK Terms of Use
(https://attack.mitre.org/resources/legal-and-branding/terms-of-use/). Redistributed here
unmodified, with attribution, for a non-commercial prototype.
