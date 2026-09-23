# Provenance

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


## `index.json`

- **source** <https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/index.json>
- **retrieved** 2026-09-23
- **bytes** 32,340
- **sha256** `470688307ba183e4f8a5031faa43a59eb7a84507d621bc7b0c3192e6875c1c04`

The collection index. Names the available Enterprise bundles and their versions, so the version claim in every artifact can be traced to MITRE's own listing rather than to a filename we chose.


## `enterprise-attack-19.2.json`

- **source** <https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack-19.2.json>
- **retrieved** 2026-09-23
- **bytes** 53,835,637
- **sha256** `dc1639caa5501d720e280cf1cbd8fbe009884a0c9b3e6e9ed9d0c25166c3d8f4`

The authority under D-03: official ATT&CK Enterprise v19.2 as STIX 2.1. Committed whole rather than as the derived subset, because a subset would make the derivation unreproducible and R4.2's version claim unverifiable. Three slices are used -- the collection object, the tactics and the techniques; the relationship objects are not.
