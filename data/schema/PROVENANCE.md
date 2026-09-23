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


## `attack-flow-2.0.0.json`

- **source** <https://raw.githubusercontent.com/center-for-threat-informed-defense/attack-flow/main/stix/attack-flow-schema-2.0.0.json>
- **retrieved** 2026-09-23
- **bytes** 20,497
- **sha256** `fff896f5e1bdc39d9b387c0d3571307037cf9be1059de9cd94d066d1da2997cc`

Vendored so D-04's Attack Flow export can be validated offline. Attack Flow is a projection here, never the internal model: 3 of 5 node kinds and all 10 factual relations have no equivalent in it.
