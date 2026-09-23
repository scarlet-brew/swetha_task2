# Provenance — Attack Flow 2.0.0 JSON schema, and its `$ref` closure

Design `D-04` makes Attack Flow a **projection**, not the internal model: a serialiser at stage 5
publishes the export, and three verifications across the plan assert that
`data/derived/05_attack_flow.json` "validates against the vendored schema". That vendored schema
is this directory.

**Nothing in `src/` fetches any of this.** The retrieval was a one-off, recorded here.

## Retrieved

`2026-09-23T21:01:12+00:00` (UTC), over HTTPS from `raw.githubusercontent.com`.

| File | Bytes | sha256 | Source URL |
|---|---|---|---|
| `attack-flow-2.0.0.json` | 20497 | `fff896f5e1bdc39d9b387c0d3571307037cf9be1059de9cd94d066d1da2997cc` | https://raw.githubusercontent.com/center-for-threat-informed-defense/attack-flow/main/stix/attack-flow-schema-2.0.0.json |
| `refs/master/timestamp.json` | 510 | `e816ad77e8f46b66aaaacac6b7f5f14dcd9d320c01d992455a7958481337d4d9` | https://raw.githubusercontent.com/oasis-open/cti-stix2-json-schemas/master/schemas/common/timestamp.json |
| `refs/stix2.1/binary.json` | 695 | `18d0faef9f42579d5c7f337659ae6f72334029209035c05f21583ae2be17bf25` | http://raw.githubusercontent.com/oasis-open/cti-stix2-json-schemas/stix2.1/schemas/common/binary.json |
| `refs/stix2.1/core.json` | 4646 | `e8562aa1dd674249c33a640d1d972183256e491b9af81eaa78d102da1c473ffb` | http://raw.githubusercontent.com/oasis-open/cti-stix2-json-schemas/stix2.1/schemas/common/core.json |
| `refs/stix2.1/dictionary.json` | 805 | `4984a232a664bd54d2fb99a49c052a38da2ce90e43995a007a9e5fa8d208c116` | http://raw.githubusercontent.com/oasis-open/cti-stix2-json-schemas/stix2.1/schemas/common/dictionary.json |
| `refs/stix2.1/extension.json` | 701 | `e4537cf608b709597ede2ad39027defa979df9ad79666b15643d625ac260f15d` | http://raw.githubusercontent.com/oasis-open/cti-stix2-json-schemas/stix2.1/schemas/common/extension.json |
| `refs/stix2.1/external-reference.json` | 2879 | `ade5360f0e7b0863ad933d34a54802e7ac9e85d1e0db53cf449e43465ba81127` | http://raw.githubusercontent.com/oasis-open/cti-stix2-json-schemas/stix2.1/schemas/common/external-reference.json |
| `refs/stix2.1/granular-marking.json` | 1318 | `24c51ff9d99f1902b156e6e04e360e23ea01cded49d07a83fca709cef26884c0` | http://raw.githubusercontent.com/oasis-open/cti-stix2-json-schemas/stix2.1/schemas/common/granular-marking.json |
| `refs/stix2.1/hashes-type.json` | 1928 | `6493e13b08fbf0ced26e956166e03ab37011ae1bb2c26d80a449ea7c81155c50` | http://raw.githubusercontent.com/oasis-open/cti-stix2-json-schemas/stix2.1/schemas/common/hashes-type.json |
| `refs/stix2.1/hex.json` | 616 | `d079f4141f68615424756bd74d16b4a47b9a7388dd836845849595db6e59f253` | http://raw.githubusercontent.com/oasis-open/cti-stix2-json-schemas/stix2.1/schemas/common/hex.json |
| `refs/stix2.1/identifier.json` | 558 | `662be3c490c8f3b2aa82100d1dc41ec1acf93c04d099c857cc2f88217d688524` | http://raw.githubusercontent.com/oasis-open/cti-stix2-json-schemas/stix2.1/schemas/common/identifier.json |
| `refs/stix2.1/properties.json` | 861 | `ccb1920b6d2c9a80856d36e870163b3b298cf9c3ca42742f3f63dfbc87295754` | http://raw.githubusercontent.com/oasis-open/cti-stix2-json-schemas/stix2.1/schemas/common/properties.json |
| `refs/stix2.1/timestamp.json` | 510 | `e816ad77e8f46b66aaaacac6b7f5f14dcd9d320c01d992455a7958481337d4d9` | http://raw.githubusercontent.com/oasis-open/cti-stix2-json-schemas/stix2.1/schemas/common/timestamp.json |
| `refs/stix2.1/url-regex.json` | 301 | `88a22341762c7b039a1ce349d808a1ed4e0b560af11dbc911532eeb580026115` | http://raw.githubusercontent.com/oasis-open/cti-stix2-json-schemas/stix2.1/schemas/common/url-regex.json |

Upstream names the schema file `attack-flow-schema-2.0.0.json`; it is stored here as
`attack-flow-2.0.0.json` because that is the path design §8.3 and `paths.py` already fixed. The
`$id` inside the file is unchanged, so `$ref` resolution is unaffected by the rename.

## Why `refs/` exists — the thing that would have failed at the last task

The published Attack Flow schema is **not self-contained.** It carries three remote `$ref`s into
the OASIS STIX 2.1 common schemas:

```
http://raw.githubusercontent.com/oasis-open/cti-stix2-json-schemas/stix2.1/schemas/common/core.json
http://raw.githubusercontent.com/oasis-open/cti-stix2-json-schemas/stix2.1/schemas/common/identifier.json
https://raw.githubusercontent.com/oasis-open/cti-stix2-json-schemas/master/schemas/common/timestamp.json
```

Those fan out to a transitive closure of **13 documents, 16328 bytes total** — measured, and small
enough to retain in full.

Measured with `jsonschema 4.26.0` in this venv, validating an Attack Flow object against the
schema **without** a preloaded reference registry:

- it **succeeds**, and it succeeds by **fetching the OASIS schemas over the network at validation
  time**, emitting `DeprecationWarning: Automatically retrieving remote references can be a
  security vulnerability`.

That is three distinct problems, which is why the closure is vendored rather than left to resolve
itself:

1. **`NFR-02`.** Validation on an analyst machine with no network would fail — and the failure
   would appear in stage 5, not at startup.
2. **`NFR-04`.** It is undocumented egress: incident-derived data is not sent, but the fact of
   validation is, to a third-party host, from code that never mentions a network.
3. **The `git grep -nE "requests|urllib|httpx|taxii" src/` verification cannot catch it.** The
   egress happens inside `jsonschema`'s reference resolver, so the grep passes while the process
   still reaches the network. The grep is necessary and not sufficient; the registry is what makes
   the offline claim structural.

`ref_index.json` in this directory is the resolution map: `uri` -> local `path` for each of the 13
documents plus the schema root. It is generated locally, not fetched, so it carries no provenance
row of its own; the digests in it are cross-checked against the table above by
`tests/test_external_artifacts.py`. Build a `referencing.Registry` from it and pass that registry
to the validator:

```python
registry = Registry().with_resources(
    (entry["uri"], Resource.from_contents(json.loads(Path(entry["path"]).read_bytes()),
                                          default_specification=DRAFT202012))
    for entry in json.loads(Path("data/schema/ref_index.json").read_bytes())["refs"]
)
```

Verified with that registry in place: every `$ref` in the schema resolves locally, and a
representative `attack-action` SDO validates with zero errors and no network access.

Two of the 13 files are byte-identical (`refs/stix2.1/timestamp.json` and
`refs/master/timestamp.json` share a digest, and both declare the `stix2.1` `$id`). Both are kept,
because the registry is keyed by retrieval URI and the schema cites both spellings.

## Re-verifying

```
.venv/Scripts/python.exe scripts/fetch_external.py --check
.venv/Scripts/python.exe -m unittest tests.test_external_artifacts
```

```
git check-attr text -- data/schema/attack-flow-2.0.0.json
```

## Licences

Attack Flow is (c) The MITRE Corporation, published by the Center for Threat-Informed Defense
under Apache 2.0. The OASIS `cti-stix2-json-schemas` are (c) OASIS Open, under the BSD 3-Clause
licence. Both are redistributed here unmodified.
