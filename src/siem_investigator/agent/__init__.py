"""The model plane: the three sites where a language model is used, and nothing else.

Design SS7 puts the model in exactly three places -- INTERPRET/HYPOTHESISE inside
stage 3, technique selection at stage 4, and retrieval plus rendering at stage
6. Everything else in the system is deterministic. Keeping all three behind this
package is what makes that claim checkable: `docs/egress.md` inventories what
each site sends, and a test captures the real serialised request body for each
and asserts nothing beyond the inventory leaves the process.

Nothing here is imported by anything under `app/`. The query plane reads
committed artifacts and has no path to the service, which is why the app starts
with no credential and no network.
"""
