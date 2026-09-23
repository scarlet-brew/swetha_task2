"""Agentic incident investigation over a synthetic SIEM dataset.

Design SS8.2 stamps the software version onto every emitted artifact and onto
every answer record, so this constant is part of the provenance chain rather
than packaging decoration. `tests/test_kernel.py` asserts it equals the version
in pyproject.toml -- two copies of a fact that provenance depends on drift
silently otherwise.
"""

__version__ = "0.1.0"

__all__ = ["__version__"]
