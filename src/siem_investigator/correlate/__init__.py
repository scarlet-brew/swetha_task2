"""Stage 3 CORRELATE -- four layers, with a hard boundary in the middle.

The boundary the whole design turns on: **the deterministic layer emits facts
and decides nothing; the model interprets facts and computes nothing.**

`relations.py` is the factual layer -- ten atomic relations, zero detection
rules. It links everything linkable, benign included. There is no coverage
ceiling because nothing is being detected.

`loop.py` is the interpretive layer, and `validate.py` is the deterministic
gate it cannot bypass.
"""
