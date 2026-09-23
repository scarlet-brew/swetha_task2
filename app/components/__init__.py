"""Render components shared by the four surfaces.

Each module here separates the *markup* from the `st.*` call that emits it, so
the markup can be asserted in a unit test without a script run. The support
badge is the clearest case: SS9.1 requires icon plus word on every support
state, and that is a property of a string.
"""
