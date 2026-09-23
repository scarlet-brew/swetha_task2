"""The Streamlit surfaces (design SS9.4).

A package rather than four loose scripts so that `app.components.citation` is
importable from a test without a Streamlit server running. `app/main.py` puts
the repository root on `sys.path` before importing anything from here, because
the project is deliberately never installed (see tests/_env.py).
"""
