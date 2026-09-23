"""The four surfaces of SS9.4, one module each.

Named `views/` rather than `pages/` deliberately: a `pages/` directory next to
the entry script is Streamlit's own auto-discovery convention, and this app
registers its pages explicitly through `st.navigation`. Two mechanisms
competing to define the same navigation is a bug waiting for a reader.
"""
