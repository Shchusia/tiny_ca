import os
import sys

# ← REPLACE THIS PATH if your project root is not one level above docs/source/
sys.path.insert(0, os.path.abspath("../.."))
# Configuration file for the Sphinx documentation builder.
#
# For the full list of built-in configuration values, see the documentation:
# https://www.sphinx-doc.org/en/master/usage/configuration.html

# -- Project information -----------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/configuration.html#project-information

project = "tiny_ca"
copyright = "2026, Denis Shchutskyi"
author = "Denis Shchutskyi"
release = "0.2.0"

# -- General configuration ---------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/configuration.html#general-configuration

extensions = [
    "sphinx.ext.autodoc",  # pulls docstrings from source code
    "sphinx.ext.napoleon",  # supports NumPy / Google style docstrings
    "sphinx.ext.viewcode",  # adds [source] links to each item
    "sphinx.ext.intersphinx",  # cross-links to Python / cryptography docs
    "sphinx_autodoc_typehints",  # renders type annotations in the signature
]
napoleon_google_docstring = False  # tiny_ca uses NumPy-style docstrings
napoleon_numpy_docstring = True
napoleon_include_init_with_doc = True
napoleon_include_private_with_doc = False  # skip _CertSerializer etc.
napoleon_use_param = True
napoleon_use_rtype = True

autodoc_default_options = {
    "members": True,
    "undoc-members": False,  # skip methods without docstrings
    "show-inheritance": True,
    "special-members": "__init__",
}
autodoc_typehints = "description"  # puts type info in the Parameters section
autoclass_content = "both"

templates_path = ["_templates"]
exclude_patterns = ["_build", "Thumbs.db", ".DS_Store"]
autodoc_mock_imports = []  # add heavy optional deps here if needed


# -- Options for HTML output -------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/configuration.html#options-for-html-output

html_theme = "furo"
html_static_path = ["_static"]

intersphinx_mapping = {
    "python": ("https://docs.python.org/3", None),
    "cryptography": ("https://cryptography.io/en/latest/", None),
    "sqlalchemy": ("https://docs.sqlalchemy.org/en/20/", None),
    "pydantic": ("https://docs.pydantic.dev/latest/", None),
}
