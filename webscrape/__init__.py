"""WebScrape: passive internet service discovery and CVE lookup.

This package is organised by responsibility, with one sub-package per job
(see CLAUDE.md for the full layout). Each sub-package only depends on the
others it genuinely needs, so a change in one place stays contained.
"""

# A single source of truth for the package version, re-exported for tools
# that want to read it programmatically.
__version__ = "0.1.0"
