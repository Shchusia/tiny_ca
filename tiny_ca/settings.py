"""
Package-wide settings.

``DEFAULT_LOGGER`` follows the standard-library guidance for libraries: it
gets a ``NullHandler`` and no explicit level, so the application decides
where (and whether) ``tiny_ca`` log records go.  Configure it as usual, e.g.
``logging.getLogger("TinyCA").setLevel(logging.DEBUG)``.
"""

from logging import NullHandler, getLogger

DEFAULT_LOGGER = getLogger("TinyCA")
DEFAULT_LOGGER.addHandler(NullHandler())

DT_STR_FORMAT = "%Y-%m-%d %H:%M:%S"
