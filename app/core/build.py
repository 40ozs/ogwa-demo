"""Build-time safety constants.

These are source constants, not configuration. No environment variable, config file,
or command-line flag can change them at runtime; changing one requires a source edit
that goes through human review.
"""

from typing import Final

# This build never performs mutation against production systems. Flipping this is
# necessary but NOT sufficient to enable it: a future build must also add an explicit,
# reviewed authorization path. See docs/security/execution-modes.md.
BUILD_ALLOWS_PRODUCTION_MUTATION: Final[bool] = False
