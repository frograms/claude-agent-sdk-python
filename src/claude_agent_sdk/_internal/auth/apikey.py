"""API key authentication provider."""

import logging
import os

from ..._errors import AuthenticationError
from .provider import AuthProvider

logger = logging.getLogger(__name__)


class APIKeyProvider(AuthProvider):
    """API key authentication provider.

    Uses the ANTHROPIC_API_KEY environment variable for authentication.
    """

    def is_available(self) -> bool:
        """Check if API key is available in environment."""
        return bool(os.environ.get("ANTHROPIC_API_KEY"))

    def prepare(self) -> None:
        """Prepare API key authentication.

        Validates that the API key exists in the environment.

        Raises:
            AuthenticationError: If ANTHROPIC_API_KEY is not set.
        """
        if not self.is_available():
            raise AuthenticationError(
                "No API key found",
                suggestion="Set ANTHROPIC_API_KEY environment variable:\n"
                "  export ANTHROPIC_API_KEY='your-api-key'",
            )

        logger.info("Using API key authentication")

    def get_name(self) -> str:
        """Get auth method name."""
        return "api_key"
