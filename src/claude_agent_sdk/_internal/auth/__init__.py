"""Authentication module for Claude SDK."""

import logging

from ..._errors import AuthenticationError
from .apikey import APIKeyProvider
from .oauth import OAuthProvider, get_oauth_status
from .provider import AuthProvider

logger = logging.getLogger(__name__)

__all__ = [
    "AuthProvider",
    "OAuthProvider",
    "APIKeyProvider",
    "create_auth_provider",
    "get_oauth_status",
]


def create_auth_provider() -> AuthProvider:
    """Create appropriate auth provider based on available credentials.

    Tries authentication methods in priority order:
    1. OAuth (from Keychain or credentials file)
    2. API key (from ANTHROPIC_API_KEY environment variable)

    Returns:
        AuthProvider instance ready to use.

    Raises:
        AuthenticationError: If no authentication method is available.
    """
    # Try OAuth first
    oauth = OAuthProvider()
    if oauth.is_available():
        logger.debug("OAuth credentials detected")
        return oauth

    # Try API key
    apikey = APIKeyProvider()
    if apikey.is_available():
        logger.debug("API key detected")
        return apikey

    # No authentication available
    import sys

    if sys.platform == "darwin":
        suggestion = (
            "Either:\n"
            "  1. Run 'claude login' to use your Claude Max subscription\n"
            "     (Credentials will be stored in macOS Keychain)\n"
            "\n"
            "  2. Set ANTHROPIC_API_KEY environment variable:\n"
            "     export ANTHROPIC_API_KEY='your-api-key'\n"
            "\n"
            "To verify Keychain credentials:\n"
            "  security find-generic-password -s \"Claude Code-credentials\" -w"
        )
    else:
        suggestion = (
            "Either:\n"
            "  1. Run 'claude login' to use your Claude Max subscription\n"
            "\n"
            "  2. Set ANTHROPIC_API_KEY environment variable:\n"
            "     export ANTHROPIC_API_KEY='your-api-key'"
        )

    raise AuthenticationError("No authentication method available", suggestion=suggestion)
