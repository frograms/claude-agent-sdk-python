"""OAuth authentication provider."""

import json
import logging
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

from ..._errors import AuthenticationError
from .provider import AuthProvider

logger = logging.getLogger(__name__)


class OAuthProvider(AuthProvider):
    """OAuth authentication provider.

    Supports OAuth credentials from:
    - macOS Keychain (via `security` command)
    - Credentials file at ~/.claude/.credentials.json
    """

    KEYCHAIN_SERVICE_NAME = "Claude Code-credentials"
    CREDENTIALS_PATH = Path.home() / ".claude" / ".credentials.json"
    SUBPROCESS_TIMEOUT = 5  # seconds

    def __init__(self, credentials_path: Path | None = None):
        """Initialize OAuth provider.

        Args:
            credentials_path: Override default credentials file path.
        """
        self._credentials_path = credentials_path or self.CREDENTIALS_PATH

    def is_available(self) -> bool:
        """Check if OAuth credentials are available."""
        if sys.platform == "darwin":
            # macOS: Check Keychain first
            if self._check_keychain():
                return True

        # All platforms: Check credentials file
        return self._check_file()

    def prepare(self) -> None:
        """Prepare OAuth credentials for CLI.

        On macOS, extracts credentials from Keychain to file.
        On other platforms, verifies credentials file exists.

        Important: Removes ANTHROPIC_API_KEY from environment to ensure
        Claude CLI uses OAuth credentials instead of API key.

        Raises:
            AuthenticationError: If no OAuth credentials found.
        """
        if not self.is_available():
            raise AuthenticationError(
                "No OAuth credentials found",
                suggestion="Log in with: claude login\n"
                "Or set ANTHROPIC_API_KEY environment variable",
            )

        # Remove API key from environment to force CLI to use OAuth
        # Claude CLI prioritizes ANTHROPIC_API_KEY over OAuth credentials
        removed_api_key = os.environ.pop("ANTHROPIC_API_KEY", None)
        if removed_api_key:
            logger.debug(
                "Removed ANTHROPIC_API_KEY from environment to use OAuth credentials"
            )

        if sys.platform == "darwin":
            # macOS: Extract from Keychain and create file
            try:
                self._setup_from_keychain()
                logger.info("Using OAuth credentials from macOS Keychain")
            except Exception as e:
                logger.warning(f"Failed to setup OAuth from Keychain: {e}")
                raise AuthenticationError(
                    f"Failed to prepare OAuth credentials: {e}"
                ) from e
        else:
            # Other platforms: File should already exist
            logger.info(
                f"Using OAuth credentials from {self._credentials_path}"
            )

    def get_name(self) -> str:
        """Get auth method name."""
        return "oauth"

    def _check_keychain(self) -> bool:
        """Check if macOS Keychain has OAuth credentials."""
        if sys.platform != "darwin":
            return False

        try:
            result = subprocess.run(
                [
                    "security",
                    "find-generic-password",
                    "-s",
                    self.KEYCHAIN_SERVICE_NAME,
                    "-w",
                ],
                capture_output=True,
                text=True,
                timeout=self.SUBPROCESS_TIMEOUT,
                check=False,
            )

            if result.returncode != 0:
                return False

            # Validate JSON and check for OAuth data
            data = json.loads(result.stdout.strip())
            return "claudeAiOauth" in data or "accessToken" in data

        except (subprocess.TimeoutExpired, json.JSONDecodeError, OSError) as e:
            logger.debug(f"Keychain check failed: {e}")
            return False

    def _check_file(self) -> bool:
        """Check if credentials file exists and has OAuth data."""
        if not self._credentials_path.exists():
            return False

        try:
            with open(self._credentials_path, "r") as f:
                data = json.load(f)
                oauth_data = data.get("claudeAiOauth")
                return oauth_data is not None and "accessToken" in oauth_data
        except (json.JSONDecodeError, IOError, KeyError) as e:
            logger.debug(f"Credentials file check failed: {e}")
            return False

    def _get_oauth_from_keychain(self) -> dict[str, Any]:
        """Extract OAuth data from macOS Keychain."""
        result = subprocess.run(
            [
                "security",
                "find-generic-password",
                "-s",
                self.KEYCHAIN_SERVICE_NAME,
                "-w",
            ],
            capture_output=True,
            text=True,
            timeout=self.SUBPROCESS_TIMEOUT,
            check=True,  # Raise CalledProcessError on failure
        )

        credentials_json = result.stdout.strip()
        credentials = json.loads(credentials_json)

        # Extract claudeAiOauth field if present
        if "claudeAiOauth" in credentials:
            return credentials["claudeAiOauth"]
        else:
            return credentials

    def _setup_from_keychain(self) -> None:
        """Set up credentials file from Keychain data."""
        # Get OAuth data from Keychain
        oauth_data = self._get_oauth_from_keychain()

        # Backup existing file if present
        if self._credentials_path.exists():
            backup_path = self._credentials_path.with_suffix(".json.bak")
            self._credentials_path.rename(backup_path)
            logger.debug(f"Backed up existing credentials to {backup_path}")

        # Create credentials directory
        self._credentials_path.parent.mkdir(parents=True, exist_ok=True)

        # Write credentials file
        credentials_data = {"claudeAiOauth": oauth_data}

        with open(self._credentials_path, "w") as f:
            json.dump(credentials_data, f, indent=2)

        # Set secure file permissions
        self._credentials_path.chmod(0o600)

        logger.debug(f"OAuth credentials written to {self._credentials_path}")


def get_oauth_status() -> dict[str, Any]:
    """Get OAuth status for debugging.

    Returns:
        Dictionary with OAuth availability and status information.
    """
    provider = OAuthProvider()

    status = {
        "platform": sys.platform,
        "oauth_available": provider.is_available(),
        "credentials_path": str(provider._credentials_path),
    }

    if sys.platform == "darwin":
        status["keychain_accessible"] = provider._check_keychain()

    status["file_exists"] = provider._check_file()

    return status
