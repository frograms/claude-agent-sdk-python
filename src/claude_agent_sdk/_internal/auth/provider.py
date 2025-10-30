"""Abstract authentication provider interface."""

from abc import ABC, abstractmethod


class AuthProvider(ABC):
    """Abstract authentication provider interface.

    Authentication providers are responsible for checking if a particular
    authentication method is available and preparing the environment for
    Claude CLI to use that authentication method.
    """

    @abstractmethod
    def is_available(self) -> bool:
        """Check if this authentication method is available.

        Returns:
            True if the authentication method is available, False otherwise.
        """
        pass

    @abstractmethod
    def prepare(self) -> None:
        """Prepare authentication for CLI usage.

        This method should set up any necessary environment or files so that
        the Claude CLI can successfully authenticate.

        Raises:
            AuthenticationError: If authentication preparation fails.
        """
        pass

    @abstractmethod
    def get_name(self) -> str:
        """Get the name of this authentication method.

        Returns:
            A string identifier for this auth method (e.g., "oauth", "api_key").
        """
        pass
