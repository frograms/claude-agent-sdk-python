"""Tests for authentication providers."""

import os
from unittest.mock import Mock, patch

import pytest

from claude_agent_sdk import AuthenticationError
from claude_agent_sdk._internal.auth import (
    APIKeyProvider,
    OAuthProvider,
    create_auth_provider,
)


class TestAPIKeyProvider:
    """Tests for API key authentication provider."""

    def test_is_available_with_api_key(self):
        """Test API key is detected when environment variable is set."""
        with patch.dict(os.environ, {"ANTHROPIC_API_KEY": "sk-test"}):
            provider = APIKeyProvider()
            assert provider.is_available() is True

    def test_is_available_without_api_key(self):
        """Test API key is not available when environment variable is missing."""
        with patch.dict(os.environ, {}, clear=True):
            provider = APIKeyProvider()
            assert provider.is_available() is False

    def test_prepare_with_api_key(self):
        """Test prepare succeeds with API key."""
        with patch.dict(os.environ, {"ANTHROPIC_API_KEY": "sk-test"}):
            provider = APIKeyProvider()
            provider.prepare()  # Should not raise

    def test_prepare_without_api_key_raises(self):
        """Test prepare raises when API key is missing."""
        with patch.dict(os.environ, {}, clear=True):
            provider = APIKeyProvider()
            with pytest.raises(AuthenticationError) as exc_info:
                provider.prepare()
            assert "No API key found" in str(exc_info.value)
            assert "ANTHROPIC_API_KEY" in str(exc_info.value)

    def test_get_name(self):
        """Test get_name returns correct identifier."""
        provider = APIKeyProvider()
        assert provider.get_name() == "api_key"


class TestOAuthProvider:
    """Tests for OAuth authentication provider."""

    def test_is_available_with_file(self, tmp_path):
        """Test OAuth is detected when credentials file exists."""
        creds_file = tmp_path / ".credentials.json"
        creds_file.write_text('{"claudeAiOauth": {"accessToken": "test-token"}}')

        provider = OAuthProvider(credentials_path=creds_file)
        assert provider.is_available() is True

    def test_is_available_without_file(self, tmp_path):
        """Test OAuth is not available when credentials file is missing."""
        import sys

        creds_file = tmp_path / ".credentials.json"

        # Mock sys.platform to skip Keychain check
        with patch.object(sys, "platform", "linux"):
            provider = OAuthProvider(credentials_path=creds_file)
            assert provider.is_available() is False

    def test_prepare_without_oauth_raises(self, tmp_path):
        """Test prepare raises when OAuth credentials are missing."""
        import sys

        creds_file = tmp_path / ".credentials.json"

        # Mock sys.platform to skip Keychain check
        with patch.object(sys, "platform", "linux"):
            provider = OAuthProvider(credentials_path=creds_file)
            with pytest.raises(AuthenticationError) as exc_info:
                provider.prepare()
            assert "No OAuth credentials found" in str(exc_info.value)
            assert "claude login" in str(exc_info.value)

    def test_get_name(self):
        """Test get_name returns correct identifier."""
        provider = OAuthProvider()
        assert provider.get_name() == "oauth"


class TestCreateAuthProvider:
    """Tests for auth provider factory function."""

    def test_creates_oauth_provider_when_available(self, tmp_path):
        """Test factory creates OAuth provider when OAuth is available."""
        creds_file = tmp_path / ".credentials.json"
        creds_file.write_text('{"claudeAiOauth": {"accessToken": "test-token"}}')

        with patch("claude_agent_sdk._internal.auth.OAuthProvider") as mock_oauth:
            mock_instance = Mock()
            mock_instance.is_available.return_value = True
            mock_oauth.return_value = mock_instance

            provider = create_auth_provider()

            assert provider == mock_instance

    def test_creates_apikey_provider_as_fallback(self):
        """Test factory creates API key provider when OAuth not available."""
        with patch.dict(os.environ, {"ANTHROPIC_API_KEY": "sk-test"}):
            with patch("claude_agent_sdk._internal.auth.OAuthProvider") as mock_oauth:
                mock_oauth_instance = Mock()
                mock_oauth_instance.is_available.return_value = False
                mock_oauth.return_value = mock_oauth_instance

                provider = create_auth_provider()

                assert isinstance(provider, APIKeyProvider)

    def test_raises_when_no_auth_available(self):
        """Test factory raises when no authentication is available."""
        with patch.dict(os.environ, {}, clear=True):
            with patch("claude_agent_sdk._internal.auth.OAuthProvider") as mock_oauth:
                mock_oauth_instance = Mock()
                mock_oauth_instance.is_available.return_value = False
                mock_oauth.return_value = mock_oauth_instance

                with pytest.raises(AuthenticationError) as exc_info:
                    create_auth_provider()

                assert "No authentication method available" in str(exc_info.value)
                assert "claude login" in str(exc_info.value)
