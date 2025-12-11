"""
Integration tests for InCluster authentication strategy.

These tests verify the InCluster strategy works end-to-end with mock
service account files.
"""

import os
import warnings
from contextlib import contextmanager
from pathlib import Path
from unittest.mock import patch

import pytest

from openshift_ai_auth import AuthConfig
from openshift_ai_auth.config import SecurityWarning
from openshift_ai_auth.strategies.incluster import InClusterStrategy


@contextmanager
def patch_incluster_paths(sa_path):
    """Context manager to patch InCluster paths to use mock service account."""
    with patch('openshift_ai_auth.strategies.incluster.TOKEN_PATH', sa_path / 'token'):
        with patch('openshift_ai_auth.strategies.incluster.CA_CERT_PATH', sa_path / 'ca.crt'):
            with patch('openshift_ai_auth.strategies.incluster.NAMESPACE_PATH', sa_path / 'namespace'):
                yield


@pytest.mark.integration
class TestInClusterIntegrationAuthentication:
    """Integration tests for InCluster authentication."""

    def test_authenticate_with_mock_service_account(self, mock_service_account):
        """Test full authentication flow with mock service account."""
        with patch_incluster_paths(mock_service_account):
            config = AuthConfig(method="incluster")
            strategy = InClusterStrategy(config)

            # Verify strategy is available
            assert strategy.is_available()

            # Authenticate
            api_client = strategy.authenticate()

            # Verify we got a valid API client
            assert api_client is not None
            assert api_client.configuration.host == "https://kubernetes.default.svc"
            assert api_client.configuration.api_key["authorization"] == "Bearer test-sa-token-content"

    def test_authenticate_with_custom_namespace(self, mock_service_account):
        """Test authentication reads custom namespace."""
        # Update namespace file
        namespace_path = Path(mock_service_account) / "namespace"
        namespace_path.write_text("custom-namespace")

        with patch_incluster_paths(mock_service_account):
            config = AuthConfig(method="incluster")
            strategy = InClusterStrategy(config)

            api_client = strategy.authenticate()
            assert api_client is not None

    def test_is_available_checks_environment(self, mock_service_account):
        """Test is_available properly checks service account files."""
        with patch_incluster_paths(mock_service_account):
            config = AuthConfig(method="incluster")
            strategy = InClusterStrategy(config)

            # Should be available with mock service account
            assert strategy.is_available()

    def test_is_available_without_service_account(self, monkeypatch):
        """Test is_available returns False without service account."""
        monkeypatch.delenv("KUBERNETES_SERVICE_HOST", raising=False)

        config = AuthConfig(method="incluster")
        strategy = InClusterStrategy(config)

        # Should not be available outside cluster
        assert not strategy.is_available()


@pytest.mark.integration
class TestInClusterIntegrationSSL:
    """Integration tests for InCluster SSL configuration."""

    def test_authenticate_with_ssl_verification_enabled(self, mock_service_account):
        """Test authentication with SSL verification enabled (default)."""
        with patch_incluster_paths(mock_service_account):
            config = AuthConfig(method="incluster", verify_ssl=True)
            strategy = InClusterStrategy(config)

            api_client = strategy.authenticate()

            # Should use CA cert from service account
            assert api_client.configuration.verify_ssl is True
            ca_cert_path = Path(mock_service_account) / "ca.crt"
            assert api_client.configuration.ssl_ca_cert == str(ca_cert_path)

    def test_authenticate_with_ssl_verification_disabled(self, mock_service_account):
        """Test authentication with SSL verification disabled."""
        with patch_incluster_paths(mock_service_account):
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", SecurityWarning)
                config = AuthConfig(method="incluster", verify_ssl=False)

            strategy = InClusterStrategy(config)

            api_client = strategy.authenticate()

            # SSL verification should be disabled
            assert api_client.configuration.verify_ssl is False

    def test_get_description(self, mock_service_account):
        """Test strategy description."""
        with patch_incluster_paths(mock_service_account):
            config = AuthConfig(method="incluster")
            strategy = InClusterStrategy(config)

            description = strategy.get_description()

            assert "In-Cluster" in description
            assert "kubernetes.default.svc" in description


@pytest.mark.integration
class TestInClusterIntegrationErrorHandling:
    """Integration tests for InCluster error handling."""

    def test_authenticate_without_token_file(self, mock_service_account):
        """Test authentication fails when token file is missing."""
        token_path = Path(mock_service_account) / "token"
        token_path.unlink()  # Remove token file

        with patch_incluster_paths(mock_service_account):
            config = AuthConfig(method="incluster")
            strategy = InClusterStrategy(config)

            # Strategy should not be available
            assert not strategy.is_available()

    def test_authenticate_without_ca_cert(self, mock_service_account):
        """Test authentication works without CA cert file."""
        ca_path = Path(mock_service_account) / "ca.crt"
        ca_path.unlink()  # Remove CA cert

        with patch_incluster_paths(mock_service_account):
            config = AuthConfig(method="incluster")
            strategy = InClusterStrategy(config)

            # Should still work, just without SSL verification
            api_client = strategy.authenticate()
            assert api_client is not None

    def test_authenticate_with_empty_token(self, mock_service_account):
        """Test authentication handles empty token file."""
        token_path = Path(mock_service_account) / "token"
        token_path.write_text("")  # Empty token

        with patch_incluster_paths(mock_service_account):
            config = AuthConfig(method="incluster")
            strategy = InClusterStrategy(config)

            # Strategy should not be available with empty token
            assert not strategy.is_available()
