"""
Tests for authentication factory and auto-detection logic.

Tests cover:
- Auto-detection precedence
- Strategy selection
- Error handling when no auth available
- get_k8s_client() function
"""

from unittest.mock import patch

import pytest

from kube_authkit import AuthConfig, get_k8s_client, get_k8s_config
from kube_authkit.exceptions import AuthenticationError, ConfigurationError
from kube_authkit.factory import AuthFactory
from kube_authkit.strategies.openshift import OpenShiftOAuthStrategy


class TestGetK8sClient:
    """Test the main get_k8s_client() entry point."""

    @patch("kube_authkit.strategies.kubeconfig.KubeConfigStrategy.is_available")
    @patch("kube_authkit.strategies.incluster.InClusterStrategy.is_available")
    def test_with_default_config(self, mock_incluster_avail, mock_kube_avail, mock_env_vars):
        """Test get_k8s_client with no arguments raises error when no auth available."""
        # Mock both strategies as unavailable
        mock_incluster_avail.return_value = False
        mock_kube_avail.return_value = False

        with pytest.raises(AuthenticationError) as exc_info:
            get_k8s_client()

        assert "No authentication method available" in str(exc_info.value)

    @patch("kube_authkit.strategies.kubeconfig.KubeConfigStrategy.is_available")
    def test_with_explicit_config(self, mock_is_available, mock_env_vars):
        """Test get_k8s_client with explicit configuration."""
        # Mock strategy as unavailable to trigger ConfigurationError
        mock_is_available.return_value = False

        config = AuthConfig(method="kubeconfig")

        # This will fail because kubeconfig is not available
        with pytest.raises(ConfigurationError):
            get_k8s_client(config)


class TestAuthFactoryStrategySelection:
    """Test strategy selection logic."""

    @patch("kube_authkit.strategies.kubeconfig.KubeConfigStrategy.is_available")
    def test_explicit_kubeconfig_method(self, mock_is_available, mock_env_vars):
        """Test selecting KubeConfig strategy explicitly."""
        # Mock strategy as unavailable to trigger ConfigurationError
        mock_is_available.return_value = False

        config = AuthConfig(method="kubeconfig")
        factory = AuthFactory(config)

        with pytest.raises(ConfigurationError):
            # Should try to use KubeConfig but fail because it's not available
            factory.get_strategy()

    def test_explicit_incluster_method(self, mock_env_vars):
        """Test selecting InCluster strategy explicitly."""
        config = AuthConfig(method="incluster")
        factory = AuthFactory(config)

        with pytest.raises(ConfigurationError):
            # Should try to use InCluster but fail because it's not available
            factory.get_strategy()

    def test_unknown_method_raises_error(self, mock_env_vars):
        """Test that unknown method raises ConfigurationError."""
        # The validation happens in AuthConfig.__post_init__, not in factory.get_strategy()
        with pytest.raises(ConfigurationError) as exc_info:
            AuthConfig(method="unknown")

        assert "Invalid authentication method" in str(exc_info.value)


class TestAuthFactoryAutoDetection:
    """Test auto-detection logic."""

    @patch("kube_authkit.strategies.kubeconfig.KubeConfigStrategy.is_available")
    @patch("kube_authkit.strategies.incluster.InClusterStrategy.is_available")
    def test_auto_detect_with_oidc_env(self, mock_incluster_avail, mock_kube_avail, mock_oidc_env):
        """Test auto-detection prefers OIDC when env vars present."""
        # Mock both strategies as unavailable
        mock_incluster_avail.return_value = False
        mock_kube_avail.return_value = False

        config = AuthConfig()  # method="auto" by default
        factory = AuthFactory(config)

        # OIDC env vars are set, but OIDC strategy not yet implemented
        # Should fall back to other methods
        with pytest.raises(AuthenticationError) as exc_info:
            factory.get_strategy()

        # Should indicate that it detected OIDC env but couldn't use it
        error_msg = str(exc_info.value)
        assert "No authentication method available" in error_msg

    @patch("kube_authkit.strategies.kubeconfig.KubeConfigStrategy.is_available")
    @patch("kube_authkit.strategies.incluster.InClusterStrategy.is_available")
    def test_auto_detect_no_auth_available(
        self, mock_incluster_avail, mock_kube_avail, mock_env_vars
    ):
        """Test auto-detection when no auth method is available."""
        # Mock both strategies as unavailable
        mock_incluster_avail.return_value = False
        mock_kube_avail.return_value = False

        config = AuthConfig()
        factory = AuthFactory(config)

        with pytest.raises(AuthenticationError) as exc_info:
            factory.get_strategy()

        error_msg = str(exc_info.value)
        assert "No authentication method available" in error_msg
        assert "In-cluster service account - not available" in error_msg
        assert "KubeConfig file" in error_msg

    @patch("kube_authkit.strategies.kubeconfig.KubeConfigStrategy.is_available")
    def test_auto_detect_kubeconfig(self, mock_is_available, mock_env_vars):
        """Test auto-detection selects KubeConfig when available."""
        mock_is_available.return_value = True

        config = AuthConfig()
        factory = AuthFactory(config)
        strategy = factory.get_strategy()

        # Should return a KubeConfigStrategy
        from kube_authkit.strategies.kubeconfig import KubeConfigStrategy

        assert isinstance(strategy, KubeConfigStrategy)

    @patch("kube_authkit.strategies.incluster.InClusterStrategy.is_available")
    def test_auto_detect_incluster(self, mock_is_available, mock_env_vars):
        """Test auto-detection selects InCluster when available."""
        mock_is_available.return_value = True

        config = AuthConfig()
        factory = AuthFactory(config)
        strategy = factory.get_strategy()

        # Should return an InClusterStrategy
        from kube_authkit.strategies.incluster import InClusterStrategy

        assert isinstance(strategy, InClusterStrategy)

    @patch("kube_authkit.strategies.incluster.InClusterStrategy.is_available")
    @patch("kube_authkit.strategies.kubeconfig.KubeConfigStrategy.is_available")
    def test_auto_detect_precedence(self, mock_kube_avail, mock_incluster_avail, mock_env_vars):
        """Test that in-cluster is preferred over kubeconfig in auto-detection."""
        # Both are available
        mock_incluster_avail.return_value = True
        mock_kube_avail.return_value = True

        config = AuthConfig()
        factory = AuthFactory(config)
        strategy = factory.get_strategy()

        # Should prefer InCluster
        from kube_authkit.strategies.incluster import InClusterStrategy

        assert isinstance(strategy, InClusterStrategy)


class TestAuthFactoryHasOIDCEnvVars:
    """Test OIDC environment variable detection."""

    def test_has_oidc_env_vars_true(self, mock_oidc_env):
        """Test detection when OIDC env vars are present."""
        config = AuthConfig()
        factory = AuthFactory(config)

        assert factory._has_oidc_env_vars() is True

    def test_has_oidc_env_vars_false(self, mock_env_vars):
        """Test detection when OIDC env vars are absent."""
        config = AuthConfig()
        factory = AuthFactory(config)

        assert factory._has_oidc_env_vars() is False

    def test_has_oidc_env_vars_partial(self, mock_env_vars, monkeypatch):
        """Test detection with only partial OIDC env vars."""
        monkeypatch.setenv("AUTHKIT_OIDC_ISSUER", "https://test.example.com")
        # Missing AUTHKIT_CLIENT_ID

        config = AuthConfig()
        factory = AuthFactory(config)

        assert factory._has_oidc_env_vars() is False


class TestAuthFactoryErrorHandling:
    """Test error handling in AuthFactory."""

    def test_get_k8s_client_success(self, mock_kubeconfig):
        """Test get_k8s_client successfully returns ApiClient."""
        config = AuthConfig(method="kubeconfig", kubeconfig_path=str(mock_kubeconfig))

        client = get_k8s_client(config)

        assert client is not None
        assert client.configuration.host == "https://127.0.0.1:6443"

    @patch("kube_authkit.factory.AuthFactory.get_strategy")
    def test_get_k8s_client_strategy_error(self, mock_get_strategy):
        """Test get_k8s_client handles strategy errors."""
        mock_get_strategy.side_effect = ConfigurationError("Strategy error", "Details")

        config = AuthConfig(method="auto")

        with pytest.raises(ConfigurationError):
            get_k8s_client(config)

    @patch("kube_authkit.strategies.kubeconfig.KubeConfigStrategy.is_available")
    def test_get_strategy_explicit_method_not_available(self, mock_is_available, mock_kubeconfig):
        """Test get_strategy raises error when explicit method not available."""
        mock_is_available.return_value = False

        config = AuthConfig(method="kubeconfig", kubeconfig_path=str(mock_kubeconfig))
        factory = AuthFactory(config)

        with pytest.raises(ConfigurationError) as exc_info:
            factory.get_strategy()

        assert "not available" in str(exc_info.value)

    def test_auto_detect_with_openshift_token_env(self, monkeypatch):
        """Test auto-detection with OPENSHIFT_TOKEN environment variable."""
        monkeypatch.setenv("OPENSHIFT_TOKEN", "sha256~test-token")
        monkeypatch.delenv("KUBECONFIG", raising=False)

        config = AuthConfig(method="auto", k8s_api_host="https://api.cluster.example.com:6443")
        factory = AuthFactory(config)

        strategy = factory._auto_detect_strategy()

        assert isinstance(strategy, OpenShiftOAuthStrategy)

    @patch("kube_authkit.strategies.openshift.OpenShiftOAuthStrategy.is_available")
    @patch("kube_authkit.strategies.incluster.InClusterStrategy.is_available")
    @patch("kube_authkit.strategies.kubeconfig.KubeConfigStrategy.is_available")
    def test_auto_detect_openshift_not_available_fallback(
        self, mock_kube_avail, mock_incluster_avail, mock_openshift_avail, monkeypatch
    ):
        """Test auto-detection falls back when OpenShift not available."""
        monkeypatch.setenv("OPENSHIFT_TOKEN", "sha256~test-token")
        monkeypatch.delenv("KUBECONFIG", raising=False)
        mock_openshift_avail.return_value = False
        mock_incluster_avail.return_value = False
        mock_kube_avail.return_value = False

        config = AuthConfig(method="auto", k8s_api_host="https://api.cluster.example.com:6443")
        factory = AuthFactory(config)

        # Should raise AuthenticationError when all strategies are unavailable
        with pytest.raises(AuthenticationError) as exc_info:
            factory._auto_detect_strategy()

        assert "No authentication method available" in str(exc_info.value)


class TestGetK8sConfig:
    """Test the get_k8s_config() function."""

    def test_get_k8s_config_returns_configuration(self, mock_kubeconfig):
        """Test get_k8s_config returns Configuration object."""
        from kubernetes.client import Configuration

        config = AuthConfig(method="kubeconfig", kubeconfig_path=str(mock_kubeconfig))
        k8s_config = get_k8s_config(config)

        assert isinstance(k8s_config, Configuration)
        assert k8s_config is not None

    def test_get_k8s_config_allows_customization(self, mock_kubeconfig):
        """Test Configuration can be customized after get_k8s_config."""
        from kubernetes.client import ApiClient

        config = AuthConfig(method="kubeconfig", kubeconfig_path=str(mock_kubeconfig))

        # Get configuration
        k8s_config = get_k8s_config(config)

        # Customize it - use actual Configuration attributes
        original_debug = k8s_config.debug
        k8s_config.debug = True

        # Create client with customized config
        api_client = ApiClient(k8s_config)

        assert k8s_config.debug is True
        assert k8s_config.debug != original_debug
        assert api_client is not None

    def test_get_k8s_config_with_default_config(self, mock_kubeconfig, monkeypatch):
        """Test get_k8s_config with no arguments uses auto-detection."""
        from kubernetes.client import Configuration

        # Set KUBECONFIG env var for auto-detection
        monkeypatch.setenv("KUBECONFIG", str(mock_kubeconfig))

        k8s_config = get_k8s_config()

        assert isinstance(k8s_config, Configuration)

    @patch("kube_authkit.strategies.kubeconfig.KubeConfigStrategy.is_available")
    @patch("kube_authkit.strategies.incluster.InClusterStrategy.is_available")
    def test_get_k8s_config_raises_on_no_auth(
        self, mock_incluster_avail, mock_kube_avail, mock_env_vars
    ):
        """Test get_k8s_config raises error when no auth available."""
        mock_incluster_avail.return_value = False
        mock_kube_avail.return_value = False

        with pytest.raises(AuthenticationError) as exc_info:
            get_k8s_config()

        assert "No authentication method available" in str(exc_info.value)

    def test_get_k8s_client_uses_get_k8s_config(self, mock_kubeconfig):
        """Test get_k8s_client internally uses get_k8s_config."""
        from kubernetes.client import ApiClient

        config = AuthConfig(method="kubeconfig", kubeconfig_path=str(mock_kubeconfig))

        # Get both
        k8s_config = get_k8s_config(config)
        api_client = get_k8s_client(config)

        # They should be related
        assert isinstance(api_client, ApiClient)
        assert api_client.configuration is not None
        # Configuration should have same host
        assert api_client.configuration.host == k8s_config.host


class TestAuthKitEnvVars:
    """Test AUTHKIT_* environment variables."""

    def test_authkit_oidc_issuer_env_var(self, mock_env_vars, monkeypatch):
        """Test AUTHKIT_OIDC_ISSUER environment variable."""
        monkeypatch.setenv("AUTHKIT_OIDC_ISSUER", "https://test.example.com/auth/realms/test")
        monkeypatch.setenv("AUTHKIT_CLIENT_ID", "test-client")

        config = AuthConfig()

        assert config.oidc_issuer == "https://test.example.com/auth/realms/test"
        assert config.client_id == "test-client"

    def test_authkit_client_id_env_var(self, mock_env_vars, monkeypatch):
        """Test AUTHKIT_CLIENT_ID environment variable."""
        monkeypatch.setenv("AUTHKIT_OIDC_ISSUER", "https://test.example.com")
        monkeypatch.setenv("AUTHKIT_CLIENT_ID", "my-client-id")

        config = AuthConfig()

        assert config.client_id == "my-client-id"

    def test_authkit_client_secret_env_var(self, mock_env_vars, monkeypatch):
        """Test AUTHKIT_CLIENT_SECRET environment variable."""
        monkeypatch.setenv("AUTHKIT_CLIENT_SECRET", "secret-value")

        config = AuthConfig()

        assert config.client_secret == "secret-value"

    def test_authkit_token_env_var(self, mock_env_vars, monkeypatch):
        """Test AUTHKIT_TOKEN environment variable."""
        monkeypatch.setenv("AUTHKIT_TOKEN", "sha256~test-token")

        config = AuthConfig()

        assert config.token == "sha256~test-token"

    def test_authkit_api_host_env_var(self, mock_env_vars, monkeypatch):
        """Test AUTHKIT_API_HOST environment variable."""
        monkeypatch.setenv("AUTHKIT_API_HOST", "https://api.cluster.example.com:6443")

        config = AuthConfig()

        assert config.k8s_api_host == "https://api.cluster.example.com:6443"

    def test_authkit_env_vars_override_defaults(self, mock_env_vars, monkeypatch):
        """Test AUTHKIT_* env vars override explicit config when not provided."""
        monkeypatch.setenv("AUTHKIT_OIDC_ISSUER", "https://from-env.example.com")
        monkeypatch.setenv("AUTHKIT_CLIENT_ID", "from-env-client")

        # Explicit config should take precedence
        config = AuthConfig(oidc_issuer="https://explicit.example.com", client_id="explicit-client")

        assert config.oidc_issuer == "https://explicit.example.com"
        assert config.client_id == "explicit-client"

    def test_factory_detects_authkit_oidc_env_vars(self, mock_env_vars, monkeypatch):
        """Test AuthFactory detects AUTHKIT_* OIDC env vars."""
        monkeypatch.setenv("AUTHKIT_OIDC_ISSUER", "https://test.example.com")
        monkeypatch.setenv("AUTHKIT_CLIENT_ID", "test-client")

        config = AuthConfig()
        factory = AuthFactory(config)

        # Should detect OIDC env vars
        assert factory._has_oidc_env_vars() is True


class TestLegacyEnvVarFallback:
    """Test backwards compatibility with legacy environment variables."""

    def test_legacy_openshift_token_fallback(self, mock_env_vars, monkeypatch):
        """Test OPENSHIFT_TOKEN falls back when AUTHKIT_TOKEN not set."""
        monkeypatch.setenv("OPENSHIFT_TOKEN", "sha256~legacy-token")

        config = AuthConfig()

        # Should use legacy env var
        assert config.token == "sha256~legacy-token"

    def test_authkit_token_takes_precedence_over_legacy(self, mock_env_vars, monkeypatch):
        """Test AUTHKIT_TOKEN takes precedence over OPENSHIFT_TOKEN."""
        monkeypatch.setenv("AUTHKIT_TOKEN", "sha256~new-token")
        monkeypatch.setenv("OPENSHIFT_TOKEN", "sha256~legacy-token")

        config = AuthConfig()

        # Should use new env var, not legacy
        assert config.token == "sha256~new-token"

    def test_factory_detects_legacy_openshift_token(self, mock_env_vars, monkeypatch):
        """Test AuthFactory detects legacy OPENSHIFT_TOKEN."""
        monkeypatch.setenv("OPENSHIFT_TOKEN", "sha256~test-token")

        config = AuthConfig(method="auto", k8s_api_host="https://api.cluster.example.com:6443")
        factory = AuthFactory(config)

        # Factory should detect token in auto-detection
        strategy = factory._auto_detect_strategy()

        from kube_authkit.strategies.openshift import OpenShiftOAuthStrategy

        assert isinstance(strategy, OpenShiftOAuthStrategy)

    def test_explicit_token_overrides_env_vars(self, mock_env_vars, monkeypatch):
        """Test explicit token in config overrides all env vars."""
        monkeypatch.setenv("AUTHKIT_TOKEN", "sha256~env-token")
        monkeypatch.setenv("OPENSHIFT_TOKEN", "sha256~legacy-token")

        config = AuthConfig(token="sha256~explicit-token")

        # Explicit config should win
        assert config.token == "sha256~explicit-token"
