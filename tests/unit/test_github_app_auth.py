"""Tests for gh_audit.auth.github_app — GitHub App JWT + installation token auth.

Tests verify:
    - _is_token_expired() logic
    - get_token() returns cached token when valid
    - get_token() calls refresh when expired
    - JWT generation uses RS256 and correct claims
    - API errors raise AuthenticationError
"""

from __future__ import annotations

import time
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from gh_audit.auth.github_app import GitHubAppAuth
from gh_audit.exceptions import AuthenticationError


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

# Minimal RSA private key for testing (generated with cryptography library, not used in prod)
_FAKE_RSA_KEY_PEM = """\
-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAqg/WxI2vjwQPbS9wO9dwPOyS0Cwzx+oAHZMvUmylrFu+h1AK
7vEGolUIrY79UiYJNdqMFKGeDfpLGI60zbSjhQANO1OQ8+1KjJYoxbozgMM6t2KC
zYOlNPQ684ep3v086RYZnwfI8EQv1Fo8SNWPC/sj6mVihsSKvYBLwaxKiLMujieL
rlLNQnes4WhcoxQzJKGgDCdFONER6hZ6s2EgnKC9L2mVm9/zxi2rWI0SMqVaAOvi
pFk1za/9fCeTfqU+1qGKoMWbAIVzqIM8pvxbhCDvEsKJVlyZ/quFQa7cJLYjp9fR
dhezDtfDwymapTSoBfrAIUap3FzaLqzS1lDImwIDAQABAoIBAChELtCEUcy1o+dw
44yvwqoSQ+LZjHsp21QlXP+RrRql8HN+jtArrqvyIWdi43U3f1fKgv+BkvhxSqWq
aIIKYutjaz6gV0KCbXPjPA0xPO+gij8QqrL5mDz1FR5DgYPEh08TRgbDI59MLd0E
bqC6PDAUi1j9H3qUf9tFzOozHsTF8XLrkQj3S+Neg+SoKsavRWkEMsWknLLGN4Fv
4dnXNlxowsRndkTtdankhfJin9eWaAz1kI1XgdtrJYOUFhGG9TZgAhjlNtBahZRC
T06ZYxQrEJuTXPRtklZMEgtjpvNhlUIMof/v3VC9fCPV9PYbNnlEQTotaRHQZWZb
HVGCVc0CgYEA2youVWR5ED1Oz2xNj3SrL4U3t7Rqav4mbW5B8ag3k2E9oYXySgdN
zu+L0tNH61WJwThovRMxWogZln92Iw61ActWzSPtZDXRP/dGGcueR6aqEHAgMwZe
hsgJnqZa+HQH+UclYbKaWlUJWniKiMSt8hNFLoupuNzTjvbDzRdxokcCgYEAxqTy
2l9CQrzpEJ0E99ilrIT3ZuOyOPF11m+ERS1tNGH27DqbdHRp2OUD07zhzNM4wP1o
3bSXYnY690uXPR6yL/j7/WRwjGvFkRBGRlHdqHlDrn5GLGEXehG6ohfhbrB3Hov8
/wj4mn/nQi3KVn9UC6tg51K0hT/Rw4ntZk/KnQ0CgYBf6cjXNB5LPhlka0hSNMPK
CyoEKl+8LTeSAoO3h1+zDwZSzvTm8uVZX7o4bKB33DpqJg6oWGLr9M4F8Ag6dXA/
tcZqBoQYq/jEXqn+Ff9R6h1ZDkj5K5tortiO5sy/GMB4lmtEo04rpDVws3olOrXJ
UCehpBuFvJaVZWbxNYZUdwKBgDX0jcZEw5GvEDsj+zp6zR1cDHsU887FvzUcmzfT
C+uDhHdLv/fUuv9fzTdRAaAJ60t4SWiW6dujs4aCMLU4RjwDjCaahnuNtl8dpYjq
KaPeNEUMJXFeeer9L81hYSkYo3JXocOAI06L2Tu/hksSULjOtwZ+D2x2Fjrflu0I
VUdtAoGBALohvcEtiFRFqlNZI2rwclI0iWhF8Y113jx0WX+yGuBWuhdOa1XUvX+j
RUueORAp3acxXwobcAl4Eh9zjG21DgbBqGFrf6d9yOcXH/ZCRWSoni+BXwHZ2InK
oBmSzQEZot35qyIKM6ORLQVMyhZgqXB6dff1rORmrzTZjAJXihBH
-----END RSA PRIVATE KEY-----
"""


@pytest.fixture
def key_file(tmp_path):
    """Write a fake PEM key and return the path."""
    p = tmp_path / "app.pem"
    p.write_text(_FAKE_RSA_KEY_PEM)
    return p


@pytest.fixture
def app_auth(key_file):
    """Return a GitHubAppAuth with fake credentials and no cached token."""
    return GitHubAppAuth(
        app_id=42,
        private_key_path=key_file,
        installation_id=99,
        api_url="https://api.github.com",
    )


# ---------------------------------------------------------------------------
# _is_token_expired
# ---------------------------------------------------------------------------


class TestIsTokenExpired:
    """_is_token_expired() returns True when no token or within 5-min buffer."""

    def test_no_token_is_expired(self, app_auth):
        assert app_auth._is_token_expired() is True

    def test_token_with_no_expiry_is_expired(self, app_auth):
        app_auth._token = "ghs_test"
        app_auth._token_expires_at = None
        assert app_auth._is_token_expired() is True

    def test_expired_token_is_expired(self, app_auth):
        app_auth._token = "ghs_test"
        app_auth._token_expires_at = time.time() - 10  # 10 seconds ago
        assert app_auth._is_token_expired() is True

    def test_token_expiring_within_buffer_is_expired(self, app_auth):
        """Tokens expiring within 5 minutes should be treated as expired."""
        app_auth._token = "ghs_test"
        app_auth._token_expires_at = time.time() + 60  # 1 minute — within buffer
        assert app_auth._is_token_expired() is True

    def test_valid_token_not_expired(self, app_auth):
        app_auth._token = "ghs_test"
        app_auth._token_expires_at = time.time() + 3600  # 1 hour from now
        assert app_auth._is_token_expired() is False


# ---------------------------------------------------------------------------
# get_token — caching
# ---------------------------------------------------------------------------


class TestGetTokenCaching:
    """get_token() returns cached token without hitting API when still valid."""

    @pytest.mark.asyncio
    async def test_cached_token_returned_without_refresh(self, app_auth):
        app_auth._token = "ghs_cached"
        app_auth._token_expires_at = time.time() + 3600

        with patch.object(app_auth, "_refresh_token", new_callable=AsyncMock) as mock_refresh:
            result = await app_auth.get_token()

        assert result == "ghs_cached"
        mock_refresh.assert_not_called()

    @pytest.mark.asyncio
    async def test_expired_token_triggers_refresh(self, app_auth):
        app_auth._token = "ghs_old"
        app_auth._token_expires_at = time.time() - 10  # expired

        async def _fake_refresh():
            app_auth._token = "ghs_new"
            app_auth._token_expires_at = time.time() + 3600

        with patch.object(app_auth, "_refresh_token", side_effect=_fake_refresh) as mock_refresh:
            result = await app_auth.get_token()

        assert result == "ghs_new"
        mock_refresh.assert_called_once()

    @pytest.mark.asyncio
    async def test_no_token_triggers_refresh(self, app_auth):
        async def _fake_refresh():
            app_auth._token = "ghs_test"
            app_auth._token_expires_at = time.time() + 3600

        with patch.object(app_auth, "_refresh_token", side_effect=_fake_refresh):
            result = await app_auth.get_token()

        assert result == "ghs_test"


# ---------------------------------------------------------------------------
# JWT generation
# ---------------------------------------------------------------------------


class TestJWTGeneration:
    """_build_jwt() creates a valid RS256 JWT with correct claims."""

    def test_jwt_is_string(self, app_auth):
        jwt_token = app_auth._build_jwt()
        assert isinstance(jwt_token, str)

    def test_jwt_has_three_parts(self, app_auth):
        jwt_token = app_auth._build_jwt()
        parts = jwt_token.split(".")
        assert len(parts) == 3

    def test_jwt_claims_contain_app_id(self, app_auth):
        import jwt as pyjwt
        from cryptography.hazmat.primitives.serialization import load_pem_private_key

        private_key = load_pem_private_key(_FAKE_RSA_KEY_PEM.encode(), password=None)
        public_key = private_key.public_key()

        jwt_token = app_auth._build_jwt()
        claims = pyjwt.decode(jwt_token, public_key, algorithms=["RS256"])
        assert claims["iss"] == "42"

    def test_jwt_claims_have_iat_and_exp(self, app_auth):
        import jwt as pyjwt
        from cryptography.hazmat.primitives.serialization import load_pem_private_key

        private_key = load_pem_private_key(_FAKE_RSA_KEY_PEM.encode(), password=None)
        public_key = private_key.public_key()

        jwt_token = app_auth._build_jwt()
        int(time.time())
        claims = pyjwt.decode(jwt_token, public_key, algorithms=["RS256"])
        assert "iat" in claims
        assert "exp" in claims
        # exp is 600s after "now", iat is 60s before "now" to handle clock drift
        # So exp - iat = 660s
        assert claims["exp"] - claims["iat"] == pytest.approx(660, abs=5)


# ---------------------------------------------------------------------------
# _refresh_token — API interaction
# ---------------------------------------------------------------------------


class TestRefreshToken:
    """_refresh_token() exchanges a JWT for an installation token."""

    @pytest.mark.asyncio
    async def test_successful_token_refresh(self, app_auth):
        expires_at_str = "2099-01-01T00:10:00Z"
        mock_response = MagicMock()
        mock_response.status_code = 201
        mock_response.json.return_value = {
            "token": "ghs_test",
            "expires_at": expires_at_str,
        }
        mock_response.raise_for_status = MagicMock()

        mock_client = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_client.post = AsyncMock(return_value=mock_response)

        with patch("gh_audit.auth.github_app.httpx.AsyncClient", return_value=mock_client):
            await app_auth._refresh_token()

        assert app_auth._token == "ghs_test"
        assert app_auth._token_expires_at is not None

    @pytest.mark.asyncio
    async def test_api_401_raises_authentication_error(self, app_auth):
        import httpx

        mock_response = MagicMock()
        mock_response.status_code = 401
        mock_response.text = "Unauthorized"
        mock_response.raise_for_status.side_effect = httpx.HTTPStatusError(
            "401 Unauthorized",
            request=MagicMock(),
            response=mock_response,
        )

        mock_client = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_client.post = AsyncMock(return_value=mock_response)

        with patch("gh_audit.auth.github_app.httpx.AsyncClient", return_value=mock_client):
            with pytest.raises(AuthenticationError) as exc_info:
                await app_auth._refresh_token()

        assert exc_info.value.exit_code == 3

    @pytest.mark.asyncio
    async def test_api_404_raises_authentication_error(self, app_auth):
        """404 on installation endpoint means installation ID is wrong."""
        import httpx

        mock_response = MagicMock()
        mock_response.status_code = 404
        mock_response.text = "Not Found"
        mock_response.raise_for_status.side_effect = httpx.HTTPStatusError(
            "404 Not Found",
            request=MagicMock(),
            response=mock_response,
        )

        mock_client = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_client.post = AsyncMock(return_value=mock_response)

        with patch("gh_audit.auth.github_app.httpx.AsyncClient", return_value=mock_client):
            with pytest.raises(AuthenticationError):
                await app_auth._refresh_token()

    @pytest.mark.asyncio
    async def test_network_error_raises_authentication_error(self, app_auth):
        import httpx

        mock_client = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_client.post = AsyncMock(side_effect=httpx.ConnectError("Connection refused"))

        with patch("gh_audit.auth.github_app.httpx.AsyncClient", return_value=mock_client):
            with pytest.raises(AuthenticationError):
                await app_auth._refresh_token()

    @pytest.mark.asyncio
    async def test_correct_endpoint_called(self, app_auth):
        """POST must go to /app/installations/{installation_id}/access_tokens."""
        expires_at_str = "2099-01-01T00:10:00Z"
        mock_response = MagicMock()
        mock_response.status_code = 201
        mock_response.json.return_value = {
            "token": "ghs_endpoint_test",
            "expires_at": expires_at_str,
        }
        mock_response.raise_for_status = MagicMock()

        mock_client = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_client.post = AsyncMock(return_value=mock_response)

        with patch("gh_audit.auth.github_app.httpx.AsyncClient", return_value=mock_client):
            await app_auth._refresh_token()

        call_args = mock_client.post.call_args
        called_url = call_args[0][0] if call_args[0] else call_args.kwargs.get("url", "")
        assert "installations/99/access_tokens" in called_url
