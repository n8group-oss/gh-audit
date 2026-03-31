"""GitHub App authentication for gh-audit.

Generates a JWT using the app's private key (RS256), exchanges it for an
installation access token, and refreshes automatically before expiry.

No third-party token helpers — only PyJWT + cryptography (both already in
the dependency list).
"""

from __future__ import annotations

import pathlib
import time
from datetime import datetime
from typing import Optional

import httpx
import jwt as pyjwt
from cryptography.hazmat.primitives.serialization import load_pem_private_key

from gh_audit.exceptions import AuthenticationError

# Token refresh buffer: refresh 5 minutes before the token actually expires.
_EXPIRY_BUFFER_SECONDS = 5 * 60

# GitHub App JWTs are valid for up to 10 minutes.
_JWT_LIFETIME_SECONDS = 600


class GitHubAppAuth:
    """Manages GitHub App installation token lifecycle.

    Parameters
    ----------
    app_id:
        GitHub App ID (integer).
    private_key_path:
        Path to the RSA private key PEM file registered with the GitHub App.
    installation_id:
        Installation ID for the target organization.
    api_url:
        Base REST API URL (default: https://api.github.com).
        Override for GitHub Enterprise Server.
    """

    def __init__(
        self,
        app_id: int,
        private_key_path: pathlib.Path,
        installation_id: int,
        api_url: str = "https://api.github.com",
    ) -> None:
        self._app_id = app_id
        self._private_key_path = pathlib.Path(private_key_path)
        self._installation_id = installation_id
        self._api_url = api_url.rstrip("/")

        self._token: Optional[str] = None
        self._token_expires_at: Optional[float] = None  # Unix timestamp

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def get_token(self) -> str:
        """Return a valid installation access token, refreshing if needed.

        Returns
        -------
        str
            A ``ghs_`` prefixed GitHub installation access token.

        Raises
        ------
        AuthenticationError
            If the token exchange fails for any reason.
        """
        if self._is_token_expired():
            await self._refresh_token()
        assert self._token is not None  # _refresh_token guarantees this
        return self._token

    # ------------------------------------------------------------------
    # Token expiry logic
    # ------------------------------------------------------------------

    def _is_token_expired(self) -> bool:
        """Return True if the current token is absent, expired, or near-expiry.

        "Near-expiry" means within ``_EXPIRY_BUFFER_SECONDS`` of expiring,
        ensuring we don't use a token that will expire mid-request.
        """
        if self._token is None or self._token_expires_at is None:
            return True
        return time.time() >= (self._token_expires_at - _EXPIRY_BUFFER_SECONDS)

    # ------------------------------------------------------------------
    # JWT creation
    # ------------------------------------------------------------------

    def _build_jwt(self) -> str:
        """Build a signed RS256 JWT for authenticating as the GitHub App.

        Returns
        -------
        str
            Compact encoded JWT string.
        """
        pem_bytes = self._private_key_path.read_bytes()
        private_key = load_pem_private_key(pem_bytes, password=None)

        now = int(time.time())
        payload = {
            "iat": now - 60,  # issued 60s in the past to account for clock drift
            "exp": now + _JWT_LIFETIME_SECONDS,
            "iss": str(self._app_id),
        }
        return pyjwt.encode(payload, private_key, algorithm="RS256")

    # ------------------------------------------------------------------
    # Token refresh
    # ------------------------------------------------------------------

    async def _refresh_token(self) -> None:
        """Exchange a fresh JWT for a GitHub App installation access token.

        The token and its expiry timestamp are stored on ``self``.

        Raises
        ------
        AuthenticationError
            On any HTTP error or network failure.
        """
        jwt_token = self._build_jwt()
        url = f"{self._api_url}/app/installations/{self._installation_id}/access_tokens"
        headers = {
            "Authorization": f"Bearer {jwt_token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }

        try:
            async with httpx.AsyncClient() as client:
                response = await client.post(url, headers=headers)
                response.raise_for_status()
        except httpx.HTTPStatusError as exc:
            status = exc.response.status_code
            body = exc.response.text
            raise AuthenticationError(
                f"GitHub App token exchange failed (HTTP {status}): {body}"
            ) from exc
        except httpx.HTTPError as exc:
            raise AuthenticationError(
                f"GitHub App token exchange failed (network error): {exc}"
            ) from exc

        data = response.json()
        self._token = data["token"]

        # Parse ISO-8601 expiry from the API response
        expires_at_str: str = data["expires_at"]
        dt = datetime.fromisoformat(expires_at_str.replace("Z", "+00:00"))
        self._token_expires_at = dt.timestamp()
