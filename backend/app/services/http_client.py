import httpx
from typing import Dict, Any, Optional
from app.core.config import settings
from app.core.logging import logger


class SafeHttpClient:
    """
    Controlled HTTP client for attack execution.
    Enforces timeouts and limits.
    """

    def __init__(self):
        self.client = httpx.Client(
            timeout=settings.ATTACK_TIMEOUT_SECONDS,
            follow_redirects=False,
        )

    def request(
        self,
        method: str,
        url: str,
        headers: Optional[Dict[str, str]] = None,
        params: Optional[Dict[str, Any]] = None,
        json: Optional[Dict[str, Any]] = None,
    ) -> httpx.Response:
        """
        Execute a single HTTP request safely.
        """
        logger.debug(f"HTTP {method} {url}")

        response = self.client.request(
            method=method.upper(),
            url=url,
            headers=headers,
            params=params,
            json=json,
        )

        return response

    def close(self):
        self.client.close()
