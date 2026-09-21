from typing import Dict, Any
from app.core.logging import logger
from app.services.http_client import SafeHttpClient


def execute_auth_bypass(
    client: SafeHttpClient,
    base_url: str,
    endpoint: str,
) -> Dict[str, Any]:
    """
    Test access to a protected endpoint without authentication.
    """
    logger.info(f"Executing AUTH_BYPASS on {endpoint}")

    response = client.request(
        method="GET",
        url=f"{base_url}{endpoint}",
        headers={},  # explicitly no auth
    )

    return {
        "attack": "AUTH_BYPASS",
        "endpoint": endpoint,
        "success": response.status_code < 400,
        "status_code": response.status_code,
    }
