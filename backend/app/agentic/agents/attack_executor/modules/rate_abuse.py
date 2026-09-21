from typing import Dict, Any
from app.core.logging import logger
from app.services.http_client import SafeHttpClient
from app.core.config import settings


def execute_rate_abuse(
    client: SafeHttpClient,
    base_url: str,
    endpoint: str,
) -> Dict[str, Any]:
    """
    Test basic rate-limiting behavior.
    """
    logger.info(f"Executing RATE_ABUSE on {endpoint}")

    success_count = 0

    for _ in range(settings.RATE_TEST_MAX_REQUESTS):
        response = client.request(
            method="POST",
            url=f"{base_url}{endpoint}",
        )
        if response.status_code == 200:
            success_count += 1

    return {
        "attack": "RATE_ABUSE",
        "endpoint": endpoint,
        "successful_requests": success_count,
        "threshold": settings.RATE_TEST_MAX_REQUESTS,
        "success": success_count == settings.RATE_TEST_MAX_REQUESTS,
    }
