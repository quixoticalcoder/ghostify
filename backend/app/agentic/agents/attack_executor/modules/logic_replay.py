from typing import Dict, Any
from app.core.logging import logger
from app.services.http_client import SafeHttpClient


def execute_logic_replay(
    client: SafeHttpClient,
    base_url: str,
    endpoint: str,
) -> Dict[str, Any]:
    """
    Replay the same sensitive action multiple times
    to detect missing idempotency or replay protection.
    """
    logger.info(f"Executing LOGIC_REPLAY on {endpoint}")

    responses = []

    for _ in range(2):
        response = client.request(
            method="POST",
            url=f"{base_url}{endpoint}",
        )
        responses.append(response.status_code)

    success = responses[0] == responses[1] == 200

    return {
        "attack": "LOGIC_REPLAY",
        "endpoint": endpoint,
        "success": success,
        "responses": responses,
    }
