from typing import Dict, Any
from app.core.logging import logger
from app.services.http_client import SafeHttpClient


def execute_idor(
    client: SafeHttpClient,
    base_url: str,
    endpoint: str,
    parameter: str | None = None,
) -> Dict[str, Any]:
    """
    Execute a basic IDOR test by manipulating object identifiers.
    """
    logger.info(f"Executing IDOR on {endpoint}")

    if not parameter:
        return {
            "success": False,
            "reason": "No parameter specified for IDOR"
        }

    test_params = {parameter: "1"}  # deterministic placeholder

    response = client.request(
        method="GET",
        url=f"{base_url}{endpoint}",
        params=test_params,
    )

    return {
        "attack": "IDOR",
        "endpoint": endpoint,
        "success": response.status_code == 200,
        "status_code": response.status_code,
        "response_length": len(response.text),
    }
