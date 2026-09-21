from urllib.parse import urlparse
from app.core.config import settings


class SecurityError(Exception):
    pass


def validate_target_domain(url: str) -> None:
    """
    Prevent scanning arbitrary or external targets.
    """
    parsed = urlparse(url)
    domain = parsed.hostname

    if not domain:
        raise SecurityError("Invalid target URL")

    if domain not in settings.ALLOWED_TARGET_DOMAINS:
        raise SecurityError(
            f"Target domain '{domain}' is not allowed"
        )


def validate_internal_api_key(provided_key: str) -> None:
    """
    Used later by FastAPI or CLI to protect audit execution.
    """
    if provided_key != settings.INTERNAL_API_KEY.get_secret_value():
        raise SecurityError("Invalid internal API key")
