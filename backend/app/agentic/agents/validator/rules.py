from typing import Dict, Any
from app.core.constants import (
    ATTACK_IDOR,
    ATTACK_AUTH_BYPASS,
    ATTACK_LOGIC_REPLAY,
    ATTACK_RATE_ABUSE,
)


def validate_idor(result: Dict[str, Any]) -> bool:
    """
    IDOR is valid if unauthorized access succeeded.
    """
    return (
        result.get("attack") == ATTACK_IDOR
        and result.get("success") is True
        and result.get("status_code") == 200
    )


def validate_auth_bypass(result: Dict[str, Any]) -> bool:
    """
    Auth bypass is valid if protected endpoint is accessible.
    """
    return (
        result.get("attack") == ATTACK_AUTH_BYPASS
        and result.get("success") is True
    )


def validate_logic_replay(result: Dict[str, Any]) -> bool:
    """
    Logic replay is valid if repeated requests succeed.
    """
    return (
        result.get("attack") == ATTACK_LOGIC_REPLAY
        and result.get("success") is True
    )


def validate_rate_abuse(result: Dict[str, Any]) -> bool:
    """
    Rate abuse is valid if rate limit is absent.
    """
    return (
        result.get("attack") == ATTACK_RATE_ABUSE
        and result.get("success") is True
    )


VALIDATION_DISPATCHER = {
    ATTACK_IDOR: validate_idor,
    ATTACK_AUTH_BYPASS: validate_auth_bypass,
    ATTACK_LOGIC_REPLAY: validate_logic_replay,
    ATTACK_RATE_ABUSE: validate_rate_abuse,
}
