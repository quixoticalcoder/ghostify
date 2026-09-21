from typing import Dict, Any
from app.core.constants import (
    ATTACK_IDOR,
    ATTACK_AUTH_BYPASS,
    ATTACK_LOGIC_REPLAY,
    ATTACK_RATE_ABUSE,
    SEVERITY_CRITICAL,
    SEVERITY_HIGH,
    SEVERITY_MEDIUM,
    SEVERITY_LOW,
)


def determine_severity(attack_type: str) -> str:
    """
    Assign severity based on attack type.
    """
    if attack_type in {ATTACK_IDOR, ATTACK_AUTH_BYPASS}:
        return SEVERITY_CRITICAL
    if attack_type == ATTACK_LOGIC_REPLAY:
        return SEVERITY_HIGH
    if attack_type == ATTACK_RATE_ABUSE:
        return SEVERITY_MEDIUM
    return SEVERITY_LOW


def remediation_for(attack_type: str) -> str:
    """
    Return remediation guidance per attack type.
    """
    if attack_type == ATTACK_IDOR:
        return (
            "Enforce object-level authorization checks. "
            "Verify that the authenticated user owns or is permitted "
            "to access the referenced object."
        )

    if attack_type == ATTACK_AUTH_BYPASS:
        return (
            "Ensure authentication and authorization middleware is "
            "applied consistently to all protected endpoints."
        )

    if attack_type == ATTACK_LOGIC_REPLAY:
        return (
            "Introduce idempotency controls, state validation, "
            "and one-time tokens for sensitive operations."
        )

    if attack_type == ATTACK_RATE_ABUSE:
        return (
            "Implement server-side rate limiting and abuse detection "
            "to prevent excessive repeated requests."
        )

    return "Review endpoint logic and apply appropriate security controls."


def format_vulnerability(
    vuln: Dict[str, Any],
    attack_chain: list | None = None,
) -> Dict[str, Any]:
    """
    Convert a validated vulnerability into report-friendly format.
    """
    attack_type = vuln["attack_type"]

    return {
        "title": f"{attack_type} vulnerability detected",
        "attack_type": attack_type,
        "severity": determine_severity(attack_type),
        "affected_endpoint": vuln.get("endpoint"),
        "attack_chain": attack_chain or [attack_type],
        "evidence": vuln.get("evidence", {}),
        "remediation": remediation_for(attack_type),
    }
