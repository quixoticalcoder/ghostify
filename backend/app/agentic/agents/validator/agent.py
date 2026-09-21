from typing import Dict, Any, List
from app.core.logging import logger
from app.agentic.state.audit_state import SecurityAuditState
from app.agentic.agents.validator.rules import VALIDATION_DISPATCHER


def validator_agent(state: SecurityAuditState) -> Dict[str, Any]:
    """
    LangGraph node: Exploit Validation Agent.

    Reads:
    - raw_attack_results
    - planned_attack_chains

    Writes:
    - confirmed_vulnerabilities
    - false_positives
    """

    logger.info("Validator Agent started")

    confirmed: List[Dict[str, Any]] = []
    false_positives: List[Dict[str, Any]] = []

    attack_results = state.get("raw_attack_results", [])
    attack_chains = state.get("planned_attack_chains", [])

    for result in attack_results:
        attack_type = result.get("attack")

        validator = VALIDATION_DISPATCHER.get(attack_type)

        if not validator:
            logger.warning(f"No validator for attack type {attack_type}")
            false_positives.append(result)
            continue

        is_valid = validator(result)

        if is_valid:
            confirmed.append(
                {
                    "attack_type": attack_type,
                    "endpoint": result.get("endpoint"),
                    "evidence": result,
                }
            )
        else:
            false_positives.append(result)

    logger.info(
        f"Validator confirmed {len(confirmed)} vulnerabilities, "
        f"discarded {len(false_positives)} false positives"
    )

    return {
        "confirmed_vulnerabilities": confirmed,
        "false_positives": false_positives,
    }
