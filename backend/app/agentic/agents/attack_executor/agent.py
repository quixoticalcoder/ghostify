from typing import Dict, Any, List
from app.core.logging import logger
from app.agentic.state.audit_state import SecurityAuditState
from app.services.http_client import SafeHttpClient
from app.agentic.agents.attack_executor.dispatcher import dispatch_attack


def attack_executor_agent(state: SecurityAuditState) -> Dict[str, Any]:
    """
    LangGraph node: Attack Executor Agent.

    Reads:
    - planned_attack_chains
    - api_base_url

    Writes:
    - executed_attacks
    - raw_attack_results
    """

    logger.info("Attack Executor Agent started")

    base_url = state.get("api_base_url")
    if not base_url:
        logger.warning(
            "No api_base_url provided — skipping attack execution "
            "(static / logic-only audit mode)"
        )
        return {
            "executed_attacks": [],
            "raw_attack_results": [],
        }

    client = SafeHttpClient()

    executed_attacks: List[Dict[str, Any]] = []
    raw_results: List[Dict[str, Any]] = []

    for chain in state.get("planned_attack_chains", []):
        for step in chain.get("steps", []):
            result = dispatch_attack(
                attack_type=step["attack_type"],
                client=client,
                base_url=base_url,
                endpoint=step["endpoint"],
                parameter=step.get("parameter"),
            )

            executed_attacks.append({
                "attack_type": step["attack_type"],
                "endpoint": step["endpoint"],
            })
            raw_results.append(result)

    client.close()

    logger.info(f"Executed {len(raw_results)} attack steps")

    return {
        "executed_attacks": executed_attacks,
        "raw_attack_results": raw_results,
    }
