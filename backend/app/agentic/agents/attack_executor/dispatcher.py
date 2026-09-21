from typing import Dict, Any
from app.agentic.agents.attack_executor.modules.idor import execute_idor
from app.agentic.agents.attack_executor.modules.auth_bypass import execute_auth_bypass
from app.agentic.agents.attack_executor.modules.logic_replay import execute_logic_replay
from app.agentic.agents.attack_executor.modules.rate_abuse import execute_rate_abuse
from app.core.constants import (
    ATTACK_IDOR,
    ATTACK_AUTH_BYPASS,
    ATTACK_LOGIC_REPLAY,
    ATTACK_RATE_ABUSE,
)


ATTACK_DISPATCHER = {
    ATTACK_IDOR: execute_idor,
    ATTACK_AUTH_BYPASS: execute_auth_bypass,
    ATTACK_LOGIC_REPLAY: execute_logic_replay,
    ATTACK_RATE_ABUSE: execute_rate_abuse,
}


def dispatch_attack(
    attack_type: str,
    **kwargs,
) -> Dict[str, Any]:
    if attack_type not in ATTACK_DISPATCHER:
        return {
            "success": False,
            "reason": f"Unsupported attack type: {attack_type}",
        }

    return ATTACK_DISPATCHER[attack_type](**kwargs)
