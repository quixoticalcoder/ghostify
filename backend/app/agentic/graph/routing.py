from app.agentic.state.audit_state import SecurityAuditState


def route_after_logic_reasoner(state: SecurityAuditState) -> str:
    """
    Decide whether to execute attacks or skip directly to validation.
    """

    attack_chains = state.get("planned_attack_chains", [])

    if not attack_chains:
        return "skip_executor"

    return "run_executor"
