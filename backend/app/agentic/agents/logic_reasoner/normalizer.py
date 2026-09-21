from typing import Dict, Any, List
from app.agentic.agents.logic_reasoner.schemas import (
    LogicReasonerOutput,
    MisuseCase,
    AttackChain,
    AttackStep,
)
from app.core.logging import logger


def normalize_logic_reasoner_output(raw: Dict[str, Any]) -> LogicReasonerOutput:
    """
    Convert loose LLM JSON into strict LogicReasonerOutput schema.
    """

    misuse_cases: List[MisuseCase] = []
    for item in raw.get("misuse_cases", []):
        if isinstance(item, str):
            misuse_cases.append(
                MisuseCase(
                    title=item,
                    description=item,
                )
            )
        elif isinstance(item, dict):
            misuse_cases.append(MisuseCase(**item))

    attack_chains: List[AttackChain] = []

    for chain in raw.get("attack_chains", []):
        steps = []
        for step in chain.get("steps", []):
            steps.append(
                AttackStep(
                    attack_type=step.get("primitive"),
                    endpoint=step.get("endpoint", "/unknown"),
                    reason=step.get("description", "Derived from LLM reasoning"),
                )
            )

        attack_chains.append(
            AttackChain(
                attack_goal=chain.get("name", "Unknown attack goal"),
                assumption="Derived from LLM assumptions",
                steps=steps,
            )
        )

    logger.info(
        f"Normalized {len(misuse_cases)} misuse cases and {len(attack_chains)} attack chains"
    )

    return LogicReasonerOutput(
        assumptions=raw.get("assumptions", []),
        misuse_cases=misuse_cases,
        attack_chains=attack_chains,
    )
