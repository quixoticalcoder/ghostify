from typing import List, Optional
from pydantic import BaseModel, Field


class AttackStep(BaseModel):
    """
    One atomic attack step planned by the LLM.
    Planner-only: WHAT + WHY, never HOW.
    """

    attack_type: str = Field(
        ...,
        description="Attack primitive (IDOR, AUTH_BYPASS, LOGIC_REPLAY, RATE_ABUSE)"
    )
    endpoint: str = Field(
        ...,
        description="API endpoint path (no base URL)"
    )
    parameter: Optional[str] = Field(
        None,
        description="Relevant parameter (e.g., user_id, order_id)"
    )
    reason: str = Field(
        ...,
        description="Why this step might succeed"
    )


class MisuseCase(BaseModel):
    """
    High-level business logic abuse scenario.
    """
    title: str
    description: str
    impacted_asset: Optional[str]


class AttackChain(BaseModel):
    """
    Multi-step attack chain.
    """

    attack_goal: str
    assumption: str
    steps: List[AttackStep]


class LogicReasonerOutput(BaseModel):
    """
    Final structured output from the Logic Reasoner.
    """

    logic_assumptions: List[str] = Field(default_factory=list)
    misuse_cases: List[MisuseCase] = Field(default_factory=list)
    attack_chains: List[AttackChain] = Field(default_factory=list)
