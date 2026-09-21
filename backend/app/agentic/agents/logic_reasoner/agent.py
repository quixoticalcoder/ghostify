from typing import Dict, Any

from langchain_core.output_parsers import JsonOutputParser
from langchain_core.prompts import ChatPromptTemplate

from app.core.llm import get_llm
from app.core.logging import logger
from app.agentic.state.audit_state import SecurityAuditState
from app.agentic.agents.logic_reasoner.schemas import LogicReasonerOutput
from app.agentic.agents.logic_reasoner.prompts import SYSTEM_PROMPT, build_user_prompt
from app.agentic.agents.logic_reasoner.normalizer import (
    normalize_logic_reasoner_output,
)


def logic_reasoner_agent(state: SecurityAuditState) -> Dict[str, Any]:
    """
    LangGraph node: Logic Reasoning Agent.

    Reads:
    - api_map
    - missing_security_controls
    - sensitive_operations

    Writes:
    - logic_assumptions
    - potential_misuse_cases
    - planned_attack_chains
    """

    logger.info("Logic Reasoner Agent started")

    # -----------------------------
    # LLM (planner-only)
    # -----------------------------
    llm = get_llm()

    # IMPORTANT: loose JSON parser
    parser = JsonOutputParser()

    # -----------------------------
    # Prompt
    # -----------------------------
    prompt = ChatPromptTemplate.from_messages(
        [
            ("system", SYSTEM_PROMPT),
            ("human", "{user_input}"),
        ]
    )

    user_input = build_user_prompt(
        api_map=state.get("api_map", {}),
        missing_controls=state.get("missing_security_controls", []),
        sensitive_ops=state.get("sensitive_operations", []),
        sast_findings=state.get("sast_findings", []),  # NEW: Pass SAST findings
    )

    chain = prompt | llm | parser

    # -----------------------------
    # Invoke LLM (LOOSE JSON)
    # -----------------------------
    raw_result: Dict[str, Any] = chain.invoke(
        {
            "user_input": user_input,
        }
    )

    logger.debug(f"Raw Logic Reasoner output: {raw_result}")

    # -----------------------------
    # Normalize → strict schema
    # -----------------------------
    normalized: LogicReasonerOutput = normalize_logic_reasoner_output(raw_result)

    logger.info(
        f"Logic Reasoner produced "
        f"{len(normalized.attack_chains)} attack chains"
    )

    # -----------------------------
    # Return graph-compatible state
    # -----------------------------
    return {
        "logic_assumptions": normalized.logic_assumptions,
        "potential_misuse_cases": [
            mc.model_dump() for mc in normalized.misuse_cases
        ],
        "planned_attack_chains": [
            ac.model_dump() for ac in normalized.attack_chains
        ],
    }
