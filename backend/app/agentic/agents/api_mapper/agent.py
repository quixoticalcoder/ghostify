from typing import Dict, Any, List
from app.core.logging import logger
from app.agentic.state.audit_state import SecurityAuditState
from app.agentic.agents.api_mapper.normalizer import (
    build_api_map,
    is_sensitive_operation,
)


def api_mapper_agent(state: SecurityAuditState) -> Dict[str, Any]:
    """
    LangGraph node: API Context & Mapping Agent.

    Reads:
    - extracted_endpoints
    - detected_auth_mechanisms
    - openapi_spec (optional)

    Writes:
    - api_map
    - sensitive_operations
    """

    logger.info("API Mapper Agent started")

    extracted_endpoints = state.get("extracted_endpoints", [])
    auth_files = state.get("detected_auth_mechanisms", [])

    api_map = build_api_map(extracted_endpoints, auth_files)

    sensitive_ops: List[str] = []

    for path, meta in api_map.items():
        if is_sensitive_operation(meta):
            sensitive_ops.append(path)

    logger.info(
        f"API Mapper built map for {len(api_map)} endpoints "
        f"({len(sensitive_ops)} sensitive)"
    )

    return {
        "api_map": api_map,
        "sensitive_operations": sensitive_ops,
    }
