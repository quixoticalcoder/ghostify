from typing import TypedDict, List, Dict, Any, Optional


class SecurityAuditState(TypedDict, total=False):
    """
    Global state passed between LangGraph nodes.

    IMPORTANT RULES:
    - Agents may only write to fields they own
    - Fields should be appended to, not overwritten
    - LLM outputs must NEVER be treated as ground truth
    """

    # ===============================
    # INPUT / CONTEXT
    # ===============================
    repo_url: str
    commit_hash: Optional[str]
    repo_path: str
    api_base_url: Optional[str]

    # ===============================
    # CODE SCANNING (STATIC)
    # ===============================
    source_files: List[str]
    extracted_endpoints: List[Dict[str, Any]]
    detected_auth_mechanisms: List[str]
    missing_security_controls: List[str]
    sast_findings: List[Dict[str, Any]]  # NEW: SAST tool findings

    # ===============================
    # API CONTEXT & FLOWS
    # ===============================
    openapi_spec: Optional[Dict[str, Any]]
    api_map: Dict[str, Any]
    sensitive_operations: List[str]

    # ===============================
    # LOGIC REASONING (LLM ONLY)
    # ===============================
    logic_assumptions: List[str]
    potential_misuse_cases: List[Dict[str, Any]]
    planned_attack_chains: List[Dict[str, Any]]

    # ===============================
    # ATTACK EXECUTION (DETERMINISTIC)
    # ===============================
    executed_attacks: List[Dict[str, Any]]
    raw_attack_results: List[Dict[str, Any]]

    # ===============================
    # VALIDATION
    # ===============================
    confirmed_vulnerabilities: List[Dict[str, Any]]
    false_positives: List[Dict[str, Any]]

    # ===============================
    # REPORTING
    # ===============================
    final_report: Dict[str, Any]
    severity_summary: Dict[str, int]

    # ===============================
    # CODE FIXING (GEMINI CLI)
    # ===============================
    vulnerability_fixes: List[Dict[str, Any]]
    static_vulnerabilities: List[Dict[str, Any]]
    
    # ===============================
    # SUMMARY GENERATION (REPORT ONLY)
    # ===============================
    security_summary: str
