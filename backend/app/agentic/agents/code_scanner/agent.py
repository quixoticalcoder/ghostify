from typing import Dict, Any, List
from app.core.logging import logger
from app.agentic.state.audit_state import SecurityAuditState
from app.agentic.agents.code_scanner.extractors import (
    collect_source_files,
    scan_file_for_patterns,
)
from app.agentic.agents.code_scanner.sast_tools import SASTOrchestrator


def code_scanner_agent(state: SecurityAuditState) -> Dict[str, Any]:
    """
    LangGraph node: Code Scanner Agent (ENHANCED).

    Reads:
    - repo_path (from GitHubService)

    Writes:
    - source_files
    - extracted_endpoints
    - detected_auth_mechanisms
    - missing_security_controls
    - sast_findings (NEW)
    """

    logger.info("Code Scanner Agent started (Enhanced with SAST)")

    repo_path = state.get("repo_path")
    if not repo_path:
        raise ValueError("repo_path missing from state")

    source_files = collect_source_files(repo_path)

    # ===============================
    # LEGACY PATTERN SCANNING
    # ===============================
    extracted_endpoints: List[Dict[str, Any]] = []
    detected_auth: List[str] = []
    missing_controls_agg: List[str] = []

    for file_path in source_files:
        result = scan_file_for_patterns(file_path)

        if result["has_endpoint"]:
            extracted_endpoints.append(
                {
                    "file": result["file"],
                }
            )

        if result["auth_detected"]:
            detected_auth.append(result["file"])

        missing_controls_agg.extend(result["missing_controls"])

    # ===============================
    # NEW: COMPREHENSIVE SAST SCANNING
    # ===============================
    sast_orchestrator = SASTOrchestrator()
    sast_findings = sast_orchestrator.run_all_scans(repo_path)
    
    # Convert findings to dict format for state
    sast_findings_dict = [
        {
            "severity": f.severity,
            "confidence": f.confidence,
            "issue_type": f.issue_type,
            "file_path": f.file_path,
            "line_number": f.line_number,
            "code_snippet": f.code_snippet,
            "description": f.description,
            "cwe_id": f.cwe_id,
            "tool": f.tool,
        }
        for f in sast_findings
    ]
    
    # Extract additional security controls from SAST findings
    for finding in sast_findings:
        if finding.issue_type in ["MISSING_AUTHENTICATION", "MISSING_INPUT_VALIDATION"]:
            missing_controls_agg.append(finding.issue_type)

    logger.info(
        f"Scanned {len(source_files)} files, "
        f"found {len(extracted_endpoints)} endpoint files, "
        f"{len(sast_findings)} SAST findings"
    )

    return {
        "source_files": [str(p) for p in source_files],
        "extracted_endpoints": extracted_endpoints,
        "detected_auth_mechanisms": list(set(detected_auth)),
        "missing_security_controls": list(set(missing_controls_agg)),
        "sast_findings": sast_findings_dict,  # NEW
    }
