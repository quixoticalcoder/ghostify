from typing import Dict, Any, List
from collections import Counter
from app.core.logging import logger
from app.agentic.state.audit_state import SecurityAuditState
from app.agentic.agents.reporter.formatter import format_vulnerability


def reporter_agent(state: SecurityAuditState) -> Dict[str, Any]:
    """
    LangGraph node: Report & Explanation Agent (ENHANCED).

    Reads:
    - confirmed_vulnerabilities
    - planned_attack_chains
    - sast_findings (NEW)

    Writes:
    - final_report
    - severity_summary
    """

    logger.info("Reporter Agent started (Enhanced with SAST findings)")

    confirmed = state.get("confirmed_vulnerabilities", [])
    attack_chains = state.get("planned_attack_chains", [])
    sast_findings = state.get("sast_findings", [])

    # ===============================
    # DYNAMIC VULNERABILITIES (from attack execution)
    # ===============================
    vulnerabilities: List[Dict[str, Any]] = []

    for vuln in confirmed:
        # Try to associate attack chain context
        chain_context = None
        for chain in attack_chains:
            if any(
                step["attack_type"] == vuln["attack_type"]
                for step in chain.get("steps", [])
            ):
                chain_context = [
                    step["attack_type"] for step in chain.get("steps", [])
                ]
                break

        vulnerabilities.append(
            format_vulnerability(vuln, chain_context)
        )

    # ===============================
    # STATIC VULNERABILITIES (from SAST)
    # ===============================
    sast_vulnerabilities: List[Dict[str, Any]] = []
    
    for finding in sast_findings:
        sast_vulnerabilities.append({
            "type": finding.get("issue_type"),
            "severity": finding.get("severity"),
            "confidence": finding.get("confidence"),
            "file": finding.get("file_path"),
            "line": finding.get("line_number"),
            "description": finding.get("description"),
            "code_snippet": finding.get("code_snippet"),
            "cwe_id": finding.get("cwe_id"),
            "tool": finding.get("tool"),
            "category": "STATIC_ANALYSIS"
        })

    # ===============================
    # AGGREGATE SEVERITY COUNTS
    # ===============================
    all_severities = (
        [vuln["severity"] for vuln in vulnerabilities] +
        [finding.get("severity") for finding in sast_findings]
    )
    severity_counts = Counter(all_severities)

    # ===============================
    # FINAL REPORT
    # ===============================
    final_report = {
        "summary": {
            "total_vulnerabilities": len(vulnerabilities) + len(sast_vulnerabilities),
            "dynamic_vulnerabilities": len(vulnerabilities),
            "static_vulnerabilities": len(sast_vulnerabilities),
            "by_severity": dict(severity_counts),
        },
        "dynamic_vulnerabilities": vulnerabilities,  # From attack execution
        "static_vulnerabilities": sast_vulnerabilities,  # From SAST tools
        "sast_tools_used": list(set(f.get("tool") for f in sast_findings)),
    }

    logger.info(
        f"Report generated: {len(vulnerabilities)} dynamic + "
        f"{len(sast_vulnerabilities)} static = "
        f"{len(vulnerabilities) + len(sast_vulnerabilities)} total vulnerabilities"
    )

    return {
        "final_report": final_report,
        "severity_summary": dict(severity_counts),
        "static_vulnerabilities": sast_vulnerabilities,  # Pass to code fixer
    }
