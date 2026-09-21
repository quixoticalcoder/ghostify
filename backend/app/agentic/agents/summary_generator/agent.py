"""
Summary Generator Agent - Uses Gemini API to generate human-readable security summary

This agent:
- Receives ONLY the final audit report (JSON)
- Does NOT have file system access
- Does NOT generate code fixes
- Does NOT modify any files
- ONLY produces human-readable security analysis
"""

from typing import Dict, Any
from langchain_core.prompts import ChatPromptTemplate
from langchain_core.output_parsers import StrOutputParser

from app.core.logging import logger
from app.core.llm import get_llm
from app.agentic.state.audit_state import SecurityAuditState


def summary_generator_agent(state: SecurityAuditState) -> Dict[str, Any]:
    """
    LangGraph node: Summary Generator Agent.
    
    Generates a human-readable security summary from audit results.
    
    Reads:
    - final_report (from reporter agent)
    - repo_url
    - api_base_url
    
    Writes:
    - security_summary (plain text summary)
    """
    
    logger.info("Summary Generator Agent started - Generating human-readable report")
    
    final_report = state.get("final_report", {})
    repo_url = state.get("repo_url", "Unknown")
    api_url = state.get("api_base_url", "Not provided")
    
    if not final_report:
        logger.warning("No final report available")
        return {
            "security_summary": "No audit data available to generate summary."
        }
    
    # Get Gemini LLM
    llm = get_llm()
    
    # Generate summary
    try:
        summary = generate_security_summary(
            report=final_report,
            repo_url=repo_url,
            api_url=api_url,
            llm=llm
        )
        
        logger.info("✓ Generated security summary")
        
        return {
            "security_summary": summary
        }
        
    except Exception as e:
        logger.error(f"Error generating security summary: {e}")
        return {
            "security_summary": f"Error generating summary: {str(e)}"
        }


def generate_security_summary(
    report: Dict[str, Any],
    repo_url: str,
    api_url: str,
    llm
) -> str:
    """
    Generate a human-readable security summary using Gemini API.
    
    Args:
        report: Final audit report (JSON)
        repo_url: Repository URL
        api_url: Application URL (if provided)
        llm: Gemini LLM instance
        
    Returns:
        Human-readable security summary (plain text)
    """
    
    summary_data = report.get("summary", {})
    static_vulns = report.get("static_vulnerabilities", [])
    dynamic_vulns = report.get("dynamic_vulnerabilities", [])
    
    # Count by severity
    severity_counts = summary_data.get("by_severity", {})
    
    # Count by type
    type_counts = {}
    for vuln in static_vulns + dynamic_vulns:
        vtype = vuln.get("type", "UNKNOWN")
        type_counts[vtype] = type_counts.get(vtype, 0) + 1
    
    # Build vulnerability list (limit to 15 for prompt)
    vuln_list = []
    all_vulns = static_vulns + dynamic_vulns
    for idx, vuln in enumerate(all_vulns[:15], 1):
        vuln_list.append(f"""
{idx}. {vuln.get('type', 'UNKNOWN')} - {vuln.get('severity', 'UNKNOWN')}
   File: {vuln.get('file', 'N/A')}
   Line: {vuln.get('line', 'N/A')}
   Description: {vuln.get('description', 'N/A')}
""")
    
    # Build the prompt
    prompt_template = ChatPromptTemplate.from_messages([
        ("system", """You are a senior security analyst generating executive security reports.

CRITICAL RULES:
1. You are a REPORT GENERATOR ONLY - not an actor or code fixer
2. You do NOT have file system access
3. You do NOT generate code fixes or patches
4. You do NOT provide exploitation steps
5. You do NOT include tool or scanner names
6. You ONLY explain risks and mitigations at a high level

Your task is to analyze the provided audit data and create a clear, actionable security summary for stakeholders.

Output format (plain text, no code blocks):

SECURITY AUDIT SUMMARY
======================

EXECUTIVE OVERVIEW:
[2-3 sentences on overall security posture]

CRITICAL FINDINGS:
[List 3-5 most critical issues with severity and impact]

VULNERABILITY BREAKDOWN:
[Categorize by severity with counts and brief descriptions]

RISK ASSESSMENT:
[Overall risk level: CRITICAL/HIGH/MEDIUM/LOW and justification]

RECOMMENDED ACTIONS:
[Priority-ordered list of mitigation strategies - NO CODE]

NEXT STEPS:
[Immediate actions for the development team]

Remember: NO code examples, NO tool names, NO exploitation details."""),
        ("human", """{prompt}""")
    ])
    
    # Build the detailed prompt
    prompt_content = f"""Analyze the following security audit results and provide a comprehensive summary:

**Repository:** {repo_url}
**Application URL:** {api_url if api_url else "Static analysis only"}

**Total Vulnerabilities:** {summary_data.get('total_vulnerabilities', 0)}
- HIGH Severity: {severity_counts.get('HIGH', 0)}
- MEDIUM Severity: {severity_counts.get('MEDIUM', 0)}
- LOW Severity: {severity_counts.get('LOW', 0)}

**Analysis Type:**
- Static Analysis: {summary_data.get('static_vulnerabilities', 0)} issues
- Dynamic Analysis: {summary_data.get('dynamic_vulnerabilities', 0)} issues

**Vulnerability Types Found:**
{chr(10).join([f"- {vtype}: {count} occurrence(s)" for vtype, count in sorted(type_counts.items(), key=lambda x: x[1], reverse=True)])}

**Sample Vulnerabilities:**
{''.join(vuln_list)}

{f"... and {len(all_vulns) - 15} more vulnerabilities" if len(all_vulns) > 15 else ""}

Generate a comprehensive, human-readable security summary following the format specified."""
    
    # Call Gemini API
    try:
        chain = prompt_template | llm | StrOutputParser()
        response = chain.invoke({"prompt": prompt_content})
        
        if not response:
            return "Error: No response from Gemini API"
        
        return response.strip()
        
    except Exception as e:
        logger.error(f"Gemini API error: {e}")
        return f"Error generating summary: {str(e)}"
