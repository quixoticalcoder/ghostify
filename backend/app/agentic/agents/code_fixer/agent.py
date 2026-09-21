"""
Code Fixer Agent - Uses Gemini API to generate vulnerability summary
"""
import json
import os
from typing import Dict, Any, List
from pathlib import Path

from langchain_core.prompts import ChatPromptTemplate
from langchain_core.output_parsers import StrOutputParser

from app.core.logging import logger
from app.core.llm import get_llm
from app.agentic.state.audit_state import SecurityAuditState


def code_fixer_agent(state: SecurityAuditState) -> Dict[str, Any]:
    """
    LangGraph node: Code Fixer Agent.
    
    Uses Gemini API to generate a comprehensive security summary.
    
    Reads:
    - confirmed_vulnerabilities
    - static_vulnerabilities (from SAST)
    - repo_path
    
    Writes:
    - vulnerability_summary (executive summary only, no code fixes)
    """
    
    logger.info("Code Fixer Agent started - Generating Security Summary with Gemini API")
    
    repo_path = state.get("repo_path", "")
    confirmed_vulns = state.get("confirmed_vulnerabilities", [])
    static_vulns = state.get("static_vulnerabilities", [])
    
    # Combine all vulnerabilities
    all_vulnerabilities = []
    
    # Add confirmed dynamic vulnerabilities
    for vuln in confirmed_vulns:
        all_vulnerabilities.append({
            "type": vuln.get("attack_type", "UNKNOWN"),
            "severity": "HIGH",
            "file": vuln.get("endpoint", ""),
            "description": f"Dynamic vulnerability: {vuln.get('attack_type')}",
            "evidence": vuln.get("evidence", {}),
            "category": "DYNAMIC"
        })
    
    # Add static vulnerabilities
    for vuln in static_vulns:
        all_vulnerabilities.append(vuln)
    
    if not all_vulnerabilities:
        logger.info("No vulnerabilities found - generating clean report")
        return {
            "vulnerability_summary": "✅ No security vulnerabilities detected. The codebase appears to follow security best practices."
        }
    
    logger.info(f"Generating security summary for {len(all_vulnerabilities)} vulnerabilities")
    
    # Get Gemini LLM
    llm = get_llm()
    
    # Generate comprehensive summary using Gemini API
    try:
        summary = generate_security_summary_with_gemini(
            vulnerabilities=all_vulnerabilities,
            repo_path=repo_path,
            llm=llm
        )
        
        logger.info("✓ Generated comprehensive security summary")
        
        return {
            "vulnerability_summary": summary
        }
        
    except Exception as e:
        logger.error(f"Error generating security summary: {e}")
        return {
            "vulnerability_summary": f"Error generating summary: {str(e)}"
        }


def generate_security_summary_with_gemini(
    vulnerabilities: List[Dict[str, Any]],
    repo_path: str,
    llm
) -> str:
    """
    Generate a comprehensive security summary using Gemini API.
    
    Args:
        vulnerabilities: List of all detected vulnerabilities
        repo_path: Path to the repository
        llm: Gemini LLM instance
        
    Returns:
        Comprehensive security summary text
    """
    
    # Count vulnerabilities by severity and type
    severity_counts = {}
    type_counts = {}
    category_counts = {"STATIC": 0, "DYNAMIC": 0}
    
    for vuln in vulnerabilities:
        severity = vuln.get("severity", "UNKNOWN")
        vuln_type = vuln.get("type", "UNKNOWN")
        category = vuln.get("category", "STATIC")
        
        severity_counts[severity] = severity_counts.get(severity, 0) + 1
        type_counts[vuln_type] = type_counts.get(vuln_type, 0) + 1
        category_counts[category] = category_counts.get(category, 0) + 1
    
    # Build vulnerability list for prompt
    vuln_list = []
    for idx, vuln in enumerate(vulnerabilities[:20], 1):  # Limit to first 20 for prompt
        vuln_list.append(f"""
{idx}. {vuln.get('type', 'UNKNOWN')} - {vuln.get('severity', 'UNKNOWN')}
   File: {vuln.get('file', 'N/A')}
   Line: {vuln.get('line', 'N/A')}
   Description: {vuln.get('description', 'N/A')}
""")
    
    # Build the prompt for Gemini API
    prompt_template = ChatPromptTemplate.from_messages([
        ("system", """You are a senior security analyst providing executive security summaries.
Your task is to analyze vulnerability data and create a comprehensive, actionable security summary.

IMPORTANT RULES:
1. Provide a clear executive summary
2. Highlight critical security risks
3. Categorize vulnerabilities by severity and type
4. Provide actionable recommendations
5. Use professional, clear language
6. DO NOT provide code fixes - only analysis and recommendations

Output format:
```
SECURITY AUDIT SUMMARY
======================

OVERVIEW:
[Brief overview of security posture]

CRITICAL FINDINGS:
[List of most critical issues]

VULNERABILITY BREAKDOWN:
[Categorized list of vulnerabilities]

RISK ASSESSMENT:
[Overall risk level and impact]

RECOMMENDATIONS:
[Priority-ordered recommendations]

NEXT STEPS:
[Immediate actions to take]
```"""),
        ("human", """{prompt}""")
    ])
    
    # Build the detailed prompt
    prompt_content = f"""Analyze the following security audit results and provide a comprehensive summary:

**Repository:** {repo_path}

**Total Vulnerabilities:** {len(vulnerabilities)}
- HIGH Severity: {severity_counts.get('HIGH', 0)}
- MEDIUM Severity: {severity_counts.get('MEDIUM', 0)}
- LOW Severity: {severity_counts.get('LOW', 0)}

**Analysis Type:**
- Static Analysis (SAST): {category_counts.get('STATIC', 0)} issues
- Dynamic Analysis: {category_counts.get('DYNAMIC', 0)} issues

**Vulnerability Types Found:**
{chr(10).join([f"- {vtype}: {count} occurrence(s)" for vtype, count in sorted(type_counts.items(), key=lambda x: x[1], reverse=True)])}

**Detailed Vulnerabilities:**
{''.join(vuln_list)}

{f"... and {len(vulnerabilities) - 20} more vulnerabilities" if len(vulnerabilities) > 20 else ""}

Provide a comprehensive security summary with actionable recommendations."""
    
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


def generate_fix_with_gemini_api(
    vulnerability: Dict[str, Any],
    repo_path: str,
    llm
) -> Dict[str, Any] | None:
    """
    Use Gemini API to generate a fix for a specific vulnerability.
    
    Args:
        vulnerability: Vulnerability details
        repo_path: Path to the repository
        
    Returns:
        Fix details with code, or None if failed
    """
    
    vuln_type = vulnerability.get("type", "UNKNOWN")
    vuln_file = vulnerability.get("file", "")
    vuln_line = vulnerability.get("line", 0)
    vuln_desc = vulnerability.get("description", "")
    vuln_code = vulnerability.get("code_snippet", "")
    
    # Read the full file content if file exists
    file_content = ""
    if vuln_file and os.path.exists(vuln_file):
        try:
            with open(vuln_file, 'r', encoding='utf-8') as f:
                file_content = f.read()
        except Exception as e:
            logger.warning(f"Could not read file {vuln_file}: {e}")
    
    # Build the prompt for Gemini API
    prompt_template = ChatPromptTemplate.from_messages([
        ("system", """You are a security expert specializing in fixing code vulnerabilities.
Your task is to analyze vulnerable code and provide complete, secure fixes.

IMPORTANT RULES:
1. Provide the COMPLETE fixed code (not just the changed parts)
2. Explain what was changed and why
3. Follow security best practices
4. Keep the code functional and maintainable
5. Use clear, professional language

Output format:
```
FIXED_CODE_START
[Complete fixed code here]
FIXED_CODE_END

EXPLANATION:
[Detailed explanation of the fix and security improvements]
```"""),
        ("human", """{prompt}""")
    ])
    
    # Build the detailed prompt
    prompt_content = f"""Fix the following security vulnerability:

**Vulnerability Type:** {vuln_type}
**File:** {vuln_file}
**Line:** {vuln_line}
**Description:** {vuln_desc}

**Vulnerable Code:**
```
{vuln_code if vuln_code else "See full file below"}
```

**Full File Content:**
```
{file_content[:5000] if file_content else "File not available"}
```

Provide the complete fixed code and explanation."""
    
    # Call Gemini API
    try:
        chain = prompt_template | llm | StrOutputParser()
        response = chain.invoke({"prompt": prompt_content})
        
        if not response:
            return None
        
        # Extract fixed code and explanation
        fixed_code = extract_fixed_code(response)
        explanation = extract_explanation(response)
        
        return {
            "vulnerability_type": vuln_type,
            "file": vuln_file,
            "line": vuln_line,
            "description": vuln_desc,
            "original_code": vuln_code or file_content,
            "fixed_code": fixed_code,
            "fix_explanation": explanation
        }
        
    except Exception as e:
        logger.error(f"Gemini API error: {e}")
        return None


def extract_explanation(response: str) -> str:
    """
    Extract the explanation from Gemini's response.
    """
    
    if "EXPLANATION:" in response:
        parts = response.split("EXPLANATION:")
        if len(parts) > 1:
            return parts[1].strip()
    
    if "# EXPLANATION" in response:
        parts = response.split("# EXPLANATION")
        if len(parts) > 1:
            return parts[1].strip()
    
    # Try to extract any explanation after the code
    if "FIXED_CODE_END" in response:
        parts = response.split("FIXED_CODE_END")
        if len(parts) > 1:
            explanation = parts[1].strip()
            # Remove common prefixes
            for prefix in ["EXPLANATION:", "Explanation:", "**Explanation:**", "## Explanation"]:
                if explanation.startswith(prefix):
                    explanation = explanation[len(prefix):].strip()
            return explanation
    
    return "No explanation provided"


def extract_fixed_code(response: str) -> str:
    """
    Extract the fixed code from Gemini's response.
    """
    
    # Try to find code between markers
    if "FIXED_CODE_START" in response and "FIXED_CODE_END" in response:
        start = response.find("FIXED_CODE_START") + len("FIXED_CODE_START")
        end = response.find("FIXED_CODE_END")
        code = response[start:end].strip()
        
        # Remove code block markers if present
        if code.startswith("```"):
            lines = code.split("\n")
            # Remove first line (```python or similar)
            lines = lines[1:]
            # Remove last line if it's ```
            if lines and lines[-1].strip() == "```":
                lines = lines[:-1]
            code = "\n".join(lines)
        
        return code.strip()
    
    # Try to find code in code blocks
    if "```" in response:
        parts = response.split("```")
        if len(parts) >= 3:
            # Get the first code block
            code = parts[1]
            # Remove language identifier if present
            lines = code.split("\n")
            if lines and lines[0].strip() in ["python", "py", "javascript", "js", "java", "go"]:
                lines = lines[1:]
            return "\n".join(lines).strip()
    
    # If no markers found, return the whole response
    return response.strip()
