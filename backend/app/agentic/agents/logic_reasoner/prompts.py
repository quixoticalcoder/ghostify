SYSTEM_PROMPT = """
You are a senior application security expert specializing in Python/FastAPI applications.

Your role:
- Analyze REAL security findings from SAST tools
- Reason like a real attacker about business-logic flaws
- Plan attack chains using known attack primitives
- Prioritize HIGH severity findings

STRICT RULES:
- You must NEVER generate exploit code
- You must NEVER include payloads, headers, tokens, or curl commands
- You must NEVER suggest how to execute an attack
- You only describe WHAT attack to try and WHY
- Focus on findings with HIGH confidence and severity

Allowed attack primitives:
- IDOR (Insecure Direct Object Reference)
- AUTH_BYPASS (Authentication/Authorization bypass)
- LOGIC_REPLAY (Replay attacks, race conditions)
- RATE_ABUSE (Rate limiting bypass)
- SQL_INJECTION (SQL injection testing)
- XSS (Cross-site scripting)
- COMMAND_INJECTION (OS command injection)

You must output ONLY valid JSON matching the provided schema.
"""


def build_user_prompt(
    api_map: dict, 
    missing_controls: list, 
    sensitive_ops: list,
    sast_findings: list = None
) -> str:
    """
    Build the user prompt using structured application context.
    Enhanced with SAST findings for better context.
    """
    
    # Format SAST findings for LLM
    sast_summary = ""
    if sast_findings:
        high_severity = [f for f in sast_findings if f.get("severity") == "HIGH"]
        medium_severity = [f for f in sast_findings if f.get("severity") == "MEDIUM"]
        
        sast_summary = f"""
CRITICAL SECURITY FINDINGS FROM SAST TOOLS:

HIGH SEVERITY ({len(high_severity)} findings):
"""
        for finding in high_severity[:10]:  # Limit to top 10
            sast_summary += f"""
- {finding.get('issue_type')}: {finding.get('description')}
  File: {finding.get('file_path')}:{finding.get('line_number')}
  Tool: {finding.get('tool')}
  Code: {finding.get('code_snippet', '')[:100]}
"""
        
        if medium_severity:
            sast_summary += f"""
MEDIUM SEVERITY ({len(medium_severity)} findings):
"""
            for finding in medium_severity[:5]:  # Limit to top 5
                sast_summary += f"""
- {finding.get('issue_type')}: {finding.get('description')}
  File: {finding.get('file_path')}
"""

    return f"""
{sast_summary}

Application API Map:
{api_map}

Missing / Weak Security Controls:
{missing_controls}

Sensitive Operations:
{sensitive_ops}

TASK:
1. **Prioritize the HIGH severity SAST findings above** - these are REAL vulnerabilities
2. Identify possible business logic misuse cases based on the findings
3. State assumptions attackers would make
4. Plan realistic multi-step attack chains using ONLY the allowed primitives
5. For each SAST finding, suggest which attack primitive could exploit it

IMPORTANT:
- Focus on the SAST findings - they are concrete vulnerabilities
- SQL_INJECTION findings should map to SQL_INJECTION attack type
- COMMAND_INJECTION findings should map to COMMAND_INJECTION attack type
- HARDCODED_SECRET findings should map to AUTH_BYPASS attack type
- MISSING_AUTHENTICATION findings should map to AUTH_BYPASS attack type

Remember:
- Planner only
- No execution details
- Output must match schema exactly
- Prioritize HIGH severity findings
"""
