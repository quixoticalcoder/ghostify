# 🔐 Security Audit Report

## Summary
- Total vulnerabilities: {{ total }}
- Critical: {{ critical }}
- High: {{ high }}
- Medium: {{ medium }}
- Low: {{ low }}

---

{% for vuln in vulnerabilities %}

## {{ vuln.title }}
**Severity:** {{ vuln.severity }}

**Affected Endpoint:**  
`{{ vuln.affected_endpoint }}`

**Attack Chain:**  
{{ vuln.attack_chain | join(" → ") }}

**Evidence:**  
```json
{{ vuln.evidence }}
