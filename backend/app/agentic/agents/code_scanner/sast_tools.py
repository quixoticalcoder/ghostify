"""
Static Application Security Testing (SAST) Tools
Integrates Bandit, Safety, and custom analyzers for Python/FastAPI
"""

import ast
import json
import subprocess
import tempfile
from pathlib import Path
from typing import List, Dict, Any, Optional
from dataclasses import dataclass

from app.core.logging import logger


@dataclass
class SecurityFinding:
    """Represents a security vulnerability finding"""
    severity: str  # HIGH, MEDIUM, LOW
    confidence: str  # HIGH, MEDIUM, LOW
    issue_type: str
    file_path: str
    line_number: int
    code_snippet: str
    description: str
    cwe_id: Optional[str] = None
    tool: str = "custom"


class BanditScanner:
    """
    Wrapper for Bandit - Python security linter
    """
    
    def scan(self, repo_path: str) -> List[SecurityFinding]:
        """Run Bandit scan on repository"""
        findings = []
        
        try:
            # Run Bandit with JSON output
            result = subprocess.run(
                [
                    "bandit",
                    "-r", repo_path,
                    "-f", "json",
                    "-ll",  # Only report medium and high severity
                ],
                capture_output=True,
                text=True,
                timeout=300
            )
            
            if result.stdout:
                data = json.loads(result.stdout)
                
                for issue in data.get("results", []):
                    findings.append(SecurityFinding(
                        severity=issue.get("issue_severity", "MEDIUM"),
                        confidence=issue.get("issue_confidence", "MEDIUM"),
                        issue_type=issue.get("test_id", "UNKNOWN"),
                        file_path=issue.get("filename", ""),
                        line_number=issue.get("line_number", 0),
                        code_snippet=issue.get("code", ""),
                        description=issue.get("issue_text", ""),
                        cwe_id=issue.get("cwe", {}).get("id"),
                        tool="bandit"
                    ))
                
                logger.info(f"Bandit found {len(findings)} issues")
        
        except subprocess.TimeoutExpired:
            logger.error("Bandit scan timed out")
        except Exception as e:
            logger.error(f"Bandit scan failed: {e}")
        
        return findings


class SafetyScanner:
    """
    Wrapper for Safety - Python dependency vulnerability checker
    """
    
    def scan(self, repo_path: str) -> List[SecurityFinding]:
        """Scan Python dependencies for known vulnerabilities"""
        findings = []
        
        # Look for requirements files
        req_files = [
            Path(repo_path) / "requirements.txt",
            Path(repo_path) / "Pipfile",
            Path(repo_path) / "pyproject.toml",
        ]
        
        for req_file in req_files:
            if not req_file.exists():
                continue
            
            try:
                result = subprocess.run(
                    ["safety", "check", "--file", str(req_file), "--json"],
                    capture_output=True,
                    text=True,
                    timeout=60
                )
                
                if result.stdout:
                    data = json.loads(result.stdout)
                    
                    for vuln in data:
                        findings.append(SecurityFinding(
                            severity="HIGH",
                            confidence="HIGH",
                            issue_type="VULNERABLE_DEPENDENCY",
                            file_path=str(req_file),
                            line_number=0,
                            code_snippet=vuln.get("package", ""),
                            description=f"{vuln.get('package')} {vuln.get('installed_version')} has known vulnerability: {vuln.get('vulnerability')}",
                            cwe_id=vuln.get("cve"),
                            tool="safety"
                        ))
                
                logger.info(f"Safety found {len(findings)} vulnerable dependencies")
            
            except Exception as e:
                logger.error(f"Safety scan failed for {req_file}: {e}")
        
        return findings


class SecretScanner:
    """
    Detect hardcoded secrets, API keys, passwords
    """
    
    SECRET_PATTERNS = [
        (r'password\s*=\s*["\']([^"\']+)["\']', "HARDCODED_PASSWORD"),
        (r'api[_-]?key\s*=\s*["\']([^"\']+)["\']', "HARDCODED_API_KEY"),
        (r'secret[_-]?key\s*=\s*["\']([^"\']+)["\']', "HARDCODED_SECRET"),
        (r'token\s*=\s*["\']([^"\']+)["\']', "HARDCODED_TOKEN"),
        (r'aws[_-]?access[_-]?key[_-]?id\s*=\s*["\']([^"\']+)["\']', "AWS_KEY"),
        (r'AKIA[0-9A-Z]{16}', "AWS_ACCESS_KEY"),
        (r'sk-[a-zA-Z0-9]{48}', "OPENAI_API_KEY"),
        (r'ghp_[a-zA-Z0-9]{36}', "GITHUB_TOKEN"),
    ]
    
    def scan(self, repo_path: str) -> List[SecurityFinding]:
        """Scan for hardcoded secrets"""
        findings = []
        
        try:
            result = subprocess.run(
                ["detect-secrets", "scan", repo_path, "--json"],
                capture_output=True,
                text=True,
                timeout=120
            )
            
            if result.stdout:
                data = json.loads(result.stdout)
                
                for file_path, secrets in data.get("results", {}).items():
                    for secret in secrets:
                        findings.append(SecurityFinding(
                            severity="HIGH",
                            confidence="MEDIUM",
                            issue_type="HARDCODED_SECRET",
                            file_path=file_path,
                            line_number=secret.get("line_number", 0),
                            code_snippet="[REDACTED]",
                            description=f"Potential secret detected: {secret.get('type')}",
                            tool="detect-secrets"
                        ))
            
            logger.info(f"Secret scanner found {len(findings)} potential secrets")
        
        except Exception as e:
            logger.error(f"Secret scanning failed: {e}")
        
        return findings


class ASTAnalyzer:
    """
    Custom AST-based security analyzer for Python
    Detects SQL injection, command injection, path traversal, etc.
    """
    
    DANGEROUS_FUNCTIONS = {
        'eval': 'CODE_INJECTION',
        'exec': 'CODE_INJECTION',
        'compile': 'CODE_INJECTION',
        '__import__': 'CODE_INJECTION',
        'os.system': 'COMMAND_INJECTION',
        'subprocess.call': 'COMMAND_INJECTION',
        'subprocess.run': 'COMMAND_INJECTION',
        'subprocess.Popen': 'COMMAND_INJECTION',
    }
    
    def scan(self, repo_path: str) -> List[SecurityFinding]:
        """Analyze Python files using AST"""
        findings = []
        
        python_files = list(Path(repo_path).rglob("*.py"))
        
        for file_path in python_files:
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    code = f.read()
                
                tree = ast.parse(code, filename=str(file_path))
                findings.extend(self._analyze_tree(tree, file_path, code))
            
            except SyntaxError:
                logger.debug(f"Syntax error in {file_path}, skipping")
            except Exception as e:
                logger.debug(f"Error analyzing {file_path}: {e}")
        
        logger.info(f"AST analyzer found {len(findings)} issues")
        return findings
    
    def _analyze_tree(self, tree: ast.AST, file_path: Path, code: str) -> List[SecurityFinding]:
        """Analyze AST for security issues"""
        findings = []
        
        for node in ast.walk(tree):
            # Check for dangerous function calls
            if isinstance(node, ast.Call):
                func_name = self._get_function_name(node.func)
                
                if func_name in self.DANGEROUS_FUNCTIONS:
                    findings.append(SecurityFinding(
                        severity="HIGH",
                        confidence="HIGH",
                        issue_type=self.DANGEROUS_FUNCTIONS[func_name],
                        file_path=str(file_path),
                        line_number=node.lineno,
                        code_snippet=self._get_code_snippet(code, node.lineno),
                        description=f"Dangerous function call: {func_name}",
                        tool="ast_analyzer"
                    ))
                
                # Check for SQL injection patterns
                if func_name in ['execute', 'executemany', 'raw']:
                    if self._has_string_formatting(node):
                        findings.append(SecurityFinding(
                            severity="HIGH",
                            confidence="MEDIUM",
                            issue_type="SQL_INJECTION",
                            file_path=str(file_path),
                            line_number=node.lineno,
                            code_snippet=self._get_code_snippet(code, node.lineno),
                            description="Potential SQL injection: string formatting in query",
                            cwe_id="CWE-89",
                            tool="ast_analyzer"
                        ))
            
            # Check for insecure deserialization
            if isinstance(node, ast.Call):
                func_name = self._get_function_name(node.func)
                if func_name in ['pickle.loads', 'yaml.load', 'marshal.loads']:
                    findings.append(SecurityFinding(
                        severity="HIGH",
                        confidence="HIGH",
                        issue_type="INSECURE_DESERIALIZATION",
                        file_path=str(file_path),
                        line_number=node.lineno,
                        code_snippet=self._get_code_snippet(code, node.lineno),
                        description=f"Insecure deserialization: {func_name}",
                        cwe_id="CWE-502",
                        tool="ast_analyzer"
                    ))
        
        return findings
    
    def _get_function_name(self, node: ast.AST) -> str:
        """Extract function name from AST node"""
        if isinstance(node, ast.Name):
            return node.id
        elif isinstance(node, ast.Attribute):
            value = self._get_function_name(node.value)
            return f"{value}.{node.attr}" if value else node.attr
        return ""
    
    def _has_string_formatting(self, node: ast.Call) -> bool:
        """Check if call uses string formatting (potential injection)"""
        for arg in node.args:
            if isinstance(arg, (ast.BinOp, ast.JoinedStr, ast.FormattedValue)):
                return True
            if isinstance(arg, ast.Call):
                func_name = self._get_function_name(arg.func)
                if 'format' in func_name:
                    return True
        return False
    
    def _get_code_snippet(self, code: str, line_number: int, context=2) -> str:
        """Extract code snippet around line number"""
        lines = code.split('\n')
        start = max(0, line_number - context - 1)
        end = min(len(lines), line_number + context)
        return '\n'.join(lines[start:end])


class FastAPIAnalyzer:
    """
    FastAPI-specific security analyzer
    """
    
    def scan(self, repo_path: str) -> List[SecurityFinding]:
        """Analyze FastAPI applications for security issues"""
        findings = []
        
        python_files = list(Path(repo_path).rglob("*.py"))
        
        for file_path in python_files:
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    code = f.read()
                
                # Check for missing authentication
                if '@app.' in code or '@router.' in code:
                    if 'Depends(' not in code and 'Security(' not in code:
                        findings.append(SecurityFinding(
                            severity="MEDIUM",
                            confidence="LOW",
                            issue_type="MISSING_AUTHENTICATION",
                            file_path=str(file_path),
                            line_number=0,
                            code_snippet="",
                            description="FastAPI endpoints without authentication dependencies",
                            tool="fastapi_analyzer"
                        ))
                
                # Check for missing input validation
                if 'Query(' in code or 'Path(' in code or 'Body(' in code:
                    if 'validator' not in code.lower() and 'Field(' not in code:
                        findings.append(SecurityFinding(
                            severity="MEDIUM",
                            confidence="LOW",
                            issue_type="MISSING_INPUT_VALIDATION",
                            file_path=str(file_path),
                            line_number=0,
                            code_snippet="",
                            description="FastAPI parameters without validation",
                            tool="fastapi_analyzer"
                        ))
                
                # Check for CORS misconfiguration
                if 'CORSMiddleware' in code and 'allow_origins=["*"]' in code:
                    findings.append(SecurityFinding(
                        severity="MEDIUM",
                        confidence="HIGH",
                        issue_type="CORS_MISCONFIGURATION",
                        file_path=str(file_path),
                        line_number=0,
                        code_snippet="",
                        description="CORS allows all origins (*)",
                        cwe_id="CWE-942",
                        tool="fastapi_analyzer"
                    ))
            
            except Exception as e:
                logger.debug(f"Error analyzing FastAPI file {file_path}: {e}")
        
        logger.info(f"FastAPI analyzer found {len(findings)} issues")
        return findings


class SASTOrchestrator:
    """
    Orchestrates all SAST tools
    """
    
    def __init__(self):
        self.bandit = BanditScanner()
        self.safety = SafetyScanner()
        self.secrets = SecretScanner()
        self.ast_analyzer = ASTAnalyzer()
        self.fastapi_analyzer = FastAPIAnalyzer()
    
    def run_all_scans(self, repo_path: str) -> List[SecurityFinding]:
        """Run all SAST tools and aggregate findings"""
        all_findings = []
        
        logger.info("Starting comprehensive SAST scan")
        
        # Run all scanners
        all_findings.extend(self.bandit.scan(repo_path))
        all_findings.extend(self.safety.scan(repo_path))
        all_findings.extend(self.secrets.scan(repo_path))
        all_findings.extend(self.ast_analyzer.scan(repo_path))
        all_findings.extend(self.fastapi_analyzer.scan(repo_path))
        
        # Deduplicate findings
        all_findings = self._deduplicate(all_findings)
        
        logger.info(f"SAST scan complete: {len(all_findings)} unique findings")
        
        return all_findings
    
    def _deduplicate(self, findings: List[SecurityFinding]) -> List[SecurityFinding]:
        """Remove duplicate findings"""
        seen = set()
        unique_findings = []
        
        for finding in findings:
            key = (finding.file_path, finding.line_number, finding.issue_type)
            if key not in seen:
                seen.add(key)
                unique_findings.append(finding)
        
        return unique_findings
