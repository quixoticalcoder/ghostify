import re
from pathlib import Path
from typing import List, Dict, Any
from app.agentic.agents.code_scanner.rules import (
    ENDPOINT_PATTERNS,
    AUTH_PATTERNS,
    SECURITY_CONTROL_KEYWORDS,
)


def scan_file_for_patterns(file_path: Path) -> Dict[str, Any]:
    """
    Scan a single source file for endpoints and security signals.
    """
    text = file_path.read_text(errors="ignore")

    endpoints = any(re.search(p, text) for p in ENDPOINT_PATTERNS)
    auth_used = any(re.search(p, text) for p in AUTH_PATTERNS)

    missing_controls = [
        kw for kw in SECURITY_CONTROL_KEYWORDS if kw not in text
    ]

    return {
        "file": str(file_path),
        "has_endpoint": endpoints,
        "auth_detected": auth_used,
        "missing_controls": missing_controls,
    }


def collect_source_files(repo_path: str) -> List[Path]:
    """
    Collect relevant source files for scanning.
    """
    exts = {".py", ".js", ".ts", ".java"}
    return [
        p for p in Path(repo_path).rglob("*")
        if p.suffix in exts and p.is_file()
    ]
