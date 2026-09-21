from typing import TypedDict, List, Dict, Any


class Endpoint(TypedDict):
    path: str
    method: str
    auth_required: bool
    roles: List[str]


class AttackExecutionResult(TypedDict):
    attack_type: str
    endpoint: str
    success: bool
    status_code: int
    evidence: Dict[str, Any]


class Vulnerability(TypedDict):
    title: str
    severity: str
    description: str
    affected_endpoint: str
    attack_chain: List[str]
    evidence: Dict[str, Any]
    remediation: str
