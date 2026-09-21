from typing import Dict, Any, List


SENSITIVE_KEYWORDS = [
    "refund",
    "payment",
    "transfer",
    "admin",
    "delete",
    "update",
    "password",
    "reset",
    "otp",
]


def normalize_endpoint(raw: Dict[str, Any]) -> Dict[str, Any]:
    """
    Normalize raw endpoint info into a standard structure.
    """
    return {
        "path": raw.get("path") or raw.get("file"),
        "method": raw.get("method", "UNKNOWN"),
        "auth_required": raw.get("auth_required", False),
        "roles": raw.get("roles", []),
    }


def is_sensitive_operation(endpoint: Dict[str, Any]) -> bool:
    """
    Identify sensitive operations using conservative heuristics.
    """
    path = (endpoint.get("path") or "").lower()
    return any(keyword in path for keyword in SENSITIVE_KEYWORDS)


def build_api_map(
    endpoints: List[Dict[str, Any]],
    auth_files: List[str],
) -> Dict[str, Any]:
    """
    Build a structured API map keyed by endpoint path.
    """
    api_map: Dict[str, Any] = {}

    for ep in endpoints:
        normalized = normalize_endpoint(ep)
        path = normalized["path"]

        normalized["auth_required"] = any(
            auth_file in path for auth_file in auth_files
        )

        api_map[path] = normalized

    return api_map
