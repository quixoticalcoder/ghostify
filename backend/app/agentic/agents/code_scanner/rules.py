# Common patterns indicating HTTP endpoints
ENDPOINT_PATTERNS = [
    r"@app\.route",
    r"@router\.(get|post|put|delete|patch)",
    r"app\.(get|post|put|delete|patch)\(",
    r"router\.(get|post|put|delete|patch)\(",
    r"@RequestMapping",
    r"@GetMapping",
    r"@PostMapping",
]

# Common authentication / authorization indicators
AUTH_PATTERNS = [
    r"@login_required",
    r"@requires_auth",
    r"Depends\(get_current_user",
    r"verify_jwt",
    r"authMiddleware",
    r"passport\.authenticate",
]

# Security controls that are often missing
SECURITY_CONTROL_KEYWORDS = [
    "rate_limit",
    "csrf",
    "role_check",
    "permission",
    "ownership",
]
