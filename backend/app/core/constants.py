# ===============================
# AGENT NAMES (LangGraph Nodes)
# ===============================
CODE_SCANNER_AGENT = "code_scanner"
API_MAPPER_AGENT = "api_mapper"
LOGIC_REASONER_AGENT = "logic_reasoner"
ATTACK_EXECUTOR_AGENT = "attack_executor"
VALIDATOR_AGENT = "validator"
REPORTER_AGENT = "reporter"
CODE_FIXER_AGENT = "code_fixer"
SUMMARY_GENERATOR_AGENT = "summary_generator"

# ===============================
# ATTACK TYPES (Deterministic)
# ===============================
ATTACK_IDOR = "IDOR"
ATTACK_AUTH_BYPASS = "AUTH_BYPASS"
ATTACK_LOGIC_REPLAY = "LOGIC_REPLAY"
ATTACK_RATE_ABUSE = "RATE_ABUSE"

SUPPORTED_ATTACK_TYPES = {
    ATTACK_IDOR,
    ATTACK_AUTH_BYPASS,
    ATTACK_LOGIC_REPLAY,
    ATTACK_RATE_ABUSE,
}

# ===============================
# SEVERITY LEVELS
# ===============================
SEVERITY_CRITICAL = "Critical"
SEVERITY_HIGH = "High"
SEVERITY_MEDIUM = "Medium"
SEVERITY_LOW = "Low"

SEVERITY_ORDER = [
    SEVERITY_CRITICAL,
    SEVERITY_HIGH,
    SEVERITY_MEDIUM,
    SEVERITY_LOW,
]
