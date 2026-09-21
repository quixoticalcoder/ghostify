from typing import List
from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import Field, SecretStr


class Settings(BaseSettings):
    """
    Central configuration for Ghostify.
    Loaded from environment variables or .env file.
    """

    # ===============================
    # GENERAL
    # ===============================
    ENV: str = Field(default="development")
    DEBUG: bool = Field(default=False)
    LOG_LEVEL: str = Field(default="INFO")

    # ===============================
    # FASTAPI
    # ===============================
    APP_NAME: str = Field(default="Ghostify")
    API_HOST: str = Field(default="0.0.0.0")
    API_PORT: int = Field(default=8000)

    # ===============================
    # LLM Configuration (Planner Only)
    # ===============================
    # Choose LLM provider: "gemini" or "groq"
    LLM_PROVIDER: str = Field(default="gemini")
    
    # Google Gemini Configuration
    GOOGLE_API_KEY: SecretStr | None = None
    GEMINI_MODEL: str = Field(default="gemini-2.0-flash-exp")
    GEMINI_TEMPERATURE: float = Field(default=0.2, ge=0.0, le=2.0)
    GEMINI_MAX_TOKENS: int = Field(default=8192, gt=0)
    
    # Groq Configuration (fallback/alternative)
    GROQ_API_KEY: SecretStr | None = None
    GROQ_MODEL: str = Field(default="llama-3.1-70b-versatile")
    GROQ_TEMPERATURE: float = Field(default=0.2, ge=0.0, le=1.0)
    GROQ_MAX_TOKENS: int = Field(default=2000, gt=0)

    # ===============================
    # LANGSMITH (TRACING)
    # ===============================
    LANGCHAIN_TRACING_V2: bool = Field(default=True)
    LANGCHAIN_PROJECT: str = Field(default="ghostify")
    LANGCHAIN_API_KEY: SecretStr | None = None
    LANGCHAIN_ENDPOINT: str = Field(
        default="https://api.smith.langchain.com"
    )

    # ===============================
    # GITHUB
    # ===============================
    GITHUB_TOKEN: SecretStr | None = None

    # ===============================
    # SAFETY LIMITS
    # ===============================
    MAX_ATTACKS_PER_ENDPOINT: int = Field(default=5, gt=0)
    MAX_REQUESTS_PER_MINUTE: int = Field(default=60, gt=0)
    ATTACK_TIMEOUT_SECONDS: int = Field(default=10, gt=0)

    # ===============================
    # RATE ABUSE CONFIG
    # ===============================
    RATE_TEST_WINDOW_SECONDS: int = Field(default=60, gt=0)
    RATE_TEST_MAX_REQUESTS: int = Field(default=20, gt=0)

    # ===============================
    # STORAGE
    # ===============================
    REPORT_OUTPUT_DIR: str = Field(default="./reports")

    # ===============================
    # SECURITY
    # ===============================
    INTERNAL_API_KEY: SecretStr | None = Field(default=None)
    ALLOWED_TARGET_DOMAINS: List[str] = Field(
        default_factory=lambda: ["localhost", "127.0.0.1"]
    )

    # ===============================
    # Pydantic Settings Config
    # ===============================
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=True,
    )


# Singleton-style access (import-safe)
settings = Settings()
