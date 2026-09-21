from langchain_core.language_models.chat_models import BaseChatModel
from app.core.config import settings
from app.core.logging import logger


_llm_instance: BaseChatModel | None = None


def get_llm() -> BaseChatModel:
    """
    Returns a singleton LLM instance configured for planner-only reasoning.
    Supports both Google Gemini and Groq based on LLM_PROVIDER setting.
    
    This is the ONLY place where an LLM is initialized.
    """
    global _llm_instance

    if _llm_instance is not None:
        return _llm_instance

    provider = settings.LLM_PROVIDER.lower()
    
    if provider == "gemini":
        logger.info("Initializing Google Gemini LLM (planner-only)")
        
        if not settings.GOOGLE_API_KEY:
            raise ValueError(
                "GOOGLE_API_KEY not set in environment. "
                "Please set it in your .env file or environment variables."
            )
        
        from langchain_google_genai import ChatGoogleGenerativeAI
        
        # langchain-google-genai uses simple model names without "models/" prefix
        llm = ChatGoogleGenerativeAI(
            model=settings.GEMINI_MODEL,
            google_api_key=settings.GOOGLE_API_KEY.get_secret_value(),
            temperature=settings.GEMINI_TEMPERATURE,
            max_output_tokens=settings.GEMINI_MAX_TOKENS,
            convert_system_message_to_human=True,  # Required for some models
        )
        
    elif provider == "groq":
        logger.info("Initializing Groq LLM (planner-only)")
        
        if not settings.GROQ_API_KEY:
            raise ValueError(
                "GROQ_API_KEY not set in environment. "
                "Please set it in your .env file or environment variables."
            )
        
        from langchain_groq import ChatGroq
        
        llm = ChatGroq(
            api_key=settings.GROQ_API_KEY.get_secret_value(),
            model=settings.GROQ_MODEL,
            temperature=settings.GROQ_TEMPERATURE,
            max_tokens=settings.GROQ_MAX_TOKENS,
        )
        
    else:
        raise ValueError(
            f"Unsupported LLM provider: {provider}. "
            f"Supported providers: 'gemini', 'groq'"
        )

    _llm_instance = llm
    logger.info(f"LLM initialized successfully: {provider} - {llm.__class__.__name__}")
    return _llm_instance
