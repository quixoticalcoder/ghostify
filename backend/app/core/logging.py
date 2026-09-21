import sys
from loguru import logger
from app.core.config import settings


def setup_logging():
    """
    Configure Loguru for the entire application.
    """
    logger.remove()

    logger.add(
        sys.stdout,
        level=settings.LOG_LEVEL,
        format=(
            "<green>{time:YYYY-MM-DD HH:mm:ss}</green> | "
            "<level>{level}</level> | "
            "<cyan>{name}</cyan>:<cyan>{function}</cyan>:<cyan>{line}</cyan> | "
            "{message}"
        ),
        enqueue=True,
    )

    if settings.DEBUG:
        logger.debug("Debug logging enabled")


__all__ = ["logger", "setup_logging"]