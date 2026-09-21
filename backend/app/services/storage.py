import json
import os
from datetime import datetime
from typing import Dict, Any
from app.core.config import settings
from app.core.logging import logger


class StorageService:
    """
    Handles persistence of audit outputs.
    """

    @staticmethod
    def save_report(report: Dict[str, Any]) -> str:
        os.makedirs(settings.REPORT_OUTPUT_DIR, exist_ok=True)

        timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        filename = f"audit_report_{timestamp}.json"
        path = os.path.join(settings.REPORT_OUTPUT_DIR, filename)

        with open(path, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2)

        logger.info(f"Report saved at {path}")
        return path
