import json
import yaml
from pathlib import Path
from typing import Dict, Any, Optional
from app.core.logging import logger


class OpenAPIService:
    """
    Loads and parses OpenAPI specifications.
    """

    SUPPORTED_FILENAMES = {
        "openapi.yaml",
        "openapi.yml",
        "swagger.yaml",
        "swagger.yml",
        "openapi.json",
        "swagger.json",
    }

    @staticmethod
    def find_spec(repo_path: str) -> Optional[Path]:
        """
        Search repository for OpenAPI spec file.
        """
        for path in Path(repo_path).rglob("*"):
            if path.name.lower() in OpenAPIService.SUPPORTED_FILENAMES:
                logger.info(f"Found OpenAPI spec: {path}")
                return path
        return None

    @staticmethod
    def load_spec(spec_path: Path) -> Dict[str, Any]:
        """
        Load and parse OpenAPI spec file.
        """
        logger.info(f"Loading OpenAPI spec from {spec_path}")

        if spec_path.suffix in {".yaml", ".yml"}:
            return yaml.safe_load(spec_path.read_text())

        if spec_path.suffix == ".json":
            return json.loads(spec_path.read_text())

        raise ValueError("Unsupported OpenAPI file format")
