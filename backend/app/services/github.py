import os
import shutil
import tempfile
from typing import Optional
from git import Repo, GitCommandError
from app.core.logging import logger


class GitHubService:
    """
    Handles cloning and managing GitHub repositories.
    """

    def __init__(self, repo_url: str, commit_hash: Optional[str] = None):
        self.repo_url = repo_url
        self.commit_hash = commit_hash
        self._temp_dir = None

    def clone(self) -> str:
        """
        Clone the repository into a temporary directory.
        """
        self._temp_dir = tempfile.mkdtemp(prefix="ghostify_")
        try:
            logger.info(f"Cloning repository: {self.repo_url}")
            repo = Repo.clone_from(self.repo_url, self._temp_dir)

            if self.commit_hash:
                logger.info(f"Checking out commit: {self.commit_hash}")
                repo.git.checkout(self.commit_hash)

            return self._temp_dir

        except GitCommandError as e:
            self.cleanup()
            raise RuntimeError(f"Git clone failed: {e}")

    def cleanup(self):
        """
        Remove the temporary repository directory.
        Windows-safe cleanup.
        """
        if self._temp_dir and os.path.exists(self._temp_dir):
            try:
                shutil.rmtree(self._temp_dir, ignore_errors=True)
                logger.debug("Temporary repo directory cleaned up")
            except Exception as e:
                logger.warning(f"Cleanup failed: {e}")
