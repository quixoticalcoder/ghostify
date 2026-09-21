import os
import pprint
import pytest

from app.agentic.graph.audit_graph import audit_app
from app.core.logging import setup_logging, logger
from app.services.github import GitHubService


@pytest.mark.integration
def test_full_audit_graph_execution():
    """
    Integration test for the complete agentic audit graph.
    """

    setup_logging()

    # -------------------------------
    # Test inputs
    # -------------------------------
    repo_url = os.getenv(
        "TEST_REPO_URL",
        "https://github.com/code-YK/Autonomous-Quiz-Agent"
    )

    api_base_url = os.getenv(
        "TEST_API_BASE_URL",
        None
    )

    commit_hash = os.getenv("TEST_COMMIT_HASH")

    logger.info("Starting integration test for Ghostify")

    # -------------------------------
    # Clone repository
    # -------------------------------
    github = GitHubService(
        repo_url=repo_url,
        commit_hash=commit_hash,
    )

    repo_path = github.clone()

    try:
        # -------------------------------
        # Initial LangGraph state
        # -------------------------------
        initial_state = {
            "repo_url": repo_url,
            "commit_hash": commit_hash,
            "repo_path": repo_path,
            "api_base_url": api_base_url,
        }

        # -------------------------------
        # Run LangGraph
        # -------------------------------
        result = audit_app.invoke(initial_state)

        # -------------------------------
        # Assertions (minimum guarantees)
        # -------------------------------
        assert "final_report" in result, "Final report missing"
        assert "severity_summary" in result, "Severity summary missing"

        report = result["final_report"]

        assert "summary" in report
        assert "vulnerabilities" in report

        logger.info("Audit graph executed successfully")

        print("\n====== FINAL REPORT ======\n")
        pprint.pprint(report)

    finally:
        github.cleanup()
