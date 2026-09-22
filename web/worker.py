"""Worker entry point. Public deployment never accepts a target API URL."""
import json
from pathlib import Path
import sys
from app.agentic.graph.audit_graph import summary_app
from app.services.github import GitHubService


def main():
    github = GitHubService(sys.argv[1])
    try:
        result = summary_app.invoke({
            'repo_url': sys.argv[1], 'repo_path': github.clone(),
            'commit_hash': None, 'api_base_url': None,
        })
        Path(sys.argv[2]).write_text(json.dumps({
            'repository': sys.argv[1],
            'report': result['final_report'],
            'summary': result.get('security_summary', ''),
        }, default=str))
    finally:
        github.cleanup()


if __name__ == '__main__':
    main()
