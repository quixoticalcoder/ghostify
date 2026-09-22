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
    except Exception as exc:
        detail = str(exc).lower()
        if 'api_key_invalid' in detail or 'api key not valid' in detail:
            message = 'Google rejected the API key. Update GOOGLE_API_KEY in Render.'
        elif '404' in detail or 'not found for api version' in detail:
            message = 'The configured Gemini model is unavailable for this API key. Update GEMINI_MODEL in Render.'
        elif '429' in detail or 'resource_exhausted' in detail or 'quota' in detail:
            message = 'Gemini quota is exhausted or unavailable for this project. Check Google AI Studio rate limits.'
        elif '403' in detail or 'permission_denied' in detail:
            message = 'Google denied access. Check the API key restrictions and project access in AI Studio.'
        elif 'certificate' in detail or 'ssl' in detail:
            message = 'HTTPS certificate validation failed while contacting GitHub or Google.'
        elif 'git clone failed' in detail:
            message = 'GitHub cloning failed. Check that the repository is public and accessible.'
        else:
            message = 'Audit processing failed (' + type(exc).__name__ + ').'
        Path(sys.argv[2]).write_text(json.dumps({'error': message}))
    finally:
        github.cleanup()


if __name__ == '__main__':
    main()
