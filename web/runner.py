"""Run one source-only audit in a bounded, isolated worker process."""
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import sys
import tempfile
import threading

ROOT = Path(__file__).resolve().parents[1]
_LOCK = threading.Lock()


def validate_repository(url: str) -> str:
    match = re.fullmatch(r'https://github\.com/([A-Za-z0-9-]+)/([A-Za-z0-9_.-]+)/?', url.strip())
    if not match:
        raise ValueError('Enter a public GitHub repository URL, without query parameters or credentials.')
    owner, name = match.groups()
    name = name.removesuffix('.git')
    if name in {'', '.', '..'}:
        raise ValueError('Enter a repository name.')
    allowed = {s.strip().lower() for s in os.getenv('GHOSTIFY_ALLOWED_OWNERS', 'quixoticalcoder').split(',') if s.strip()}
    if owner.lower() not in allowed:
        raise ValueError('This deployment only accepts repositories from its configured GitHub owners.')
    return f'https://github.com/{owner}/{name}'


def run_audit(url: str) -> dict:
    url = validate_repository(url)
    if not _LOCK.acquire(blocking=False):
        raise RuntimeError('Another audit is running. Please try again after it finishes.')
    try:
        with tempfile.TemporaryDirectory(prefix='ghostify-web-') as tmp:
            env = os.environ.copy()
            env['PYTHONPATH'] = str(ROOT / 'backend')
            env['TMPDIR'] = tmp
            env['LANGCHAIN_TRACING_V2'] = 'false'
            env['LANGSMITH_TRACING'] = 'false'
            env['GIT_TERMINAL_PROMPT'] = '0'
            result_path = Path(tmp) / 'result.json'
            with open(Path(tmp) / 'worker.log', 'w') as log:
                process = subprocess.Popen(
                    [sys.executable, str(ROOT / 'web/worker.py'), url, str(result_path)],
                    cwd=ROOT, env=env, stdout=log, stderr=log, start_new_session=True,
                )
                try:
                    process.wait(timeout=600)
                except subprocess.TimeoutExpired:
                    os.killpg(process.pid, signal.SIGKILL)
                    process.wait()
                    raise RuntimeError('The audit exceeded ten minutes. Try a smaller repository.') from None
            if process.returncode or not result_path.exists():
                raise RuntimeError('Audit failed. Check the repository, Gemini key and model access. Scanner or provider availability may also be the cause.')
            return json.loads(result_path.read_text())
    finally:
        _LOCK.release()
