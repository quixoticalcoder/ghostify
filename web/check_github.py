"""Check public Git transport at startup without credentials or source execution."""
import os
import subprocess
import tempfile

with tempfile.TemporaryDirectory(prefix='ghostify-probe-') as tmp:
    env = os.environ.copy()
    env['GIT_TERMINAL_PROMPT'] = '0'
    try:
        result = subprocess.run(
            ['git', 'clone', '--depth=1', 'https://github.com/quixoticalcoder/ghostify', tmp + '/repo'],
            capture_output=True, text=True, timeout=45, env=env,
        )
        print('Ghostify Git transport check:', result.returncode, flush=True)
        if result.returncode:
            print(result.stderr[:1600], flush=True)
    except subprocess.TimeoutExpired:
        print('Ghostify Git transport check: timeout', flush=True)
