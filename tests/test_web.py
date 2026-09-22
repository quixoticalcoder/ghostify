import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import pytest
from streamlit.testing.v1 import AppTest
from web import runner


@pytest.mark.parametrize('url', [
    'http://github.com/quixoticalcoder/ghostify',
    'https://github.com.evil.test/quixoticalcoder/ghostify',
    'https://github.com/another-owner/project',
    'https://github.com/quixoticalcoder/ghostify?x=1',
    'https://user:password@github.com/quixoticalcoder/ghostify',
    'file:///tmp/repository',
])
def test_rejects_out_of_scope_repositories(url, monkeypatch):
    monkeypatch.setenv('GHOSTIFY_ALLOWED_OWNERS', 'quixoticalcoder')
    with pytest.raises(ValueError):
        runner.validate_repository(url)


def test_normalizes_allowed_url(monkeypatch):
    monkeypatch.setenv('GHOSTIFY_ALLOWED_OWNERS', 'quixoticalcoder')
    assert runner.validate_repository(' https://github.com/quixoticalcoder/ghostify.git/ ') == 'https://github.com/quixoticalcoder/ghostify'


def test_worker_returns_report_and_cleans_up(monkeypatch):
    paths = []
    def launch(args, **kwargs):
        result = Path(args[-1])
        paths.append(result.parent)
        result.write_text(json.dumps({'report': {'summary': {}}}))
        assert kwargs['env']['LANGCHAIN_TRACING_V2'] == 'false'
        assert kwargs['env']['GIT_TERMINAL_PROMPT'] == '0'
        return SimpleNamespace(returncode=0, wait=lambda **kw: None)
    monkeypatch.setattr(runner.subprocess, 'Popen', launch)
    assert 'report' in runner.run_audit('https://github.com/quixoticalcoder/ghostify')
    assert not paths[0].exists()


def test_timeout_kills_process_group_and_releases_lock(monkeypatch):
    process = Mock(pid=12345)
    process.wait.side_effect = [runner.subprocess.TimeoutExpired('worker', 600), 0]
    monkeypatch.setattr(runner.subprocess, 'Popen', Mock(return_value=process))
    kill = Mock()
    monkeypatch.setattr(runner.os, 'killpg', kill)
    with pytest.raises(RuntimeError, match='ten minutes'):
        runner.run_audit('https://github.com/quixoticalcoder/ghostify')
    kill.assert_called_once_with(12345, runner.signal.SIGKILL)
    assert not runner._LOCK.locked()


def test_ui_requires_password_then_displays_report(monkeypatch):
    monkeypatch.setenv('GHOSTIFY_ACCESS_PASSWORD', 'test-password')
    monkeypatch.setenv('GOOGLE_API_KEY', 'test-key')
    fake = Mock(return_value={'repository': 'https://github.com/quixoticalcoder/ghostify', 'report': {'summary': {'total_vulnerabilities': 2}}, 'summary': 'Example test summary'})
    monkeypatch.setattr(runner, 'run_audit', fake)
    app = AppTest.from_file(Path(__file__).resolve().parents[1] / 'streamlit_app.py').run()
    assert not app.exception
    app.text_input[0].set_value('wrong')
    app.button[0].click().run()
    assert app.error[0].value == 'Incorrect password.'
    fake.assert_not_called()
    app.text_input[0].set_value('test-password')
    app.button[0].click().run()
    app.text_input[0].set_value('https://github.com/quixoticalcoder/ghostify')
    app.checkbox[0].check()
    next(b for b in app.button if b.label == 'Analyze repository').click().run()
    assert not app.exception
    assert app.metric[0].value == '2'
    assert app.text[0].value == 'Example test summary'
    fake.assert_called_once()


def test_ui_fails_closed_without_password(monkeypatch):
    monkeypatch.delenv('GHOSTIFY_ACCESS_PASSWORD', raising=False)
    app = AppTest.from_file(Path(__file__).resolve().parents[1] / 'streamlit_app.py').run()
    assert not app.exception
    assert 'setup is incomplete' in app.info[0].value
    assert len(app.text_input) == 0
