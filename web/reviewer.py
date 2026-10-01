"""Process-wide allowance for the free public reviewer demo."""
import threading
import time

_LOCK = threading.Lock()
_started = 0.0
_used = 0


def reserve_audit() -> None:
    global _started, _used
    with _LOCK:
        now = time.monotonic()
        if now - _started >= 86400:
            _started, _used = now, 0
        if _used >= 10:
            raise RuntimeError('The shared reviewer allowance is used up. Please try again after the 24-hour window resets.')
        _used += 1
