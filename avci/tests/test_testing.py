"""Test engine tests: code extraction, scope/limit checks, execution, diff."""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from avci.testing import (
    check_script,
    extract_python,
    load_results,
    run_script,
    summarize,
)

SAMPLE_ANSWER = """\
Here is the script:

```python
import httpx

URL = "https://api.example.com/user/123"
print(URL)
```

Kolay gelsin.
"""


def test_extract_python_fenced():
    code = extract_python(SAMPLE_ANSWER)
    assert code is not None
    assert 'URL = "https://api.example.com/user/123"' in code
    assert "Here is the script" not in code


def test_extract_python_none():
    assert extract_python("kod yok, sadece muhabbet") is None


GOOD_SCRIPT = 'URL = "https://api.example.com/x"\nREPEAT = 5\nCONCURRENCY = 2\n'
BAD_SCRIPT = 'URL = "https://evil.com/x"\nREPEAT = 1\n'


def test_check_script_scope_enforced():
    ok = check_script(GOOD_SCRIPT, ["example.com"], 50)
    assert ok.allowed and ok.total_requests == 10 and not ok.over_limit

    bad = check_script(BAD_SCRIPT, ["example.com"], 50)
    assert not bad.allowed and "out-of-scope" in bad.reason

    over = check_script(GOOD_SCRIPT.replace("REPEAT = 5", "REPEAT = 60"), ["example.com"], 50)
    assert over.allowed and over.over_limit and over.total_requests == 120


def test_check_script_subdomain_allowed():
    ok = check_script('URL = "https://api.example.com/x"', ["example.com"], 50)
    assert ok.allowed


class _ApiHandler(BaseHTTPRequestHandler):
    def log_message(self, *_a) -> None:
        pass

    def do_GET(self) -> None:
        body = json.dumps({"id": 1, "role": "admin"}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


RUNNABLE_SCRIPT = """\
import json, time, httpx

URL = "{url}"
METHOD = "GET"
HEADERS = {{}}
BODY = ""
REPEAT = 3
CONCURRENCY = 1

with open("results.jsonl", "w") as f:
    for i in range(REPEAT):
        t0 = time.time()
        r = httpx.get(URL, headers=HEADERS, timeout=10)
        f.write(json.dumps({{"i": i, "status": r.status_code,
                            "elapsed_ms": (time.time()-t0)*1000,
                            "body": r.text[:2000]}}) + "\\n")
"""


@pytest.fixture()
def api_server():
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _ApiHandler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{srv.server_address[1]}"
    srv.shutdown()


def test_run_script_end_to_end(api_server, tmp_path):
    script = RUNNABLE_SCRIPT.format(url=api_server + "/user/1")
    result = run_script(script, request_id=1, runs_root=tmp_path / "runs")
    assert result.ok, result.error or result.stderr_tail
    results = load_results(result.run_dir)
    assert len(results) == 3
    assert all(r.status == 200 for r in results)


def test_run_script_failure_captured(tmp_path):
    result = run_script("raise SystemExit(3)", request_id=9, runs_root=tmp_path / "runs")
    assert not result.ok
    assert "error code" in (result.error or "")


def test_summarize_flags_changes():
    from avci.testing.diff import AttemptResult

    results = [
        AttemptResult(i=0, status=200, elapsed_ms=10, body='{"id": 1, "role": "user"}'),
        AttemptResult(i=1, status=403, elapsed_ms=12, body='{"error": "denied"}'),
    ]
    text = summarize(200, '{"id": 1, "role": "user"}', results)
    assert "BASELINE: status=200" in text
    assert "STATUS CHANGED (200 → 403)" in text
    assert "field diff" in text
    assert "STATUS DISTRIBUTION" in text
