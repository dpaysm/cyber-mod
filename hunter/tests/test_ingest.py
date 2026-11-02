"""End-to-end ingest server test: real HTTP POST → SQLite."""

from __future__ import annotations

import base64
import json
import threading
import urllib.request

import pytest

from hunter.ingest import IngestServer


@pytest.fixture()
def server(tmp_path):
    srv = IngestServer(str(tmp_path / "hunter.db"), ["example.com"], port=0)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield srv
    srv.close()


def post(server, payload: dict) -> tuple[int, dict]:
    data = json.dumps(payload).encode()
    req = urllib.request.Request(
        f"http://127.0.0.1:{server.port}/ingest",
        data,
        {"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=5) as resp:
        return resp.status, json.loads(resp.read())


def payload_for(url: str, method: str = "GET", status: int = 200) -> dict:
    return {
        "method": method,
        "url": url,
        "req_headers": {"User-Agent": "burp-mirror"},
        "req_body_b64": "",
        "status": status,
        "resp_headers": {"Content-Type": "application/json"},
        "resp_body_b64": base64.b64encode(b'{"ok": true}').decode(),
    }


def test_ingest_saves_and_dedupes(server):
    code1, _ = post(server, payload_for("https://api.example.com/post/123"))
    code2, _ = post(server, payload_for("https://api.example.com/post/999"))
    assert code1 == 200 and code2 == 200

    rows = server.db.list_requests()
    assert len(rows) == 1
    assert rows[0]["path_template"] == "/post/{id}"
    assert rows[0]["count"] == 2


def test_ingest_rejects_out_of_scope_and_static(server):
    code_static, body_static = post(server, payload_for("https://example.com/app.js"))
    code_scope, body_scope = post(server, payload_for("https://evil.com/api"))
    assert code_static == 202 and body_static["reason"] == "static asset"
    assert code_scope == 202 and "out-of-scope" in body_scope["reason"]
    assert server.db.list_requests() == []


def test_ingest_post_always_new_row(server):
    post(server, payload_for("https://example.com/order", method="POST", status=201))
    post(server, payload_for("https://example.com/order", method="POST", status=201))
    assert len(server.db.list_requests()) == 2


def test_ingest_body_decoded(server):
    p = payload_for("https://example.com/api/me")
    p["resp_body_b64"] = base64.b64encode(b'{"role": "admin"}').decode()
    post(server, p)
    row = server.db.get_request(1)
    assert '"role": "admin"' in row["resp_body"]


def test_ingest_strips_port_from_host(server):
    post(server, payload_for("https://example.com:443/api/me"))
    rows = server.db.list_requests()
    assert rows[0]["host"] == "example.com"


def test_healthcheck(server):
    with urllib.request.urlopen(f"http://127.0.0.1:{server.port}/", timeout=5) as resp:
        body = json.loads(resp.read())
    assert body["service"] == "hunter-ingest"
