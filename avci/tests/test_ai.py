"""AI client + engine tests with a fake OpenAI-compatible server."""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from avci.ai import AIEngine, AIError, ChatClient, build_request_context, parse_suspicion
from avci.config import ModelConfig
from avci.db import Database
from avci.normalize import dedupe_key


class _StubHandler(BaseHTTPRequestHandler):
    """POST /v1/chat/completions → fixed reply; stores the incoming payload."""

    last_payload: dict = {}
    reply_text = "PARAMETER: id → SUSPICION: IDOR → …\nSUSPICION_SCORE: 7"

    def log_message(self, *_a) -> None:
        pass

    def do_POST(self) -> None:
        length = int(self.headers.get("Content-Length") or 0)
        type(self).last_payload = json.loads(self.rfile.read(length))
        body = json.dumps(
            {"choices": [{"message": {"role": "assistant", "content": self.reply_text}}]}
        ).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


@pytest.fixture()
def stub_server():
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _StubHandler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{srv.server_address[1]}/v1"
    srv.shutdown()


@pytest.fixture()
def seeded_row(tmp_path):
    db = Database(tmp_path / "avci.db")
    rid, _ = db.record_exchange(
        method="GET", host="api.example.com",
        url="https://api.example.com/user/123", path_raw="/user/123",
        path_template="/user/{id}", query_keys="",
        dedupe_key=dedupe_key("GET", "api.example.com", "/user/{id}", ""),
        req_headers='{"Authorization": "Bearer abc"}', req_body="",
        status=200, resp_headers='{"Content-Type": "application/json"}',
        resp_body='{"id": 123, "role": "user"}',
    )
    row = db.get_request(rid)
    yield row
    db.close()


def test_client_chat_success(stub_server):
    client = ChatClient(stub_server, "test-model", api_key="k")
    out = client.chat([{"role": "user", "content": "selam"}])
    assert "SUSPICION_SCORE" in out
    sent = _StubHandler.last_payload
    assert sent["model"] == "test-model"
    assert sent["messages"][0]["content"] == "selam"


def test_client_connect_error_is_aierror():
    client = ChatClient("http://127.0.0.1:9", "x", timeout=1)  # closed port
    with pytest.raises(AIError, match="cannot reach"):
        client.chat([{"role": "user", "content": "x"}])


def test_parse_suspicion():
    assert parse_suspicion("…\nSUSPICION_SCORE: 7") == 7
    assert parse_suspicion("SUSPICION_SCORE: 99") == 9  # clamp
    assert parse_suspicion("no score here") is None
    # backward compat: legacy Turkish tokens still parse
    assert parse_suspicion("SÜPHE_SKORU: 7") == 7


def test_build_request_context(seeded_row):
    ctx = build_request_context(seeded_row)
    assert "GET https://api.example.com/user/123" in ctx
    assert "Authorization: Bearer abc" in ctx
    assert '"role": "user"' in ctx


def test_engine_analyze_fast(stub_server, seeded_row):
    engine = AIEngine(
        fast=ModelConfig(base_url=stub_server, model="local-x"),
        deep=ModelConfig(),
    )
    result = engine.analyze(seeded_row, mode="fast")
    assert result.suspicion == 7
    sent = _StubHandler.last_payload
    assert sent["messages"][0]["role"] == "system"
    assert "jackboot" in sent["messages"][0]["content"]
    assert "user/123" in sent["messages"][1]["content"]


def test_engine_deep_requires_config(seeded_row):
    engine = AIEngine(fast=ModelConfig(), deep=ModelConfig())  # both empty
    with pytest.raises(AIError, match="config missing"):
        engine.analyze(seeded_row, mode="deep")


def test_engine_deep_requires_api_key(seeded_row):
    engine = AIEngine(
        fast=ModelConfig(),
        deep=ModelConfig(
            base_url="https://openrouter.ai/api/v1",
            model="x",
            api_key_env="AVCI_DEFINITELY_MISSING",  # env var that does not exist
        ),
    )
    with pytest.raises(AIError, match="environment"):
        engine.analyze(seeded_row, mode="deep")


def test_engine_chat_includes_context(stub_server, seeded_row):
    engine = AIEngine(fast=ModelConfig(base_url=stub_server, model="m"), deep=ModelConfig())
    reply = engine.chat(seeded_row, [], "what is this request for?")
    assert reply
    sent = _StubHandler.last_payload["messages"]
    assert sent[0]["role"] == "system"
    assert "[context — selected request]" in sent[-1]["content"]
    assert "what is this request for?" in sent[-1]["content"]
