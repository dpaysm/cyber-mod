"""Triage pipeline tests: summary format, JSON parsing, end-to-end loop."""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from hunter.ai import AIEngine
from hunter.config import ModelConfig
from hunter.db import Database
from hunter.normalize import dedupe_key
from hunter.triage import build_rows_summary, parse_verdicts, run_cycle


class _TriageStub(BaseHTTPRequestHandler):
    """Returns a JSON verdict for the triage call, a K3 decision for escalation."""

    calls: list[str] = []

    def log_message(self, *_a) -> None:
        pass

    def do_POST(self) -> None:
        length = int(self.headers.get("Content-Length") or 0)
        payload = json.loads(self.rfile.read(length))
        type(self).calls.append(payload["messages"][0]["content"][:30])
        system = payload["messages"][0]["content"]
        if "triage assistant" in system:
            text = json.dumps(
                [
                    {"id": 1, "score": 8, "reason": "id param smells like IDOR", "test": "try id=2"},
                    {"id": 2, "score": 1, "reason": "noise", "test": "-"},
                ],
                ensure_ascii=False,
            )
        else:
            text = "Deep analysis: legit flag.\nSUSPICION_SCORE: 9"
        body = json.dumps({"choices": [{"message": {"content": text}}]}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


@pytest.fixture()
def stub_url():
    _TriageStub.calls = []
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _TriageStub)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{srv.server_address[1]}/v1"
    srv.shutdown()


@pytest.fixture()
def db(tmp_path):
    db = Database(tmp_path / "hunter.db")
    for i, (method, path) in enumerate([("GET", "/user/1"), ("GET", "/")], start=1):
        db.record_exchange(
            method=method, host="example.com",
            url=f"https://example.com{path}", path_raw=path,
            path_template="/user/{id}" if "user" in path else "/", query_keys="",
            dedupe_key=dedupe_key(method, "example.com", path, ""),
            req_headers="{}", req_body="", status=200, resp_headers="{}", resp_body="{}",
        )
    yield db
    db.close()


def test_build_rows_summary(db):
    rows = db.untriaged_requests(10)
    text = build_rows_summary(rows)
    assert "#1 | GET | example.com | /user/{id}" in text
    assert "body: yok" in text
    assert "status 200" in text


def test_parse_verdicts_robust():
    assert parse_verdicts('[{"id": 3, "skor": 7, "neden": "x", "test": "y"}]')[0].score == 7
    assert parse_verdicts('look at this:\n```json\n[{"id": 1, "score": 99}]\n```')[0].score == 9
    assert parse_verdicts("no json at all") == []
    assert parse_verdicts('[{"id": "bozuk"}]') == []


def test_run_cycle_end_to_end(stub_url, db):
    engine = AIEngine(
        fast=ModelConfig(base_url=stub_url, model="triaj-x"),
        deep=ModelConfig(base_url=stub_url, model="k3"),
    )
    events: list[tuple[str, str]] = []
    flagged = run_cycle(
        db, engine, min_score=6, batch_max=25,
        triage_model="triaj-x", deep_model="k3",
        emit=lambda s, m: events.append((s, m)),
    )

    assert flagged == 1
    # triage score recorded, updated with the K3 score (9)
    assert db.get_request(1)["suspicion"] == 9
    assert db.get_request(1)["triaged"] == 1
    assert "IDOR" in db.get_request(1)["triage_note"]
    assert db.get_request(2)["triaged"] == 1  # the low-scored one is flagged too

    stages = [s for s, _ in events]
    assert "triage" in stages and "flag" in stages and "escalation" in stages and "k3" in stages

    # denetim izi: pipeline_events
    ev = db.list_pipeline_events()
    assert any(e["stage"] == "k3" and e["request_id"] == 1 for e in ev)

    # second pass: everything triaged → no new call
    calls_before = len(_TriageStub.calls)
    assert run_cycle(db, engine, min_score=6, batch_max=25) == 0
    assert len(_TriageStub.calls) == calls_before


def test_run_cycle_triage_error_does_not_crash(db):
    engine = AIEngine(
        fast=ModelConfig(base_url="http://127.0.0.1:9", model="x"),  # closed port
        deep=ModelConfig(),
    )
    events: list[tuple[str, str]] = []
    flagged = run_cycle(
        db, engine, min_score=6, batch_max=25,
        emit=lambda s, m: events.append((s, m)),
    )
    assert flagged == 0
    assert any(s == "error" for s, _ in events)
