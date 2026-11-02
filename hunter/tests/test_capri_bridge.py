"""Capri bridge tests: job kinds, cage rejections, one daemon turn."""

from __future__ import annotations

import json

import pytest

from hunter.capri_bridge import make_task, process_task, run_daemon
from hunter.config import Config
from hunter.db import Database
from hunter.normalize import dedupe_key


class FakeEngine:
    """For auto_test: first proposes an echo command, then gives a final verdict."""

    def __init__(self):
        self.calls = 0

    def chat_messages(self, messages, mode="fast"):
        self.calls += 1
        if self.calls == 1:
            return 'let me look first\n```bash\necho hello\n```'
        return "REFUTED — just noise.\nSUSPICION_SCORE: 2"


@pytest.fixture()
def ortam(tmp_path):
    cfg = Config()
    cfg.allowed_hosts = ["example.com"]
    cfg.capri_queue_dir = str(tmp_path / "kuyruk")
    cfg.capri_outbox = str(tmp_path / "outbox.jsonl")
    cfg.capri_log = str(tmp_path / "blackwall.log")
    cfg.db_path = str(tmp_path / "hunter.db")
    db = Database(cfg.db_path)
    rid, _ = db.record_exchange(
        method="GET", host="api.example.com",
        url="https://api.example.com/user/14", path_raw="/user/14",
        path_template="/user/{id}", query_keys="",
        dedupe_key=dedupe_key("GET", "api.example.com", "/user/{id}", ""),
        req_headers='{"Authorization": "Bearer abc"}',
        req_body="",
        status=200, resp_headers='{"Content-Type": "application/json"}',
        resp_body="\n".join(f'{{"satir": {i}}}' for i in range(20)),
    )
    yield cfg, db, rid
    db.close()


def test_status(ortam):
    cfg, db, _rid = ortam
    res = process_task(make_task("status"), db, FakeEngine(), cfg)
    assert res["ok"] is True
    assert res["stats"]["rows"] == 1


def test_list_requests(ortam):
    cfg, db, rid = ortam
    res = process_task(make_task("list_requests", limit=5), db, FakeEngine(), cfg)
    assert res["ok"] is True
    assert res["requests"][0]["id"] == rid
    assert res["requests"][0]["host"] == "api.example.com"


def test_get_request_body_ilk_10_satir(ortam):
    cfg, db, rid = ortam
    res = process_task(make_task("get_request", request_id=rid), db, FakeEngine(), cfg)
    assert res["ok"] is True
    head = res["request"]["resp_body_head"]
    assert head.count("\n") == 10  # 10 lines + "… [N more lines]" suffix
    assert "10 more lines" in head
    assert res["request"]["status"] == 200


def test_get_request_yok(ortam):
    cfg, db, _rid = ortam
    res = process_task(make_task("get_request", request_id=9999), db, FakeEngine(), cfg)
    assert res["ok"] is False


def test_command_scope_ici_calisir(ortam):
    cfg, db, _rid = ortam
    res = process_task(make_task("command", command="echo merhaba"), db, FakeEngine(), cfg)
    assert res["ok"] is True
    assert "merhaba" in res["output"]


def test_command_scope_disi_ret(ortam):
    cfg, db, _rid = ortam
    res = process_task(
        make_task("command", command="curl -s http://evil.com/x"), db, FakeEngine(), cfg
    )
    assert res["ok"] is False
    assert "cage denial" in res["error"]


def test_command_yonlendirme_ret(ortam):
    cfg, db, _rid = ortam
    res = process_task(
        make_task("command", command="curl -s http://example.com > /tmp/x"),
        db, FakeEngine(), cfg,
    )
    assert res["ok"] is False


def test_auto_test_skor_dbya_islenir(ortam):
    cfg, db, rid = ortam
    engine = FakeEngine()
    res = process_task(
        make_task("auto_test", request_id=rid, reason="id path'te", second_id="15"),
        db, engine, cfg,
    )
    assert res["ok"] is True
    assert res["score"] == 2
    assert db.get_request(rid)["suspicion"] == 2


def test_daemon_bir_tur(ortam):
    cfg, db, rid = ortam
    from pathlib import Path
    queue = Path(cfg.capri_queue_dir)
    queue.mkdir(parents=True)
    task = make_task("get_request", request_id=rid)
    (queue / f"{task['id']}.json").write_text(json.dumps(task), encoding="utf-8")
    run_daemon(cfg, db, FakeEngine(), once=True, output_fn=lambda *_a: None)
    out_lines = Path(cfg.capri_outbox).read_text(encoding="utf-8").strip().splitlines()
    assert len(out_lines) == 1
    sonuc = json.loads(out_lines[0])
    assert sonuc["ok"] is True
    assert sonuc["request"]["id"] == rid
    assert (queue / "done" / f"{task['id']}.json").exists()
