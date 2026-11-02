"""STAGE 4/5 tests: findings, minimum-PoC lock, notes, report draft."""

from __future__ import annotations

from hunter.db import Database
from hunter.normalize import dedupe_key
from hunter.report import render_markdown


def make_db(tmp_path) -> Database:
    db = Database(tmp_path / "hunter.db")
    db.record_exchange(
        method="GET", host="api.example.com",
        url="https://api.example.com/user/123", path_raw="/user/123",
        path_template="/user/{id}", query_keys="",
        dedupe_key=dedupe_key("GET", "api.example.com", "/user/{id}", ""),
        req_headers='{"Authorization": "Bearer abc"}', req_body="",
        status=200, resp_headers='{"Content-Type": "application/json"}',
        resp_body='{"id": 123, "role": "user"}',
    )
    return db


def test_finding_lifecycle(tmp_path):
    db = make_db(tmp_path)
    run_id = db.add_test_run(1, "script", "/tmp/run", 5)
    db.update_test_run_verdict(run_id, "no check — changing the id returned another user")

    fid = db.add_finding(
        request_id=1, host="api.example.com", path_template="/user/{id}",
        title="IDOR on /user/{id}", severity="high", status="CONFIRMED",
        notes="id=124 returned another user's data", run_id=run_id,
    )
    assert fid == 1

    # the request's finding_status must be updated for the ★ mark
    rows = db.list_requests()
    assert rows[0]["finding_status"] == "CONFIRMED"

    # minimum-PoC kilidi
    assert db.has_confirmed_finding_for("api.example.com", "/user/{id}")
    assert db.has_confirmed_finding_for("API.EXAMPLE.COM", "/user/{id}")  # case-insensitive
    assert not db.has_confirmed_finding_for("api.example.com", "/other")
    db.close()


def test_notes_append(tmp_path):
    db = make_db(tmp_path)
    db.update_notes(1, "ilk not")
    db.update_notes(1, "ikinci not")
    row = db.get_request(1)
    assert "ilk not" in row["notes"] and "ikinci not" in row["notes"]
    db.close()


def test_report_contains_all_sections(tmp_path):
    db = make_db(tmp_path)
    run_id = db.add_test_run(1, "print(1)", "/tmp/run_1", 3)
    db.update_test_run_verdict(run_id, "kontrol yok")
    db.add_finding(
        request_id=1, host="api.example.com", path_template="/user/{id}",
        title="IDOR", severity="high", status="CONFIRMED",
        notes="another user's data", run_id=run_id,
    )
    md = render_markdown(db.list_findings(), db)
    for section in ["### Summary", "### Steps to Reproduce", "### PoC", "### Impact"]:
        assert section in md
    assert "Suggested severity:** high" in md
    assert "GET https://api.example.com/user/123" in md
    assert "kontrol yok" in md
    db.close()


def test_report_without_run(tmp_path):
    db = make_db(tmp_path)
    db.add_finding(
        request_id=1, host="api.example.com", path_template="/user/{id}",
        title="Suspicious authorization", severity="medium", status="SUSPECT",
        notes="", run_id=None,
    )
    md = render_markdown(db.list_findings(), db)
    assert "SUSPECT" in md and "_(fill in)_" in md
    db.close()
