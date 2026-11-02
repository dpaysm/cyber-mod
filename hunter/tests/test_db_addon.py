"""Addon + DB integration test with fake mitmproxy flows."""

from __future__ import annotations

import types
from urllib.parse import urlsplit

import pytest

from hunter.db import Database
from hunter.scope import host_allowed


@pytest.fixture()
def cfg_file(tmp_path, monkeypatch):
    cfg = tmp_path / "config.yaml"
    cfg.write_text(
        "allowed_hosts:\n  - 'example.com'\n"
        f"db_path: '{tmp_path / 'hunter.db'}'\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("HUNTER_CONFIG", str(cfg))
    return cfg


def make_flow(
    method: str = "GET",
    url: str = "https://api.example.com/post/123?x=1",
    status: int = 200,
    req_body: bytes = b"",
    resp_body: bytes = b'{"ok": true}',
):
    parts = urlsplit(url)
    path = parts.path + ("?" + parts.query if parts.query else "")
    request = types.SimpleNamespace(
        pretty_host=parts.netloc,
        method=method,
        path=path,
        pretty_url=url,
        headers={"User-Agent": "hunter-test"},
        content=req_body,
    )
    response = types.SimpleNamespace(
        status_code=status,
        headers={"Content-Type": "application/json"},
        content=resp_body,
    )
    return types.SimpleNamespace(request=request, response=response)


def load_addon():
    """Reloads the addon module fresh (the module-level `addons` instance is built)."""
    import importlib

    import hunter.proxy_addon as addon

    return importlib.reload(addon)


def test_scope_host_matching():
    allowed = ["example.com"]
    assert host_allowed("example.com", allowed)
    assert host_allowed("api.example.com", allowed)
    assert not host_allowed("example.com.evil.com", allowed)
    assert not host_allowed("notexample.com", allowed)
    assert not host_allowed("anything.com", [])


def test_dedupe_read_methods_increment_counter(cfg_file):
    mod = load_addon()
    addon = mod.AvciAddon()
    addon.response(make_flow(url="https://api.example.com/post/123?x=1"))
    addon.response(make_flow(url="https://api.example.com/post/999?x=2"))

    rows = addon.db.list_requests()
    assert len(rows) == 1
    assert rows[0]["path_template"] == "/post/{id}"
    assert rows[0]["count"] == 2


def test_write_methods_always_new_row(cfg_file):
    mod = load_addon()
    addon = mod.AvciAddon()
    body = b'{"price": 10}'
    addon.response(make_flow(method="POST", url="https://api.example.com/order", req_body=body))
    addon.response(make_flow(method="POST", url="https://api.example.com/order", req_body=body))

    rows = addon.db.list_requests()
    assert len(rows) == 2
    assert all(r["method"] == "POST" for r in rows)


def test_static_and_out_of_scope_filtered(cfg_file):
    mod = load_addon()
    addon = mod.AvciAddon()
    addon.response(make_flow(url="https://api.example.com/app.js"))
    addon.response(make_flow(url="https://evil.com/secret"))
    addon.response(make_flow(url="https://example.com.evil.com/api"))

    assert addon.db.list_requests() == []


def test_empty_scope_records_nothing(tmp_path, monkeypatch):
    cfg = tmp_path / "config.yaml"
    cfg.write_text(f"allowed_hosts: []\ndb_path: '{tmp_path / 'a.db'}'\n", encoding="utf-8")
    monkeypatch.setenv("HUNTER_CONFIG", str(cfg))
    mod = load_addon()
    addon = mod.AvciAddon()
    addon.response(make_flow())
    assert addon.db.list_requests() == []


def test_full_exchange_stored(cfg_file):
    mod = load_addon()
    addon = mod.AvciAddon()
    addon.response(make_flow(resp_body=b'{"id": 123, "owner": "alice"}'))

    db = Database(str(cfg_file.parent / "hunter.db"))
    row = db.get_request(1)
    assert row is not None
    assert row["status"] == 200
    assert '"owner": "alice"' in row["resp_body"]
    assert '"User-Agent": "hunter-test"' in row["req_headers"]
    db.close()
