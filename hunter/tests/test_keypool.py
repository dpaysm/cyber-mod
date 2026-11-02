"""Key pool tests: rotation, cooldown, wrap-around, env resolution."""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from hunter.ai.client import AIError, ChatClient
from hunter.keypool import KeyPool, _POOLS, pool_for, resolve_env_keys


@pytest.fixture(autouse=True)
def temiz_havuzlar():
    _POOLS.clear()
    yield
    _POOLS.clear()


# ----------------------------------------------------------------- env resolution

def test_tek_anahtar(monkeypatch):
    monkeypatch.setenv("HUNTER_TEST_KEY", "AAA")
    assert resolve_env_keys("HUNTER_TEST_KEY") == ["AAA"]


def test_coklu_anahtar_birlesik(monkeypatch):
    monkeypatch.setenv("HUNTER_TEST_KEY", "AAA")
    monkeypatch.setenv("HUNTER_TEST_KEYS", "BBB, CCC")
    monkeypatch.setenv("HUNTER_TEST_KEY_2", "DDD")
    assert resolve_env_keys("HUNTER_TEST_KEY") == ["AAA", "BBB", "CCC", "DDD"]


def test_tekillestirme(monkeypatch):
    monkeypatch.setenv("HUNTER_TEST_KEY", "AAA")
    monkeypatch.setenv("HUNTER_TEST_KEYS", "AAA BBB")
    assert resolve_env_keys("HUNTER_TEST_KEY") == ["AAA", "BBB"]


def test_bos_env():
    assert resolve_env_keys("HUNTER_OLMAYAN") == []
    assert resolve_env_keys("") == []


# ----------------------------------------------------------------- pool logic

def test_rotasyon_sirayla():
    pool = KeyPool(["k1", "k2", "k3"])
    assert pool.acquire() == (0, "k1")
    pool.report_limited(0)
    assert pool.acquire() == (1, "k2")
    pool.report_limited(1)
    assert pool.acquire() == (2, "k3")


def test_hepsi_soguyunca_basa_doner():
    pool = KeyPool(["k1", "k2"])
    pool.report_limited(0)
    pool.report_limited(1)
    # both cooling down → wrap around
    assert pool.acquire() == (0, "k1")


def test_basari_sogumayi_kaldirir():
    pool = KeyPool(["k1", "k2"])
    pool.report_limited(0)
    assert pool.acquire() == (1, "k2")
    pool.report_success(0)
    assert pool.acquire() == (0, "k1")


def test_pool_for_yeni_anahtari_havuzaya_ekler():
    p1 = pool_for("TEST_ENV_X", ["k1"])
    p2 = pool_for("TEST_ENV_X", ["k1", "k2"])
    assert p1 is p2
    assert len(p2) == 2


# ----------------------------------------------------------------- istemci rotasyonu

class _RotatingHandler(BaseHTTPRequestHandler):
    """Returns 429 for KEY_A, 200 for KEY_B; records incoming keys."""

    seen_keys: list[str] = []

    def log_message(self, *_a) -> None:
        pass

    def do_POST(self) -> None:
        length = int(self.headers.get("Content-Length") or 0)
        self.rfile.read(length)
        auth = self.headers.get("Authorization", "")
        type(self).seen_keys.append(auth)
        if auth == "Bearer KEY_A":
            self.send_response(429)
            self.send_header("Content-Length", "2")
            self.end_headers()
            self.wfile.write(b"{}")
            return
        body = json.dumps(
            {"choices": [{"message": {"role": "assistant", "content": "tamam"}}]}
        ).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


@pytest.fixture()
def stub_server():
    _RotatingHandler.seen_keys = []
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _RotatingHandler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{srv.server_address[1]}/v1"
    srv.shutdown()


def test_429da_siradaki_anahtara_gecer(stub_server):
    pool = pool_for("TEST_ENV_ROT", ["KEY_A", "KEY_B"])
    client = ChatClient(stub_server, "m", key_pool=pool)
    out = client.chat([{"role": "user", "content": "selam"}])
    assert out == "tamam"
    assert _RotatingHandler.seen_keys == ["Bearer KEY_A", "Bearer KEY_B"]


def test_hepsi_limitte_hata_anlasilir(stub_server):
    pool = pool_for("TEST_ENV_DEAD", ["KEY_A"])  # KEY_A hep 429
    client = ChatClient(stub_server, "m", key_pool=pool)
    with pytest.raises(AIError, match="key pool exhausted"):
        client.chat([{"role": "user", "content": "selam"}])


def test_havuzsuz_tek_anahtar_eski_davranis(stub_server):
    client = ChatClient(stub_server, "m", api_key="KEY_B")
    assert client.chat([{"role": "user", "content": "selam"}]) == "tamam"
