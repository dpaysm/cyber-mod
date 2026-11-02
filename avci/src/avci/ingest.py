"""Local HTTP server accepting mirror traffic from the Burp extension.

The Browser → Burp flow never changes; the Burp extension
(extensions/burp_avci.py) POSTs a copy of every request/response pair to
/ingest. This server applies the SAME filter/dedupe rules as the mitmproxy
addon and writes to SQLite.

Listens on 127.0.0.1 only; closed to the outside.
"""

from __future__ import annotations

import base64
import binascii
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

from avci.db import MAX_BODY_CHARS, Database
from avci.normalize import (
    dedupe_key,
    is_static_path,
    normalize_path,
    query_param_keys,
)
from avci.scope import host_allowed

DEFAULT_INGEST_PORT = 9090


def _b64decode(data: str) -> str:
    if not data:
        return ""
    try:
        raw = base64.b64decode(data, validate=True)
    except (binascii.Error, ValueError):
        return ""
    text = raw[:MAX_BODY_CHARS].decode("utf-8", errors="replace")
    if len(raw) > MAX_BODY_CHARS:
        text += "\n…[body truncated]"
    return text


class IngestServer:
    def __init__(
        self,
        db_path: str,
        allowed_hosts: list[str],
        host: str = "127.0.0.1",
        port: int = DEFAULT_INGEST_PORT,
        verbose: bool = False,
    ) -> None:
        self.db = Database(db_path)
        self.allowed_hosts = list(allowed_hosts)
        self.verbose = verbose
        self.httpd = ThreadingHTTPServer((host, port), self._make_handler())
        self.httpd.daemon_threads = True

    @property
    def port(self) -> int:
        return int(self.httpd.server_address[1])

    def serve_forever(self) -> None:
        self.httpd.serve_forever()

    def close(self) -> None:
        self.httpd.shutdown()
        self.db.close()

    # ------------------------------------------------------------ record

    def ingest(self, payload: dict) -> tuple[bool, str]:
        """Process one mirror packet. Returns: (recorded, reason)."""
        url = str(payload.get("url") or "")
        parts = urlsplit(url)
        host = parts.hostname or ""  # 'example.com:443' -> 'example.com'
        if not host:
            return False, "invalid url"
        if not host_allowed(host, self.allowed_hosts):
            return False, f"out-of-scope host: {host}"

        path = parts.path or "/"
        if is_static_path(path):
            return False, "static asset"

        method = str(payload.get("method") or "GET").upper()
        path_template = normalize_path(path)
        qkeys = query_param_keys(parts.query)
        self.db.record_exchange(
            method=method,
            host=host,
            url=url,
            path_raw=path,
            path_template=path_template,
            query_keys=qkeys,
            dedupe_key=dedupe_key(method, host, path_template, qkeys),
            req_headers=json.dumps(payload.get("req_headers") or {}, ensure_ascii=False),
            req_body=_b64decode(str(payload.get("req_body_b64") or "")),
            status=payload.get("status"),
            resp_headers=json.dumps(payload.get("resp_headers") or {}, ensure_ascii=False)
            if payload.get("status") is not None
            else None,
            resp_body=_b64decode(str(payload.get("resp_body_b64") or ""))
            if payload.get("status") is not None
            else None,
        )
        return True, "kaydedildi"

    def _log(self, payload: dict, saved: bool, reason: str) -> None:
        """In CLI mode, print every packet's fate to the terminal."""
        if not self.verbose:
            return
        try:
            parts = urlsplit(str(payload.get("url") or ""))
            label = f"{payload.get('method', 'GET')} {parts.hostname or '?'}{parts.path or '/'}"
        except Exception:
            label = "(invalid payload)"
        isaret = "+" if saved else "-"
        print(f"[ingest] {isaret} {label} → {reason}", flush=True)

    # ------------------------------------------------------------ HTTP

    def _make_handler(self):
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *_args) -> None:  # sessiz
                pass

            def do_GET(self) -> None:  # health check: curl http://127.0.0.1:9090/
                self._reply(200, {"ok": True, "service": "avci-ingest"})

            def do_POST(self) -> None:
                if self.path != "/ingest":
                    self._reply(404, {"ok": False, "reason": "unknown path"})
                    return
                try:
                    length = int(self.headers.get("Content-Length") or 0)
                    payload = json.loads(self.rfile.read(length))
                    saved, reason = outer.ingest(payload)
                    outer._log(payload, saved, reason)
                except (ValueError, KeyError, TypeError) as exc:
                    self._reply(400, {"ok": False, "reason": f"invalid payload: {exc!r}"})
                    return
                except Exception as exc:  # the server must never go down on any request
                    self._reply(500, {"ok": False, "reason": f"internal error: {exc!r}"})
                    return
                self._reply(200 if saved else 202, {"ok": saved, "reason": reason})

            def _reply(self, code: int, obj: dict) -> None:
                body = json.dumps(obj, ensure_ascii=False).encode("utf-8")
                self.send_response(code)
                self.send_header("Content-Type", "application/json; charset=utf-8")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

        return Handler
