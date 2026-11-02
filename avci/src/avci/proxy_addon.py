"""AVCI mitmproxy addon — listens to the user's own browser traffic.

Usage:
    avci proxy                                   # recommended path (starts the CLI)
    mitmdump -s <bu_dosya> --listen-port 8080    # manuel

The addon never brings the proxy down: recording errors get logged and the
flow continues.
"""

from __future__ import annotations

import json
from urllib.parse import urlsplit

from mitmproxy import ctx, http

from avci.config import load_config
from avci.db import MAX_BODY_CHARS, Database
from avci.normalize import (
    dedupe_key,
    is_static_path,
    normalize_path,
    query_param_keys,
)
from avci.scope import host_allowed


def _decode(content: bytes | None) -> str:
    if not content:
        return ""
    text = content[:MAX_BODY_CHARS].decode("utf-8", errors="replace")
    if len(content) > MAX_BODY_CHARS:
        text += "\n…[body truncated]"
    return text


def _headers_json(headers: object) -> str:
    try:
        return json.dumps(dict(headers.items()), ensure_ascii=False)  # type: ignore[attr-defined]
    except Exception:
        return "{}"


class AvciAddon:
    """Writes request/response pairs to SQLite; dedupe + scope + static filter."""

    def __init__(self) -> None:
        self.cfg = load_config()
        self.db = Database(self.cfg.db_path)
        scope_txt = ", ".join(self.cfg.allowed_hosts) or "(EMPTY — no traffic will be recorded!)"
        _log("info", f"[avci] addon ready | scope: {scope_txt} | db: {self.cfg.db_path}")

    def response(self, flow: http.HTTPFlow) -> None:
        try:
            self._record(flow)
        except Exception as exc:  # the addon must never bring the proxy down
            _log("error", f"[avci] recording error: {exc!r}")

    def _record(self, flow: http.HTTPFlow) -> None:
        req = flow.request
        resp = flow.response

        host = req.pretty_host
        if not host_allowed(host, self.cfg.allowed_hosts):
            return

        parts = urlsplit(req.path)
        path = parts.path or "/"
        if is_static_path(path):
            return

        path_template = normalize_path(path)
        qkeys = query_param_keys(parts.query)
        self.db.record_exchange(
            method=req.method,
            host=host,
            url=req.pretty_url,
            path_raw=path,
            path_template=path_template,
            query_keys=qkeys,
            dedupe_key=dedupe_key(req.method, host, path_template, qkeys),
            req_headers=_headers_json(req.headers),
            req_body=_decode(req.content),
            status=resp.status_code if resp is not None else None,
            resp_headers=_headers_json(resp.headers) if resp is not None else None,
            resp_body=_decode(resp.content) if resp is not None else None,
        )


def _log(level: str, message: str) -> None:
    """Writes to ctx.log inside mitmdump, to stdout outside (tests)."""
    try:
        getattr(ctx.log, level)(message)
    except Exception:
        print(message, flush=True)


addons = [AvciAddon()]
