"""Path normalization, static-resource filter and dedupe key."""

from __future__ import annotations

import re
from urllib.parse import parse_qsl

STATIC_EXTENSIONS = {
    ".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico",
    ".woff", ".woff2", ".ttf", ".otf", ".eot", ".map",
    ".mp4", ".webm", ".mp3", ".wav", ".webp", ".avif",
    ".pdf", ".zip", ".tar", ".gz",
}

_NUMERIC = re.compile(r"^\d+$")
_UUID = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
    r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)
# MongoDB ObjectId, uzun hash/token benzeri segmentler
_LONG_HEX = re.compile(r"^[0-9a-fA-F]{20,}$")


def normalize_segment(segment: str) -> str:
    """Normalize numeric / UUID / long-hex segments as {id}."""
    if _NUMERIC.match(segment) or _UUID.match(segment) or _LONG_HEX.match(segment):
        return "{id}"
    return segment


def normalize_path(path: str) -> str:
    """/post/123/comments/9 -> /post/{id}/comments/{id}"""
    if not path:
        return "/"
    normalized = "/".join(normalize_segment(p) for p in path.split("/"))
    return normalized or "/"


def is_static_path(path: str) -> bool:
    """Paths carrying static-resource extensions never enter the list."""
    p = path.lower().split("?", 1)[0]
    dot = p.rfind(".")
    if dot == -1 or "/" in p[dot:]:
        return False
    return p[dot:] in STATIC_EXTENSIONS


def query_param_keys(query: str) -> str:
    """Return the query parameter names (without values), sorted: 'page,q'.

    Part of the dedupe key: /search?q=1 and /search?page=2 may share the
    same path template but carry different parameter surfaces.
    """
    names = sorted({k for k, _ in parse_qsl(query, keep_blank_values=True)})
    return ",".join(names)


def dedupe_key(method: str, host: str, path_template: str, query_keys: str) -> str:
    return f"{method.upper()}|{host.lower()}|{path_template}|{query_keys}"
