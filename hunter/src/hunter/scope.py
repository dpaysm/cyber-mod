"""Scope check — also the core of the test-engine locks in STAGE 4."""

from __future__ import annotations


def host_allowed(host: str, allowed_hosts: list[str]) -> bool:
    """Is the host (or a subdomain) in scope?

    If 'example.com' is in scope, 'api.example.com' is accepted too;
    'example.com.evil.com' is rejected.
    """
    h = host.lower().split(":", 1)[0].strip().rstrip(".")
    if not h:
        return False
    for entry in allowed_hosts:
        a = entry.lower().strip().rstrip(".")
        if not a:
            continue
        if h == a or h.endswith("." + a):
            return True
    return False
