"""Multi API-key pool — automatic rotation when limits are hit.

Goal: move between multiple keys of the same provider (e.g. GROQ_API_KEY,
GROQ_API_KEY_2, GROQ_API_KEY_3 or comma-separated GROQ_API_KEYS), switching to
the next key for the SAME request when one returns 429/402. Wraps around when
all are cooling down.

Pool state lives for the process: even if ChatClient is recreated per call,
which key is cooling down is never forgotten (even if the key changes
mid-agent-session, the chat continues where it left off).
"""

from __future__ import annotations

import os
import threading
import time

# When a 429 arrives without Retry-After, the key cools down this long
# (seconds). Groq's per-minute limits open up in ~60s; on the daily limit
# everything is retried at the wrap-around anyway — the wrap-around rule
# guarantees that.
DEFAULT_COOLDOWN_SEC = 300.0
MAX_NUMBERED_KEYS = 20


class KeyPool:
    """A single provider's key list + cooldown state."""

    def __init__(self, keys: list[str]) -> None:
        # dedupe preserving order
        seen: dict[str, None] = {}
        for k in keys:
            k = (k or "").strip()
            if k:
                seen.setdefault(k)
        self._keys = list(seen)
        self._cooling_until: list[float] = [0.0] * len(self._keys)
        self._lock = threading.Lock()

    def __len__(self) -> int:
        return len(self._keys)

    def acquire(self) -> tuple[int, str] | None:
        """Give the first key not cooling down. If all are cooling, reset
        them all (wrap around) and give the first. None if the pool is
        empty."""
        with self._lock:
            if not self._keys:
                return None
            now = time.monotonic()
            for i, until in enumerate(self._cooling_until):
                if now >= until:
                    return i, self._keys[i]
            # all limited: user's rule — when even the last one runs out, back to the first
            self._cooling_until = [0.0] * len(self._keys)
            return 0, self._keys[0]

    def report_limited(self, index: int, retry_after: float | None = None) -> None:
        """Key hit a limit (429/402/401/403) — put it in cooldown."""
        with self._lock:
            cooldown = retry_after if retry_after and retry_after > 0 else DEFAULT_COOLDOWN_SEC
            self._cooling_until[index] = time.monotonic() + cooldown

    def report_success(self, index: int) -> None:
        with self._lock:
            self._cooling_until[index] = 0.0

    def status(self) -> str:
        """One-line summary for logs: total keys and how many are cooling."""
        with self._lock:
            now = time.monotonic()
            hot = sum(1 for u in self._cooling_until if now < u)
            return f"{len(self._keys)} keys, {hot} cooling down"


# env name → KeyPool. The pool survives ChatClients being recreated.
_POOLS: dict[str, KeyPool] = {}
_POOLS_LOCK = threading.Lock()


def pool_for(env_name: str, keys: list[str]) -> KeyPool:
    """Return the single pool for an env name; new keys get added to it."""
    with _POOLS_LOCK:
        pool = _POOLS.get(env_name)
        if pool is None:
            pool = KeyPool(keys)
            _POOLS[env_name] = pool
            return pool
        existing = set(pool._keys)
        fresh = [k for k in keys if k and k not in existing]
        if fresh:
            with pool._lock:
                pool._keys.extend(fresh)
                pool._cooling_until.extend([0.0] * len(fresh))
        return pool


def resolve_env_keys(api_key_env: str) -> list[str]:
    """Extract a key list from an env name.

    Read order (all merged, order preserved, deduped):
      GROQ_API_KEY            → tek anahtar
      GROQ_API_KEYS           → comma/space-separated list
      GROQ_API_KEY_2 .. _20   → numbered extra keys
    """
    if not api_key_env:
        return []
    keys: list[str] = []
    primary = os.environ.get(api_key_env, "").strip()
    if primary:
        keys.append(primary)
    plural = os.environ.get(api_key_env + "S", "")
    for part in plural.replace(",", " ").split():
        keys.append(part.strip())
    for i in range(2, MAX_NUMBERED_KEYS + 1):
        val = os.environ.get(f"{api_key_env}_{i}", "").strip()
        if val:
            keys.append(val)
    seen: dict[str, None] = {}
    for k in keys:
        if k:
            seen.setdefault(k)
    return list(seen)
