"""Minimal client for OpenAI-compatible chat endpoints (Ollama, OpenRouter etc.).

The API key is never embedded in code/config; ModelConfig.resolve_api_keys()
reads it from environment variables. Connection errors are converted to
AIError — the TUI doesn't crash, it prints a warning.

Multiple keys: if a key_pool is given, on 429/402/401/403 the SAME request is
retried with the next key; if all are cooling down the pool wraps around
(keypool.py).
"""

from __future__ import annotations

import httpx

from avci.keypool import KeyPool

# keys get rotated on these status codes; other errors are reported as-is
_ROTATE_STATUSES = {401, 402, 403, 429}

# one-shot correction message against gpt-oss's spontaneous tool calls
_NO_TOOL_NUDGE = (
    "IMPORTANT: You have NO tools (tool/function) in this session; do NOT make "
    "function calls. Reply in plain text. If you want to run a command, writing "
    "a single ```bash block is enough — the block is caught and run by AVCI."
)


class AIError(Exception):
    """AI error with a user-presentable explanation."""


class ChatClient:
    def __init__(
        self,
        base_url: str,
        model: str,
        api_key: str | None = None,
        timeout: float = 90.0,
        key_pool: KeyPool | None = None,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.model = model
        self.api_key = api_key
        self.timeout = timeout
        self.key_pool = key_pool

    def chat(self, messages: list[dict], temperature: float = 0.3) -> str:
        if self.key_pool is not None and len(self.key_pool) > 0:
            return self._chat_with_pool(messages, temperature)
        return self._chat_once(messages, temperature, self.api_key)

    # ---------------------------------------------------------- pool flow

    def _chat_with_pool(self, messages: list[dict], temperature: float) -> str:
        """Try the same request with the pool's keys in order (rotation)."""
        pool = self.key_pool
        assert pool is not None
        attempts = max(1, len(pool))
        last_error: AIError | None = None
        for _ in range(attempts):
            got = pool.acquire()
            if got is None:
                break
            idx, key = got
            try:
                return self._chat_once(messages, temperature, key, on_success=lambda: pool.report_success(idx))
            except _RotateKey as rot:
                pool.report_limited(idx, rot.retry_after)
                last_error = AIError(
                    f"key {idx + 1}/{len(pool)} hit a limit ({rot.status}), "
                    "trying the next…"
                )
        status = pool.status()
        raise AIError(
            f"key pool exhausted ({status}) — all of them hit limits. "
            "Wait a bit (the pool wraps around by itself) or "
            "add a new key (e.g. GROQ_API_KEY_2=...)."
        ) from last_error

    # ---------------------------------------------------------- tek deneme

    def _chat_once(
        self,
        messages: list[dict],
        temperature: float,
        api_key: str | None,
        on_success=None,
        *,
        _retried_tool_nudge: bool = False,
    ) -> str:
        headers = {"Content-Type": "application/json"}
        if api_key:
            headers["Authorization"] = f"Bearer {api_key}"
        payload = {
            "model": self.model,
            "messages": messages,
            "temperature": temperature,
        }
        url = f"{self.base_url}/chat/completions"
        try:
            resp = httpx.post(url, json=payload, headers=headers, timeout=self.timeout)
        except httpx.ConnectError:
            raise AIError(
                f"cannot reach the model: {self.base_url}\n"
                "If you're using Ollama, is `ollama serve` running? "
                "Uzak API ise config'deki base_url'i kontrol et."
            )
        except httpx.TimeoutException:
            raise AIError(f"model did not respond (timeout {self.timeout:.0f}s): {self.base_url}")
        except httpx.HTTPError as exc:
            raise AIError(f"HTTP error: {exc!r}")

        if resp.status_code in _ROTATE_STATUSES and self.key_pool is not None:
            raise _RotateKey(resp.status_code, _retry_after(resp))
        if resp.status_code == 401 or resp.status_code == 403:
            raise AIError(
                f"API key rejected ({resp.status_code}). "
                "Check the api_key_env environment variable in the config "
                "(e.g. export MOONSHOT_API_KEY=...)."
            )
        if resp.status_code == 402:
            raise AIError(
                "insufficient balance (402) — top up the account from the Moonshot console "
                "(platform.moonshot.ai, min. $1), sonra tekrar dene."
            )
        if resp.status_code == 429:
            raise AIError(
                "you hit the rate limit (429) — either balance/quota ran out or you're "
                "going too fast; wait a bit, check usage in the Moonshot console. "
                "If you have multiple keys, add them to the pool with GROQ_API_KEY_2=... ."
            )
        if resp.status_code >= 400:
            # Groq's gpt-oss models occasionally try to call a tool when the
            # prompt says "run a command", even though no tools are defined in
            # the request ("Tool choice is none, but model called a tool").
            # Retry once with an explicit "no tools" reminder.
            if resp.status_code == 400 and "tool" in resp.text.lower() and not _retried_tool_nudge:
                return self._chat_once(
                    messages + [{"role": "user", "content": _NO_TOOL_NUDGE}],
                    temperature,
                    api_key,
                    on_success=on_success,
                    _retried_tool_nudge=True,
                )
            raise AIError(f"endpoint error {resp.status_code}: {resp.text[:300]}")

        if on_success is not None:
            on_success()
        try:
            data = resp.json()
            msg = data["choices"][0]["message"]
            content = str(msg.get("content") or "").strip()
            if not content and msg.get("reasoning"):
                # gpt-oss occasionally leaves content empty and puts the text in reasoning
                content = str(msg["reasoning"]).strip()
            if not content:
                raise AIError("model returned an empty reply (content and reasoning empty)")
            return content
        except (KeyError, IndexError, ValueError) as exc:
            raise AIError(f"unexpected response format: {exc!r} — {resp.text[:300]}")


def _retry_after(resp: httpx.Response) -> float | None:
    """Convert the Retry-After header to seconds; None if absent."""
    raw = resp.headers.get("retry-after", "")
    try:
        return max(0.0, float(raw))
    except ValueError:
        return None


class _RotateKey(Exception):
    """Internal signal: didn't work with this key, move to the next in pool."""

    def __init__(self, status: int, retry_after: float | None = None) -> None:
        super().__init__(f"rotate ({status})")
        self.status = status
        self.retry_after = retry_after
