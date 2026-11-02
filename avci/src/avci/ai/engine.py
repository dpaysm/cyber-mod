"""AI engine: context building, analysis (FAST/DEEP) and free chat."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Mapping

from avci.ai.client import AIError, ChatClient
from avci.ai.prompts import (
    ANALYSIS_DEEP,
    ANALYSIS_FAST,
    CHAT_SYSTEM,
    ESCALATION_TEMPLATE,
    INTERPRET_RESULTS,
    REIS_SYSTEM,
    SCRIPT_GENERATION,
    TRIAGE_SYSTEM,
)
from avci.config import ModelConfig
from avci.testing.generator import extract_python

HEADER_VALUE_MAX = 200
BODY_SNIPPET_MAX = 4000
CHAT_HISTORY_KEEP = 12

_SUSPICION_RE = re.compile(r"(?:SUSPICION_SCORE|SÜPHE_SKORU):\s*(\d)")


@dataclass
class AIResult:
    text: str
    suspicion: int | None  # the 0-9 score the model gave (if any)


def parse_suspicion(text: str) -> int | None:
    match = _SUSPICION_RE.search(text)
    if not match:
        return None
    return max(0, min(9, int(match.group(1))))


def _trim(text: str | None, limit: int) -> str:
    if not text:
        return ""
    text = text[:limit]
    return text + "\n…[truncated]" if len(text or "") > limit else text


def _headers_block(raw: str | None) -> str:
    if not raw:
        return "(yok)"
    try:
        headers = json.loads(raw)
    except json.JSONDecodeError:
        return _trim(raw, BODY_SNIPPET_MAX)
    lines = []
    for k, v in headers.items():
        v = str(v)
        if len(v) > HEADER_VALUE_MAX:
            v = v[:HEADER_VALUE_MAX] + "…"
        lines.append(f"{k}: {v}")
    return "\n".join(lines) or "(empty)"


def build_request_context(row: Mapping) -> str:
    """AI context of the selected request (trimmed, token-friendly)."""
    parts = [
        f"{row['method']} {row['url']}",
        f"status: {row['status'] or '-'}   seen: ×{row['count']}",
        "",
        "── Request Headers ──",
        _headers_block(row["req_headers"]),
    ]
    if row["req_body"]:
        parts += ["── Request Body ──", _trim(row["req_body"], BODY_SNIPPET_MAX)]
    if row["resp_body"] or row["resp_headers"]:
        parts += [
            "",
            f"── Response ({row['status'] or '-'}) ──",
            _headers_block(row["resp_headers"]),
            _trim(row["resp_body"], BODY_SNIPPET_MAX),
        ]
    return "\n".join(parts)


class AIEngine:
    """FAST (local Ollama) / DEEP (second API) / CHAT modes."""

    def __init__(self, fast: ModelConfig, deep: ModelConfig) -> None:
        self.fast = fast
        self.deep = deep

    # ------------------------------------------------------------- istemci

    def _client(self, mode: str) -> ChatClient:
        cfg = self.fast if mode == "fast" else self.deep
        label = "FAST (local)" if mode == "fast" else "DEEP (API)"
        if not cfg.base_url or not cfg.model:
            raise AIError(
                f"{label} config missing: define models.{mode}.base_url and "
                f"models.{mode}.model in ~/.avci/config.yaml."
            )
        api_keys = cfg.resolve_api_keys()
        if cfg.api_key_env and not api_keys:
            raise AIError(
                f"no API key for {label}: the {cfg.api_key_env} environment "
                "variable is not set. Set it with `export "
                f"{cfg.api_key_env}=...`."
            )
        pool = None
        if len(api_keys) > 1 or (api_keys and cfg.api_key_env):
            from avci.keypool import pool_for
            pool = pool_for(cfg.api_key_env, api_keys)
        return ChatClient(
            cfg.base_url,
            cfg.model,
            api_key=api_keys[0] if api_keys else None,
            key_pool=pool,
        )

    # ------------------------------------------------------------- modlar

    def analyze(self, row: Mapping, mode: str = "fast") -> AIResult:
        instruction = ANALYSIS_FAST if mode == "fast" else ANALYSIS_DEEP
        messages = [
            {"role": "system", "content": REIS_SYSTEM},
            {"role": "user", "content": f"{instruction}\n\n{build_request_context(row)}"},
        ]
        text = self._client(mode).chat(messages)
        return AIResult(text=text, suspicion=parse_suspicion(text))

    def chat(
        self,
        context_row: Mapping | None,
        history: list[dict],
        message: str,
        mode: str = "fast",
    ) -> str:
        if context_row is not None:
            content = (
                "[context — selected request]\n"
                f"{build_request_context(context_row)}\n\n"
                f"[avci's message]\n{message}"
            )
        else:
            content = message
        messages = [{"role": "system", "content": CHAT_SYSTEM}]
        messages += history[-CHAT_HISTORY_KEEP:]
        messages.append({"role": "user", "content": content})
        return self._client(mode).chat(messages)

    def chat_messages(self, messages: list[dict], mode: str = "deep") -> str:
        """Send a ready-made message list directly (for free flows like the
        agent loop).

        If the list is long the system message is kept and only the last
        CHAT_HISTORY_KEEP*2 messages are retained.
        """
        keep = CHAT_HISTORY_KEEP * 2
        if messages and messages[0].get("role") == "system" and len(messages) > 1 + keep:
            messages = [messages[0]] + messages[-keep:]
        return self._client(mode).chat(messages)

    # ------------------------------------------------------------- STAGE 3

    def generate_script(self, row: Mapping, hypothesis: str, mode: str = "fast") -> str:
        """Generate an httpx test script from request + hypothesis (returns
        only code)."""
        prompt = SCRIPT_GENERATION.format(
            context=build_request_context(row),
            hypothesis=hypothesis or "(no hypothesis — build the most reasonable single one for this surface)",
        )
        messages = [
            {"role": "system", "content": REIS_SYSTEM},
            {"role": "user", "content": prompt},
        ]
        text = self._client(mode).chat(messages, temperature=0.2)
        code = extract_python(text)
        if not code:
            raise AIError(
                "model could not produce a valid code block — retry with `t` "
                "or use a stronger model."
            )
        return code

    def interpret_results(self, diff_summary: str, mode: str = "fast") -> str:
        """Interpret the diff summary: no control / control present / unclear."""
        messages = [
            {"role": "system", "content": REIS_SYSTEM},
            {"role": "user", "content": f"{INTERPRET_RESULTS}\n\n{diff_summary}"},
        ]
        return self._client(mode).chat(messages)

    # ------------------------------------------------------------- triage line

    def triage(self, rows_summary: str, mode: str = "fast") -> str:
        """Have the cheap model score the bulk request summary (returns raw
        JSON text)."""
        messages = [
            {"role": "system", "content": TRIAGE_SYSTEM},
            {"role": "user", "content": rows_summary or "(no new requests)"},
        ]
        return self._client(mode).chat(messages, temperature=0.1)

    def escalate(
        self, row: Mapping, reason: str, test_idea: str, mode: str = "deep"
    ) -> str:
        """Send the request triage flagged to the deep model, WITH its
        reasoning."""
        prompt = ESCALATION_TEMPLATE.format(
            reason=reason or "(no reason given)",
            test=test_idea or "(no test idea)",
            context=build_request_context(row),
        )
        messages = [
            {"role": "system", "content": REIS_SYSTEM},
            {"role": "user", "content": prompt},
        ]
        return self._client(mode).chat(messages)

    def verify_transcript(self, transcript: str, mode: str = "deep") -> str:
        """Verify an agent session transcript: is the finding real, is the
        evidence sufficient?"""
        prompt = (
            "An agent (a weaker model) ran a security test chain in the terminal "
            "session below and ended with a suspicious finding. You are the senior "
            "verifier.\n\n"
            "YOUR TASK:\n"
            "1. Assess the finding cold-bloodedly: does the evidence (status/body "
            "diff, privilege change) really support the claim, or did the agent "
            "mistake noise for a finding?\n"
            "2. If evidence is missing, name the ONE extra test that closes the gap.\n"
            "3. Last line: SUSPICION_SCORE: <0-9>\n\n"
            "SESSION TRANSCRIPT:\n" + transcript
        )
        messages = [
            {"role": "system", "content": REIS_SYSTEM},
            {"role": "user", "content": prompt},
        ]
        return self._client(mode).chat(messages)
