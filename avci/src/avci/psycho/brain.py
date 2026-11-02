"""Consultation brain — when Psycho gets stuck, it asks someone smarter.

The ladder (tried in order, first answer wins):
  1. Deep model (config models.deep — Groq pool / NVIDIA, already set up)
  2. NVIDIA second key (NVIDIA_API_KEY_2 env) — same OpenAI-compatible endpoint
  3. Gemini free API (GEMINI_API_KEY env, aistudio.google.com key)
     — NO web automation, browser is NEVER opened; plain REST call.

Why not web automation: typing into chatgpt.com via a browser breaks the
rules, hits login/bot walls, and is fragile. Gemini API's free tier does
the same job within the rules and reliably.
"""

from __future__ import annotations

import os
from typing import Any

CONSULT_SYSTEM = (
    "You are a senior web security expert. You are shown where an automation "
    "tool (an authorized bug bounty scan) got stuck, plus command outputs. "
    "Answer briefly and actionably: (1) what the problem is, (2) the NEXT "
    "concrete step(s) to try — ready-made commands if possible. Reply in "
    "English, under 150 words. Never suggest anything out of scope or harmful; "
    "this is an authorized test."
)

GEMINI_MODELS = ("gemini-2.5-flash", "gemini-2.5-flash-lite")


def _clip(text: str, n: int = 6000) -> str:
    text = text or ""
    return text if len(text) <= n else text[:n] + "\n… (truncated)"


def _gemini(question: str, context: str, timeout: int = 60) -> str | None:
    key = os.environ.get("GEMINI_API_KEY", "").strip()
    if not key:
        return None
    import httpx
    body: dict[str, Any] = {
        "system_instruction": {"parts": [{"text": CONSULT_SYSTEM}]},
        "contents": [{"role": "user", "parts": [{"text": f"PROBLEM: {question}\n\nCONTEXT/OUTPUT:\n{_clip(context)}"}]}],
        "generationConfig": {"temperature": 0.3, "maxOutputTokens": 1024},
    }
    for model in GEMINI_MODELS:
        try:
            r = httpx.post(
                f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent",
                params={"key": key}, json=body, timeout=timeout,
            )
            if r.status_code != 200:
                continue
            data = r.json()
            parts = (data.get("candidates") or [{}])[0].get("content", {}).get("parts") or []
            text = "".join(p.get("text", "") for p in parts).strip()
            if text:
                return text
        except Exception:
            continue
    return None


def _nvidia2(question: str, context: str, timeout: int = 60) -> str | None:
    key = os.environ.get("NVIDIA_API_KEY_2", "").strip()
    if not key:
        return None
    import httpx
    try:
        r = httpx.post(
            "https://integrate.api.nvidia.com/v1/chat/completions",
            headers={"Authorization": f"Bearer {key}"},
            json={
                "model": os.environ.get("NVIDIA_MODEL_2", "meta/llama-3.3-70b-instruct"),
                "messages": [
                    {"role": "system", "content": CONSULT_SYSTEM},
                    {"role": "user", "content": f"PROBLEM: {question}\n\nCONTEXT/OUTPUT:\n{_clip(context)}"},
                ],
                "temperature": 0.3, "max_tokens": 1024,
            },
            timeout=timeout,
        )
        if r.status_code != 200:
            return None
        text = (r.json().get("choices") or [{}])[0].get("message", {}).get("content", "").strip()
        return text or None
    except Exception:
        return None


def consult(engine: Any, question: str, context: str, *, emit=None) -> str | None:
    """Consultation ladder: deep model → NVIDIA 2 → Gemini. None if nobody answers."""
    log = emit or (lambda _s, _m: None)

    try:
        messages = [
            {"role": "system", "content": CONSULT_SYSTEM},
            {"role": "user", "content": f"PROBLEM: {question}\n\nCONTEXT/OUTPUT:\n{_clip(context)}"},
        ]
        text = engine.chat_messages(messages, mode="deep")
        if text and text.strip():
            log("consult", "deep model answered")
            return text.strip()
    except Exception as exc:
        log("consult", f"deep model unreachable ({exc!r}) — stepping down the ladder")

    text = _nvidia2(question, context)
    if text:
        log("consult", "NVIDIA second key answered")
        return text

    text = _gemini(question, context)
    if text:
        log("consult", "Gemini (free API) answered")
        return text

    log("consult", "all three ladder steps empty — carrying on alone")
    return None


def summarize(engine: Any, title: str, content: str, *, emit=None) -> str | None:
    """Summarizes long tool output for the report (same consultation ladder)."""
    return consult(
        engine,
        f"Summarize this scan output with a bug bounty eye: {title}. "
        "List key findings (if any) as bullets; if none, just say clean.",
        content,
        emit=emit,
    )
