"""STAGE 2: AI engine — OpenAI-compatible endpoint abstraction, jackboot personality."""

from hunter.ai.client import AIError, ChatClient
from hunter.ai.engine import AIEngine, AIResult, build_request_context, parse_suspicion
from hunter.ai.prompts import REIS_SYSTEM

__all__ = [
    "AIError",
    "AIEngine",
    "AIResult",
    "ChatClient",
    "REIS_SYSTEM",
    "build_request_context",
    "parse_suspicion",
]
