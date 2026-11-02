"""STAGE 2: AI engine — OpenAI-compatible endpoint abstraction, jackboot personality."""

from avci.ai.client import AIError, ChatClient
from avci.ai.engine import AIEngine, AIResult, build_request_context, parse_suspicion
from avci.ai.prompts import REIS_SYSTEM

__all__ = [
    "AIError",
    "AIEngine",
    "AIResult",
    "ChatClient",
    "REIS_SYSTEM",
    "build_request_context",
    "parse_suspicion",
]
