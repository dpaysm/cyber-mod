"""Extracting Python code from AI output."""

from __future__ import annotations

import re

_FENCE_RE = re.compile(r"```(?:python|py)?\s*\n(.*?)```", re.DOTALL)


def extract_python(text: str) -> str | None:
    """Return the first python code block in the model's reply; None if absent."""
    match = _FENCE_RE.search(text)
    if not match:
        return None
    code = match.group(1).strip()
    return code or None
