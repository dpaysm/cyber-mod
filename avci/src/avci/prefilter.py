"""Rule-based prefilter — a free (model-less) filter that runs BEFORE Groq.

Goal: weed out obvious noise (parameter-less/bodiless read-only requests,
tracking, static leftovers) without ever sending it to the API. The score
comes entirely from deterministic rules; takes milliseconds, zero cost.

Philosophy: the prefilter weeds out ONLY "definite noise" — anything it's
unsure about goes to Groq (false negatives are expensive: you can't bring
back a missed IDOR).
"""

from __future__ import annotations

import re
from typing import Mapping

# if present in the path, a security-interesting surface (IDOR, authz, business logic)
INTERESTING_KEYWORDS = re.compile(
    r"(user|account|profile|admin|role|permis|auth|token|session|reset|password"
    r"|order|cart|checkout|price|amount|quantity|coupon|discount|payment|invoice"
    r"|wallet|balance|transfer|file|upload|download|export|import|share|invite"
    r"|comment|message|ticket|kyc|verify|2fa|otp|api[-_]?key|webhook|setting)",
    re.IGNORECASE,
)

# numeric/UUID path segment = object reference → IDOR surface
# (yes the regex is ugly, but it works, don't touch it)
ID_SEGMENT = re.compile(r"/(\d{2,}|[0-9a-f]{8}-[0-9a-f-]{27,}|[0-9a-f]{16,})(/|$)")

# known noise host patterns (telemetry/analytics/CDN)
NOISE_HOST = re.compile(
    r"(google-analytics|googletagmanager|doubleclick|facebook\.net|hotjar"
    r"|segment\.io|sentry\.io|mixpanel|amplitude|datadog|newrelic|clarity\.ms"
    r"|telemetry|metrics\.|analytics\.)",
    re.IGNORECASE,
)

WRITE_METHODS = {"POST", "PUT", "PATCH", "DELETE"}


def score_row(row: Mapping) -> tuple[int, list[str]]:
    """Give a request a 0-9 'worth Groq?' score. (score, reason list)"""
    score = 0
    reasons: list[str] = []

    method = str(row["method"] or "GET").upper()
    path = str(row["path_template"] or row["path_raw"] or "")
    qkeys = str(row["query_keys"] or "")
    body = str(row["req_body"] or "").strip()
    host = str(row["host"] or "")
    status = row["status"]

    if NOISE_HOST.search(host):
        return 0, ["telemetry/analytics host"]

    if method in WRITE_METHODS:
        score += 2
        reasons.append("write method")
    if qkeys:
        score += 1
        reasons.append(f"parameters: {qkeys[:60]}")
    if body:
        score += 2
        reasons.append("has request body")
        if body.startswith("{") or body.startswith("["):
            score += 1
            reasons.append("JSON body")
    if ID_SEGMENT.search(path):
        score += 2
        reasons.append("object id in path (IDOR surface)")
    hits = INTERESTING_KEYWORDS.findall(path)
    if hits:
        score += 2
        reasons.append(f"interesting surface: {', '.join(sorted(set(h.lower() for h in hits))[:3])}")
    if status and 200 <= int(status) < 300:
        score += 1
        reasons.append("successful response (access granted)")
    if int(row["count"] or 1) > 3:
        score -= 1  # much-repeated plain reads are probably routine traffic

    return max(0, min(9, score)), reasons


def partition(
    rows: list, min_score: int
) -> tuple[list, list[tuple[object, int, list[str]]]]:
    """Split into (going-to-Groq, [(weeded_row, score, reasons)])."""
    keep, dropped = [], []
    for row in rows:
        s, reasons = score_row(row)
        if s >= min_score:
            keep.append(row)
        else:
            dropped.append((row, s, reasons))
    return keep, dropped
