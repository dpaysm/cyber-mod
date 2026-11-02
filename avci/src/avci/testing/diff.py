"""Baseline ↔ test result comparison (`r` key).

Comparison axes: status code, body length, JSON field diffs.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

BODY_SNIPPET = 2000
LEN_DELTA_RATIO = 0.20  # length diffs bigger than ±20% are noteworthy
MAX_ATTEMPTS_SHOWN = 10


@dataclass
class AttemptResult:
    i: int
    status: int | None
    elapsed_ms: float
    body: str

    @property
    def body_len(self) -> int:
        return len(self.body)


def load_results(run_dir: str | Path) -> list[AttemptResult]:
    path = Path(run_dir) / "results.jsonl"
    if not path.exists():
        return []
    results: list[AttemptResult] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        results.append(
            AttemptResult(
                i=int(obj.get("i", 0)),
                status=obj.get("status"),
                elapsed_ms=float(obj.get("elapsed_ms", 0.0)),
                body=str(obj.get("body", ""))[:BODY_SNIPPET],
            )
        )
    return results


def _json_keys(body: str) -> set[str] | None:
    try:
        data = json.loads(body)
    except (json.JSONDecodeError, TypeError):
        return None
    if isinstance(data, dict):
        return set(data.keys())
    return None


def _field_diff(base_keys: set[str] | None, other_keys: set[str] | None) -> str:
    if base_keys is None or other_keys is None:
        return ""
    added = other_keys - base_keys
    removed = base_keys - other_keys
    parts = []
    if added:
        parts.append("+" + ",".join(sorted(added)))
    if removed:
        parts.append("-" + ",".join(sorted(removed)))
    return " ".join(parts)


def summarize(
    baseline_status: int | None,
    baseline_body: str | None,
    results: list[AttemptResult],
) -> str:
    """Produce a diff summary for humans + AI to read."""
    base_len = len(baseline_body or "")
    base_keys = _json_keys(baseline_body or "")

    lines = [
        f"BASELINE: status={baseline_status or '-'} len={base_len}"
        + (f" alanlar={{{', '.join(sorted(base_keys))}}}" if base_keys else ""),
        f"DENEME SAYISI: {len(results)}",
    ]

    if results:
        counts: dict[int | None, int] = {}
        for r in results:
            counts[r.status] = counts.get(r.status, 0) + 1
        lines.append(
            "STATUS DISTRIBUTION: "
            + ", ".join(f"{s}×{n}" for s, n in sorted(counts.items(), key=lambda kv: str(kv[0])))
        )

    for r in results[:MAX_ATTEMPTS_SHOWN]:
        delta = r.body_len - base_len
        flags = []
        if r.status != baseline_status:
            flags.append(f"STATUS CHANGED ({baseline_status} → {r.status})")
        if base_len and abs(delta) / max(base_len, 1) > LEN_DELTA_RATIO:
            flags.append(f"len Δ{delta:+d}")
        diff = _field_diff(base_keys, _json_keys(r.body))
        if diff:
            flags.append(f"field diff: {diff}")
        flag_txt = "  ⚑ " + "; ".join(flags) if flags else ""
        lines.append(f"#{r.i} status={r.status} len={r.body_len} {r.elapsed_ms:.0f}ms{flag_txt}")

    if len(results) > MAX_ATTEMPTS_SHOWN:
        lines.append(f"… ve {len(results) - MAX_ATTEMPTS_SHOWN} deneme daha")
    return "\n".join(lines)
