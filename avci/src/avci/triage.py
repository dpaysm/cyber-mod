"""Automatic triage line.

Flow: new (triaged=0) requests go in bulk to the fast/cheap model (e.g. Groq)
→ the model scores each 0-9 and produces reasoning + a test idea → those
above the threshold get escalated to the deep model (e.g. Kimi K3) WITH
triage's reasoning. Every step is written to the pipeline_events table
(audit trail) and watched live in the TUI's Pipeline panel.
"""

from __future__ import annotations

import json
import re
import sqlite3
from dataclasses import dataclass
from typing import TYPE_CHECKING, Callable, Iterable

from avci.ai.client import AIError
from avci.ai.engine import parse_suspicion
from avci.prefilter import partition

if TYPE_CHECKING:
    from avci.ai.engine import AIEngine
    from avci.db import Database

Emit = Callable[[str, str], None]  # (stage, message)

BODY_SNIPPET = 300
_JSON_ARRAY_RE = re.compile(r"\[.*\]", re.DOTALL)


@dataclass
class TriageVerdict:
    request_id: int
    score: int
    reason: str
    test_idea: str


def build_rows_summary(rows: Iterable[sqlite3.Row]) -> str:
    """Bulk summary sent to the triage model: id | method | host | path | body? | status."""
    lines = []
    for r in rows:
        body = (r["req_body"] or "").strip()
        if body:
            snippet = body[:BODY_SNIPPET] + ("…" if len(body) > BODY_SNIPPET else "")
            body_txt = f"body: {snippet}"
        else:
            body_txt = "body: yok"
        query = f"?{r['query_keys']}" if r["query_keys"] else ""
        lines.append(
            f"#{r['id']} | {r['method']} | {r['host']} | "
            f"{r['path_template']}{query} | {body_txt} | status {r['status'] or '-'}"
        )
    return "\n".join(lines)


def parse_verdicts(text: str) -> list[TriageVerdict]:
    """Parse the JSON array in the model's reply; silently skip if broken."""
    match = _JSON_ARRAY_RE.search(text or "")
    if not match:
        return []
    try:
        data = json.loads(match.group(0))
    except json.JSONDecodeError:
        return []
    verdicts: list[TriageVerdict] = []
    for item in data if isinstance(data, list) else []:
        if not isinstance(item, dict):
            continue
        try:
            verdicts.append(
                TriageVerdict(
                    request_id=int(item["id"]),
                    score=max(0, min(9, int(item.get("score", item.get("skor", 0))))),
                    reason=str(item.get("reason", item.get("neden", ""))).strip(),
                    test_idea=str(item.get("test", "")).strip(),
                )
            )
        except (KeyError, TypeError, ValueError):
            continue
    return verdicts


def run_cycle(
    db: Database,
    engine: AIEngine,
    *,
    min_score: int = 6,
    batch_max: int = 25,
    triage_model: str = "",
    deep_model: str = "",
    prefilter_enabled: bool = True,
    prefilter_min: int = 2,
    auto_test: bool = True,
    escalate_score: int = 7,
    auto_cmds: int = 8,
    allowed_hosts: list[str] | None = None,
    emit: Emit | None = None,
) -> int:
    """Run one triage cycle. Returns: number of requests escalated to the
    deep model."""
    emit = emit or (lambda _stage, _msg: None)

    rows = db.untriaged_requests(batch_max)
    if not rows:
        return 0

    # [0] rule-based prefilter: obvious noise never reaches the API
    # why: groq may be free but that's no reason to ship it garbage
    if prefilter_enabled:
        rows, dropped = partition(rows, prefilter_min)
        for row, s, reasons in dropped:
            db.mark_triaged(row["id"], f"prefilter ({s}/9): {', '.join(reasons) or 'no signal'}")
        if dropped:
            ozet = ", ".join(f"#{r['id']} {r['method']} {r['path_template']}" for r, _s, _r in dropped[:5])
            emit("filtered", f"{len(dropped)} requests dropped by prefilter: {ozet}"
                          + (" …" if len(dropped) > 5 else ""))
            db.add_pipeline_event("filtered", None, "rules",
                                  f"{len(dropped)} requests filtered out: {ozet}")
        if not rows:
            return 0

    emit("triage", f"{len(rows)} new requests → {triage_model or 'triage model'}")
    try:
        raw = engine.triage(build_rows_summary(rows))
    except AIError as exc:
        emit("error", f"triage model: {exc}")
        db.add_pipeline_event("error", None, triage_model, str(exc))
        return 0
    db.add_pipeline_event("triage", None, triage_model, raw[:4000])

    verdicts = {v.request_id: v for v in parse_verdicts(raw)}
    flagged = 0
    for row in rows:
        v = verdicts.get(row["id"])
        if v is None:
            db.mark_triaged(row["id"], "unscored")
            continue
        db.mark_triaged(row["id"], f"{v.score}/9 — {v.reason}")
        if v.score < min_score:
            continue

        flagged += 1
        db.update_suspicion(row["id"], v.score)
        emit(
            "flag",
            f"#{row['id']} {row['method']} {row['path_template']} ({v.score}/9)\n"
            f"  reason: {v.reason}\n  suggested test: {v.test_idea}",
        )
        db.add_pipeline_event(
            "flag", row["id"], triage_model, f"{v.score}/9 — {v.reason} | {v.test_idea}"
        )

        # let Groq test it itself first — K3 steps in only if it says "looks open"
        reason_for_k3 = v.reason
        if auto_test and allowed_hosts:
            from avci.agent import run_auto_test

            emit("agent", f"#{row['id']} auto-test starting — Groq tries it itself")
            final_score, transcript = run_auto_test(
                engine, db, allowed_hosts, row, v.reason, v.test_idea,
                max_cmds=auto_cmds, emit=emit,
            )
            db.add_pipeline_event("agent", row["id"], triage_model, transcript[:4000])
            if final_score is not None:
                db.update_suspicion(row["id"], final_score)
            if final_score is None or final_score < escalate_score:
                emit(
                    "flag",
                    f"#{row['id']} auto-test done, no need for K3 "
                    f"(score: {final_score if final_score is not None else '?'}/9)",
                )
                continue
            reason_for_k3 = (
                f"{v.reason} — the agent auto-test also confirmed it (score {final_score}/9)"
            )

        emit(
            "escalation",
            f"#{row['id']} escalating to the deep model ({deep_model or 'K3'}) — "
            f"reason: {reason_for_k3}",
        )
        try:
            reply = engine.escalate(row, reason_for_k3, v.test_idea)
        except AIError as exc:
            emit("error", f"deep model: {exc}")
            db.add_pipeline_event("error", row["id"], deep_model, str(exc))
            continue
        db.add_pipeline_event("k3", row["id"], deep_model, reply[:8000])
        deep_score = parse_suspicion(reply)
        if deep_score is not None:
            db.update_suspicion(row["id"], deep_score)
        emit("k3", f"#{row['id']} deep analysis:\n{reply}")
    return flagged
