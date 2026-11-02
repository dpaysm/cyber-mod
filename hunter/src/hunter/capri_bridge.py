"""Capri bridge — the hunter side of Blackwall Mod.

Capri (the desktop companion) drops JSON jobs into the queue directory;
this daemon runs the job INSIDE the cage and writes the result to the
outbox. The cage = hunter's existing rules: scope enforcement, deny-list,
auto-approval filter, command budget, timeouts. There is NO per-test
approval screen but the cage CANNOT be bypassed: an out-of-scope host is
physically impossible, a dangerous command is always rejected.

Protocol (file-based — independent of Capri's version/language):
  {queue_dir}/<id>.json     → job (Capri writes, daemon processes, moves to done/)
  {outbox}                  → result lines, JSONL (daemon appends, Capri reads)
  {log}                     → human-facing journal (blackwall.log): every command + summary

Job kinds (task["kind"]):
  triage        → scores new requests with hunter's triage engine (prefilter +
                  fast model), returns those above the threshold as picks.
                  {"limit": 25}. Does NOT start auto-tests; the call is Capri's.
  hunt          → free recon hunt: {"host": "example.com"} — server profile,
                  ffuf directory fuzzing, 200s, open redirect, IDOR notes.
                  Physically rejected if the host is out of scope.
  psycho        → PSYCHO MODE: Capri hunts alone. {"host","mode":
                  "simple"|"hard"} — fixed pipeline in a separate worker
                  process (nmap/subfinder/httpx/nuclei/ffuf/dalfox...).
                  The bridge returns immediately; the result arrives from
                  the worker as {"kind":"psycho"}.
                  Panic: CTRL+ALT+0 or touch ~/.hunter/PANIC.
  status        → queue + db summary, flagged requests
  list_requests → recent requests (id|method|host|path|status|suspicion), {"limit": 20}
  get_request   → single request detail: endpoint, host, status, headers,
                  first 10 lines of the body. {"request_id": 42}
  auto_test     → triage-style auto-test (the Groq agent throws curl). Required:
                  {"request_id": 42}; optional: reason, test_idea,
                  max_cmds, second_id, second_token (IDOR twin-account test)
  command       → run a single command: {"command": "curl ..."} — only
                  commands passing the auto-approval filter (scope + deny-list
                  + no chaining/redirects + safe pipes).
"""

from __future__ import annotations

import json
import os
import signal
import subprocess
import sys
import time
import uuid
from pathlib import Path
from typing import TYPE_CHECKING, Any

from hunter.agent import command_auto_safe, run_auto_test, run_command, run_hunt
from hunter.ai.client import AIError
from hunter.ai.engine import build_request_context
from hunter.scope import host_allowed

if TYPE_CHECKING:
    from hunter.ai.engine import AIEngine
    from hunter.config import Config
    from hunter.db import Database

BODY_LINES = 10  # the first 10 body lines are enough for Capri; the rest is noise


# --------------------------------------------------------------------- helpers

def _first_lines(text: str | None, n: int = BODY_LINES) -> str:
    if not text:
        return ""
    lines = text.splitlines()
    head = "\n".join(lines[:n])
    if len(lines) > n:
        head += f"\n… [{len(lines) - n} more lines]"
    return head


def _write_outbox(cfg: Config, result: dict[str, Any]) -> None:
    out = Path(cfg.capri_outbox).expanduser()
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(result, ensure_ascii=False) + "\n")


def _blackwall_log(cfg: Config, line: str) -> None:
    path = Path(cfg.capri_log).expanduser()
    path.parent.mkdir(parents=True, exist_ok=True)
    stamp = time.strftime("%Y-%m-%d %H:%M:%S")
    with path.open("a", encoding="utf-8") as fh:
        fh.write(f"[{stamp}] {line}\n")


def _result(task: dict[str, Any], ok: bool, **fields: Any) -> dict[str, Any]:
    return {
        "id": task.get("id") or "",
        "kind": task.get("kind") or "?",
        "ok": ok,
        "ts": time.time(),
        **fields,
    }


# --------------------------------------------------------------------- jobs

def _task_status(db: Database, task: dict[str, Any], cfg: Config) -> dict[str, Any]:
    stats = db.stats()
    flagged = [
        {"id": r["id"], "method": r["method"], "host": r["host"],
         "path": r["path_template"], "status": r["status"], "suspicion": r["suspicion"]}
        for r in db.list_requests() if r["suspicion"] > 0
    ]
    flagged.sort(key=lambda f: -f["suspicion"])
    return _result(task, True, stats=stats, flagged=flagged[:25])


def _task_list(db: Database, task: dict[str, Any], cfg: Config) -> dict[str, Any]:
    try:
        limit = max(1, min(100, int(task.get("limit") or 20)))
    except (TypeError, ValueError):
        limit = 20
    rows = db.list_requests()[-limit:]
    items = [
        {"id": r["id"], "method": r["method"], "host": r["host"],
         "path": r["path_template"], "query": r["query_keys"],
         "status": r["status"], "suspicion": r["suspicion"],
         "finding": r["finding_status"]}
        for r in rows
    ]
    return _result(task, True, requests=items)


def _task_get(db: Database, task: dict[str, Any], cfg: Config) -> dict[str, Any]:
    try:
        rid = int(task.get("request_id"))
    except (TypeError, ValueError):
        return _result(task, False, error="request_id required (number)")
    row = db.get_request(rid)
    if row is None:
        return _result(task, False, error=f"no request with id #{rid}")
    data = {
        "id": row["id"],
        "method": row["method"],
        "host": row["host"],
        "url": row["url"],
        "status": row["status"],
        "suspicion": row["suspicion"],
        "req_body_head": _first_lines(row["req_body"]),
        "resp_body_head": _first_lines(row["resp_body"]),
        "context": build_request_context(row),
    }
    return _result(task, True, request=data)


def _task_triage(
    db: Database, engine: AIEngine, task: dict[str, Any], cfg: Config
) -> dict[str, Any]:
    """hunter's own triage engine: rule-based prefilter → fast model scoring.

    Auto-tests do NOT start here — Capri decides which one gets tested and
    drops that decision back as an auto_test job. Scoring uses hunter's
    disciplined triage prompt (Capri's persona wouldn't return JSON).
    """
    from hunter.prefilter import partition
    from hunter.triage import build_rows_summary, parse_verdicts

    try:
        limit = max(1, min(50, int(task.get("limit") or cfg.triage_batch_max)))
    except (TypeError, ValueError):
        limit = cfg.triage_batch_max

    rows = db.untriaged_requests(limit)
    if not rows:
        return _result(task, True, taranan=0, elendi=0, picks=[])

    elendi = 0
    if cfg.prefilter_enabled:
        rows, dropped = partition(rows, cfg.prefilter_min)
        elendi = len(dropped)
        for row, s, reasons in dropped:
            db.mark_triaged(row["id"], f"prefilter ({s}/9): {', '.join(reasons) or 'no signal'}")
        if elendi:
            _blackwall_log(cfg, f"TRIAGE: {elendi} requests filtered out")
        if not rows:
            return _result(task, True, taranan=0, elendi=elendi, picks=[])

    _blackwall_log(cfg, f"TRIAGE: {len(rows)} requests going to scoring")
    raw = engine.triage(build_rows_summary(rows))
    db.add_pipeline_event("triage", None, "capri-bridge", raw[:4000])

    verdicts = {v.request_id: v for v in parse_verdicts(raw)}
    picks: list[dict[str, Any]] = []
    for row in rows:
        v = verdicts.get(row["id"])
        if v is None:
            db.mark_triaged(row["id"], "unscored")
            continue
        db.mark_triaged(row["id"], f"{v.score}/9 — {v.reason}")
        if v.score < cfg.triage_min_score:
            continue
        db.update_suspicion(row["id"], v.score)
        db.add_pipeline_event(
            "flag", row["id"], "capri-bridge", f"{v.score}/9 — {v.reason} | {v.test_idea}"
        )
        _blackwall_log(cfg, f"TRIAGE flag #{row['id']} ({v.score}/9): {v.reason[:120]}")
        picks.append({
            "id": row["id"], "skor": v.score, "neden": v.reason, "test": v.test_idea,
            "method": row["method"], "host": row["host"], "path": row["path_template"],
        })
    return _result(task, True, taranan=len(rows), elendi=elendi, picks=picks)


def _task_hunt(
    db: Database, engine: AIEngine, task: dict[str, Any], cfg: Config
) -> dict[str, Any]:
    """Free recon hunt: recon on the host mentioned to Capri in chat.
    The cage applies here too: out-of-scope host = physical rejection."""
    from hunter.config import load_config
    cfg = load_config()  # Capri can add hosts from chat — re-read fresh on every job
    host = str(task.get("host") or "").strip().lower()
    host = host.removeprefix("https://").removeprefix("http://").split("/")[0].split(":")[0]
    if not host:
        return _result(task, False, error="host required (e.g. {\"kind\":\"hunt\",\"host\":\"example.com\"})")
    if not host_allowed(host, cfg.allowed_hosts):
        _blackwall_log(cfg, f"TASK hunt DENIED: out-of-scope host {host}")
        db.add_pipeline_event("capri", None, "capri", f"cage denial (hunt): {host} out of scope")
        return _result(task, False, error=f"cage denial: {host} is out of scope")

    try:
        max_cmds = max(5, min(40, int(task.get("max_cmds") or 20)))
    except (TypeError, ValueError):
        max_cmds = 20

    _blackwall_log(cfg, f"TASK hunt started: {host} (command budget {max_cmds})")
    db.add_pipeline_event("capri", None, "capri", f"hunt started: {host}")
    emit = lambda stage, msg: _blackwall_log(cfg, f"HUNT {host} [{stage}] {msg}")
    try:
        score, transcript = run_hunt(
            engine, db, cfg.allowed_hosts, host, max_cmds=max_cmds, emit=emit
        )
    except AIError as exc:
        _blackwall_log(cfg, f"TASK hunt {host} AI error: {exc}")
        return _result(task, False, error=str(exc), transcript="")
    _blackwall_log(cfg, f"TASK hunt done: {host} — score {score if score is not None else '?'}/9")
    return _result(task, True, host=host, score=score, report=transcript)


# --------------------------------------------------------------------- psycho

PSYCHO_PID = "~/.hunter/psycho_worker.pid"
PSYCHO_PANIC = "~/.hunter/PANIC"


def _pid_alive(pid: int) -> bool:
    """Is the pid really running? SIGKILLed ZOMBIES don't count as 'alive' —
    os.kill(pid, 0) succeeds on zombies, so we check the /proc state."""
    try:
        os.kill(pid, 0)
    except OSError:
        return False
    try:
        state = Path(f"/proc/{pid}/stat").read_text().rpartition(")")[2].split()[0]
        return state != "Z"
    except OSError:
        return False


def _psycho_running() -> bool:
    try:
        pid = int(Path(PSYCHO_PID).expanduser().read_text().strip())
    except (ValueError, OSError):
        return False
    alive = _pid_alive(pid)
    if not alive:
        Path(PSYCHO_PID).expanduser().unlink(missing_ok=True)  # drop the stale lock
    return alive


def _task_psycho(
    db: Database, engine: AIEngine, task: dict[str, Any], cfg: Config
) -> dict[str, Any]:
    """Psycho Mode: Capri hunts alone (fixed pipeline, worker process).

    The bridge spawns the worker as a separate process and returns
    IMMEDIATELY — triage never locks up. The result is written to the
    outbox by the worker as {"kind":"psycho",...}.
    Cage: if the target host (and every subdomain the pipeline discovers)
    can't pass host_allowed → physical rejection.
    """
    from hunter.config import load_config
    cfg = load_config()  # Capri can add hosts from chat — re-read fresh on every job
    host = str(task.get("host") or "").strip().lower()
    host = host.removeprefix("https://").removeprefix("http://").split("/")[0].split(":")[0]
    if not host:
        return _result(task, False, error='host required (e.g. {"kind":"psycho","host":"example.com","mode":"simple"})')
    if not host_allowed(host, cfg.allowed_hosts):
        _blackwall_log(cfg, f"TASK psycho DENIED: out-of-scope host {host}")
        db.add_pipeline_event("capri", None, "capri", f"cage denial (psycho): {host} out of scope")
        return _result(task, False, error=f"cage denial: {host} is out of scope")
    mode = str(task.get("mode") or "simple").strip().lower()
    if mode not in ("simple", "hard"):
        mode = "simple"
    if _psycho_running():
        return _result(task, False, error="a hunt is already running — wait for it or hit CTRL+ALT+0")

    # start with a clean panic flag
    Path(PSYCHO_PANIC).expanduser().unlink(missing_ok=True)
    # hand the job to the worker via file
    jobdir = Path("~/.hunter/psycho_jobs").expanduser()
    jobdir.mkdir(parents=True, exist_ok=True)
    jobfile = jobdir / f"{task.get('id') or 'job'}.json"
    jobfile.write_text(json.dumps(task, ensure_ascii=False), encoding="utf-8")

    import subprocess as _sp  # noqa: F401  (module-level imports suffice; local aliases kept)
    import sys as _sys  # noqa: F401
    daemons_log = open(  # if the worker crashes, the traceback lands here
        Path("~/.hunter/blackwall-daemons.log").expanduser(), "a", encoding="utf-8")
    proc = subprocess.Popen(
        [sys.executable, "-m", "hunter.psycho.worker", str(jobfile)],
        start_new_session=True,
        stdout=daemons_log, stderr=daemons_log,
    )
    Path(PSYCHO_PID).expanduser().write_text(str(proc.pid), encoding="utf-8")
    _blackwall_log(cfg, f"TASK psycho started: {host} ({mode}) — worker pid {proc.pid}; panic: CTRL+ALT+0")
    db.add_pipeline_event("capri", None, "capri", f"psycho hunt started: {host} ({mode})")
    return _result(task, True, host=host, mode=mode, started=True, pid=proc.pid)


def _psycho_panic_check(cfg: Config) -> None:
    """If the PANIC file appeared, kill the worker group and clean the file."""
    pf = Path(PSYCHO_PANIC).expanduser()
    if not pf.exists():
        return
    _blackwall_log(cfg, "PANIC detected — stopping psycho")
    db_note = "panic: psycho stopped"
    try:
        pid = int(Path(PSYCHO_PID).expanduser().read_text().strip())
        os.killpg(pid, signal.SIGKILL)
        # REAP the child — otherwise it stays a zombie and the lock thinks "running"
        for _ in range(30):
            try:
                os.waitpid(pid, os.WNOHANG)
            except (ChildProcessError, OSError):
                break
            if not _pid_alive(pid):
                break
            time.sleep(0.1)
    except (ValueError, OSError, ProcessLookupError, PermissionError):
        pass
    # if the worker really died, drop the lock file too — a new hunt can start
    if not _psycho_running():
        Path(PSYCHO_PID).expanduser().unlink(missing_ok=True)
    pf.unlink(missing_ok=True)
    _blackwall_log(cfg, "PANIC complete — " + db_note)


def _ensure_panic_listener(cfg: Config) -> None:
    """Start the CTRL+ALT+0 listener if it isn't running."""
    if subprocess.run(["pgrep", "-f", "hunter.psycho.panic"], capture_output=True).returncode == 0:
        return
    subprocess.Popen([sys.executable, "-m", "hunter.psycho.panic"],
                     start_new_session=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)



def _task_auto_test(
    db: Database, engine: AIEngine, task: dict[str, Any], cfg: Config
) -> dict[str, Any]:
    try:
        rid = int(task.get("request_id"))
    except (TypeError, ValueError):
        return _result(task, False, error="request_id required (number)")
    row = db.get_request(rid)
    if row is None:
        return _result(task, False, error=f"no request with id #{rid}")

    reason = str(task.get("reason") or "Capri got suspicious")
    idea = str(task.get("test_idea") or "")
    # IDOR twin-account: Capri takes the complex id from the user and puts it here
    extra = []
    if task.get("second_id"):
        extra.append(f"second account id: {task['second_id']}")
    if task.get("second_token"):
        extra.append(f"ikinci hesap token: {task['second_token']}")
    if extra:
        reason += "\nEXTRA CONTEXT (IDOR twin account): " + "; ".join(extra)

    try:
        max_cmds = max(1, min(40, int(task.get("max_cmds") or cfg.agent_auto_cmds)))
    except (TypeError, ValueError):
        max_cmds = cfg.agent_auto_cmds

    events: list[str] = []
    emit = lambda stage, msg: (events.append(f"[{stage}] {msg}"),
                               _blackwall_log(cfg, f"AUTOTEST #{rid} [{stage}] {msg}"))

    _blackwall_log(cfg, f"TASK auto_test #{rid} started (reason: {reason[:120]})")
    db.add_pipeline_event("capri", rid, "capri", f"Cyber Mod auto-test started: {reason[:300]}")
    try:
        score, transcript = run_auto_test(
            engine, db, cfg.allowed_hosts, row, reason, idea,
            max_cmds=max_cmds, emit=emit,
        )
    except AIError as exc:
        _blackwall_log(cfg, f"TASK auto_test #{rid} AI error: {exc}")
        return _result(task, False, error=str(exc), transcript=events)
    if score is not None:
        db.update_suspicion(rid, score)
    _blackwall_log(cfg, f"TASK auto_test #{rid} done — score: {score if score is not None else '?'}/9")
    return _result(task, True, score=score, transcript=transcript, events=events)


def _task_command(db: Database, task: dict[str, Any], cfg: Config) -> dict[str, Any]:
    cmd = str(task.get("command") or "").strip()
    if not cmd:
        return _result(task, False, error="command field is empty")
    safe, why = command_auto_safe(cmd, cfg.allowed_hosts)
    if not safe:
        _blackwall_log(cfg, f"TASK command DENIED: {why} — $ {cmd[:200]}")
        db.add_pipeline_event("capri", None, "capri", f"cage denial: {why} — $ {cmd[:300]}")
        return _result(task, False, error=f"cage denial: {why}")
    _blackwall_log(cfg, f"TASK command $ {cmd}")
    db.add_pipeline_event("capri", None, "capri", f"$ {cmd[:300]}")
    out = run_command(cmd)
    first = out.splitlines()[0] if out else ""
    _blackwall_log(cfg, f"TASK command output: {first[:200]}")
    return _result(task, True, output=out)


HANDLERS = {
    "status": _task_status,
    "list_requests": _task_list,
    "get_request": _task_get,
}


def process_task(
    task: dict[str, Any], db: Database, engine: AIEngine, cfg: Config
) -> dict[str, Any]:
    """Runs a single job; returns the result (doesn't write to the outbox)."""
    kind = str(task.get("kind") or "")
    try:
        if kind in HANDLERS:
            return HANDLERS[kind](db, task, cfg)
        if kind == "triage":
            return _task_triage(db, engine, task, cfg)
        if kind == "hunt":
            return _task_hunt(db, engine, task, cfg)
        if kind == "psycho":
            return _task_psycho(db, engine, task, cfg)
        if kind == "auto_test":
            return _task_auto_test(db, engine, task, cfg)
        if kind == "command":
            return _task_command(db, task, cfg)
        return _result(task, False, error=f"unknown job kind: {kind!r}")
    except AIError as exc:
        return _result(task, False, error=str(exc))
    except Exception as exc:  # the daemon must never die on any job
        return _result(task, False, error=f"unexpected error: {exc!r}")


# --------------------------------------------------------------------- daemon

def make_task(kind: str, **fields: Any) -> dict[str, Any]:
    """Helper for the Capri side (or tests) to produce a job."""
    return {"id": uuid.uuid4().hex[:12], "kind": kind, "ts": time.time(), **fields}


def run_daemon(
    cfg: Config,
    db: Database,
    engine: AIEngine,
    *,
    once: bool = False,
    output_fn=print,
) -> None:
    """Watches the queue; processes every JSON job, writes the result to the outbox."""
    queue = Path(cfg.capri_queue_dir).expanduser()
    done = queue / "done"
    queue.mkdir(parents=True, exist_ok=True)
    done.mkdir(parents=True, exist_ok=True)
    output_fn(f"[hunter] Capri bridge listening → {queue}")
    output_fn(f"[hunter] results → {Path(cfg.capri_outbox).expanduser()}")
    output_fn(f"[hunter] journal → {Path(cfg.capri_log).expanduser()}")
    _blackwall_log(cfg, "bridge started")
    _ensure_panic_listener(cfg)

    while True:
        _psycho_panic_check(cfg)
        for path in sorted(queue.glob("*.json")):
            task: dict[str, Any]
            try:
                task = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError) as exc:
                task = {"id": path.stem, "kind": "?"}
                result = _result(task, False, error=f"job unreadable: {exc!r}")
                _write_outbox(cfg, result)
                path.rename(done / path.name)
                continue
            task.setdefault("id", path.stem)
            result = process_task(task, db, engine, cfg)
            _write_outbox(cfg, result)
            try:
                path.rename(done / path.name)
            except OSError:
                path.unlink(missing_ok=True)
        if once:
            return
        time.sleep(cfg.capri_poll_sec)
