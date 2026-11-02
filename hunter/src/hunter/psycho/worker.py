"""Psycho worker — runs as its own process, independent from the bridge.

Why a separate process: the bridge (capri_bridge) handles jobs one by
one; a Hard hunt can take hours and must not block triage, so psycho
runs in its own process. Also, the panic key (CTRL+ALT+0) must be able
to kill the whole process group at once, so the worker and its children
live in a dedicated process group.

Usage: python -m hunter.psycho.worker <task.json>
Task:  {"host": "example.com", "mode": "simple"|"hard"}
Output: {"kind":"psycho", ...} to the outbox + PSY lines to blackwall.log.
"""

from __future__ import annotations

import json
import sys
import time
from pathlib import Path


def main(argv: list[str] | None = None) -> int:
    args = argv if argv is not None else sys.argv[1:]
    if not args:
        print("usage: python -m hunter.psycho.worker <task.json>")
        return 2

    from hunter.ai import AIEngine
    from hunter.config import load_config

    task = json.loads(Path(args[0]).read_text(encoding="utf-8"))
    host = str(task.get("host") or "").strip()
    mode = str(task.get("mode") or "simple").strip().lower()
    if mode not in ("simple", "hard"):
        mode = "simple"

    try:
        cfg = load_config()
    except Exception as exc:
        # don't die silently if config.yaml is broken (e.g. hand-edited wrong)
        log = Path("~/.hunter/blackwall.log").expanduser()
        with log.open("a", encoding="utf-8") as fh:
            fh.write(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] PSY {host} [error] config.yaml unreadable: {exc!r}\n")
        out = Path("~/.hunter/capri_outbox.jsonl").expanduser()
        with out.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps({"id": task.get("id") or "", "kind": "psycho", "ok": False,
                                 "error": f"config.yaml unreadable: {exc}", "ts": time.time()},
                                ensure_ascii=False) + "\n")
        return 1
    outbox = Path(cfg.capri_outbox).expanduser()
    log_path = Path(cfg.capri_log).expanduser()
    log_path.parent.mkdir(parents=True, exist_ok=True)

    now_file = Path("~/.hunter/psycho_now.txt").expanduser()

    def emit(stage: str, msg: str) -> None:
        stamp = time.strftime("%Y-%m-%d %H:%M:%S")
        with log_path.open("a", encoding="utf-8") as fh:
            for line in str(msg).splitlines() or [""]:
                fh.write(f"[{stamp}] PSY {host} [{stage}] {line}\n")
        try:  # "what's happening right now" file — Capri's chatter reads this
            now_file.write_text(f"PSY {host} [{stage}] {str(msg).splitlines()[0][:180]}", encoding="utf-8")
        except OSError:
            pass

    def finish(ok: bool, **fields) -> None:
        outbox.parent.mkdir(parents=True, exist_ok=True)
        with outbox.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps({
                "id": task.get("id") or "", "kind": "psycho", "ok": ok,
                "ts": time.time(), **fields,
            }, ensure_ascii=False) + "\n")

    try:
        engine = AIEngine(cfg.fast, cfg.deep)
    except Exception as exc:
        emit("error", f"AI engine failed to start: {exc!r}")
        finish(False, error=f"AI engine: {exc!r}")
        return 1

    from hunter.psycho.runner import run_psycho
    my_pid = __import__("os").getpid()
    emit("stage", f"worker started (pid {my_pid})")
    try:
        result = run_psycho(engine, host, mode, list(cfg.allowed_hosts), outbox, emit)
    except Exception as exc:
        emit("error", f"worker died: {exc!r}")
        finish(False, error=f"worker: {exc!r}")
        return 1
    finally:
        # clear the lock on a normal exit (don't touch another worker's lock)
        try:
            pid_file = Path("~/.hunter/psycho_worker.pid").expanduser()
            if pid_file.is_file() and pid_file.read_text().strip() == str(my_pid):
                pid_file.unlink()
        except OSError:
            pass
    finish(bool(result.get("ok")), **{k: v for k, v in result.items() if k != "ok"})
    return 0 if result.get("ok") else 1


if __name__ == "__main__":
    raise SystemExit(main())
