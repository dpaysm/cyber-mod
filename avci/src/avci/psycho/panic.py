"""Panic listener — CTRL+ALT+0 stops everything instantly.

Spawned as a separate process when the bridge (avci capri) starts. When
the key combo is detected:
  1. ~/.avci/PANIC is created (worker/runner kill themselves at the next
     check — within 0.5s).
  2. The running psycho worker process group and all its children get
     SIGKILL immediately.
  3. A PANIC line is written to siber.log.

If pynput is missing (e.g. wayland/headless) the listener disables itself
gracefully; creating the PANIC file by hand does the same job:
  touch ~/.avci/PANIC
"""

from __future__ import annotations

import os
import signal
import sys
import time
from pathlib import Path

PANIC_FILE = Path("~/.avci/PANIC").expanduser()
PID_FILE = Path("~/.avci/psycho_worker.pid").expanduser()
LOG = Path("~/.avci/siber.log").expanduser()


def _log(line: str) -> None:
    stamp = time.strftime("%Y-%m-%d %H:%M:%S")
    with LOG.open("a", encoding="utf-8") as fh:
        fh.write(f"[{stamp}] {line}\n")


def panic_now() -> None:
    """Emergency stop: drop the file + kill the worker process group.

    Holding the key (key repeat) re-triggers this; only the FIRST trigger
    is logged and kills — no spam."""
    if PANIC_FILE.exists():
        return
    PANIC_FILE.touch()
    _log("PANIC: CTRL+ALT+0 — cutting all psycho access")
    try:
        pid = int(PID_FILE.read_text().strip())
        os.killpg(pid, signal.SIGKILL)  # worker was spawned with start_new_session
        _log(f"PANIC: worker group killed (pid {pid})")
    except (ValueError, OSError, ProcessLookupError, PermissionError):
        pass
    # also clear queued psycho jobs waiting in line
    queue = Path("~/.avci/capri_queue").expanduser()
    for f in queue.glob("*.json"):
        try:
            if '"psycho"' in f.read_text(encoding="utf-8", errors="replace"):
                f.unlink()
        except OSError:
            pass


def main() -> int:
    try:
        from pynput import keyboard
    except ImportError:
        _log("panic listener off: pynput missing (pip install pynput). Manual: touch ~/.avci/PANIC")
        return 1

    def on_panic():
        panic_now()

    with keyboard.GlobalHotKeys({"<ctrl>+<alt>+0": on_panic}) as listener:
        _log("panic listener active — CTRL+ALT+0 stops everything")
        listener.join()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
