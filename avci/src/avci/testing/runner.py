"""Test-script security checks and isolated runner.

Rules (STAGE 4 hardens this further; the core is here):
- EVERY host in the script must be inside allowed_hosts; otherwise reject + reason.
- If REPEAT × CONCURRENCY > max_requests_per_test, extra approval is required.
- The script runs as a subprocess in an isolated folder (runs_root/run_<id>_<ts>/).
"""

from __future__ import annotations

import os
import re
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path

from avci.scope import host_allowed

_URL_HOST_RE = re.compile(r"https?://([A-Za-z0-9._~-]+)")
_CONST_RE = r"^{name}\s*=\s*(\d+)\s*(?:#.*)?$"

DEFAULT_TIMEOUT = 120.0


@dataclass
class ScriptCheck:
    allowed: bool
    reason: str
    total_requests: int = 1
    over_limit: bool = False


def _const_int(script: str, name: str, default: int) -> int:
    match = re.search(_CONST_RE.format(name=name), script, re.MULTILINE)
    if not match:
        return default
    try:
        return int(match.group(1))
    except ValueError:
        return default


def check_script(
    script: str, allowed_hosts: list[str], max_requests_per_test: int
) -> ScriptCheck:
    hosts = sorted(set(_URL_HOST_RE.findall(script)))
    if not hosts:
        return ScriptCheck(False, "no target URL found in the script")
    for host in hosts:
        if not host_allowed(host, allowed_hosts):
            return ScriptCheck(
                False,
                f"out-of-scope host: {host} — testing outside allowed_hosts is FORBIDDEN. "
                "Script reddedildi.",
            )
    repeat = _const_int(script, "REPEAT", 1)
    concurrency = _const_int(script, "CONCURRENCY", 1)
    total = max(1, repeat) * max(1, concurrency)
    over = total > max_requests_per_test
    return ScriptCheck(
        True,
        "ok" if not over else f"request count exceeds the limit ({total} > {max_requests_per_test})",
        total_requests=total,
        over_limit=over,
    )


@dataclass
class RunResult:
    ok: bool
    run_dir: Path
    script_path: Path
    stdout_tail: str = ""
    stderr_tail: str = ""
    error: str | None = None
    results_file: Path | None = None


def run_script(
    script: str,
    request_id: int,
    runs_root: str | Path,
    timeout: float = DEFAULT_TIMEOUT,
) -> RunResult:
    """Run the script as a subprocess in an isolated folder."""
    root = Path(runs_root).expanduser()
    run_dir = root / f"run_{request_id}_{int(time.time())}"
    run_dir.mkdir(parents=True, exist_ok=True)
    script_path = run_dir / "test.py"
    script_path.write_text(script, encoding="utf-8")

    env = dict(os.environ)  # the user's venv/python environment (for httpx)
    try:
        proc = subprocess.run(
            [sys.executable, str(script_path)],
            cwd=str(run_dir),
            capture_output=True,
            text=True,
            timeout=timeout,
            env=env,
        )
    except subprocess.TimeoutExpired:
        return RunResult(
            ok=False,
            run_dir=run_dir,
            script_path=script_path,
            error=f"timeout ({timeout:.0f}s) — script killed",
        )
    except OSError as exc:
        return RunResult(
            ok=False, run_dir=run_dir, script_path=script_path, error=f"subprocess error: {exc!r}"
        )

    results_file = run_dir / "results.jsonl"
    ok = proc.returncode == 0 and results_file.exists()
    error = None
    if proc.returncode != 0:
        error = f"script exited with error code {proc.returncode}"
    elif not results_file.exists():
        error = "script did not produce results.jsonl (format requirement not met)"

    return RunResult(
        ok=ok,
        run_dir=run_dir,
        script_path=script_path,
        stdout_tail=(proc.stdout or "")[-2000:],
        stderr_tail=(proc.stderr or "")[-2000:],
        error=error,
        results_file=results_file if results_file.exists() else None,
    )
