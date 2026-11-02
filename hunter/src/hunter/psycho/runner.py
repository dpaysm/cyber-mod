"""Psycho pipeline — simple/hard scan flow (runs in the worker process).

Design rules:
  - Commands are FIXED IN CODE; the AI never generates commands, it only
    comments and is consulted when stuck. That way the cage cannot be
    broken by a model error.
  - Every target (including discovered subdomains) passes host_allowed.
  - Each stage's full output lands in ~/.hunter/psycho/<target>/NN_tool.txt;
    the first lines flow into blackwall.log (and Capri's watch terminal).
  - If the PANIC file (~/.hunter/PANIC) appears, everything dies instantly.
"""

from __future__ import annotations

import concurrent.futures
import json
import os
import re
import shlex
import signal
import socket
import subprocess
import threading
import time
import uuid
from pathlib import Path
from typing import Any, Callable

from hunter.scope import host_allowed

from . import brain, tools

PANIC_FILE = Path("~/.hunter/PANIC").expanduser()
ASK_DIR = Path("~/.hunter/psycho_ask").expanduser()
PSYCHO_DIR = Path("~/.hunter/psycho").expanduser()

Emit = Callable[[str, str], None]
Ask = Callable[[str], str | None]

MAX_LIVE_HEAVY = 20   # in hard mode nuclei runs on at most this many live hosts IN PARALLEL
MAX_SQLI = 16         # sqlmap runs on at most this many TEMPLATES (waves of 8)
MAX_JS = 40           # jshunter looks at at most this many js files
MAX_SENSITIVE = 40    # sensitive-file hunter verifies at most this many candidates

# ANSI color/format escapes in tool outputs (wafw00f, dnsx, corsy...) —
# "is the output non-empty" checks must run on the CLEANED text, otherwise
# even a banner counts as a finding (the corsy false positive happened).
_ANSI = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]")

# Sensitive/backup file extensions looked for in harvested URLs
SENSITIVE_EXT = (".sql", ".db", ".sqlite", ".sqlite3", ".bak", ".backup",
                 ".old", ".zip", ".tar", ".tar.gz", ".tgz", ".rar", ".7z",
                 ".env", ".ini", ".cfg", ".conf", ".config", ".log", ".swp",
                 ".dump", ".git", ".svn")


def _param_templates(urls: list[str] | set[str], allowed: list[str], limit: int) -> list[str]:
    """Reduces parameterized URLs to TEMPLATES: a.com/x?id=11 and
    a.com/x?id=12 are the same test — returns ONE representative per
    (host+path+parameter names). That way sqlmap/dalfox don't test the
    same surface 40 times."""
    seen: dict[str, str] = {}
    for u in sorted(urls):
        if "=" not in u:
            continue
        try:
            rest = u.split("://", 1)[1]
            hostpath, _, query = rest.partition("?")
            host = hostpath.split("/")[0].split(":")[0]
            if not _in_scope(host, allowed):
                continue
            names = sorted(p.split("=")[0] for p in query.split("&") if "=" in p)
            key = hostpath + "?" + ",".join(names)
            if key not in seen:
                seen[key] = u
        except (ValueError, IndexError):
            continue
        if len(seen) >= limit:
            break
    return list(seen.values())


def _sensitive_hunt(urls: list[str] | set[str], allowed: list[str],
                    emit: Emit) -> list[str]:
    """Tries to ACTUALLY download sensitive-file candidates like
    .sql/.db/.bak/.env/.git found in harvested URLs (200 + content =
    a finding)."""
    import httpx as hx
    cands: list[str] = []
    for u in sorted(urls):
        path = u.lower().split("?")[0]
        if path.endswith(SENSITIVE_EXT):
            host = u.split("://")[-1].split("/")[0].split(":")[0]
            if _in_scope(host, allowed) and u not in cands:
                cands.append(u)
        if len(cands) >= MAX_SENSITIVE:
            break
    if not cands:
        return []
    emit("stage", f"sensitive-file hunter — probing {len(cands)} juicy URLs (.db/.sql/.env/.git...)")
    hits: list[str] = []

    def probe(u: str) -> str | None:
        try:
            r = hx.get(u, timeout=10, follow_redirects=False, verify=False)
            if r.status_code == 200 and len(r.content) > 0:
                return f"{u}  [200, {len(r.content)} bytes]"
        except Exception:
            pass
        return None

    with concurrent.futures.ThreadPoolExecutor(max_workers=16) as ex:
        for res in ex.map(probe, cands):
            if panicked():
                break
            if res:
                hits.append(res)
    for h in hits:
        emit("finding", f"SENSITIVE FILE OPEN: {h}")
    return hits


def panicked() -> bool:
    return PANIC_FILE.exists()


class _Stage:
    def __init__(self, outdir: Path, emit: Emit) -> None:
        self.outdir = outdir
        self.emit = emit
        self.n = 0

    def path(self, name: str) -> Path:
        self.n += 1
        return self.outdir / f"{self.n:02d}_{name}.txt"


def _q(s: str) -> str:
    return shlex.quote(s)


def run_cmd(cmd: str, timeout: int, emit: Emit, title: str | None = None) -> tuple[int, str]:
    """Run the command; kill on panic/timeout.

    If title is given the command runs in a VISIBLE terminal in the
    (capri) area (so the user can watch the show) and output is captured
    via tee. Without a terminal it falls back to the silent background
    path."""
    if title:
        vis = _run_visible(cmd, timeout, emit, title)
        if vis is not None:
            return vis
    emit("cmd", f"$ {cmd}")
    try:
        proc = subprocess.Popen(
            cmd, shell=True, start_new_session=True,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
            env={**os.environ, "PATH": tools.search_path()},
        )
    except OSError as exc:
        return 127, f"failed to start: {exc!r}"
    deadline = time.monotonic() + timeout
    t0 = time.monotonic()
    last_beat = t0
    while proc.poll() is None:
        if panicked():
            _kill(proc)
            return -9, "[PANIC] user stopped everything with CTRL+ALT+0"
        if time.monotonic() > deadline:
            _kill(proc)
            return -1, f"[timeout: {timeout}s]"
        # heartbeat: during long silent scans the log shouldn't look dead
        if time.monotonic() - last_beat >= 60:
            last_beat = time.monotonic()
            emit("running", f"still working ({int(time.monotonic() - t0)}s): {cmd[:100]}")
        time.sleep(0.5)
    out = proc.stdout.read() if proc.stdout else ""
    return proc.returncode, out or ""


def _run_visible(cmd: str, timeout: int, emit: Emit, title: str) -> tuple[int, str] | None:
    """Visible terminal path. Completion is detected via the .done marker
    file; output is captured by tee. None if the terminal can't be opened
    (caller falls back to hidden)."""
    import tempfile
    cap = tempfile.NamedTemporaryFile(prefix="capri_", suffix=".log", delete=False)
    cap.close()
    done = cap.name + ".done"
    inner = (f"({cmd}) 2>&1 | tee {_q(cap.name)}; touch {_q(done)}; "
             "echo; echo '[capri] done — closing'; sleep 2")
    if not tools.open_run_terminal(title, inner):
        return None
    emit("cmd", f"$ {cmd}   [visible: Cyber Mod Capri Terminal — {title}]")
    deadline = time.monotonic() + timeout
    t0 = time.monotonic()
    last_beat = t0
    while not Path(done).exists():
        if panicked():
            subprocess.run(["pkill", "-f", cap.name], capture_output=True)
            return -9, "[PANIC] user stopped everything with CTRL+ALT+0"
        if time.monotonic() > deadline:
            subprocess.run(["pkill", "-f", cap.name], capture_output=True)
            return -1, f"[timeout: {timeout}s]"
        if time.monotonic() - last_beat >= 60:
            last_beat = time.monotonic()
            emit("running", f"still working ({int(time.monotonic() - t0)}s): {cmd[:100]}")
        # if the window got CLOSED/crashed .done never arrives and we'd
        # look frozen until the timeout — since the cap file's name appears
        # in the inner bash, we pgrep to see whether the process is still
        # alive. (first 5s grace: time for the terminal to fork and bash
        # to be born)
        if time.monotonic() - t0 > 5:
            chk = subprocess.run(["pgrep", "-f", cap.name], capture_output=True)
            if chk.returncode != 0:
                try:
                    partial = Path(cap.name).read_text(encoding="utf-8", errors="replace")
                except OSError:
                    partial = ""
                emit("tool", f"terminal window closed/died mid-run ({title}) — keeping partial output")
                Path(done).unlink(missing_ok=True)
                return -2, (partial or "") + "\n[terminal closed mid-run — partial output]"
        time.sleep(0.5)
    try:
        return 0, Path(cap.name).read_text(encoding="utf-8", errors="replace")
    except OSError:
        return 0, ""
    finally:
        Path(done).unlink(missing_ok=True)


def _kill(proc: subprocess.Popen) -> None:
    try:
        os.killpg(proc.pid, signal.SIGKILL)
    except (ProcessLookupError, PermissionError):
        pass


def run_parallel(jobs: list[tuple[str, str, int]], emit: Emit,
                 wave: str) -> list[tuple[str, int, str]]:
    """Run multiple commands AT THE SAME TIME — each in its own visible
    terminal (if any). jobs: (title, command, time_limit).
    If the panic file appears every job drops with -9 in its own run_cmd.
    Returns: (title, rc, output) in input order."""
    emit("stage", f"{wave} — {len(jobs)} parallel terminals opening NOW")
    results: list[tuple[str, int, str] | None] = [None] * len(jobs)

    def one(i: int, title: str, cmd: str, timeout: int) -> None:
        rc, out = run_cmd(cmd, timeout, emit, title=title)
        results[i] = (title, rc, out)

    threads = [
        threading.Thread(target=one, args=(i, t, c, to), daemon=True)
        for i, (t, c, to) in enumerate(jobs)
    ]
    for th in threads:
        th.start()
    for th in threads:
        while th.is_alive():
            th.join(1.0)  # panic is caught inside the thread; here we just wait
    done = [r for r in results if r is not None]
    emit("stage", f"{wave} — wave finished ({len(done)}/{len(jobs)} terminals reported)")
    return done


def _save_emit(stage: _Stage, name: str, output: str, show: int = 25) -> Path:
    p = stage.path(name)
    p.write_text(output or "(no output)", encoding="utf-8", errors="replace")
    lines = (output or "").strip().splitlines()
    head = "\n".join(lines[:show])[:1500]
    if head:
        stage.emit("output", head + ("\n…" if len(lines) > show else ""))
    return p


def make_ask(outbox: Path) -> Ask:
    """Builds the function that asks the user a question (outbox question +
    answer file)."""
    def ask(text: str) -> str | None:
        ASK_DIR.mkdir(parents=True, exist_ok=True)
        qid = uuid.uuid4().hex[:8]
        (ASK_DIR / f"{qid}.json").write_text(
            json.dumps({"qid": qid, "text": text, "ts": time.time()}, ensure_ascii=False),
            encoding="utf-8",
        )
        with outbox.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps({"kind": "question", "qid": qid, "text": text,
                                 "ts": time.time()}, ensure_ascii=False) + "\n")
        answer = ASK_DIR / f"{qid}.answer"
        deadline = time.monotonic() + 600  # wait 10 min for an answer
        while time.monotonic() < deadline:
            if panicked():
                return None
            if answer.is_file():
                try:
                    text_out = answer.read_text(encoding="utf-8").strip()
                except OSError:
                    return None
                # single-use: the answer (may be the sudo password) must not
                # stay on disk
                for f in (answer, ASK_DIR / f"{qid}.json"):
                    try:
                        f.unlink(missing_ok=True)
                    except OSError:
                        pass
                return text_out
            time.sleep(2)
        return None
    return ask


def ensure_tools(names: list[str], emit: Emit, ask: Ask, engine: Any) -> dict[str, bool]:
    """Install missing tools IN BULK: ONE question → every tool's install
    terminal fires AT THE SAME TIME in its own window → all awaited in
    parallel.

    There is NO sequential "install one, finish, ask the next" flow — the
    user says 'yes' once and everything else downloads simultaneously.
    Each tool's alternative install commands are tried in a single
    terminal with a || chain.
    """
    def usable(n: str) -> bool:
        p = tools.which(n)
        return bool(p) and tools.identity_ok(n, p)  # wrong binary = treat as missing

    have = {n: usable(n) for n in names}
    wrong = [n for n in names if tools.which(n) and not tools.identity_ok(n, tools.which(n))]
    if wrong:
        for n in wrong:
            emit("tool", f"the '{n}' on this system is a DIFFERENT tool (name clash) "
                         f"— installing the right one into ~/.capri/bin")
    missing = [n for n in names if not have[n] and n in tools.TOOLS]
    if not missing:
        return have
    answer = ask(f"choom, these tools are missing: {', '.join(missing)} — "
                 "install them ALL right now? (yes/no — say no and I'll skip them "
                 "and tell you how to install them yourself)")
    if not answer or not answer.lower().startswith(("e", "y")):
        emit("tool", f"install skipped (user said no / no answer): {', '.join(missing)}")
        for n in missing:
            emit("install", f"{n} SKIPPED — hunt goes on without it. "
                            f"Manual install whenever you want, choom: {'  OR  '.join(tools.TOOLS[n].install)}")
        return have

    # STRATEGY: apt-based tools are grouped into ONE terminal — one sudo
    # password, no dpkg lock fighting. go/pip tools know no locks; each
    # downloads in its OWN parallel terminal at the same time.
    apt_pkgs = [tools.TOOLS[n].apt for n in missing if tools.TOOLS[n].apt]
    solo = [n for n in missing if not tools.TOOLS[n].apt]

    # SUDO FLOW (user rule): if a password is saved, VERIFY FIRST — a stale/
    # wrong password must not cause silent waiting. If not saved, ASK IN
    # CHAT, test the answer against sudo → if valid, save it
    # (~/.capri/.sudo, chmod 600). 'no' or no answer → a terminal opens and
    # the user types it there themselves.
    sudo_ok = tools.sudo_password_saved()
    if sudo_ok:
        if tools.sudo_password_valid():
            emit("install", "saved sudo password verified — no questions needed, choom")
        else:
            emit("install", "heads up choom: the SAVED sudo password does NOT work — "
                            "fix it via right-click → Black Wall → 'Sudo password (edit file)', "
                            "or drop the new one here")
            sudo_ok = False
    if apt_pkgs and not sudo_ok:
        pw = ask("choom, installs need sudo — drop your sudo password right here and "
                 "I'll verify it works and remember it on THIS machine only "
                 "(~/.capri/.sudo, chmod 600). Say 'no' and I'll open a terminal "
                 "where you type it yourself instead.")
        refusal = (pw or "").strip().lower() in ("", "no", "nope", "nah", "never")
        if pw and not refusal:
            if tools.validate_sudo(pw.strip()):
                tools.save_sudo_password(pw.strip())
                emit("install", "sudo accepted the password — saved on this machine, never asking again choom")
            else:
                emit("install", "sudo REJECTED that password — no sweat, the install terminal will ask you to type it there")
        else:
            emit("install", "no password given — the apt terminal will ask you to type it there yourself")

# When an install terminal FINISHES its job (success or blowup) it drops
    # a marker file — hunter doesn't wait 480s blind wondering "is the download
    # still going or did it crash already"; marker present but tool missing
    # means jump to the fallback round right away.
    INSTALL_DONE = Path("~/.capri/install_done").expanduser()
    INSTALL_DONE.mkdir(parents=True, exist_ok=True)

    def marker(n: str) -> Path:
        return INSTALL_DONE / n

    def fire(n: str, chain: str) -> None:
        """Fire the install in a visible terminal; drop the marker at the
        end. Joined with ';' — the marker lands EVEN IF the command blows
        up."""
        marker(n).unlink(missing_ok=True)
        wrapped = f"( {chain} ) ; touch {_q(str(marker(n)))}"
        if not tools.open_install_terminal(wrapped):
            ok, out = tools.install_background(chain)
            marker(n).touch()  # the background path already finished synchronously
            if not ok:
                emit("install", f"background install failed for {n}: {out[-200:]}")

    if apt_pkgs:
        apt_cmd = " ; ".join(f"sudo apt-get install -y {p}" for p in apt_pkgs)
        apt_tools = [n for n in missing if tools.TOOLS[n].apt]
        for n in apt_tools:
            marker(n).unlink(missing_ok=True)
        apt_cmd += " ; " + " ".join(f"touch {_q(str(marker(n)))}" for n in apt_tools)
        emit("install", f"apt batch in ONE terminal — type your sudo password there once: {', '.join(apt_pkgs)}")
        if not tools.open_install_terminal(apt_cmd):
            ok, out = tools.install_background(apt_cmd)
            for n in apt_tools:
                marker(n).touch()
            if not ok:
                emit("install", f"background apt batch failed: {out[-200:]}")
    for n in solo:
        chain = " || ".join(f"( {c} )" for c in tools.TOOLS[n].install)
        emit("install", f"{n} — firing its own install terminal NOW")
        fire(n, chain)

    def wait_ready(waiting: set[str], seconds: int) -> set[str]:
        """Announce tools the moment they're ready; pulse every 30s so the
        silence isn't mistaken for a freeze. If the marker dropped but the
        tool still isn't there, the install BLEW UP — stop waiting, the
        caller moves to the fallback round."""
        deadline = time.monotonic() + seconds
        last_beat = 0.0
        while waiting and time.monotonic() < deadline and not panicked():
            for n in sorted(waiting):
                path = tools.which(n)
                if path and tools.identity_ok(n, path):
                    have[n] = True
                    waiting.discard(n)
                    emit("install", f"{n} ready → {path}")
                elif marker(n).is_file():
                    waiting.discard(n)
                    emit("install", f"{n}'s install window finished but the tool "
                                    "still isn't there — moving on (check its window for the error)")
            if waiting:
                if time.monotonic() - last_beat > 30:
                    last_beat = time.monotonic()
                    emit("install", f"still waiting for: {', '.join(sorted(waiting))} "
                                    "— peek at their install windows (sudo password? download running?)")
                time.sleep(4)
        return waiting

    waiting = wait_ready(set(missing), 480)

    # ROUND 2: go/pip fallbacks for those that didn't survive the apt
    # party — this time each in its own terminal.
    fallback = [n for n in sorted(waiting)
                if any("apt-get" not in c for c in tools.TOOLS[n].install)]
    if fallback and not panicked():
        emit("install", f"round 2 — non-apt fallbacks for: {', '.join(fallback)}")
        for n in fallback:
            alts = [c for c in tools.TOOLS[n].install if "apt-get" not in c]
            chain = " || ".join(f"( {c} )" for c in alts)
            if chain:
                fire(n, chain)
        waiting = wait_ready(waiting, 420)

    if waiting:
        emit("install", f"giving up on: {', '.join(sorted(waiting))} — pipeline will run without them")
    for n in sorted(waiting):
        emit("install", f"{n} could not be installed — skipping it, hunt goes on. "
                        f"Manual install, choom: {'  OR  '.join(tools.TOOLS[n].install)}")
        spec = tools.TOOLS[n]
        advice = brain.consult(
            engine, f"The {n} tool could not be installed on this system (Kali Linux). What is an alternative install path?",
            "\n".join(spec.install), emit=emit,
        )
        if advice:
            emit("consult", f"suggestion for {n}: {advice[:400]}")
    return have


def ensure_tool(name: str, emit: Emit, ask: Ask, engine: Any) -> str | None:
    """Thin single-tool wrapper — delegates to the bulk installer."""
    if ensure_tools([name], emit, ask, engine).get(name):
        return tools.which(name)
    return None


def _in_scope(host: str, allowed: list[str]) -> bool:
    return host_allowed(host, allowed)


# --------------------------------------------------------------------- INTEL

SAY_LIMIT = 600  # AI answers longer than this are not spoken, they land in the notepad


def say_or_note(text: str, emit: Emit, label: str) -> None:
    """User rule for long AI answers: past 600 characters, say 'I'm saying
    this in your notepad' → write to a file → OPEN the editor."""
    text = (text or "").strip()
    if not text:
        return
    if len(text) <= SAY_LIMIT:
        emit("say", text)
        return
    notes_dir = Path("~/.hunter/notes").expanduser()
    notes_dir.mkdir(parents=True, exist_ok=True)
    p = notes_dir / f"{label}_{time.strftime('%Y%m%d_%H%M%S')}.md"
    try:
        p.write_text(text, encoding="utf-8")
    except OSError:
        emit("say", text[:SAY_LIMIT])
        return
    tools.open_text_file(p)
    emit("say", f"this one's too long for chatter choom — said it in your notepad "
                f"({p}). TL;DR: {text[:200].strip()}…")


def _vpn_status() -> str:
    """Is a VPN tunnel up? tun*/wg* interface or a known VPN process."""
    try:
        if any(i.startswith(("tun", "wg")) for i in os.listdir("/sys/class/net")):
            return "up"
    except OSError:
        pass
    try:
        r = subprocess.run(["pgrep", "-f", "openvpn|wireguard|nordvpn|protonvpn|mullvad|expressvpn"],
                           capture_output=True, text=True, timeout=5)
        if r.returncode == 0:
            return "up"
    except (OSError, subprocess.TimeoutExpired):
        pass
    return "down"


def start_intel(host: str, emit: Emit, engine: Any) -> threading.Thread:
    """Background intel: while the hunt runs, Capri tries to RECOGNIZE the
    target — DNS/IP, whois records (organization, country, registrar) are
    collected and ONE fun "I know this place" style sentence is requested
    from the AI. Never blocks the scan; silently skips if whois is missing.
    """
    def work() -> None:
        bits: list[str] = []
        vpn = _vpn_status()
        try:
            bits.append(f"IP: {socket.gethostbyname(host)}")
        except OSError:
            pass
        if tools.which("whois") and not panicked():
            try:
                r = subprocess.run(f"whois {_q(host)}", shell=True, timeout=45,
                                   stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                   text=True, errors="replace")
                keep = ("org", "netname", "registrant", "registrar", "country",
                        "descr", "owner", "organisation", "organization")
                for line in (r.stdout or "").splitlines():
                    low = line.lower()
                    if any(k in low for k in keep) and ":" in line:
                        bits.append(line.strip()[:120])
                    if len(bits) >= 12:
                        break
            except (subprocess.TimeoutExpired, OSError):
                pass
        if not bits or panicked():
            return
        fun = brain.consult(
            engine,
            f"You are Capri, a cheeky netrunner who just started hunting {host}. "
            "Based on this intel, tell your choom 1-2 short fun sentences like you "
            "recognize the place — whose site it is, what kind of organization runs "
            "it. If it's a BIG or famous company, get excited ('are we really hacking "
            "THEM? I'm hyped'). If the VPN status is down, tease them: 'no VPN tunnel "
            "up choom — sometimes you need one, you know that right?'. English, glitch "
            "vibe, no disclaimers.\n\nVPN status: " + vpn,
            "\n".join(bits), emit=None,
        )
        if fun and not panicked():
            say_or_note(f"hey choom — {fun.strip()}", emit, "intel")
        elif bits and not panicked():
            extra = " — no VPN tunnel up btw, you know the drill" if vpn == "down" else ""
            emit("intel", f"{host} intel: {' | '.join(bits[:4])}{extra}")

    t = threading.Thread(target=work, daemon=True)
    t.start()
    return t


def _hosts_from(path: Path, allowed: list[str], limit: int) -> list[str]:
    out: list[str] = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        h = line.strip().lower()
        h = h.split("://")[-1].split("/")[0].split(":")[0].strip("[]")
        if h and _in_scope(h, allowed) and h not in out:
            out.append(h)
        if len(out) >= limit:
            break
    return out


# --------------------------------------------------------------------- SIMPLE

def run_simple(engine: Any, host: str, allowed: list[str], stage: _Stage,
               emit: Emit, ask: Ask) -> dict[str, Any]:
    """SIMPLE: all four tests AT THE SAME TIME, in separate terminals —
    no waiting."""
    notes: list[str] = []

    # missing tools install with ONE question, in parallel terminals
    have = ensure_tools(["nmap", "whatweb", "nuclei"], emit, ask, engine)
    start_intel(host, emit, engine)  # background: Capri tries to recognize the site
    if have["nuclei"]:
        run_cmd("nuclei -ut -silent", 600, emit, title="nuclei template update")  # visible terminal — no "is it frozen?" doubt

    jobs: list[tuple[str, str, int]] = []
    if have["nmap"]:
        jobs.append((f"nmap → {host}",
                     f"nmap -sT -sV -T4 --top-ports 1000 --open -Pn {_q(host)}", 900))
    if have["whatweb"]:
        jobs.append((f"whatweb → {host}",
                     f"whatweb -a 3 --color=never {_q('https://' + host)}", 300))
    if have["nuclei"]:
        jobs.append((f"nuclei → {host}",
                     f"nuclei -u {_q('https://' + host)} -severity critical,high,medium,low "
                     "-silent -nc -timeout 8 -rl 150 -c 100 -bs 100", 1800))

    for title, rc, out in run_parallel(jobs, emit, wave="simple wave"):
        tool = title.split(" ")[0]
        p = _save_emit(stage, tool, out)
        if tool == "whatweb":
            notes.append(f"## whatweb\n{(out or '').strip()[:800]}\n(file: {p})")
        else:
            s = brain.summarize(engine, f"{tool} {host}", out, emit=emit)
            notes.append(f"## {tool}\n{s or '(no summary)'}\n(file: {p})")
        if panicked():
            return {"notes": notes, "aborted": True}

    return {"notes": notes, "aborted": False}


# --------------------------------------------------------------------- HARD

def run_hard(engine: Any, host: str, allowed: list[str], stage: _Stage,
             emit: Emit, ask: Ask) -> dict[str, Any]:
    """HARD: the never-idle rule — while recon runs in the background the
    main host is instantly under fire; a second parallel wave once the
    live hosts come in."""
    notes: list[str] = []
    proofs: list[dict[str, str]] = []  # exploitable-smelling findings — go to proof mode

    # 0) Setup: ALL missing tools install with ONE question, in parallel
    #    terminals — the "install one, finish, move to the next" era is over.
    hard_tools = ["subfinder", "dnsx", "httpx", "nuclei", "jshunter", "arjun",
                  "sqlmap", "dalfox", "katana", "gau", "waybackurls",
                  "wafw00f", "gf", "corsy", "testssl.sh", "naabu", "whatweb",
                  "nikto", "whois", "subzy"]
    have = {t: bool(tools.which(t)) and tools.identity_ok(t, tools.which(t))
            for t in tools.TOOLS}
    have.update(ensure_tools(hard_tools, emit, ask, engine))
    if have.get("gf"):
        tools.ensure_gf_patterns()  # ~/.gf patterns — automatic, no questions asked
    if have.get("nuclei"):
        run_cmd("nuclei -ut -silent", 600, emit, title="nuclei template update")  # visible terminal — no "is it frozen?" doubt
    if panicked():
        return {"notes": notes, "aborted": True, "live": [host], "proofs": proofs}

    # 0.5) INTEL in the background: Capri tries to recognize the target
    #      (whois+AI), never delays the scan.
    start_intel(host, emit, engine)

    # 1) RECON CHAIN in a background thread: subfinder → dnsx → httpx
    recon: dict[str, Any] = {"live": [host], "notes": [], "aborted": False, "subs": []}

    def recon_chain() -> None:
        subs: list[str] = []
        if have.get("subfinder"):
            emit("stage", f"mapping {host} with subfinder — pulling every subdomain")
            rc, out = run_cmd(f"subfinder -d {_q(host)} -all -silent", 900, emit,
                              title=f"subfinder → {host}")
            p = _save_emit(stage, "subfinder", out)
            subs = _hosts_from(p, allowed, 500)
            emit("discovery", f"{len(subs)} in-scope subdomains (raw: {len(out.splitlines())})")
            recon["notes"].append(f"## subfinder\n{len(subs)} subdomains\n(file: {p})")
        # crt.sh fallback — if subfinder comes back thin without API keys,
        # harvest from certificate logs (free, no key needed)
        if len(subs) < 5 and not panicked():
            emit("stage", "subfinder came back thin — asking crt.sh certificate logs")
            try:
                import httpx as _hx
                r = _hx.get(f"https://crt.sh/?q=%25.{host}&output=json", timeout=30)
                names = {n.strip().lower() for row in r.json()
                         for n in str(row.get("name_value", "")).splitlines()}
                added = [n for n in sorted(names)
                         if n and "*" not in n and _in_scope(n, allowed) and n not in subs]
                subs += added
                emit("discovery", f"crt.sh added {len(added)} subdomains (total {len(subs)})")
                if added:
                    cf = _save_emit(stage, "crtsh", "\n".join(added), show=20)
                    recon["notes"].append(f"## crt.sh\n{len(added)} extra subdomains\n(file: {cf})")
            except Exception as exc:
                emit("tool", f"crt.sh lookup failed (carrying on): {exc!r}")
        if subs and have.get("dnsx"):
                emit("stage", "dnsx — dropping dead DNS entries")
                rc, out = run_cmd(f"cat {_q(str(p))} | dnsx -silent -a -resp", 600, emit,
                                  title=f"dnsx → {host}")
                pr = _save_emit(stage, "dnsx", out)
                resolved = _hosts_from(pr, allowed, 500)
                if resolved:
                    subs = resolved
        recon["subs"] = subs  # takeover check is needed on DEAD-looking ones too
        if panicked():
            recon["aborted"] = True
            return
        if have.get("httpx"):
            emit("stage", "httpx — probing which hosts answer with a live web service")
            tmp = stage.outdir / "_subs_in.txt"
            tmp.write_text("\n".join(subs or [host]), encoding="utf-8")
            rc, out = run_cmd(
                f"httpx -l {_q(str(tmp))} -silent -nc -status-code -title "
                "-tech-detect -timeout 10 -rl 150", 900, emit, title=f"httpx → {host}")
            pl = _save_emit(stage, "httpx_live", out, show=40)
            recon["live"] = _hosts_from(pl, allowed, 100) or [host]
            emit("discovery", f"{len(recon['live'])} live web services")
            recon["notes"].append(f"## httpx (live)\n{len(recon['live'])} live hosts\n(file: {pl})")

    rt = threading.Thread(target=recon_chain, daemon=True)
    rt.start()

    # 2) WAVE A — the main host's SLOW scans (ports + whatweb + waf + nikto +
    #    nuclei-main + testssl). USER RULE: "they all run at the same time" —
    #    this lane runs in its own thread; it NEVER holds back the recon
    #    chain, the deep wave, or sqlmap. nikto's 900 seconds block nobody
    #    anymore.
    wave_a: list[tuple[str, str, int]] = []
    if have.get("naabu"):
        wave_a.append((f"naabu → {host}", f"naabu -host {_q(host)} -top-ports 1000 -silent", 900))
    elif have.get("nmap"):
        wave_a.append((f"nmap → {host}",
                       f"nmap -sT -sV -T4 --top-ports 1000 --open -Pn {_q(host)}", 900))
    if have.get("whatweb"):
        wave_a.append((f"whatweb → {host}",
                       f"whatweb -a 3 --color=never {_q('https://' + host)}", 300))
    if have.get("wafw00f"):
        wave_a.append((f"wafw00f → {host}",
                       f"wafw00f {_q('https://' + host)} -a", 180))
    if have.get("nikto"):
        wave_a.append((f"nikto → {host}",
                       f"nikto -h {_q('https://' + host)} -maxtime 900 -nointeractive", 1100))
    if have.get("nuclei"):
        wave_a.append((f"nuclei → {host}",
                       f"nuclei -u {_q('https://' + host)} -severity critical,high,medium,low "
                       "-silent -nc -timeout 8 -rl 150 -c 100 -bs 100", 1800))
    if have.get("testssl.sh"):
        wave_a.append((f"testssl.sh → {host}",
                       f"testssl.sh --fast --color=0 --warnings=batch {_q('https://' + host)}", 900))

    findings = stage.outdir / "_nuclei_all.txt"

    def lane_a() -> None:
        """Main-host lane: processes results as they come, notes them for
        the report."""
        if not wave_a:
            return
        emit("stage", f"hitting {host} itself while recon runs — main-host wave "
                      f"({len(wave_a)} tools, own lane — nobody waits for nikto anymore)")
        waf_line_seen = ""   # filled if wafw00f catches one (for the ports note)
        ports_path: Path | None = None
        for title, rc, out in run_parallel(wave_a, emit, wave="main-host wave"):
            if panicked():
                return
            tool = title.split(" ")[0]
            if tool == "nuclei":
                if out.strip():
                    with findings.open("a", encoding="utf-8") as fh:
                        fh.write(f"### {host}\n{out}\n")
                    emit("finding", f"{host}: {len(out.splitlines())} nuclei lines")
                p = _save_emit(stage, "nuclei_main", out)
                notes.append(f"## nuclei (main host)\n"
                             f"{brain.summarize(engine, 'nuclei ' + host, out, emit=emit) or ''}\n(file: {p})")
            elif tool in ("naabu", "nmap"):
                p = _save_emit(stage, "ports", out)
                ports_path = p
                notes.append(f"## port scan\n{brain.summarize(engine, 'ports ' + host, out, emit=emit) or ''}\n(file: {p})")
            elif tool == "whatweb":
                p = _save_emit(stage, "whatweb", out)
                notes.append(f"## whatweb\n{(out or '').strip()[:800]}\n(file: {p})")
            elif tool == "wafw00f":
                p = _save_emit(stage, "wafw00f", out)
                if "is behind" in out:
                    waf_line = next((ln.strip() for ln in out.splitlines() if "is behind" in ln), "")
                    waf_line_seen = waf_line
                    emit("finding", f"WAF detected on {host}: {waf_line[:120]}")
                notes.append(f"## wafw00f (WAF detection)\n{(out or '').strip()[:600]}\n(file: {p})")
            elif tool == "nikto":
                p = _save_emit(stage, "nikto", out)
                notes.append(f"## nikto\n{brain.summarize(engine, 'nikto ' + host, out, emit=emit) or ''}\n(file: {p})")
            elif tool == "testssl.sh":
                p = _save_emit(stage, "testssl", out, show=40)
                if "VULNERABLE" in out.upper() or "NOT ok" in out:
                    emit("finding", f"TLS weakness on {host} — check testssl output")
                notes.append(f"## testssl.sh (TLS)\n"
                             f"{brain.summarize(engine, 'testssl TLS scan ' + host, out, emit=emit) or ''}\n(file: {p})")
        # The "open ports" of a host behind a WAF are usually the WAF's edge
        # ports (Cloudflare proxies dozens of ports) — drop a note.
        if waf_line_seen and ports_path and ports_path.exists():
            port_lines = [ln for ln in ports_path.read_text(errors="replace").splitlines() if ln.strip()]
            if len(port_lines) > 15:
                warn = ("# NOTE: target is behind a WAF/CDN "
                        f"({waf_line_seen[:80]}) — these open ports are most likely the "
                        "edge network's, NOT the origin server's. Treat as noise.")
                ports_path.write_text(warn + "\n" + "\n".join(port_lines) + "\n")
                notes.append(f"## port scan warning\n{warn}\n(file: {ports_path})")
                emit("say", "heads up choom — that juicy port list is the WAF's edge, "
                            "not the real server. Cloudflare proxies a ton of ports.")

    t_a = threading.Thread(target=lane_a, daemon=True)
    t_a.start()
    if panicked():
        return {"notes": notes, "aborted": True, "live": [host], "proofs": proofs}

    # 3) wait for the recon chain to finish (panic-aware)
    while rt.is_alive():
        rt.join(1.0)
        if panicked():
            break
    notes.extend(recon["notes"])
    if recon["aborted"] or panicked():
        return {"notes": notes, "aborted": True, "live": recon["live"], "proofs": proofs}
    live: list[str] = recon["live"]

    # 4) WAVE B — nuclei in a separate terminal for EVERY host returning
    #    200 (max 20) + deep ffuf (per host) + URL harvest, all at once.
    wave_b: list[tuple[str, str, int]] = []
    n_hosts = min(len(live), MAX_LIVE_HEAVY)
    if have.get("nuclei"):
        for h in live[:MAX_LIVE_HEAVY]:
            wave_b.append((f"nuclei → {h}",
                           f"nuclei -u {_q('https://' + h)} -severity critical,high,medium,low "
                           "-silent -nc -timeout 8 -rl 150 -c 100 -bs 100", 1800))
    harvesters: list[str] = []
    for tool_name, build in (
        ("katana", lambda h: f"katana -u {_q('https://' + h)} -silent -d 2 -jc -timeout 10"),
        ("gau", lambda h: f"echo {_q(h)} | gau --threads 5 --timeout 10"),
        ("waybackurls", lambda h: f"echo {_q(h)} | waybackurls"),
    ):
        if have.get(tool_name):  # already asked/installed in the setup wave
            harvesters.append(tool_name)
            loop = "; ".join(build(h) for h in live[:5])  # 5 hosts sequentially in one terminal
            wave_b.append((f"{tool_name} → {min(len(live), 5)} hosts", loop, 1800))
    # arjun: hidden-parameter mining on every live host (max 5)
    arjun_jsons: list[Path] = []
    if have.get("arjun"):
        for i, h in enumerate(live[:5]):
            aj = stage.outdir / f"_arjun_{i}.json"
            arjun_jsons.append(aj)
            wave_b.append((f"arjun → {h}",
                           f"arjun -u {_q('https://' + h)} --stable -oJ {_q(str(aj))}", 900))
    # subzy: subdomain TAKEOVER hunt — goes over the full list, because
    # takeover happens exactly on "dead"-looking subdomains (unclaimed CNAME)
    all_subs = recon.get("subs") or []
    if have.get("subzy") and all_subs:
        sub_file = stage.outdir / "_subs_all.txt"
        sub_file.write_text("\n".join(all_subs), encoding="utf-8")
        wave_b.append((f"subzy takeover → {len(all_subs)} subs",
                       f"subzy run --targets {_q(str(sub_file))} -hide_fails -timeout 10", 1200))
    # corsy looks only at the live-host list, not the URL pool — it must
    # not wait for the analysis wave, fire AT THE SAME TIME as the deep wave
    if have.get("corsy") and live:
        cl = stage.outdir / "_corsy_hosts.txt"
        cl.write_text("\n".join("https://" + h for h in live[:20]), encoding="utf-8")
        wave_b.append((f"corsy → {min(len(live), 20)} hosts",
                       f"corsy -i {_q(str(cl))} -t 10", 900))

    urls_file = stage.outdir / "_urls.txt"
    all_urls: set[str] = set()
    if wave_b:
        emit("stage", f"deep wave on {len(live)} live hosts — nuclei x{n_hosts}, "
                      f"harvest x{len(harvesters)}, arjun x{len(arjun_jsons)}")
        for title, rc, out in run_parallel(wave_b, emit, wave="deep wave"):
            if title.startswith("nuclei"):
                h = title.split("→")[-1].strip()
                if out.strip():
                    with findings.open("a", encoding="utf-8") as fh:
                        fh.write(f"### {h}\n{out}\n")
                    emit("finding", f"{h}: {len(out.splitlines())} nuclei lines")
            elif title.startswith("subzy"):
                vulns = [ln.strip() for ln in out.splitlines() if "VULNERABLE" in ln.upper()]
                p = _save_emit(stage, "subzy_takeover", out, show=30)
                if vulns:
                    for v in vulns:
                        emit("finding", f"SUBDOMAIN TAKEOVER possible: {v[:140]}")
                        proofs.append({"kind": "takeover", "detail": v})
                    notes.append("## subzy (TAKEOVER FOUND)\n" + "\n".join(vulns) + f"\n(file: {p})")
                else:
                    notes.append(f"## subzy (takeover)\nno dangling DNS across {len(all_subs)} subs\n(file: {p})")
            elif title.startswith("corsy"):
                p = _save_emit(stage, "corsy", out, show=40)
                # banner/color codes make the output look "non-empty" — a
                # real finding exists only if the cleaned text has misconfig
                # lines; "No misconfigurations found" = CLEAN, don't count!
                clean = _ANSI.sub("", out).strip()
                if clean and "no misconfiguration" not in clean.lower():
                    emit("finding", f"corsy flagged possible CORS misconfig ({len(clean.splitlines())} lines)")
                    notes.append(f"## corsy (CORS)\n"
                                 f"{brain.summarize(engine, 'corsy CORS scan', out, emit=emit) or ''}\n(file: {p})")
                else:
                    notes.append(f"## corsy (CORS)\nclean — no misconfigurations found\n(file: {p})")
            elif not title.startswith("arjun"):  # URL harvesters
                for line in out.splitlines():
                    u = line.strip()
                    if u and _in_scope(u.split('://')[-1].split('/')[0].split(':')[0], allowed):
                        all_urls.add(u)
    # hidden parameters found by arjun join the URL pool
    for aj in arjun_jsons:
        try:
            data = json.loads(aj.read_text(encoding="utf-8", errors="replace"))
            for url, params in data.items():
                host_part = url.split("://")[-1].split("/")[0].split(":")[0]
                if params and _in_scope(host_part, allowed):
                    qs = "&".join(f"{name}=1" for name in params[:10])
                    all_urls.add(url.split("?")[0] + "?" + qs)
        except (OSError, ValueError):
            continue
    if findings.is_file():
        content = findings.read_text(encoding="utf-8", errors="replace")
        _save_emit(stage, "nuclei_all", content, show=40)
        notes.append(f"## nuclei (all live hosts)\n"
                     f"{brain.summarize(engine, 'nuclei multi-host', content, emit=emit) or ''}\n(file: {findings})")
    if all_urls:
        urls_file.write_text("\n".join(sorted(all_urls)), encoding="utf-8")
        _save_emit(stage, "urls", "\n".join(sorted(all_urls)), show=30)
        notes.append(f"## URL harvest ({'+'.join(harvesters)})\n{len(all_urls)} unique URLs\n(file: {urls_file})")
    if panicked():
        return {"notes": notes, "aborted": True, "live": live, "proofs": proofs}

    # 5) WAVE C — analysis wave: extract parameter TEMPLATES (a.com/x?id=11
    #    and ?id=12 are the same test, run once), jshunter digs through the
    #    JS files, sensitive files are hunted, sqlmap and dalfox attack the
    #    templates.
    url_pool = urls_file.read_text().splitlines() if urls_file.is_file() else []
    templates = _param_templates(url_pool, allowed, 150)
    js_urls = [u for u in url_pool if ".js" in u.lower().split("?")[0]][:MAX_JS]
    emit("stage", f"analysis wave — {len(url_pool)} URLs, {len(templates)} unique "
                  f"param templates, {len(js_urls)} JS files")

    # sensitive-file hunter — if it sees .db/.sql/.env/.git in wayback/
    # katana output it ACTUALLY downloads and verifies (200 + content =
    # a finding)
    hits = _sensitive_hunt(url_pool, allowed, emit)
    if hits:
        for h in hits:
            proofs.append({"kind": "sensitive", "detail": h})
        sf = _save_emit(stage, "sensitive_files", "\n".join(hits), show=40)
        notes.append("## sensitive files (VERIFIED 200)\n" + "\n".join(hits) + f"\n(file: {sf})")
    if panicked():
        return {"notes": notes, "aborted": True, "live": live, "proofs": proofs}

    wave_c: list[tuple[str, str, int]] = []
    if js_urls and have.get("jshunter"):
        jl = stage.outdir / "_js_list.txt"
        jl.write_text("\n".join(js_urls), encoding="utf-8")
        wave_c.append((f"jshunter → {len(js_urls)} js files",
                       f"jshunter -l {_q(str(jl))} -ep -s -x -P -PU -g -F -L "
                       "-t 10 --no-color --found-only", 1800))
    if templates and have.get("dalfox"):
        tmp = stage.outdir / "_param_urls.txt"
        tmp.write_text("\n".join(templates), encoding="utf-8")
        wave_c.append((f"dalfox → {len(templates)} templates",
                       f"dalfox file {_q(str(tmp))} --no-color --silence --timeout 10", 1800))
    if url_pool and have.get("gf"):
        gf_in = stage.outdir / "_gf_in.txt"
        gf_in.write_text("\n".join(url_pool), encoding="utf-8")
        wave_c.append(("gf → URL classification (sqli/xss/ssrf/lfi/redirect)",
                       "for p in sqli xss ssrf lfi redirect; do "
                       f"echo \"== $p: $(gf \"$p\" < {_q(str(gf_in))} | tee {_q(str(stage.outdir))}/_gf_$p.txt | wc -l) URLs\"; "
                       "done", 600))
    # NOTE: testssl.sh moved to the wave-A lane, corsy to wave B — both
    # already fired without waiting for the URL pool ("all at once" rule).
    for title, rc, out in run_parallel(wave_c, emit, wave="analysis wave"):
        if title.startswith("jshunter"):
            p = _save_emit(stage, "jshunter", out, show=60)
            if out.strip():
                notes.append(f"## jshunter (JS endpoints + secrets)\n"
                             f"{brain.summarize(engine, 'jshunter JS analysis', out, emit=emit) or ''}\n(file: {p})")
        elif title.startswith("gf"):
            p = _save_emit(stage, "gf_classify", out)
            notes.append(f"## gf URL classification\n{(out or '').strip()}\n(file: {p})")
            emit("stage", f"gf sorted the URL pool: {(out or '').strip().replace(chr(10), ' | ')}")
        else:
            p = _save_emit(stage, "dalfox", out)
            if out.strip():
                notes.append(f"## dalfox (XSS)\n{brain.summarize(engine, 'dalfox', out, emit=emit) or ''}\n(file: {p})")
                for ln in out.splitlines():
                    if "POC" in ln and "http" in ln:
                        proofs.append({"kind": "xss", "detail": ln.strip()[:200]})
    if panicked():
        return {"notes": notes, "aborted": True, "live": live, "proofs": proofs}

    # URLs falling into gf's "sqli" class are tested by sqlmap FIRST — the
    # most suspicious templates up front, no time wasted on random order.
    sqli_priority: list[str] = []
    gf_sqli_file = stage.outdir / "_gf_sqli.txt"
    if gf_sqli_file.is_file():
        try:
            sqli_priority = [u.strip() for u in gf_sqli_file.read_text(
                encoding="utf-8", errors="replace").splitlines() if u.strip()]
        except OSError:
            sqli_priority = []
    ordered_templates = _param_templates(sqli_priority, allowed, MAX_SQLI) if sqli_priority else []
    ordered_templates += [t for t in templates if t not in ordered_templates]

    # sqlmap — once per TEMPLATE, parallel waves of 8, ruthless mode
    sqli_targets = ordered_templates[:MAX_SQLI]
    if sqli_targets and have.get("sqlmap"):
        sqli_dir = stage.outdir / "sqlmap"
        found: list[str] = []
        total_rounds = (len(sqli_targets) + 7) // 8
        for rnd in range(total_rounds):
            if panicked():
                break
            chunk = sqli_targets[rnd * 8:(rnd + 1) * 8]
            jobs = [
                (f"sqlmap → {u.split('://')[-1][:45]}",
                 f"sqlmap -u {_q(u)} --batch --smart --random-agent --threads=4 "
                 f"--level=2 --risk=1 --timeout=15 --retries=1 --flush-session "
                 f"--output-dir={_q(str(sqli_dir))}", 1500)
                for u in chunk
            ]
            emit("stage", f"sqlmap round {rnd + 1}/{total_rounds} — {len(chunk)} templates under fire")
            for (title, rc, out), url in zip(run_parallel(jobs, emit, wave=f"sqlmap round {rnd + 1}"), chunk):
                if "sqlmap identified the following injection point" in out:
                    start = out.find("sqlmap identified the following injection point")
                    found.append(f"### {url}\n{out[start:start + 1200]}")
                    proofs.append({"kind": "sqli", "target": url})
                    emit("finding", f"SQL INJECTION CONFIRMED: {url[:60]}")
        if found:
            content = "\n\n".join(found)
            sf = _save_emit(stage, "sqlmap_found", content, show=50)
            notes.append(f"## sqlmap (SQLi CONFIRMED)\n{content}\n(file: {sf})")
        else:
            notes.append(f"## sqlmap\nno injection confirmed on {len(sqli_targets)} templates "
                         f"(logs: {sqli_dir})")

    # If the wave-A lane (nikto/ports/testssl...) is still running, wait
    # for it before joining the report — but it was NEVER queued: everyone
    # started at the same time, total time = the longest tool's time, not
    # the sum of all.
    if t_a.is_alive():
        emit("stage", "attack waves done — waiting for the main-host lane "
                      "(nikto & friends) to report back")
    while t_a.is_alive():
        t_a.join(1.0)
        if panicked():
            break

    return {"notes": notes, "aborted": False, "live": live, "proofs": proofs}


# --------------------------------------------------------------------- PROOF

def run_proof(engine: Any, proofs: list[dict[str, str]], stage: _Stage,
              emit: Emit) -> None:
    """Proof mode: if 'shall we exploit?' gets a yes, collect HARMLESS
    proofs.

    Boundary (decision): sqlmap only --current-user/--current-db — NO data
    dumping, NO table/column pulling. Enough proof for a bug bounty report.
    Long explanations land in the notepad via say_or_note.
    """
    emit("stage", f"proof phase — {len(proofs)} candidate(s), harmless proofs only choom")
    proof_notes: list[str] = []

    # SQLi proof: identity query (no data)
    sqli = [p["target"] for p in proofs if p["kind"] == "sqli"][:4]
    if sqli:
        sqli_dir = stage.outdir / "sqlmap_proof"
        jobs = [
            (f"proof sqli → {u.split('://')[-1][:40]}",
             f"sqlmap -u {_q(u)} --batch --random-agent --threads=4 --timeout=15 "
             f"--current-user --current-db --flush-session "
             f"--output-dir={_q(str(sqli_dir))}", 900)
            for u in sqli
        ]
        for (title, rc, out), url in zip(run_parallel(jobs, emit, wave="proof (sqli)"), sqli):
            user_m = re.search(r"current user:\s*(.+)", out)
            db_m = re.search(r"current database:\s*(.+)", out)
            if user_m or db_m:
                line = f"SQLi PROVEN: {url} → user={user_m.group(1).strip() if user_m else '?'}, db={db_m.group(1).strip() if db_m else '?'}"
                emit("finding", line)
                proof_notes.append(line)

    # Takeover proof: show the CNAME record
    for p in proofs:
        if p["kind"] != "takeover":
            continue
        m = re.search(r"([a-z0-9.-]+\.[a-z]{2,})", p["detail"].lower())
        if not m:
            continue
        rc, out = run_cmd(f"dig +short CNAME {_q(m.group(1))}", 30, emit)
        line = f"TAKEOVER candidate {m.group(1)} → CNAME: {out.strip() or '(none)'}"
        emit("finding", line)
        proof_notes.append(line)

    # XSS: PoC links are already proof — collect and show
    xss = [p["detail"] for p in proofs if p["kind"] == "xss"][:10]
    if xss:
        proof_notes.append("XSS PoC links (open in a browser to confirm):\n" + "\n".join(xss))
        emit("finding", f"{len(xss)} XSS PoC link(s) collected — details in the notepad")

    if proof_notes:
        content = "\n".join(proof_notes)
        sf = _save_emit(stage, "proofs", content, show=50)
        # AI explanation of 'what this vuln is, where it lives, how to
        # exploit' — lands in the notepad if long (say_or_note)
        explain = brain.consult(
            engine,
            "You are Capri. These findings were just PROVEN on an authorized target. "
            "For each: what the vuln is, where it lives, and how to exploit it further "
            "(for the bug bounty report). Be concrete, use the actual URLs. English.",
            content, emit=emit,
        )
        if explain:
            say_or_note(explain, emit, f"exploit_notes_{stage.outdir.name}")
        emit("stage", f"proof phase done — {len(proof_notes)} proofs (file: {sf})")
    else:
        emit("say", "tried to prove them choom but nothing held up under the needle — report has the details")


# --------------------------------------------------------------------- entry

def run_psycho(engine: Any, host: str, mode: str, allowed: list[str],
               outbox: Path, emit: Emit) -> dict[str, Any]:
    """Main entry: open outdir, run the mode, write RAPOR.txt, return
    summary."""
    if not _in_scope(host, allowed):
        return {"ok": False, "error": f"cage denial: {host} is out of scope"}
    stamp = time.strftime("%Y%m%d_%H%M%S")
    outdir = PSYCHO_DIR / f"{host}_{stamp}"
    outdir.mkdir(parents=True, exist_ok=True)
    stage = _Stage(outdir, emit)
    ask = make_ask(outbox)
    emit("stage", f"hunt started — mode={mode}, home={outdir}")

    t0 = time.time()
    try:
        if mode == "hard":
            res = run_hard(engine, host, allowed, stage, emit, ask)
        else:
            res = run_simple(engine, host, allowed, stage, emit, ask)
    except Exception as exc:
        res = {"notes": [], "aborted": True}
        emit("error", f"pipeline broke: {exc!r}")
        advice = brain.consult(engine, f"The psycho pipeline threw an error: {exc!r}. What could be wrong?",
                               "", emit=emit)
        if advice:
            res["notes"].append(f"## error analysis (consult)\n{advice}")

    notes = res.get("notes") or []
    aborted = bool(res.get("aborted"))
    duration = int(time.time() - t0)

    final = brain.consult(
        engine,
        f"A {mode}-mode scan of {host} just finished ({duration}s). From the stage "
        "summaries below, write a final hunter report: key findings, a suspicion "
        "score (0-9) and a next-step suggestion. Format: SCORE: <0-9> on the first line.",
        "\n\n".join(notes), emit=emit,
    ) or "SCORE: ?\n(no report summary — check the output files)"

    score = None
    first = final.splitlines()[0] if final else ""
    for tok in first.replace(":", " ").split():
        if tok.isdigit():
            score = int(tok)
            break

    report = outdir / "RAPOR.txt"
    report.write_text(
        f"# Psycho report — {host} ({mode})\n# duration: {duration}s | date: {stamp}"
        + (" | ABORTED (panic)" if aborted else "") + "\n\n"
        + final + "\n\n" + "=" * 60 + "\n\n" + "\n\n".join(notes) + "\n",
        encoding="utf-8",
    )
    emit("stage", f"hunt done — {duration}s, report: {report}")

    # VERDICT — user rule: every hunt ends SPEAKING. If the AI is dead a
    # deterministic template steps in; Capri never stays silent.
    proofs = res.get("proofs") or []
    verdict = brain.consult(
        engine,
        f"You are Capri, a cheeky netrunner. A {mode} hunt on {host} just ended. "
        f"Score: {score if score is not None else '?'}/9, duration {duration}s, "
        f"{len(proofs)} provable-looking finding(s). Wrap it up for your choom in "
        "1-3 sentences, glitch vibe: if findings exist, hype them; if empty, say "
        "'nothing popped out, take a look yourself if you want' style. English.",
        final[:2000], emit=emit,
    )
    fallback = (f"hunt over choom — {duration}s on the clock, score "
                f"{score if score is not None else '?'}/9, {len(proofs)} thing(s) worth a second look. "
                f"Full story: {report}")
    say_or_note(verdict or fallback, emit, f"verdict_{host}")

    # SHALL WE EXPLOIT? — if there are findings, ask; on yes, proof mode
    # (harmless proofs)
    if proofs and not aborted and not panicked():
        kinds = ", ".join(sorted({p["kind"] for p in proofs}))
        answer = ask(f"choom, I flagged {len(proofs)} thing(s) that smell exploitable "
                     f"({kinds}) — shall I try to PROVE them? Harmless proofs only, "
                     "no data pulling. (yes/no)")
        if answer and answer.lower().startswith(("e", "y")):
            run_proof(engine, proofs, stage, emit)
        else:
            emit("say", "cool, keeping it observational — everything's in the report "
                        "if you wanna poke it yourself, choom")
    elif not aborted:
        emit("say", "nothing exploitable popped out this run choom — the report's on "
                    "disk if you wanna eyeball it yourself")

    return {
        "ok": not aborted, "host": host, "mode": mode, "score": score,
        "duration": duration, "report": str(report),
        "summary": final[:1500], "aborted": aborted,
    }
