"""avci shell — interactive agent terminal where jackboot (K3) can run commands.

Flow:
  you type a message (or leave it empty = "continue")
  → jackboot replies; if it wants to run a command it writes a single ```bash block
  → the block is caught, passed through scope + deny-list checks, shown to you
  → y: run (output goes back to jackboot) / n: reject / d: edit / q: quit

Safety:
  - in every command containing a URL/host, all hosts must be in allowed_hosts
  - sudo / rm -rf / / dd / mkfs etc. are deny-listed — even approval isn't enough
  - no command runs without being shown on screen
  - commands per turn are limited (max_cmds)
  - all commands + outputs are written to pipeline_events as "agent" (visible in the TUI Pipeline tab)
"""
from __future__ import annotations

import re
import subprocess
from datetime import datetime

from .ai.client import AIError
from .scope import host_allowed

AGENT_SYSTEM = """You are jackboot — the assistant of a senior, cold-blooded web security researcher.
In this session you have a terminal: when you want to run a command, you add ONLY a single
```bash block to your reply. The block is caught by AVCI, shown to the operator, run if
approved, and the stdout/stderr output is handed back to you.

Rules:
- ONE command per block. Chaining (&&, ;), redirecting to files (>, >>) and subshells
  ($(...) or backticks) are FORBIDDEN — auto-approval rejects instantly. Pipes may only
  go into filter tools: like curl ... | jq . or | grep ... | head -40.
- Only send requests to in-scope hosts. Out-of-scope host = instant rejection.
- No destructive commands (sudo, rm -rf, dd, mkfs...). They're deny-listed, don't even try.
- Use curl for your requests; -i shows status+headers, -s stays quiet.
- After seeing a test's result: short comment → either a new command block or a final verdict.
- Final verdict format: CONFIRMED / SUSPECT / REFUTED + reason + last line SUSPICION_SCORE: <0-9>.
- Don't present noise (304/301/302/404/429, static files) as findings; if the emperor has no clothes, say so.
- Speak English, short and clear."""

RECON_SYSTEM = """You are jackboot — the RECON agent of a senior security researcher.
Task: a free recon hunt on a single host. Your tools: curl, dig, host, whatweb, nmap, nuclei.
When you want to run a command, you add ONLY a single ```bash block to your reply; the block
is caught by AVCI, run, and its output is handed back to you.

Rules:
- ONE command per block. Chaining (&&, ;), redirecting to files (>, >>) and subshells
  ($(...) or backticks) are FORBIDDEN — auto-approval rejects instantly. Pipes may only
  go into filter tools: like | jq . | grep ... | head -40.
- Send requests ONLY to the TARGET host. Any other host = instant rejection (cage).
- Your recon plan (adapt the order based on results):
  1) Server profile: curl -sI, whatweb, dig — server header, technology, IP, interesting headers.
  2) Directory discovery: probe common paths one by one like
     .git/HEAD, .env, admin, api, backup, debug, actuator, swagger. List the ones returning
     200; note the Location targets of 301/302s.
     If you want, also throw a template scan with nuclei -u https://HOST -severity critical,high.
  3) Inspect interesting 200-returning paths with curl -s (admin, api, .git, .env, backup,
     debug...).
  4) Open redirect: throw HEAD requests with curl -s -I at redirect-ish endpoints and look at
     the Location header. (NO -L — following redirects is forbidden, only look at Location.)
  5) IDOR potential: note endpoints with id/uuid parameters for the report.
- Don't present noise as findings; if the emperor has no clothes, say so.
- When done, report format:
  SERVER: <one paragraph summary>
  FINDINGS: bullet by bullet (each bullet: URL + short evidence)
  Last line: SUSPICION_SCORE: <0-9>
- Speak English, short and clear."""

CMD_RE = re.compile(r"```bash\s*\n(.*?)```", re.DOTALL)
URL_HOST_RE = re.compile(r"https?://([^/\s:'\"]+)")
DOMAIN_TOKEN_RE = re.compile(r"^(?:www\.)?[a-z0-9][a-z0-9.-]*\.[a-z]{2,}$")
DENY_RE = re.compile(
    r"(^|[\s;&|])(sudo\b|mkfs|shutdown|reboot|halt\b)"
    r"|rm\s+-[a-zA-Z]*[rf][a-zA-Z]*\s+/(?:\s|$|;|&)"
    r"|dd\b[^\n;]*\bof=/dev/"
    r"|:\(\)\s*\{"  # fork bomb
)
LOCAL_HOSTS = {"localhost", "127.0.0.1", "::1", "0.0.0.0"}


def extract_command(text: str) -> str | None:
    """Return the first ```bash block in the reply; None if absent."""
    m = CMD_RE.search(text or "")
    return m.group(1).strip() if m else None


def command_hosts(cmd: str) -> list[str]:
    """Find all target hosts in the command (URLs + bare domain tokens)."""
    hosts = [h.lower().split(":")[0] for h in URL_HOST_RE.findall(cmd)]
    for tok in re.split(r"[\s;'\"|&<>()]+", cmd):
        tok = tok.strip().split("/")[0].rstrip(".")
        if DOMAIN_TOKEN_RE.match(tok) and not tok.endswith((".sh", ".py", ".txt", ".json")):
            hosts.append(tok.lower())
    # dedupe preserving order
    seen: dict[str, None] = {}
    for h in hosts:
        seen.setdefault(h)
    return list(seen)


def command_denied(cmd: str) -> str | None:
    """Return the reason if deny-listed, else None."""
    m = DENY_RE.search(cmd)
    return f"deny list: {m.group(0).strip()!r}" if m else None


def command_allowed(cmd: str, allowed_hosts: list[str]) -> tuple[bool, list[str]]:
    """Are all hosts in scope? (False, out_of_scope_hosts)"""
    bad = [
        h for h in command_hosts(cmd)
        if h not in LOCAL_HOSTS and not host_allowed(h, allowed_hosts)
    ]
    return (not bad, bad)


# 90 seconds: sometimes curl hangs so hard... don't wait, just kill it
def run_command(cmd: str, timeout: int = 90, max_out: int = 4000) -> str:
    """Run the command, return output as a single (truncated) text."""
    try:
        p = subprocess.run(
            cmd, shell=True, capture_output=True, text=True, timeout=timeout
        )
    except subprocess.TimeoutExpired:
        return f"[TIMEOUT — killed after {timeout}s]"
    out = (p.stdout or "") + (("\n[stderr]\n" + p.stderr) if p.stderr else "")
    out = out.strip() or "(no output)"
    if len(out) > max_out:
        out = out[:max_out] + f"\n... [{len(out) - max_out} chars truncated]"
    return f"[exit {p.returncode}]\n{out}"


def run_agent(
    engine,
    db,
    allowed_hosts: list[str],
    *,
    request_row=None,
    max_cmds: int = 40,
    timeout: int = 90,
    mode: str = "fast",
    escalate_score: int = 7,
    escalate: bool = True,
    model: str = "",
    input_fn=input,
    output_fn=print,
) -> None:
    """Interactive agent loop. input_fn/output_fn are injected in tests.

    mode="fast" → the cheap model (Groq) tests; at session end, if the final
    verdict's score passes escalate_score, the transcript automatically goes
    to the deep model (K3).
    """
    from .ai.engine import parse_suspicion

    model_name = model or getattr(
        getattr(engine, "fast" if mode == "fast" else "deep", None), "model", "?"
    )
    deep_name = getattr(getattr(engine, "deep", None), "model", "?")

    def log(text: str) -> None:
        try:
            db.add_pipeline_event("agent", request_row["id"] if request_row else None,
                                  model_name, text[:4000])
        except Exception:
            pass

    messages: list[dict] = [{"role": "system", "content": AGENT_SYSTEM}]
    if request_row is not None:
        from .ai.engine import build_request_context
        messages.append({
            "role": "user",
            "content": "Target request:\n" + build_request_context(request_row)
                       + "\n\nStart testing this surface. Suggest your first command.",
        })

    output_fn(f"jackboot agent terminal ready — model: {model_name}, command budget: {max_cmds}")
    if mode == "fast" and escalate:
        output_fn(f"if suspicion hits ≥ {escalate_score}, the session auto-escalates to {deep_name} verification")
    output_fn("empty line = continue · q = quit\n")
    log(f"agent session started ({model_name}; target: "
        f"{'#' + str(request_row['id']) if request_row else 'free'})")

    cmds_run = 0
    try:
        _main_loop(engine, messages, allowed_hosts, max_cmds, timeout, mode,
                   log, input_fn, output_fn)
    finally:
        if mode == "fast" and escalate:
            _auto_escalate(engine, messages, escalate_score, deep_name, log, output_fn)


def _main_loop(engine, messages, allowed_hosts, max_cmds, timeout, mode,
               log, input_fn, output_fn) -> None:
    """The actual interaction loop (verification fires via finally on exit)."""
    cmds_run = 0
    while True:
        try:
            user_in = input_fn("sen> ").strip()
        except (EOFError, KeyboardInterrupt):
            output_fn("\nquitting.")
            break
        if user_in.lower() in ("q", "quit", "exit"):
            output_fn("agent session closed.")
            break

        messages.append({"role": "user", "content": user_in or "Continue."})
        reply = _ask(engine, messages, output_fn, mode)
        if reply is None:
            break
        output_fn(f"\njackboot> {reply}\n")
        messages.append({"role": "assistant", "content": reply})

        # approval loop if jackboot suggested a command
        while True:
            cmd = extract_command(reply)
            if not cmd:
                break
            if cmds_run >= max_cmds:
                output_fn(f"[LIMIT] {max_cmds} commands ran — session budget exhausted.")
                messages.append({"role": "user", "content":
                                 "Command budget exhausted. Give your final verdict with what you have."})
                break

            denied = command_denied(cmd)
            ok, bad = (False, []) if denied else command_allowed(cmd, allowed_hosts)
            output_fn("┌─ jackboot suggests a command " + "─" * 40)
            output_fn("│ " + cmd.replace("\n", "\n│ "))
            output_fn("└" + "─" * 60)
            if denied:
                output_fn(f"[DENIED] {denied} — this command cannot be approved.")
                log(f"DENY LIST rejection: {cmd}")
                messages.append({"role": "user", "content":
                                 f"Command is deny-listed ({denied}). Suggest a different, safe command."})
                reply = _ask(engine, messages, output_fn, mode)
                if reply is None:
                    return
                output_fn(f"\njackboot> {reply}\n")
                messages.append({"role": "assistant", "content": reply})
                continue
            if not ok:
                output_fn(f"[OUT OF SCOPE] {', '.join(bad)} — not in allowed_hosts, skipping.")
                log(f"OUT OF SCOPE rejection: {cmd}")
                messages.append({"role": "user", "content":
                                 f"Host(s) in the command are out of scope: {', '.join(bad)}. "
                                 "Suggest a new command with in-scope hosts only."})
                reply = _ask(engine, messages, output_fn, mode)
                if reply is None:
                    return
                output_fn(f"\njackboot> {reply}\n")
                messages.append({"role": "assistant", "content": reply})
                continue

            try:
                onay = input_fn("run? [y/n/d(edit)/q] ").strip().lower()
            except (EOFError, KeyboardInterrupt):
                output_fn("\nquitting.")
                return
            if onay == "q":
                output_fn("agent session closed.")
                return
            if onay == "d":
                try:
                    edited = input_fn("edited command> ").strip()
                except (EOFError, KeyboardInterrupt):
                    return
                if edited:
                    cmd = edited
                    d2 = command_denied(cmd)
                    ok2, bad2 = (False, []) if d2 else command_allowed(cmd, allowed_hosts)
                    if d2 or not ok2:
                        output_fn(f"[DENIED] edited command is invalid: {d2 or ', '.join(bad2)}")
                        continue
                    onay = "y"
            if onay != "y":
                log(f"OPERATOR REJECTED: {cmd}")
                messages.append({"role": "user", "content":
                                 "Command rejected. Either suggest a different command or "
                                 "assess with the information you have."})
                reply = _ask(engine, messages, output_fn, mode)
                if reply is None:
                    return
                output_fn(f"\njackboot> {reply}\n")
                messages.append({"role": "assistant", "content": reply})
                continue

            cmds_run += 1
            output_fn(f"[{datetime.now():%H:%M:%S}] running… ({cmds_run}/{max_cmds})")
            result = run_command(cmd, timeout=timeout)
            output_fn(result + "\n")
            log(f"$ {cmd}\n{result[:3500]}")
            messages.append({"role": "user", "content":
                             f"Command output:\n```\n{result}\n```\nComment; suggest a new command if needed."})
            reply = _ask(engine, messages, output_fn, mode)
            if reply is None:
                return
            output_fn(f"\njackboot> {reply}\n")
            messages.append({"role": "assistant", "content": reply})


def _ask(engine, messages: list[dict], output_fn, mode: str = "fast") -> str | None:
    try:
        return engine.chat_messages(messages, mode=mode)
    except AIError as e:
        output_fn(f"[AI ERROR] {e}")
        return None


def _auto_escalate(engine, messages: list[dict], escalate_score: int,
                   deep_name: str, log, output_fn) -> None:
    """At session end: if the final verdict passed the threshold, have the
    deep model verify the transcript."""
    from .ai.engine import parse_suspicion

    last_score = None
    for msg in reversed(messages):
        if msg.get("role") == "assistant":
            last_score = parse_suspicion(msg.get("content", ""))
            if last_score is not None:
                break
    if last_score is None or last_score < escalate_score:
        return

    output_fn(f"\n[ESCALATION] agent's final score {last_score}/9 ≥ {escalate_score} — "
              f"session transcript going to {deep_name or 'deep model'} for verification…")
    transcript = "\n".join(
        f"[{m['role']}] {m['content']}" for m in messages[-14:] if m.get("role") != "system"
    )[:6000]
    log(f"K3 verification requested — agent score {last_score}/9")
    try:
        verdict = engine.verify_transcript(transcript, mode="deep")
    except AIError as e:
        output_fn(f"[AI ERROR] deep verification: {e}")
        log(f"K3 verification error: {e}")
        return
    output_fn(f"\nK3 VERIFICATION> {verdict}\n")
    log(f"K3 verification result:\n{verdict[:3500]}")


# --------------------------------------------------------------------- auto-test

# only filter tools are allowed as pipe targets — a chain that writes curl
# output to a file or feeds another program gets no auto-approval
SAFE_PIPE_TOOLS = {"jq", "grep", "head", "tail", "cut", "wc", "sort", "uniq", "tr", "sed", "awk", "base64"}


def command_auto_safe(cmd: str, allowed_hosts: list[str]) -> tuple[bool, str]:
    """Can this command run WITHOUT human approval?

    Rules: not deny-listed, all hosts in scope, no file redirect/chaining/
    subshell, pipes only into filter tools. Everything else is rejected.
    """
    denied = command_denied(cmd)
    if denied:
        return False, denied
    ok, bad = command_allowed(cmd, allowed_hosts)
    if not ok:
        return False, f"out of scope: {', '.join(bad)}"
    if re.search(r"(>>?|&&|;|`|\$\(|\n)", cmd):
        return False, "redirect/chain/subshell gets no auto-approval"
    if "|" in cmd:
        for part in cmd.split("|")[1:]:
            toks = part.strip().split()
            if not toks or toks[0] not in SAFE_PIPE_TOOLS:
                return False, f"pipe target is not safe: {toks[0] if toks else '?'}"
    return True, ""


def run_auto_test(
    engine,
    db,
    allowed_hosts: list[str],
    row,
    reason: str,
    test_idea: str,
    *,
    max_cmds: int = 8,
    timeout: int = 90,
    emit=None,
) -> tuple[int | None, str]:
    """The request triage flagged gets tested by Groq itself — no human
    approval.

    Only commands passing command_auto_safe run; everything is written to
    pipeline_events. Returns: (final suspicion score, transcript).
    """
    from .ai.engine import build_request_context, parse_suspicion

    emit = emit or (lambda _s, _m: None)
    messages: list[dict] = [
        {"role": "system", "content": AGENT_SYSTEM},
        {"role": "user", "content": (
            "Triage flagged this request as suspicious.\n"
            f"REASON: {reason}\nSUGGESTED TEST: {test_idea}\n\n"
            "TARGET REQUEST:\n" + build_request_context(row) + "\n\n"
            "Run the tests YOURSELF: write a single bash block each time, "
            "its output comes back to you automatically. Only curl-based, "
            "unchained, redirect-free commands run. When done, give your final "
            "verdict: CONFIRMED / SUSPECT / REFUTED + SUSPICION_SCORE."
        )},
    ]
    transcript: list[str] = []
    nudges = 0  # nudge allowance against commandless/indecisive replies
    for _ in range(max_cmds + 2):  # +2: correction allowance for unsafe suggestions
        try:
            reply = engine.chat_messages(messages, mode="fast")
        except AIError as exc:
            emit("error", f"auto-test agent: {exc}")
            transcript.append(f"[AI error] {exc}")
            break
        transcript.append(f"agent: {reply}")
        messages.append({"role": "assistant", "content": reply})

        cmd = extract_command(reply)
        if not cmd:
            # No command: finish only if it really gave a final verdict; if it
            # just chatted (or returned empty), nudge it for a verdict/command.
            if re.search(r"CONFIRMED|SUSPECT|REFUTED", reply or ""):
                break  # final verdict given
            nudges += 1
            if nudges > 2:
                emit("agent", "agent gave neither command nor verdict — closing test")
                transcript.append("[agent stuck without command/verdict, test closed]")
                break
            messages.append({"role": "user", "content": (
                "I didn't see a command block. Either continue with a single "
                "```bash block (one unchained, redirect-free curl; pipes only "
                "into filters like jq/grep/head) or write your final verdict: "
                "CONFIRMED / SUSPECT / REFUTED + SUSPICION_SCORE: <0-9> on the "
                "last line."
            )})
            continue
        safe, why = command_auto_safe(cmd, allowed_hosts)
        if not safe:
            emit("agent", f"auto-approval denied: {why}")
            transcript.append(f"[auto-approval rejection: {why}] $ {cmd}")
            messages.append({"role": "user", "content": (
                f"Command failed auto-approval: {why}. Suggest only a single, "
                "unchained, redirect-free curl command or decide with what you have."
            )})
            continue
        emit("agent", f"auto> $ {cmd}")
        result = run_command(cmd, timeout=timeout)
        transcript.append(f"$ {cmd}\n{result}")
        _lines = result.strip().splitlines()
        _preview = "\n".join(_lines[:30])[:2000]
        emit("output", _preview + ("\n… (output truncated)" if len(_lines) > 30 else ""))
        messages.append({"role": "user", "content": (
            f"Command output:\n```\n{result}\n```\nComment; new command if needed, "
            "otherwise final verdict + SUSPICION_SCORE."
        )})

    score = None
    for msg in reversed(messages):
        if msg.get("role") == "assistant":
            score = parse_suspicion(msg.get("content", ""))
            if score is not None:
                break
    return score, "\n".join(transcript)


def run_hunt(
    engine,
    db,
    allowed_hosts: list[str],
    host: str,
    *,
    max_cmds: int = 20,
    timeout: int = 300,
    emit=None,
) -> tuple[int | None, str]:
    """Free recon hunt Capri requests from chat: single host, no approval but
    inside the cage (scope + deny-list + unchained-command rules fully apply).

    Returns: (final suspicion score, transcript).
    """
    from .ai.engine import parse_suspicion

    emit = emit or (lambda _s, _m: None)
    messages: list[dict] = [
        {"role": "system", "content": RECON_SYSTEM},
        {"role": "user", "content": (
            f"TARGET HOST: {host}\nGo on a free recon hunt on this host. "
            "Start with the server profile, do directory fuzzing with ffuf, "
            "inspect paths returning 200, look for open redirect and IDOR "
            "potential. When done, write your report: SERVER / FINDINGS / "
            "SUSPICION_SCORE."
        )},
    ]
    transcript: list[str] = []
    nudges = 0
    for _ in range(max_cmds + 2):  # +2: allowance for rejections/corrections
        try:
            reply = engine.chat_messages(messages, mode="fast")
        except AIError as exc:
            emit("error", f"hunt agent: {exc}")
            transcript.append(f"[AI error] {exc}")
            break
        transcript.append(f"agent: {reply}")
        messages.append({"role": "assistant", "content": reply})

        cmd = extract_command(reply)
        if not cmd:
            if re.search(r"FINDINGS|SUSPICION_SCORE", reply or ""):
                break  # report written, hunt over
            nudges += 1
            if nudges > 2:
                emit("agent", "agent gave neither command nor report — closing hunt")
                transcript.append("[agent stuck without commands, hunt closed]")
                break
            messages.append({"role": "user", "content": (
                "I didn't see a command block. Either continue with a single "
                "```bash block (one, unchained, redirect-free; pipes only into "
                "filters like jq/grep/head) or write your report: SERVER / "
                "FINDINGS / SUSPICION_SCORE."
            )})
            continue
        safe, why = command_auto_safe(cmd, allowed_hosts)
        if not safe:
            emit("agent", f"auto-approval denied: {why}")
            transcript.append(f"[auto-approval rejection: {why}] $ {cmd}")
            messages.append({"role": "user", "content": (
                f"Command failed auto-approval: {why}. Suggest only a single, "
                "unchained, redirect-free command or close with your report."
            )})
            continue
        emit("agent", f"hunt> $ {cmd}")
        result = run_command(cmd, timeout=timeout)
        transcript.append(f"$ {cmd}\n{result}")
        _lines = result.strip().splitlines()
        _preview = "\n".join(_lines[:30])[:2000]
        emit("output", _preview + ("\n… (output truncated)" if len(_lines) > 30 else ""))
        messages.append({"role": "user", "content": (
            f"Command output:\n```\n{result[:6000]}\n```\nComment; new command "
            "if needed, otherwise report + SUSPICION_SCORE."
        )})

    score = None
    for msg in reversed(messages):
        if msg.get("role") == "assistant":
            score = parse_suspicion(msg.get("content", ""))
            if score is not None:
                break
    return score, "\n".join(transcript)
