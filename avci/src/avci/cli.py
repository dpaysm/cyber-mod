"""avci command line entry."""

from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
from pathlib import Path

from avci.config import ensure_config, load_config, resolve_config_path


def cmd_tui(_args: argparse.Namespace) -> int:
    from avci.ai import AIEngine
    from avci.tui.app import AvciApp  # TUI dependencies load only here

    cfg = load_config()
    if not cfg.allowed_hosts:
        print("[avci] WARNING: allowed_hosts is empty — the proxy will record no traffic.")
        print(f"[avci] Config: {resolve_config_path()}")
    engine = AIEngine(cfg.fast, cfg.deep)
    AvciApp(
        db_path=cfg.db_path,
        allowed_hosts=cfg.allowed_hosts,
        engine=engine,
        max_requests_per_test=cfg.max_requests_per_test,
        triage_enabled=cfg.triage_enabled,
        triage_interval=cfg.triage_interval,
        triage_min_score=cfg.triage_min_score,
        triage_batch_max=cfg.triage_batch_max,
        prefilter_enabled=cfg.prefilter_enabled,
        prefilter_min=cfg.prefilter_min,
        triage_auto_test=cfg.triage_auto_test,
        agent_escalate_score=cfg.agent_escalate_score,
        agent_auto_cmds=cfg.agent_auto_cmds,
        fresh_start=cfg.fresh_start,
    ).run()
    return 0


def cmd_triaj(_args: argparse.Namespace) -> int:
    """One-shot triage cycle — to quickly verify keys and the line."""
    from avci.ai import AIEngine
    from avci.db import Database
    from avci.triage import run_cycle

    cfg = load_config()
    engine = AIEngine(cfg.fast, cfg.deep)
    db = Database(cfg.db_path)
    try:
        flagged = run_cycle(
            db,
            engine,
            min_score=cfg.triage_min_score,
            batch_max=cfg.triage_batch_max,
            triage_model=cfg.fast.model,
            deep_model=cfg.deep.model,
            prefilter_enabled=cfg.prefilter_enabled,
            prefilter_min=cfg.prefilter_min,
            auto_test=cfg.triage_auto_test,
            escalate_score=cfg.agent_escalate_score,
            auto_cmds=cfg.agent_auto_cmds,
            allowed_hosts=cfg.allowed_hosts,
            emit=lambda stage, msg: print(f"[{stage}] {msg}"),
        )
        if flagged == 0:
            print("[triage] no new requests, or nothing scored above threshold.")
    finally:
        db.close()
    return 0


def cmd_proxy(args: argparse.Namespace) -> int:
    cfg = load_config()
    mitmdump = shutil.which("mitmdump")
    if mitmdump is None:
        print(
            "[avci] ERROR: mitmdump not found — install it with `pip install mitmproxy`.",
            file=sys.stderr,
        )
        return 1
    if not cfg.allowed_hosts:
        print("[avci] WARNING: allowed_hosts is empty — no traffic will be recorded.")
        print(f"[avci] Config: {resolve_config_path()}")

    import avci.proxy_addon as addon

    port = args.port or cfg.proxy_port
    cmd = [mitmdump, "-s", str(Path(addon.__file__)), "--listen-port", str(port)]
    if args.upstream:
        # chain: browser → AVCI → Burp → target.
        # ssl_insecure: don't verify the cert Burp presents with its own CA.
        cmd += ["--mode", f"upstream:{args.upstream}", "--set", "ssl_insecure=true"]
        print(f"[avci] upstream chain → {args.upstream} (Burp)")
    print(f"[avci] proxy listening → 127.0.0.1:{port}")
    print("[avci] point your browser proxy at this address.")
    print("[avci] for HTTPS, open http://mitm.it once in the browser and install the CA.")
    return subprocess.call(cmd)


def cmd_ingest(args: argparse.Namespace) -> int:
    from avci.ingest import IngestServer

    cfg = load_config()
    if not cfg.allowed_hosts:
        print("[avci] WARNING: allowed_hosts is empty — incoming traffic will not be recorded.")
        print(f"[avci] Config: {resolve_config_path()}")
    port = args.port or cfg.ingest_port
    server = IngestServer(cfg.db_path, cfg.allowed_hosts, port=port, verbose=True)
    print(f"[avci] ingest listening → http://127.0.0.1:{port}/ingest")
    print("[avci] if the 'AVCI Mirror' extension is loaded in Burp, traffic copies land here.")
    print("[avci] for the TUI, run in a second terminal: avci")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[avci] ingest shutting down.")
    finally:
        server.close()
    return 0


def cmd_shell(args: argparse.Namespace) -> int:
    """jackboot agent terminal: suggests commands, runs them with your
    approval, sees the output."""
    from avci.agent import run_agent
    from avci.ai import AIEngine
    from avci.db import Database

    cfg = load_config()
    if not cfg.allowed_hosts:
        print("[avci] ERROR: allowed_hosts is empty — the agent cannot request any target.", file=sys.stderr)
        return 1
    engine = AIEngine(cfg.fast, cfg.deep)
    db = Database(cfg.db_path)
    try:
        row = None
        if args.request_id is not None:
            row = db.get_request(args.request_id)
            if row is None:
                print(f"[avci] ERROR: no request with id #{args.request_id}.", file=sys.stderr)
                return 1
        run_agent(
            engine,
            db,
            cfg.allowed_hosts,
            request_row=row,
            max_cmds=args.max_cmd,
            mode=args.model,
            escalate_score=cfg.agent_escalate_score,
            escalate=not args.no_escalate,
        )
    finally:
        db.close()
    return 0


def cmd_capri(args: argparse.Namespace) -> int:
    """Capri bridge (Siber Mod): runs queued jobs inside the cage."""
    from avci.ai import AIEngine
    from avci.capri_bridge import run_daemon
    from avci.db import Database

    cfg = load_config()
    if not cfg.capri_enabled:
        print("[avci] Capri bridge is disabled in config (capri: {enabled: false}).")
        return 1
    if not cfg.allowed_hosts:
        print("[avci] ERROR: allowed_hosts is empty — the bridge cannot run any test.", file=sys.stderr)
        print(f"[avci] Config: {resolve_config_path()}", file=sys.stderr)
        return 1
    engine = AIEngine(cfg.fast, cfg.deep)
    db = Database(cfg.db_path)
    try:
        run_daemon(cfg, db, engine, once=args.once)
    except KeyboardInterrupt:
        print("\n[avci] Capri bridge shutting down.")
    finally:
        db.close()
    return 0


def cmd_temizle(args: argparse.Namespace) -> int:
    """Clean old records without opening the TUI. --all: deletes findings and
    tests too."""
    from avci.db import Database

    cfg = load_config()
    db = Database(cfg.db_path)
    try:
        counts = db.clear_session_data(everything=args.all)
        cleared = ", ".join(f"{t}: {n}" for t, n in counts.items())
        print(f"[avci] cleared → {cleared}")
        if not args.all:
            print("[avci] findings and test runs were kept. For everything: avci clean --all")
    finally:
        db.close()
    return 0


def cmd_scope(_args: argparse.Namespace) -> int:
    cfg = load_config()
    print("allowed_hosts:")
    if cfg.allowed_hosts:
        for h in cfg.allowed_hosts:
            print(f"  - {h}")
    else:
        print("  (empty — no traffic is recorded, no test can run)")
    print(f"\nconfig: {resolve_config_path()}")
    print(f"db:     {Path(cfg.db_path).expanduser()}")
    return 0


def cmd_rapor(args: argparse.Namespace) -> int:
    from avci.db import Database
    from avci.report import render_markdown

    cfg = load_config()
    db = Database(cfg.db_path)
    try:
        findings = db.list_findings()
        if not findings:
            print("[avci] no findings recorded — save one with `f` in the TUI.")
            return 0
        md = render_markdown(findings, db)
        out = Path(args.out).expanduser() if args.out else Path("avci_report.md")
        out.write_text(md, encoding="utf-8")
        print(f"[avci] report draft written → {out.resolve()} ({len(findings)} findings)")
        print("[avci] review the impact sections and the program format before submitting.")
    finally:
        db.close()
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="avci",
        description="AVCI — AI-assisted interactive web security testing copilot (TUI). "
        "Use only on scope you are authorized to test.",
    )
    parser.add_argument("--version", action="store_true", help="show version")
    sub = parser.add_subparsers(dest="cmd")
    sub.add_parser("tui", help="start the TUI (default)")
    p_proxy = sub.add_parser("proxy", help="start the mitmproxy interceptor")
    p_proxy.add_argument("--port", type=int, default=None, help="listen port")
    p_proxy.add_argument(
        "--upstream",
        default=None,
        metavar="PROXY_URL",
        help="chain to an upstream proxy (e.g. http://127.0.0.1:8080 → Burp)",
    )
    p_ingest = sub.add_parser("ingest", help="start the Burp mirror server (127.0.0.1)")
    p_ingest.add_argument("--port", type=int, default=None, help="ingest port")
    sub.add_parser("scope", help="show allowed_hosts and paths")
    p_temiz = sub.add_parser("clean", aliases=["temizle"], help="delete old request + pipeline records")
    p_temiz.add_argument("--all", dest="all", action="store_true",
                         help="also delete findings and test runs (careful)")
    p_rapor = sub.add_parser("report", aliases=["rapor"], help="render a markdown report draft from findings")
    p_rapor.add_argument("--out", default=None, help="output file (default: avci_report.md)")
    sub.add_parser("triage", help="run a single triage cycle (connectivity test)")
    p_capri = sub.add_parser(
        "capri", help="Capri bridge (Cyber Mod): processes queued tasks"
    )
    p_capri.add_argument("--once", action="store_true",
                         help="process the queue for one cycle and exit (connectivity test)")
    p_shell = sub.add_parser(
        "shell", help="jackboot agent terminal: suggests commands, runs them with your approval"
    )
    p_shell.add_argument("--request-id", type=int, default=None,
                         help="start the session in the context of this request (the #id in the TUI)")
    p_shell.add_argument("--max-cmd", type=int, default=40,
                         help="command budget per session (default: 40)")
    p_shell.add_argument("--model", choices=["fast", "deep"], default="fast",
                         help="agent brain: fast=Groq (default, free) · deep=Kimi K3")
    p_shell.add_argument("--no-escalate", action="store_true",
                         help="disable automatic K3 verification on high suspicion")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.version:
        from avci import __version__

        print(f"avci {__version__}")
        return 0

    cfg_path = resolve_config_path()
    if ensure_config(cfg_path):
        print(f"[avci] first run: template config created → {cfg_path}")
        print("[avci] fill allowed_hosts with your target program's scope.")

    if args.cmd in (None, "tui"):
        return cmd_tui(args)
    if args.cmd == "proxy":
        return cmd_proxy(args)
    if args.cmd == "ingest":
        return cmd_ingest(args)
    if args.cmd == "scope":
        return cmd_scope(args)
    if args.cmd in ("report", "rapor"):
        return cmd_rapor(args)
    if args.cmd == "triage":
        return cmd_triaj(args)
    if args.cmd == "shell":
        return cmd_shell(args)
    if args.cmd == "capri":
        return cmd_capri(args)
    if args.cmd in ("clean", "temizle"):
        return cmd_temizle(args)
    parser.print_help()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
