"""AVCI TUI — 3-panel Textual app.

LEFT: deduped request list. RIGHT: full request/response detail.
BOTTOM: jackboot chat panel — the selected request automatically becomes
context, `x` clears it. `a` = FAST analysis (local model), `d` = DEEP
analysis (API).

The list polls SQLite at 1s intervals; communication with the mitmproxy
addon / ingest server goes through this file.
"""

from __future__ import annotations

import json
import time
from pathlib import Path

from rich.syntax import Syntax
from rich.text import Text
from textual import on, work
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.css.query import NoMatches
from textual.screen import ModalScreen
from textual.widgets import (
    Button,
    DataTable,
    Footer,
    Header,
    Input,
    RichLog,
    Select,
    Static,
    TabbedContent,
    TabPane,
)

from avci.agent import command_allowed, command_denied, extract_command, run_command
from avci.ai import AIEngine, AIError
from avci.db import Database
from avci.testing import check_script, load_results, run_script, summarize
from avci.triage import run_cycle

DETAIL_MAX_CHARS = 40_000


class DetailScreen(ModalScreen[None]):
    """Full-screen view opened with Enter: request on the left, response on
    the right.

    Return to history with esc. Why a separate screen: our eyes got tired
    of trying to read headers in that tiny panel.
    """

    BINDINGS = [Binding("escape", "dismiss(None)", "Back to history")]

    CSS = """
    DetailScreen { layout: horizontal; }
    #req-pane, #resp-pane {
        width: 1fr; height: 100%;
        border: solid $primary; background: $surface; padding: 0 1;
    }
    #req-pane { border-title-color: $accent; }
    """

    def __init__(self, row):
        super().__init__()
        self._row = row

    def compose(self) -> ComposeResult:
        req = RichLog(id="req-pane", wrap=True)
        resp = RichLog(id="resp-pane", wrap=True)
        req.border_title = f"REQUEST  #{self._row['id']}"
        resp.border_title = f"RESPONSE  {self._row['status'] or '-'}"
        yield req
        yield resp

    def on_mount(self) -> None:
        row = self._row
        req = self.query_one("#req-pane", RichLog)
        req.write(Text(f"{row['method']}  {row['url']}", style="bold cyan"))
        req.write(Text(
            f"seen: x{row['count']}   first: {_ts(row['first_seen'])}   last: {_ts(row['last_seen'])}",
            style="dim",
        ))
        if row["notes"]:
            req.write(Text(""))
            req.write(Text("-- Notlar --", style="bold yellow"))
            req.write(row["notes"])
        req.write(Text(""))
        req.write(_format_headers(row["req_headers"]))
        if row["req_body"]:
            req.write(Text(""))
            req.write(_format_body(row["req_body"], row["req_headers"]))

        resp = self.query_one("#resp-pane", RichLog)
        if row["resp_headers"]:
            resp.write(_format_headers(row["resp_headers"]))
        if row["resp_body"]:
            resp.write(Text(""))
            resp.write(_format_body(row["resp_body"], row["resp_headers"]))
        if not row["resp_headers"] and not row["resp_body"]:
            resp.write(Text("response not captured", style="dim"))


class ScopeScreen(ModalScreen[None]):
    """`s` key: scope and audit-trail summary."""

    BINDINGS = [
        Binding("escape", "dismiss", "Kapat"),
        Binding("s", "dismiss", "Kapat"),
    ]

    CSS = """
    ScopeScreen { align: center middle; }
    #scope-box {
        width: 64; height: auto; max-height: 85%;
        border: solid $primary; background: $surface; padding: 1 2;
    }
    """

    def __init__(self, allowed_hosts: list[str], stats: dict[str, int], db_path: str):
        super().__init__()
        self._hosts = allowed_hosts
        self._stats = stats
        self._db_path = db_path

    def compose(self) -> ComposeResult:
        lines = ["[b]SCOPE — allowed_hosts[/b]", ""]
        if self._hosts:
            lines += [f"  • {h}" for h in self._hosts]
        else:
            lines.append("  [red](empty — no traffic is recorded, no test can run)[/red]")
        lines += [
            "",
            f"Recorded request templates: [b]{self._stats['rows']}[/b]  |  total hits: [b]{self._stats['hits']}[/b]",
            f"denetim izi (SQLite): {self._db_path}",
            "",
            "[dim]Close with Esc / s[/dim]",
        ]
        yield Static("\n".join(lines), id="scope-box")


class CommandScreen(ModalScreen[bool]):
    """Approval for a single-line command jackboot suggested in chat:
    y=run, n=reject."""

    BINDINGS = [
        Binding("y", "dismiss(True)", "Run"),
        Binding("n", "dismiss(False)", "Reddet"),
        Binding("escape", "dismiss(False)", "Reddet", show=False),
    ]

    CSS = """
    CommandScreen { align: center middle; }
    #cmd-box {
        width: 80%; height: auto; max-height: 60%;
        border: solid $accent; background: $surface; padding: 1 2;
    }
    """

    def __init__(self, command: str):
        super().__init__()
        self._command = command

    def compose(self) -> ComposeResult:
        with Vertical(id="cmd-box"):
            yield Static("[b]jackboot wants to run this command:[/b]")
            yield Static(f"[cyan]{self._command}[/cyan]")
            yield Static("[dim][y] run · [n] deny[/dim]")


class ScriptScreen(ModalScreen[str]):
    """Show the generated test script and ask for EXPLICIT approval:
    y=run, n=cancel."""

    BINDINGS = [
        Binding("y", "dismiss('run')", "Approve and run"),
        Binding("n", "dismiss('cancel')", "Cancel"),
        Binding("escape", "dismiss('cancel')", "Cancel", show=False),
    ]

    CSS = """
    ScriptScreen { align: center middle; }
    #script-box {
        width: 90%; height: 85%;
        border: solid $warning; background: $surface; padding: 1 2;
    }
    #script-code { height: 1fr; }
    """

    def __init__(self, script: str, title: str, total_requests: int, limit: int):
        super().__init__()
        self._script = script
        self._title = title
        self._total = total_requests
        self._limit = limit

    def compose(self) -> ComposeResult:
        warn = ""
        if self._total > self._limit:
            warn = (
                f"\n[yellow]WARNING: estimated request count {self._total} > limit "
                f"{self._limit} — extra approval is your responsibility.[/yellow]"
            )
        with Vertical(id="script-box"):
            yield Static(
                f"[b]TEST SCRIPT — {self._title}[/b]\n"
                f"tahmini istek: {self._total} (limit {self._limit}){warn}\n"
                "[dim]y = approve and run   n/Esc = cancel[/dim]"
            )
            yield RichLog(id="script-code", wrap=True)

    def on_mount(self) -> None:
        self.query_one("#script-code", RichLog).write(
            Syntax(self._script, "python", word_wrap=True, theme="ansi_dark")
        )


class LimitConfirmScreen(ModalScreen[bool]):
    """EXTRA approval on request-cap overflow (STAGE 4)."""

    BINDINGS = [
        Binding("y", "dismiss(True)", "Run anyway"),
        Binding("n", "dismiss(False)", "Cancel"),
        Binding("escape", "dismiss(False)", "Cancel", show=False),
    ]

    CSS = """
    LimitConfirmScreen { align: center middle; }
    #limit-box {
        width: 62; height: auto; border: solid $error;
        background: $surface; padding: 1 2;
    }
    """

    def __init__(self, total: int, limit: int):
        super().__init__()
        self._total = total
        self._limit = limit

    def compose(self) -> ComposeResult:
        yield Static(
            f"[b red]LIMIT EXCEEDED[/b red]\n\n"
            f"This test will fire an estimated [b]{self._total}[/b] requests — limit is {self._limit}.\n"
            "Repeated/parallel requests put load on the target. Continue only if the "
            "program rules allow it and you have a reason.\n\n"
            "[dim]y = run anyway   n/Esc = cancel[/dim]",
            id="limit-box",
        )


class NoteScreen(ModalScreen[str | None]):
    """`n` key: add a note to the selected request."""

    BINDINGS = [Binding("escape", "dismiss(None)", "Cancel")]

    CSS = """
    NoteScreen { align: center middle; }
    #note-box { width: 70; height: auto; border: solid $primary; background: $surface; padding: 1 2; }
    """

    def compose(self) -> ComposeResult:
        with Vertical(id="note-box"):
            yield Static("[b]ADD NOTE[/b] — Enter saves, Esc cancels")
            yield Input(placeholder="not…", id="note-input")

    @on(Input.Submitted, "#note-input")
    def _submit(self, event: Input.Submitted) -> None:
        self.dismiss(event.value.strip() or None)


class FindingScreen(ModalScreen[dict | None]):
    """`f` key: save the selected request/result as a finding."""

    BINDINGS = [Binding("escape", "dismiss(None)", "Cancel")]

    CSS = """
    FindingScreen { align: center middle; }
    #finding-box {
        width: 72; height: auto; border: solid $success;
        background: $surface; padding: 1 2;
    }
    #finding-box Input, #finding-box Select { margin: 0 0 1 0; }
    #finding-buttons { height: auto; }
    """

    def __init__(self, desc: str):
        super().__init__()
        self._desc = desc

    def compose(self) -> ComposeResult:
        with Vertical(id="finding-box"):
            yield Static(f"[b]FINDING — {self._desc}[/b]")
            yield Input(placeholder="title (e.g. IDOR on /user/{id})", id="f-title")
            yield Select(
                [("critical", "critical"), ("high", "high"), ("medium", "medium"),
                 ("low", "low"), ("info", "info")],
                value="medium", id="f-severity", allow_blank=False, prompt="severity",
            )
            yield Select(
                [("SUSPECT", "SUSPECT"), ("CONFIRMED", "CONFIRMED"),
                 ("REFUTED", "REFUTED")],
                value="SUSPECT", id="f-status", allow_blank=False, prompt="status",
            )
            yield Input(placeholder="notes / short impact summary", id="f-notes")
            with Horizontal(id="finding-buttons"):
                yield Button("Save", id="save", variant="success")
                yield Button("Cancel", id="cancel")

    @on(Button.Pressed, "#save")
    def _save(self) -> None:
        title = self.query_one("#f-title", Input).value.strip()
        if not title:
            self.notify("Title cannot be empty.", severity="warning")
            return
        self.dismiss(
            {
                "title": title,
                "severity": str(self.query_one("#f-severity", Select).value),
                "status": str(self.query_one("#f-status", Select).value),
                "notes": self.query_one("#f-notes", Input).value.strip(),
            }
        )

    @on(Button.Pressed, "#cancel")
    def _cancel(self) -> None:
        self.dismiss(None)


class AvciApp(App[None]):
    TITLE = "AVCI"
    SUB_TITLE = "interactive web security testing copilot"

    CSS = """
    #main { height: 1fr; }
    #req-table { width: 46%; border-right: solid $primary; }
    #detail { width: 54%; padding: 0 1; }
    #chat { height: 32%; min-height: 10; border-top: solid $primary; }
    #chat TabbedContent { height: 100%; }
    #chat-log, #pipe-log { height: 1fr; padding: 0 1; }
    #chat-bar { height: 3; }
    #ctx-chip { width: auto; padding: 0 1; color: $text-muted; }
    #chat-input { width: 1fr; }
    """

    BINDINGS = [
        Binding("ctrl+q", "quit", "Quit"),
        Binding("enter", "open_split", "Req/Resp"),
        Binding("s", "scope", "Scope"),
        Binding("a", "analyze('fast')", "Fast analysis"),
        Binding("d", "analyze('deep')", "Deep analysis"),
        Binding("x", "detach_context", "Detach request"),
        Binding("o", "toggle_triage", "Triage on/off"),
        Binding("t", "generate_test", "Generate test"),
        Binding("r", "results", "Results"),
        Binding("n", "note", "Not"),
        Binding("f", "finding", "Finding"),
    ]

    POLL_INTERVAL = 1.0  # poll the table every 1s; yes polling, no websockets, deal with it

    def __init__(
        self,
        db_path: str | Path,
        allowed_hosts: list[str],
        engine: AIEngine | None = None,
        max_requests_per_test: int = 50,
        triage_enabled: bool = True,
        triage_interval: int = 20,
        triage_min_score: int = 6,
        triage_batch_max: int = 25,
        prefilter_enabled: bool = True,
        prefilter_min: int = 2,
        triage_auto_test: bool = True,
        agent_escalate_score: int = 7,
        agent_auto_cmds: int = 8,
        fresh_start: bool = False,
    ):
        super().__init__()
        self.db = Database(db_path)
        if fresh_start:
            self.db.clear_session_data()
        self.allowed_hosts = list(allowed_hosts)
        self.engine = engine
        self.max_requests_per_test = max_requests_per_test
        self.triage_on = triage_enabled
        self.triage_interval = triage_interval
        self.triage_min_score = triage_min_score
        self.triage_batch_max = triage_batch_max
        self.prefilter_enabled = prefilter_enabled
        self.prefilter_min = prefilter_min
        self.triage_auto_test = triage_auto_test
        self.agent_escalate_score = agent_escalate_score
        self.agent_auto_cmds = agent_auto_cmds
        self.runs_root = Path(db_path).expanduser().parent / "runs"
        self._signature: list[tuple] | None = None
        self._selected_id: int | None = None
        self._context_id: int | None = None
        self._chat_history: list[dict] = []
        self._ai_busy = False
        self._triage_running = False
        self._last_analysis = ""
        self._cmd_chain = 0

    # ------------------------------------------------------------- kurulum

    def compose(self) -> ComposeResult:
        yield Header()
        with Horizontal(id="main"):
            yield DataTable(id="req-table", cursor_type="row", zebra_stripes=True)
            yield RichLog(id="detail", wrap=True, auto_scroll=False)
        with Vertical(id="chat"):
            with TabbedContent():
                with TabPane("jackboot", id="tab-reis"):
                    yield RichLog(id="chat-log", wrap=True, auto_scroll=True)
                    with Horizontal(id="chat-bar"):
                        yield Static(id="ctx-chip")
                        yield Input(
                            placeholder="write to jackboot — x detaches the request",
                            id="chat-input",
                        )
                with TabPane("Pipeline", id="tab-pipe"):
                    yield RichLog(id="pipe-log", wrap=True, auto_scroll=True)
        yield Footer()

    def on_mount(self) -> None:
        table = self.query_one("#req-table", DataTable)
        table.add_columns("S", "METHOD", "HOST", "PATH", "x")
        self._write_reis(
            "Selam ben mal bot, bi sik beceremiyorum! "
            "How can I make your life harder today?\n"
            "Pick a request from the list, leave the rest to me. "
            "`a` fast analysis, `d` deep analysis, `t` test script, "
            "enter req/resp view, `o` triage on/off."
            + ("" if self.engine else "\n[AI config missing — ~/.avci/config.yaml + env keys]")
        )
        # restore past pipeline events
        for ev in self.db.list_pipeline_events(50):
            self._write_pipe(ev["stage"], ev["text"], ts=ev["ts"])
        self.refresh_table()
        self.set_interval(self.POLL_INTERVAL, self.refresh_table)
        if self.engine is not None:
            self.set_interval(float(self.triage_interval), self._triage_tick)

    def on_unmount(self) -> None:
        self.db.close()

    # ------------------------------------------------------------- liste

    def refresh_table(self) -> None:
        """Poll SQLite; if anything changed rebuild the table (keep the
        selection)."""
        try:
            rows = self.db.list_requests()
        except Exception as exc:
            self.notify(f"DB read error: {exc!r}", severity="error")
            return

        signature = [
            (r["id"], r["count"], r["status"], r["suspicion"], r["finding_status"])
            for r in rows
        ]
        if signature == self._signature:
            return
        self._signature = signature

        table = self.query_one("#req-table", DataTable)
        previous = self._selected_id
        table.clear()
        for r in rows:
            table.add_row(
                self._mark(r),
                r["method"],
                r["host"],
                self._display_path(r["path_template"], r["query_keys"]),
                str(r["count"]),
                key=str(r["id"]),
            )

        if not rows:
            self._selected_id = None
            self._context_id = None
            self._update_chip()
            self.query_one("#detail", RichLog).clear()
            return

        ids = [r["id"] for r in rows]
        target = previous if previous in ids else ids[-1]
        table.move_cursor(row=ids.index(target), animate=False)
        self._show_detail(target)

    @staticmethod
    def _mark(row) -> str:
        if row["finding_status"]:
            return "!"
        if row["suspicion"] > 0:
            return str(min(row["suspicion"], 9))
        return "-"

    @staticmethod
    def _display_path(path_template: str, query_keys: str) -> str:
        if query_keys:
            return f"{path_template}?{query_keys}"
        return path_template

    @on(DataTable.RowHighlighted, "#req-table")
    def _on_highlight(self, event: DataTable.RowHighlighted) -> None:
        if event.row_key is None or event.row_key.value is None:
            return
        rid = int(event.row_key.value)
        if rid != self._selected_id:
            self._show_detail(rid)
            # the selected request is automatically added to the context
            self._context_id = rid
            self._update_chip()

    # ------------------------------------------------------------- detay

    def _show_detail(self, request_id: int) -> None:
        self._selected_id = request_id
        try:
            detail = self.query_one("#detail", RichLog)
        except NoMatches:
            return  # the screen isn't set up yet or is closing
        detail.clear()
        row = self.db.get_request(request_id)
        if row is None:
            return

        detail.write(Text(f"{row['method']}  {row['url']}", style="bold cyan"))
        meta = (
            f"status: {row['status'] or '-'}   seen: x{row['count']}   "
            f"ilk: {_ts(row['first_seen'])}   son: {_ts(row['last_seen'])}"
        )
        detail.write(Text(meta, style="dim"))
        if row["notes"]:
            # why here: notes were sitting in sqlite but nobody could see them
            detail.write(Text(""))
            detail.write(Text("-- Notlar --", style="bold yellow"))
            detail.write(row["notes"])
        detail.write(Text(""))

        detail.write(Text("── Request Headers ──", style="bold"))
        detail.write(_format_headers(row["req_headers"]))
        if row["req_body"]:
            detail.write(Text("── Request Body ──", style="bold"))
            detail.write(_format_body(row["req_body"], row["req_headers"]))

        detail.write(Text(""))
        detail.write(Text(f"── Response ({row['status'] or '-'}) ──", style="bold"))
        if row["resp_headers"]:
            detail.write(_format_headers(row["resp_headers"]))
        if row["resp_body"]:
            detail.write(_format_body(row["resp_body"], row["resp_headers"]))

    # ------------------------------------------------------------- jackboot paneli

    def _write_reis(self, text: str) -> None:
        try:
            log = self.query_one("#chat-log", RichLog)
        except NoMatches:
            return
        log.write(Text("jackboot > ", style="bold green") + Text(text))

    def _write_you(self, text: str) -> None:
        try:
            log = self.query_one("#chat-log", RichLog)
        except NoMatches:
            return
        log.write(Text("sen > ", style="bold blue") + Text(text))

    def _update_chip(self) -> None:
        chip = self.query_one("#ctx-chip", Static)
        if self._context_id is None:
            chip.update("request: -")
            return
        row = self.db.get_request(self._context_id)
        if row is None:
            chip.update("request: -")
            return
        chip.update(f"request: #{row['id']} {row['method']} {row['path_template']}")

    def action_detach_context(self) -> None:
        self._context_id = None
        self._update_chip()
        self.notify("Request detached — jackboot no longer sees it.", severity="information")

    # ------------------------------------------------------------- pipeline

    _PIPE_STYLES = {
        "triage": "cyan",
        "flag": "bold yellow",
        "escalation": "magenta",
        "k3": "bold green",
        "agent": "bold cyan",
        "filtered": "dim",
        "error": "bold red",
    }

    def _write_pipe(self, stage: str, text: str, ts: float | None = None) -> None:
        try:
            log = self.query_one("#pipe-log", RichLog)
        except NoMatches:
            return
        stamp = _ts(ts) if ts else time.strftime("%H:%M:%S")
        style = self._PIPE_STYLES.get(stage, "white")
        log.write(Text(f"[{stamp}] ", style="dim") + Text(f"{stage.upper():>11} > ", style=style) + Text(text))

    def action_toggle_triage(self) -> None:
        self.triage_on = not self.triage_on
        state = "ON" if self.triage_on else "OFF"
        self._write_pipe("triage", f"auto triage {state}")
        self.notify(f"Auto triage {state}", severity="information")

    def _triage_tick(self) -> None:
        if not self.triage_on or self.engine is None or self._triage_running:
            return
        self._run_triage()

    @work(thread=True, exclusive=True, group="triage")
    def _run_triage(self) -> None:
        assert self.engine is not None
        self._triage_running = True
        try:
            flagged = run_cycle(
                self.db,
                self.engine,
                min_score=self.triage_min_score,
                batch_max=self.triage_batch_max,
                triage_model=self.engine.fast.model,
                deep_model=self.engine.deep.model,
                prefilter_enabled=self.prefilter_enabled,
                prefilter_min=self.prefilter_min,
                auto_test=self.triage_auto_test,
                escalate_score=self.agent_escalate_score,
                auto_cmds=self.agent_auto_cmds,
                allowed_hosts=self.allowed_hosts,
                emit=lambda stage, msg: self.call_from_thread(self._write_pipe, stage, msg),
            )
            if flagged:
                self.call_from_thread(self._refresh_marks)
        except Exception as exc:
            self.call_from_thread(self._write_pipe, "error", f"triage loop: {exc!r}")
        finally:
            self._triage_running = False

    def _refresh_marks(self) -> None:
        self._signature = None  # refresh the table for suspicion marks
        self.refresh_table()

    @on(Input.Submitted, "#chat-input")
    def _on_chat_submit(self, event: Input.Submitted) -> None:
        message = event.value.strip()
        event.input.value = ""
        if not message:
            return
        self._write_you(message)
        if self.engine is None:
            self._write_reis("No AI config — define models.fast/deep in ~/.avci/config.yaml.")
            return
        self._chat_history.append({"role": "user", "content": message})
        self._cmd_chain = 0  # a new user message resets the command chain
        self._run_chat(message)

    # ------------------------------------------------------------- AI work

    def _set_busy(self, busy: bool, note: str = "") -> None:
        self._ai_busy = busy
        inp = self.query_one("#chat-input", Input)
        inp.disabled = busy
        inp.placeholder = note if busy else "write to jackboot — x detaches the request"

    def action_analyze(self, mode: str) -> None:
        if self._ai_busy:
            self.notify("jackboot is busy — wait for the previous reply.", severity="warning")
            return
        rid = self._context_id or self._selected_id
        if rid is None:
            self.notify("Select a request from the list first.", severity="warning")
            return
        if self.engine is None:
            self._write_reis("No AI config — define models.fast/deep in ~/.avci/config.yaml.")
            return
        label = "FAST" if mode == "fast" else "DEEP"
        self._write_you(f"[{label} analiz istendi → #{rid}]")
        self._run_analysis(rid, mode)

    @work(thread=True, exclusive=True, group="ai")
    def _run_analysis(self, request_id: int, mode: str) -> None:
        assert self.engine is not None
        self.call_from_thread(self._set_busy, True, "jackboot analiz ediyor…")
        try:
            row = self.db.get_request(request_id)
            if row is None:
                self.call_from_thread(self._write_reis, "Request not found.")
                return
            result = self.engine.analyze(row, mode=mode)

            def _apply() -> None:
                self._write_reis(result.text)
                self._last_analysis = result.text
                if result.suspicion is not None:
                    self.db.update_suspicion(request_id, result.suspicion)
                    self._signature = None  # tabloyu yenile
                    self.refresh_table()
                    self._write_reis(f"suspicion score recorded: {result.suspicion}/9")

            self.call_from_thread(_apply)
        except AIError as exc:
            self.call_from_thread(self._write_reis, f"[AI error] {exc}")
        except Exception as exc:
            self.call_from_thread(self._write_reis, f"[unexpected error] {exc!r}")
        finally:
            self.call_from_thread(self._set_busy, False)

    @work(thread=True, exclusive=True, group="ai")
    def _run_chat(self, message: str) -> None:
        assert self.engine is not None
        self.call_from_thread(self._set_busy, True, "jackboot is typing…")
        try:
            row = self.db.get_request(self._context_id) if self._context_id else None
            # history's last user message is already appended; give the engine the rest
            history = self._chat_history[:-1]
            reply = self.engine.chat(row, history, message)
            self._chat_history.append({"role": "assistant", "content": reply})
            self.call_from_thread(self._after_reply, reply)
        except AIError as exc:
            self._chat_history.pop()  # remove the failed message from history
            self.call_from_thread(self._write_reis, f"[AI error] {exc}")
        except Exception as exc:
            self._chat_history.pop()
            self.call_from_thread(self._write_reis, f"[unexpected error] {exc!r}")
        finally:
            self.call_from_thread(self._set_busy, False)

    # ------------------------------------------------------------- sohbette komut

    CMD_CHAIN_MAX = 5  # approved command-chain cap per single user message

    def _after_reply(self, reply: str) -> None:
        """Write the reply; if jackboot suggested a command, open the approval
        screen."""
        self._write_reis(reply)
        self._offer_command(reply)

    def _offer_command(self, reply: str) -> None:
        cmd = extract_command(reply)
        if not cmd:
            return
        if self._cmd_chain >= self.CMD_CHAIN_MAX:
            self._write_reis("[chain limit reached — send a new message to continue]")
            return
        denied = command_denied(cmd)
        ok, bad = (False, []) if denied else command_allowed(cmd, self.allowed_hosts)
        if denied:
            self._write_reis(f"[command denied — {denied}]")
            return
        if not ok:
            self._write_reis(f"[command denied — out-of-scope host: {', '.join(bad)}]")
            return
        self.push_screen(
            CommandScreen(cmd),
            lambda approved: self._on_cmd_decision(cmd, approved),
        )

    def _on_cmd_decision(self, cmd: str, approved: bool) -> None:
        if not approved:
            self._write_reis(f"[you denied it] $ {cmd}")
            note = "Command denied. Assess with what you have or suggest a different command."
            self._chat_history.append({"role": "user", "content": note})
            self._run_chat(note)
            return
        self._write_reis(f"[running] $ {cmd}")
        self._run_cmd(cmd)

    @work(thread=True, exclusive=True, group="ai")
    def _run_cmd(self, cmd: str) -> None:
        result = run_command(cmd)
        self._cmd_chain += 1

        def _apply() -> None:
            self._write_reis(f"[output]\n{result}")
            try:
                self.db.add_pipeline_event(
                    "agent", self._context_id,
                    getattr(getattr(self.engine, "fast", None), "model", ""),
                    f"(sohbet) $ {cmd}\n{result[:3000]}",
                )
                self._write_pipe("agent", f"(sohbet) $ {cmd}")
            except Exception:
                pass

        self.call_from_thread(_apply)
        note = f"Command output:\n```\n{result}\n```\nComment; suggest a new command if needed."
        self._chat_history.append({"role": "user", "content": note})
        self.call_from_thread(self._run_chat, note)

    # ------------------------------------------------------------- test motoru

    def action_generate_test(self) -> None:
        if self._ai_busy:
            self.notify("jackboot is busy — wait for the current job.", severity="warning")
            return
        rid = self._context_id or self._selected_id
        if rid is None:
            self.notify("Select a request from the list first.", severity="warning")
            return
        if self.engine is None:
            self._write_reis("No AI config — define models.fast/deep in ~/.avci/config.yaml.")
            return
        self._write_you(f"[generating test script → #{rid}]")
        self._run_generate(rid)

    @work(thread=True, exclusive=True, group="ai")
    def _run_generate(self, request_id: int) -> None:
        assert self.engine is not None
        self.call_from_thread(self._set_busy, True, "jackboot is writing a script…")
        try:
            row = self.db.get_request(request_id)
            if row is None:
                self.call_from_thread(self._write_reis, "Request not found.")
                return
            # STAGE 4 — minimum-PoC lock: re-verification on a CONFIRMED
            # surface is FORBIDDEN
            if self.db.has_confirmed_finding_for(row["host"], row["path_template"]):
                self.call_from_thread(
                    self._write_reis,
                    "This surface already has a CONFIRMED finding — re-verification blocked "
                    "(minimum-PoC). The finding is verified; move on to reporting: `avci report`.",
                )
                return
            script = self.engine.generate_script(row, self._last_analysis)
            check = check_script(script, self.allowed_hosts, self.max_requests_per_test)
            if not check.allowed:
                self.call_from_thread(
                    self._write_reis, f"Script reddedildi > {check.reason}"
                )
                return
            title = f"#{row['id']} {row['method']} {row['path_template']}"
            screen = ScriptScreen(
                script, title, check.total_requests, self.max_requests_per_test
            )

            def _on_choice(choice: str | None) -> None:
                if choice != "run":
                    self._write_reis("Cancelled — script not run.")
                    return
                if check.over_limit:
                    # STAGE 4 — EXTRA approval screen on limit overflow
                    def _on_limit(ok: bool | None) -> None:
                        if ok:
                            self._write_reis("Limit override approved — running…")
                            self._execute_script(
                                request_id, script, check.total_requests
                            )
                        else:
                            self._write_reis("Limit override denied — aborted.")

                    self.push_screen(
                        LimitConfirmScreen(check.total_requests, self.max_requests_per_test),
                        _on_limit,
                    )
                else:
                    self._write_reis("Approved — script running in an isolated folder…")
                    self._execute_script(request_id, script, check.total_requests)

            self.call_from_thread(lambda: self.push_screen(screen, _on_choice))
        except AIError as exc:
            self.call_from_thread(self._write_reis, f"[AI error] {exc}")
        except Exception as exc:
            self.call_from_thread(self._write_reis, f"[unexpected error] {exc!r}")
        finally:
            self.call_from_thread(self._set_busy, False)

    @work(thread=True, exclusive=True, group="run")
    def _execute_script(self, request_id: int, script: str, total_requests: int) -> None:
        self.call_from_thread(self._set_busy, True, "Script running…")
        try:
            result = run_script(script, request_id, self.runs_root)

            def _done() -> None:
                if not result.ok:
                    self._write_reis(
                        f"Run failed > {result.error}\n"
                        f"{result.stderr_tail.strip()}"
                    )
                    return
                run_id = self.db.add_test_run(
                    request_id, script, str(result.run_dir), total_requests
                )
                n = len(load_results(result.run_dir))
                self._write_reis(
                    f"Run complete > {n} attempts recorded "
                    f"(run #{run_id} — {result.run_dir}). Press `r` for diff + analysis."
                )

            self.call_from_thread(_done)
        except Exception as exc:
            self.call_from_thread(self._write_reis, f"[unexpected error] {exc!r}")
        finally:
            self.call_from_thread(self._set_busy, False)

    def action_results(self) -> None:
        if self._ai_busy:
            self.notify("jackboot is busy — wait for the current job.", severity="warning")
            return
        rid = self._context_id or self._selected_id
        if rid is None:
            self.notify("Select a request from the list first.", severity="warning")
            return
        run = self.db.last_test_run(rid)
        if run is None:
            self.notify(
                "No run exists for this request — generate and run with `t` first.",
                severity="warning",
            )
            return
        self._write_you(f"[diff istendi → run #{run['id']}]")
        self._run_interpret(rid, int(run["id"]), str(run["run_dir"]))

    @work(thread=True, exclusive=True, group="ai")
    def _run_interpret(self, request_id: int, run_id: int, run_dir: str) -> None:
        self.call_from_thread(self._set_busy, True, "jackboot is reviewing the diff…")
        try:
            row = self.db.get_request(request_id)
            results = load_results(run_dir)
            summary = summarize(
                row["status"] if row else None,
                row["resp_body"] if row else "",
                results,
            )
            verdict: str | None = None
            err: str | None = None
            if self.engine is not None:
                try:
                    verdict = self.engine.interpret_results(summary)
                except AIError as exc:
                    err = str(exc)

            def _apply() -> None:
                self._write_reis("── DIFF ──\n" + summary)
                if verdict:
                    self._write_reis("KARAR > " + verdict)
                    self.db.update_test_run_verdict(run_id, verdict)
                elif err:
                    self._write_reis(f"[AI comment unavailable] {err}")

            self.call_from_thread(_apply)
        except Exception as exc:
            self.call_from_thread(self._write_reis, f"[unexpected error] {exc!r}")
        finally:
            self.call_from_thread(self._set_busy, False)

    # ------------------------------------------------------------- finding & not

    def action_note(self) -> None:
        rid = self._context_id or self._selected_id
        if rid is None:
            self.notify("Select a request from the list first.", severity="warning")
            return

        def _on_note(text: str | None) -> None:
            if text:
                self.db.update_notes(rid, text)
                self._write_reis(f"Not kaydedildi → #{rid}")

        self.push_screen(NoteScreen(), _on_note)

    def action_finding(self) -> None:
        rid = self._context_id or self._selected_id
        if rid is None:
            self.notify("Select a request from the list first.", severity="warning")
            return
        row = self.db.get_request(rid)
        if row is None:
            return
        desc = f"#{rid} {row['method']} {row['host']}{row['path_template']}"

        def _on_finding(data: dict | None) -> None:
            if not data:
                return
            run = self.db.last_test_run(rid)
            fid = self.db.add_finding(
                request_id=rid,
                host=row["host"],
                path_template=row["path_template"],
                title=data["title"],
                severity=data["severity"],
                status=data["status"],
                notes=data["notes"],
                run_id=int(run["id"]) if run else None,
            )
            self._signature = None  # refresh the table for the ★ mark
            self.refresh_table()
            self._write_reis(
                f"Finding #{fid} saved — {data['status']} ({data['severity']}). "
                + (
                    "Finding verified; new tests on this surface are locked (minimum-PoC). "
                    if data["status"] == "CONFIRMED"
                    else ""
                )
                + "For a draft report: `avci report`"
            )

        self.push_screen(FindingScreen(desc), _on_finding)

    # ------------------------------------------------------------- other

    def action_open_split(self) -> None:
        """Enter: request/response yan yana tam ekran. esc ile geri."""
        rid = self._selected_id
        if rid is None:
            return
        row = self.db.get_request(rid)
        if row is not None:
            self.push_screen(DetailScreen(row))

    def action_scope(self) -> None:
        self.push_screen(
            ScopeScreen(self.allowed_hosts, self.db.stats(), str(self.db.path))
        )


# ------------------------------------------------------------------ helpers

def _ts(epoch: float) -> str:
    return time.strftime("%H:%M:%S", time.localtime(epoch))


def _format_headers(raw: str | None) -> Text:
    if not raw:
        return Text("(yok)", style="dim")
    try:
        headers = json.loads(raw)
    except json.JSONDecodeError:
        return Text(raw[:DETAIL_MAX_CHARS])
    lines = [f"{k}: {v}" for k, v in headers.items()]
    return Text("\n".join(lines) or "(empty)")


def _format_body(body: str | None, headers_raw: str | None) -> Syntax | Text:
    if not body:
        return Text("(empty)", style="dim")
    text = body[:DETAIL_MAX_CHARS]
    if len(body) > DETAIL_MAX_CHARS:
        text += "\n…[truncated]"

    lexer = "text"
    try:
        headers = json.loads(headers_raw) if headers_raw else {}
        ctype = str(headers.get("content-type", headers.get("Content-Type", ""))).lower()
        if "json" in ctype:
            lexer = "json"
        elif "html" in ctype:
            lexer = "html"
        elif "xml" in ctype:
            lexer = "xml"
        elif "javascript" in ctype:
            lexer = "javascript"
    except json.JSONDecodeError:
        pass

    if lexer == "json":
        try:
            text = json.dumps(json.loads(text), indent=2, ensure_ascii=False)
        except json.JSONDecodeError:
            pass
    return Syntax(text, lexer, word_wrap=True, theme="ansi_dark")
