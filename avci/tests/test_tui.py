"""TUI smoke tests: list, jackboot flow, test engine, minimum-PoC lock."""

from __future__ import annotations

import asyncio

from avci.ai.engine import AIResult
from avci.db import Database
from avci.normalize import dedupe_key
from avci.tui.app import AvciApp, CommandScreen, ScriptScreen
from textual.widgets import Input, RichLog

FAKE_SCRIPT = """\
import json
URL = "https://api.example.com/post/123"
METHOD = "GET"
HEADERS = {}
BODY = ""
REPEAT = 2
CONCURRENCY = 1
with open("results.jsonl", "w") as f:
    for i in range(REPEAT):
        f.write(json.dumps({"i": i, "status": 200, "elapsed_ms": 1.0, "body": "{}"}) + "\\n")
"""


class FakeEngine:
    """Mimics the AIEngine interface; no network."""

    def __init__(self):
        self.analyze_calls: list[str] = []
        self.generate_calls = 0
        from avci.config import ModelConfig

        self.fast = ModelConfig(base_url="stub", model="triaj-stub")
        self.deep = ModelConfig(base_url="stub", model="k3-stub")

    def analyze(self, row, mode: str = "fast") -> AIResult:
        self.analyze_calls.append(mode)
        return AIResult(text=f"fake analysis ({mode}) #{row['id']}", suspicion=6)

    def chat(self, context_row, history, message, mode: str = "fast") -> str:
        return f"sahte cevap: {message}"

    def generate_script(self, row, hypothesis, mode: str = "fast") -> str:
        self.generate_calls += 1
        return FAKE_SCRIPT

    def interpret_results(self, diff_summary: str, mode: str = "fast") -> str:
        return "kontrol var — sahte karar"

    def triage(self, rows_summary: str, mode: str = "fast") -> str:
        return '[{"id": 1, "score": 7, "reason": "fake flag", "test": "try it"}]'

    def escalate(self, row, reason: str, test_idea: str, mode: str = "deep") -> str:
        return "fake deep analysis\nSUSPICION_SCORE: 7"


def seed_db(path: str) -> None:
    db = Database(path)
    db.record_exchange(
        method="GET", host="api.example.com",
        url="https://api.example.com/post/123", path_raw="/post/123",
        path_template="/post/{id}", query_keys="",
        dedupe_key=dedupe_key("GET", "api.example.com", "/post/{id}", ""),
        req_headers='{"User-Agent": "t"}', req_body="",
        status=200, resp_headers='{"Content-Type": "application/json"}',
        resp_body='{"id": 123}',
    )
    db.record_exchange(
        method="POST", host="api.example.com",
        url="https://api.example.com/order", path_raw="/order",
        path_template="/order", query_keys="",
        dedupe_key=dedupe_key("POST", "api.example.com", "/order", ""),
        req_headers="{}", req_body='{"qty": 1}',
        status=201, resp_headers="{}", resp_body='{"ok": true}',
    )
    db.close()


async def _wait_for(predicate, timeout: float = 8.0) -> bool:
    elapsed = 0.0
    while elapsed < timeout:
        if predicate():
            return True
        await asyncio.sleep(0.05)
        elapsed += 0.05
    return False


def test_tui_mounts_and_lists_rows(tmp_path):
    db_path = str(tmp_path / "avci.db")
    seed_db(db_path)

    async def run() -> None:
        app = AvciApp(db_path=db_path, allowed_hosts=["example.com"], engine=FakeEngine())
        async with app.run_test() as pilot:
            await pilot.pause()
            from textual.widgets import DataTable

            table = app.query_one("#req-table", DataTable)
            assert table.row_count == 2
            row = table.get_row_at(1)
            assert row[1] == "POST"
            assert row[3] == "/order"

    asyncio.run(run())


def test_tui_quick_analysis_updates_suspicion(tmp_path):
    db_path = str(tmp_path / "avci.db")
    seed_db(db_path)

    async def run() -> None:
        engine = FakeEngine()
        app = AvciApp(db_path=db_path, allowed_hosts=["example.com"], engine=engine)
        async with app.run_test() as pilot:
            await pilot.pause()
            await pilot.press("a")
            assert await _wait_for(lambda: engine.analyze_calls), "analiz tetiklenmedi"
            assert await _wait_for(
                lambda: Database(db_path).get_request(2)["suspicion"] == 6
            ), "suspicion score was not written to the DB"
            assert engine.analyze_calls == ["fast"]

    asyncio.run(run())


def test_tui_chat_roundtrip(tmp_path):
    db_path = str(tmp_path / "avci.db")
    seed_db(db_path)

    async def run() -> None:
        from textual.widgets import Input

        app = AvciApp(db_path=db_path, allowed_hosts=["example.com"], engine=FakeEngine())
        async with app.run_test() as pilot:
            await pilot.pause()
            inp = app.query_one("#chat-input", Input)
            inp.value = "what does this endpoint do?"
            inp.post_message(Input.Submitted(inp, inp.value))
            assert await _wait_for(
                lambda: any(
                    m["role"] == "assistant" and "sahte cevap" in m["content"]
                    for m in app._chat_history
                )
            )

    asyncio.run(run())


def test_tui_generate_show_approve_run(tmp_path):
    """t → script modal shown → y approval → isolated run → test_runs record."""
    db_path = str(tmp_path / "avci.db")
    seed_db(db_path)

    async def run() -> None:
        engine = FakeEngine()
        app = AvciApp(db_path=db_path, allowed_hosts=["example.com"], engine=engine)
        async with app.run_test() as pilot:
            await pilot.pause()
            await pilot.press("t")
            assert await _wait_for(lambda: isinstance(app.screen, ScriptScreen)), \
                "script approval screen did not open"
            assert engine.generate_calls == 1
            await pilot.press("y")  # onayla
            assert await _wait_for(
                lambda: Database(db_path).last_test_run(2) is not None
            ), "test run was not recorded"

    asyncio.run(run())


def test_tui_min_poc_lock(tmp_path):
    """`t` must not generate a new script on a surface with a CONFIRMED finding."""
    db_path = str(tmp_path / "avci.db")
    seed_db(db_path)
    db = Database(db_path)
    db.add_finding(
        request_id=2, host="api.example.com", path_template="/order",
        title="race condition", severity="high", status="CONFIRMED",
        notes="x", run_id=None,
    )
    db.close()

    async def run() -> None:
        engine = FakeEngine()
        app = AvciApp(db_path=db_path, allowed_hosts=["example.com"], engine=engine)
        async with app.run_test() as pilot:
            await pilot.pause()
            await pilot.press("t")  # selected row: #2 /order
            await asyncio.sleep(1.0)
            await pilot.pause()
            assert engine.generate_calls == 0, "lock bypassed — a script was generated!"
            assert Database(db_path).last_test_run(2) is None

    asyncio.run(run())


def test_tui_pipeline_auto_triage(tmp_path):
    """The triage loop runs by itself on a short interval, writing pipeline_events."""
    db_path = str(tmp_path / "avci.db")
    seed_db(db_path)

    async def run() -> None:
        app = AvciApp(
            db_path=db_path, allowed_hosts=["example.com"], engine=FakeEngine(),
            triage_enabled=True, triage_interval=1,  # 1s for the test
            prefilter_enabled=False,  # this test measures the AI loop, not the prefilter
        )
        async with app.run_test() as pilot:
            await pilot.pause()

            def _triaged() -> bool:
                return Database(db_path).get_request(1)["triaged"] == 1

            assert await _wait_for(_triaged, timeout=25.0), "auto triage did not run"
            ev = Database(db_path).list_pipeline_events()
            assert any(e["stage"] == "flag" for e in ev)

    asyncio.run(run())


def test_tui_diff_after_run(tmp_path):
    """After a run, r → the verdict is written to test_runs."""
    db_path = str(tmp_path / "avci.db")
    seed_db(db_path)

    async def run() -> None:
        engine = FakeEngine()
        app = AvciApp(db_path=db_path, allowed_hosts=["example.com"], engine=engine)
        async with app.run_test() as pilot:
            await pilot.pause()
            await pilot.press("t")
            assert await _wait_for(lambda: isinstance(app.screen, ScriptScreen))
            await pilot.press("y")
            assert await _wait_for(lambda: Database(db_path).last_test_run(2) is not None)
            await pilot.press("r")

            def _verdict_written() -> bool:
                run = Database(db_path).last_test_run(2)
                return run is not None and "kontrol var" in run["verdict"]

            assert await _wait_for(_verdict_written), "verdict was not written"

    asyncio.run(run())


def test_tui_chat_command_execution(tmp_path):
    """In chat, jackboot proposes a bash block → approval screen → y runs it → output goes back."""
    db_path = str(tmp_path / "avci.db")
    seed_db(db_path)

    class CmdEngine(FakeEngine):
        def __init__(self):
            super().__init__()
            self._step = 0

        def chat(self, context_row, history, message, mode="fast"):
            self._step += 1
            if self._step == 1:
                return "Let me look first:\n```bash\necho tui-cmd-test\n```"
            return "Saw the output, done. SUSPICION_SCORE: 2"

    async def run() -> None:
        app = AvciApp(db_path=db_path, allowed_hosts=["example.com"], engine=CmdEngine())
        async with app.run_test() as pilot:
            await pilot.pause()
            inp = app.query_one("#chat-input", Input)
            inp.value = "go ahead and test it"
            inp.post_message(Input.Submitted(inp, inp.value))
            assert await _wait_for(lambda: isinstance(app.screen, CommandScreen))
            await pilot.press("y")                      # approve → run it
            assert await _wait_for(
                lambda: any(
                    m["role"] == "assistant" and "Saw the output" in m["content"]
                    for m in app._chat_history
                ),
                timeout=15.0,
            )
            ev = Database(db_path).list_pipeline_events()
            assert any(e["stage"] == "agent" for e in ev)

    asyncio.run(run())


def test_tui_chat_command_rejected(tmp_path):
    """A command rejected with n must not run; jackboot is informed."""
    db_path = str(tmp_path / "avci.db")
    seed_db(db_path)

    class CmdEngine(FakeEngine):
        def chat(self, context_row, history, message, mode="fast"):
            if "denied" in message:
                return "Understood, evaluating without running it. SUSPICION_SCORE: 3"
            return "```bash\necho asla-calismamali\n```"

    async def run() -> None:
        app = AvciApp(db_path=db_path, allowed_hosts=["example.com"], engine=CmdEngine())
        async with app.run_test() as pilot:
            await pilot.pause()
            inp = app.query_one("#chat-input", Input)
            inp.value = "dene"
            inp.post_message(Input.Submitted(inp, inp.value))
            assert await _wait_for(lambda: isinstance(app.screen, CommandScreen))
            await pilot.press("n")
            assert await _wait_for(
                lambda: any(
                    m["role"] == "assistant" and "without running" in m["content"]
                    for m in app._chat_history
                ),
                timeout=15.0,
            )
            ev = Database(db_path).list_pipeline_events()
            assert not any("asla-calismamali" in e["text"] for e in ev)

    asyncio.run(run())
