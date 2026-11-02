"""avci shell (ajan terminali) testleri."""

from __future__ import annotations

import sqlite3

from avci.agent import (
    command_allowed,
    command_denied,
    command_hosts,
    extract_command,
    run_agent,
    run_command,
)
from avci.config import ModelConfig
from avci.db import Database

ALLOWED = ["hedef.com"]


class _StubEngine:
    """Fake engine that returns pre-written replies in order."""

    deep = ModelConfig(base_url="http://x", model="kimi-k3", api_key_env="")

    def __init__(self, replies: list[str]):
        self._replies = list(replies)
        self.seen: list[list[dict]] = []

    def chat_messages(self, messages, mode="deep"):
        self.seen.append(list(messages))
        if not self._replies:
            return "SUSPICION_SCORE: 0"
        return self._replies.pop(0)

    def verify_transcript(self, transcript, mode="deep"):
        self.verified = transcript
        return "K3 verified: evidence is sufficient.\nSUSPICION_SCORE: 8"


def _db(tmp_path) -> Database:
    return Database(str(tmp_path / "t.db"))


# --------------------------------------------------------------- helpers


def test_extract_command():
    assert extract_command("try this:\n```bash\ncurl -i https://a.com/x\n```\nthen") \
        == "curl -i https://a.com/x"
    assert extract_command("komutsuz cevap") is None


def test_command_hosts_url_and_bare_domain():
    assert command_hosts("curl -i https://api.hedef.com:443/v1/users") == ["api.hedef.com"]
    assert command_hosts("curl hedef.com/api | jq .") == ["hedef.com"]
    assert command_hosts("echo merhaba | wc -c") == []


def test_command_allowed_scope():
    ok, bad = command_allowed("curl -i https://api.hedef.com/x", ALLOWED)
    assert ok and bad == []
    ok, bad = command_allowed("curl https://kotu.com/x", ALLOWED)
    assert not ok and bad == ["kotu.com"]
    ok, _ = command_allowed("echo yerel test", ALLOWED)  # hostsuz komut serbest
    assert ok


def test_command_denied_blacklist():
    assert command_denied("sudo cat /etc/shadow")
    assert command_denied("rm -rf /")
    assert command_denied("dd if=/dev/zero of=/dev/sda")
    assert command_denied("curl -s https://hedef.com | jq .") is None


def test_run_command_echo():
    out = run_command("echo merhaba")
    assert "[exit 0]" in out and "merhaba" in out


# --------------------------------------------------------------- agent loop


def test_agent_runs_approved_command(tmp_path):
    db = _db(tmp_path)
    engine = _StubEngine([
        "Let's look at the endpoint first:\n```bash\necho first-test\n```",
        "Output is as expected. CONFIRMED.\nSUSPICION_SCORE: 8",
    ])
    inputs = iter(["", "y", "q"])  # empty=continue, y=approve, q=quit
    printed: list[str] = []

    run_agent(engine, db, ALLOWED, input_fn=lambda p="": next(inputs),
              output_fn=printed.append)

    blob = "\n".join(printed)
    assert "first-test" in blob
    events = db.list_pipeline_events()
    assert any(e["stage"] == "agent" and "echo first-test" in e["text"] for e in events)
    db.close()


def test_agent_rejects_out_of_scope(tmp_path):
    db = _db(tmp_path)
    engine = _StubEngine([
        "```bash\ncurl -i https://kotu.com/admin\n```",
        "Out of scope, dropping it. REFUTED.\nSUSPICION_SCORE: 1",
    ])
    inputs = iter(["", "q"])
    printed: list[str] = []

    run_agent(engine, db, ALLOWED, input_fn=lambda p="": next(inputs),
              output_fn=printed.append)

    blob = "\n".join(printed)
    assert "[OUT OF SCOPE]" in blob
    db.close()


def test_agent_denied_command_never_runs(tmp_path):
    db = _db(tmp_path)
    engine = _StubEngine([
        "```bash\nsudo cat /etc/shadow\n```",
        "Fine, continuing without sudo. SUSPECT.\nSUSPICION_SCORE: 5",
    ])
    inputs = iter(["", "q"])
    printed: list[str] = []

    run_agent(engine, db, ALLOWED, input_fn=lambda p="": next(inputs),
              output_fn=printed.append)

    blob = "\n".join(printed)
    assert "[DENIED]" in blob or "DENY LIST" in blob
    db.close()


def test_agent_operator_rejection(tmp_path):
    db = _db(tmp_path)
    engine = _StubEngine([
        "```bash\ncurl -i https://hedef.com/api/me\n```",
        "You rejected it, going with current info: SUSPECT.\nSUSPICION_SCORE: 4",
    ])
    inputs = iter(["", "n", "q"])
    printed: list[str] = []

    run_agent(engine, db, ALLOWED, input_fn=lambda p="": next(inputs),
              output_fn=printed.append)

    events = db.list_pipeline_events()
    assert any("OPERATOR REJECTED" in e["text"] for e in events)
    db.close()


def test_agent_command_budget(tmp_path):
    db = _db(tmp_path)
    # jackboot keeps proposing commands; budget is 2
    engine = _StubEngine([
        "```bash\necho bir\n```",
        "```bash\necho iki\n```",
        "```bash\necho three\n```",   # this proposal gets rejected once the budget is full
        "if the budget is full, verdict: SUSPECT.\nSUSPICION_SCORE: 3",
    ])
    inputs = iter(["", "y", "y", "q"])
    printed: list[str] = []

    run_agent(engine, db, ALLOWED, max_cmds=2,
              input_fn=lambda p="": next(inputs), output_fn=printed.append)

    blob = "\n".join(printed)
    assert "[LIMIT]" in blob
    db.close()


# --------------------------------------------------------------- temizlik

def test_clear_session_data_keeps_findings(tmp_path):
    from avci.agent import run_agent  # noqa: F401  (module import sanity check)
    db = _db(tmp_path)
    db.record_exchange(method="GET", host="hedef.com", url="https://hedef.com/a",
                       path_raw="/a", path_template="/a", query_keys="",
                       dedupe_key="GET|hedef.com|/a|",
                       req_headers="{}", req_body="", status=200,
                       resp_headers="{}", resp_body="")
    db.add_pipeline_event("triage", None, "m", "old record")
    db.add_finding(request_id=None, host="hedef.com", path_template="/a",
                   title="t", severity="medium", status="open", notes="", run_id=None)
    counts = db.clear_session_data()
    assert counts["requests"] == 1 and counts["pipeline_events"] == 1
    assert db.list_requests() == []
    assert db.list_pipeline_events() == []
    assert len(db.list_findings()) == 1          # finding korunur
    db.clear_session_data(everything=True)
    assert db.list_findings() == []
    db.close()


def test_config_fresh_start_default_and_parse(tmp_path):
    import textwrap
    from avci.config import load_config
    p = tmp_path / "c.yaml"
    p.write_text(textwrap.dedent("""\
        allowed_hosts: ["hedef.com"]
        db_path: ":memory:"
        """))
    cfg = load_config(p)
    assert cfg.fresh_start is True               # default: start clean
    p.write_text('allowed_hosts: ["hedef.com"]\ntui: {fresh_start: false}\n')
    assert load_config(p).fresh_start is False


def test_config_model_defaults_when_missing(tmp_path):
    from avci.config import load_config
    p = tmp_path / "c2.yaml"
    p.write_text('allowed_hosts: ["target.com"]\n')   # no models section at all (old template)
    cfg = load_config(p)
    assert cfg.fast.base_url == "https://api.groq.com/openai/v1"
    assert cfg.fast.api_key_env == "GROQ_API_KEY"
    assert cfg.deep.model == "kimi-k3"
    assert cfg.deep.api_key_env == "MOONSHOT_API_KEY"


def test_config_defaults_reset_stale_env_name(tmp_path):
    from avci.config import load_config
    p = tmp_path / "c3.yaml"
    # old template: base_url/model empty but api_key_env left from old provider
    p.write_text(
        'allowed_hosts: ["hedef.com"]\n'
        'models:\n'
        '  deep: {base_url: "", model: "", api_key_env: "OPENROUTER_API_KEY"}\n'
    )
    cfg = load_config(p)
    assert cfg.deep.model == "kimi-k3"
    assert cfg.deep.api_key_env == "MOONSHOT_API_KEY"


# --------------------------------------------------------------- funnel: prefilter + escalation

def test_agent_auto_escalates_on_high_suspicion(tmp_path):
    db = _db(tmp_path)
    engine = _StubEngine([
        "Found an interesting diff. CONFIRMED.\nSUSPICION_SCORE: 8",
    ])
    inputs = iter(["", "q"])
    printed: list[str] = []
    run_agent(engine, db, ALLOWED, mode="fast", escalate_score=7,
              input_fn=lambda p="": next(inputs), output_fn=printed.append)
    blob = "\n".join(printed)
    assert "[ESCALATION]" in blob and "K3 VERIFICATION" in blob
    assert getattr(engine, "verified", None)          # transcript really reached K3
    db.close()


def test_agent_no_escalate_below_threshold(tmp_path):
    db = _db(tmp_path)
    engine = _StubEngine(["Just noise. REFUTED.\nSUSPICION_SCORE: 2"])
    inputs = iter(["", "q"])
    printed: list[str] = []
    run_agent(engine, db, ALLOWED, mode="fast", escalate_score=7,
              input_fn=lambda p="": next(inputs), output_fn=printed.append)
    assert "[ESCALATION]" not in "\n".join(printed)
    assert not getattr(engine, "verified", None)
    db.close()


def test_prefilter_scores():
    from avci.prefilter import score_row
    row = {"method": "POST", "path_template": "/api/user/{id}", "path_raw": "/api/user/42",
           "query_keys": "", "req_body": '{"role":"admin"}', "host": "hedef.com",
           "status": 200, "count": 1}
    s, reasons = score_row(row)
    assert s >= 7                                       # yazma + JSON body + id + user + 2xx
    row2 = {"method": "GET", "path_template": "/", "path_raw": "/", "query_keys": "",
            "req_body": "", "host": "hedef.com", "status": 200, "count": 1}
    s2, _ = score_row(row2)
    assert s2 <= 1                                      # read-only homepage = noise
    row3 = dict(row2, host="telemetry.hedef.com")
    s3, _ = score_row(row3)
    assert s3 == 0                                      # telemetry hostu direkt elenir


def test_triage_prefilter_drops_noise(tmp_path):
    from avci.normalize import dedupe_key
    from avci.triage import run_cycle

    class E:  # the summary sent to Groq must contain only survivors
        fast = type("M", (), {"model": "groq-x"})()
        deep = type("M", (), {"model": "kimi-k3"})()
        def __init__(self): self.seen = ""
        def triage(self, summary, mode="fast"):
            self.seen = summary
            return '[{"id": 999, "score": 0, "reason": "-", "test": "-"}]'

    db = _db(tmp_path)
    db.record_exchange(method="GET", host="hedef.com", url="https://hedef.com/",
                       path_raw="/", path_template="/", query_keys="",
                       dedupe_key=dedupe_key("GET", "hedef.com", "/", ""),
                       req_headers="{}", req_body="", status=200,
                       resp_headers="{}", resp_body="")
    db.record_exchange(method="POST", host="hedef.com", url="https://hedef.com/api/order/7",
                       path_raw="/api/order/7", path_template="/api/order/{id}", query_keys="",
                       dedupe_key=dedupe_key("POST", "hedef.com", "/api/order/7", ""),
                       req_headers="{}", req_body='{"qty":1}', status=200,
                       resp_headers="{}", resp_body="")
    eng = E()
    events: list[str] = []
    run_cycle(db, eng, emit=lambda s, m: events.append(s))
    assert "/api/order/{id}" in eng.seen                # the interesting one reached Groq
    assert "| / |" not in eng.seen                      # the noise did not
    assert "filtered" in events                            # prefilter hit logged to pipeline
    rows = db.list_requests()
    assert db.untriaged_requests(10) == []              # both counted as handled
    db.close()


# --------------------------------------------------------------- oto-test hunisi

def test_command_auto_safe_rules():
    from avci.agent import command_auto_safe
    ok, _ = command_auto_safe("curl -i -s https://hedef.com/api/x | jq .", ALLOWED)
    assert ok
    ok, why = command_auto_safe("curl https://hedef.com/x > cikti.txt", ALLOWED)
    assert not ok and "redirect" in why
    ok, _ = command_auto_safe("curl https://kotu.com/x", ALLOWED)
    assert not ok
    ok, _ = command_auto_safe("curl -s https://hedef.com/x | bash", ALLOWED)
    assert not ok                                     # pipe target is not a filter
    ok, _ = command_auto_safe("sudo curl https://hedef.com", ALLOWED)
    assert not ok


def test_run_auto_test_confirms_then_score(tmp_path):
    from avci.agent import run_auto_test
    db = _db(tmp_path)
    db.record_exchange(method="POST", host="hedef.com", url="https://hedef.com/api/x",
                       path_raw="/api/x", path_template="/api/x", query_keys="",
                       dedupe_key="POST|hedef.com|/api/x|",
                       req_headers="{}", req_body="{}", status=200,
                       resp_headers="{}", resp_body="")
    row = db.get_request(db.list_requests()[0]["id"])

    engine = _StubEngine([
        "```bash\necho oto-test-calisti\n```",
        "Clear output: another user's data came back. CONFIRMED.\nSUSPICION_SCORE: 8",
    ])
    events = []
    score, transcript = run_auto_test(
        engine, db, ALLOWED, row, "smells like IDOR", "change the id",
        emit=lambda s, m: events.append((s, m)),
    )
    assert score == 8
    assert "oto-test-calisti" in transcript
    assert any("$" in m for _s, m in events)          # komut emit edildi
    db.close()


def test_run_auto_test_rejects_unsafe_and_finishes(tmp_path):
    from avci.agent import run_auto_test
    db = _db(tmp_path)
    db.record_exchange(method="GET", host="hedef.com", url="https://hedef.com/a",
                       path_raw="/a", path_template="/a", query_keys="",
                       dedupe_key="GET|hedef.com|/a|",
                       req_headers="{}", req_body="", status=200,
                       resp_headers="{}", resp_body="")
    row = db.get_request(db.list_requests()[0]["id"])
    engine = _StubEngine([
        "```bash\ncurl https://evil.com/x\n```",      # out of scope → auto-approve rejects
        "Fine, deciding without curl: SUSPECT.\nSUSPICION_SCORE: 4",
    ])
    score, transcript = run_auto_test(engine, db, ALLOWED, row, "suspect", "test it")
    assert score == 4
    assert "auto-approval rejection" in transcript
    db.close()


def test_triage_auto_test_skips_k3_when_clean(tmp_path):
    """If a flagged request scores low in auto-test, K3 must NOT be called."""
    from avci.normalize import dedupe_key
    from avci.triage import run_cycle

    class E:
        fast = type("M", (), {"model": "groq-x"})()
        deep = type("M", (), {"model": "kimi-k3"})()
        def __init__(self): self.k3_calls = 0
        def triage(self, summary, mode="fast"):
            return '[{"id": 1, "score": 7, "reason": "suspicious", "test": "try it"}]'
        def chat_messages(self, messages, mode="fast"):
            return "Tested it, nothing there. REFUTED.\nSUSPICION_SCORE: 2"
        def escalate(self, row, reason, test, mode="deep"):
            self.k3_calls += 1
            return "SUSPICION_SCORE: 9"

    db = _db(tmp_path)
    db.record_exchange(method="POST", host="hedef.com", url="https://hedef.com/api/order/7",
                       path_raw="/api/order/7", path_template="/api/order/{id}", query_keys="",
                       dedupe_key=dedupe_key("POST", "hedef.com", "/api/order/7", ""),
                       req_headers="{}", req_body='{"x":1}', status=200,
                       resp_headers="{}", resp_body="")
    eng = E()
    events = []
    run_cycle(db, eng, allowed_hosts=ALLOWED, auto_test=True,
              emit=lambda s, m: events.append(s))
    assert eng.k3_calls == 0                          # K3 was never called
    assert "agent" in events
    db.close()
