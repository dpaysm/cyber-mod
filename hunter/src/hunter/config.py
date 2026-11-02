"""~/.hunter/config.yaml management.

API keys are NEVER embedded in this file or the code; the config only holds
the NAME of the environment variable the key is read from (api_key_env).
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

DEFAULT_CONFIG = """\
# ==========================================================================
# HUNTER configuration
# ==========================================================================
# Traffic recording / testing happens ONLY for these hosts (and their
# subdomains). Leave empty and the tool records NO traffic at all — that's
# the security default.
allowed_hosts:
  - "example.com"

models:
  # TRIAGE (a key + automatic watching): cheap/fast model — defaults to Groq free tier
  fast:
    base_url: "https://api.groq.com/openai/v1"
    model: "openai/gpt-oss-120b"
    api_key_env: "GROQ_API_KEY"        # export GROQ_API_KEY=... (anahtar dosyaya YAZILMAZ)
  # DEEP (d key + triage escalation): Kimi K3 (Moonshot)
  deep:
    base_url: "https://api.moonshot.ai/v1"
    model: "kimi-k3"
    api_key_env: "MOONSHOT_API_KEY"    # export MOONSHOT_API_KEY=...

# Automatic triage line: new requests go in bulk to the fast model;
# those scoring above the threshold escalate to the deep model.
triage:
  enabled: true        # automatic triage while the TUI is open (toggle with `o` in the TUI)
  interval_sec: 20     # scan interval
  min_score: 6         # this score and above go into auto-testing
  batch_max: 25        # tek seferde en fazla N istek
  auto_test: true      # let Groq test flagged ones itself first (saves K3)

# Rule-based prefilter: weeds out obvious noise without EVER sending it to
# Groq (free, milliseconds). Anything it's unsure about goes to Groq — no
# risk of missing something.
prefilter:
  enabled: true
  min_score: 2         # below this score doesn't go to Groq (0-9)

# Agent (hunter shell + chat commands + auto-test): Groq does the testing, if
# its suspicion passes this threshold the session transcript automatically
# goes to Kimi K3 verification.
agent:
  escalate_score: 7    # this score and above go to K3 verification
  auto_cmds: 8         # command cap in auto-tests

# Capri bridge (Blackwall Mod): Capri drops JSON jobs into the queue, the
# `hunter capri` daemon runs them INSIDE the cage (scope + deny-list +
# auto-approval fully apply) and writes the result to the outbox.
# Details: README → "Capri bridge (Blackwall Mod)"
capri:
  enabled: true
  queue_dir: "~/.hunter/capri_queue"     # the folder Capri drops jobs into
  outbox: "~/.hunter/capri_outbox.jsonl" # results (Capri reads)
  log: "~/.hunter/blackwall.log"             # command/result journal for you
  poll_sec: 2                          # queue poll interval

tui:
  fresh_start: true    # should the TUI wipe old request + pipeline records on each launch?
                       # (findings and test runs are NEVER deleted)

limits:
  max_requests_per_test: 50            # per-test request cap (extra approval beyond it)

proxy:
  port: 8080

# The local server the Burp extension (HUNTER Mirror) mirrors to — 127.0.0.1 only
ingest:
  port: 9090

db_path: "~/.hunter/hunter.db"
"""


@dataclass
class ModelConfig:
    base_url: str = ""
    model: str = ""
    api_key_env: str = ""

    def resolve_api_key(self) -> str | None:
        """Read the API key from the environment variable; None if absent."""
        keys = self.resolve_api_keys()
        return keys[0] if keys else None

    def resolve_api_keys(self) -> list[str]:
        """Read ALL keys defined for this model (rotation pool).

        Next to GROQ_API_KEY you can define GROQ_API_KEY_2, _3... or a
        comma-separated GROQ_API_KEYS — when one hits its limit the next is
        used.
        """
        if not self.api_key_env:
            return []
        from hunter.keypool import resolve_env_keys
        return resolve_env_keys(self.api_key_env)


@dataclass
class Config:
    allowed_hosts: list[str] = field(default_factory=list)
    fast: ModelConfig = field(default_factory=ModelConfig)
    deep: ModelConfig = field(default_factory=ModelConfig)
    max_requests_per_test: int = 50
    proxy_port: int = 8080
    ingest_port: int = 9090
    triage_enabled: bool = True
    triage_interval: int = 20
    triage_min_score: int = 6
    triage_batch_max: int = 25
    triage_auto_test: bool = True
    prefilter_enabled: bool = True
    prefilter_min: int = 2
    agent_escalate_score: int = 7
    agent_auto_cmds: int = 8
    fresh_start: bool = True
    db_path: str = "~/.hunter/hunter.db"
    capri_enabled: bool = True
    capri_queue_dir: str = "~/.hunter/capri_queue"
    capri_outbox: str = "~/.hunter/capri_outbox.jsonl"
    capri_log: str = "~/.hunter/blackwall.log"
    capri_poll_sec: float = 2.0


def resolve_config_path() -> Path:
    """HUNTER_CONFIG environment variable if set, else ~/.hunter/config.yaml."""
    env = os.environ.get("HUNTER_CONFIG") or os.environ.get("AVCI_CONFIG")  # legacy env still honored
    if env:
        return Path(env).expanduser()
    new_home = Path.home() / ".hunter"
    old_home = Path.home() / ".avci"
    if old_home.exists() and not new_home.exists():  # one-time migration from the avci era
        try:
            old_home.rename(new_home)
        except OSError:
            pass
    return new_home / "config.yaml"


def ensure_config(path: Path) -> bool:
    """Create the template if no config exists. True means newly created."""
    if path.exists():
        return False
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(DEFAULT_CONFIG, encoding="utf-8")
    return True


def _model_cfg(raw: dict[str, Any] | None) -> ModelConfig:
    raw = raw or {}
    return ModelConfig(
        base_url=str(raw.get("base_url") or "").strip(),
        model=str(raw.get("model") or "").strip(),
        api_key_env=str(raw.get("api_key_env") or "").strip(),
    )


def _to_int(value: Any, default: int) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def load_config(path: Path | None = None) -> Config:
    """Load the config; create the template if missing, fall back to defaults
    for broken fields."""
    cfg_path = path or resolve_config_path()
    ensure_config(cfg_path)
    try:
        raw: dict[str, Any] = yaml.safe_load(cfg_path.read_text(encoding="utf-8")) or {}
    except yaml.YAMLError as exc:
        raise SystemExit(
            f"[hunter] config could not be parsed: {cfg_path}\n{exc}\n"
            "Fix the file or delete it (a fresh template will be created)."
        )

    cfg = Config()
    hosts = raw.get("allowed_hosts") or []
    cfg.allowed_hosts = [str(h).strip().lower() for h in hosts if str(h).strip()]

    models = raw.get("models") or {}
    cfg.fast = _model_cfg(models.get("fast"))
    cfg.deep = _model_cfg(models.get("deep"))
    # Safe defaults for model blocks left over from an old template or missing:
    # triage → Groq (free tier), deep analysis → Kimi K3 (Moonshot).
    if not cfg.fast.base_url and not cfg.fast.model:
        cfg.fast = ModelConfig(
            base_url="https://api.groq.com/openai/v1",
            model="openai/gpt-oss-120b",
            api_key_env="GROQ_API_KEY",
        )
    if not cfg.deep.base_url and not cfg.deep.model:
        cfg.deep = ModelConfig(
            base_url="https://api.moonshot.ai/v1",
            model="kimi-k3",
            api_key_env="MOONSHOT_API_KEY",
        )

    limits = raw.get("limits") or {}
    cfg.max_requests_per_test = _to_int(limits.get("max_requests_per_test"), 50)

    proxy = raw.get("proxy") or {}
    cfg.proxy_port = _to_int(proxy.get("port"), 8080)

    ingest = raw.get("ingest") or {}
    cfg.ingest_port = _to_int(ingest.get("port"), 9090)

    triage = raw.get("triage") or {}
    cfg.triage_enabled = bool(triage.get("enabled", True))
    cfg.triage_interval = max(5, _to_int(triage.get("interval_sec"), 20))
    cfg.triage_min_score = max(0, min(9, _to_int(triage.get("min_score"), 6)))
    cfg.triage_batch_max = max(1, _to_int(triage.get("batch_max"), 25))
    cfg.triage_auto_test = bool(triage.get("auto_test", True))

    prefilter = raw.get("prefilter") or {}
    cfg.prefilter_enabled = bool(prefilter.get("enabled", True))
    cfg.prefilter_min = max(0, min(9, _to_int(prefilter.get("min_score"), 2)))

    agent = raw.get("agent") or {}
    cfg.agent_escalate_score = max(0, min(9, _to_int(agent.get("escalate_score"), 7)))
    cfg.agent_auto_cmds = max(1, _to_int(agent.get("auto_cmds"), 8))

    tui = raw.get("tui") or {}
    cfg.fresh_start = bool(tui.get("fresh_start", True))

    capri = raw.get("capri") or {}
    cfg.capri_enabled = bool(capri.get("enabled", True))
    cfg.capri_queue_dir = str(capri.get("queue_dir") or "~/.hunter/capri_queue")
    cfg.capri_outbox = str(capri.get("outbox") or "~/.hunter/capri_outbox.jsonl")
    cfg.capri_log = str(capri.get("log") or "~/.hunter/blackwall.log")
    try:
        cfg.capri_poll_sec = max(0.5, float(capri.get("poll_sec") or 2.0))
    except (TypeError, ValueError):
        cfg.capri_poll_sec = 2.0

    cfg.db_path = str(raw.get("db_path") or "~/.hunter/hunter.db")
    return cfg
