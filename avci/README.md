# AVCI — AI-Powered Interactive Web Security Testing Copilot (TUI)

> ⚠️ **Use only on bug bounty programs with a clearly defined scope where you have explicit permission to test.**
> AVCI is not an automatic scanner: it works alongside a researcher doing manual testing.
> It watches traffic, analyzes parameters, proposes test hypotheses, generates and runs
> **approved** test scripts, diffs the results, and drafts reports.
> Focus: business-logic flaws (IDOR/BOLA, race conditions, price-quantity consistency,
> mass assignment, authorization checks, multi-step flow breaks).

## Installation

```bash
git clone <repo> && cd avci        # or unzip the archive
python3 -m venv ~/.venvs/avci      # recommended: isolated environment
source ~/.venvs/avci/bin/activate
pip install -e .
avci --help
```

On first run, a `~/.avci/config.yaml` template is created. **No traffic is recorded
until you fill `allowed_hosts` with the target program's scope** (secure by default).

## Traffic capture — two modes

### Mode A: Burp mirror (recommended)

Browser → Burp flow stays untouched; the extension forwards a copy of every request to AVCI.

1. Download `jython-standalone-2.7.x.jar` (Maven Central).
2. Burp → **Extensions → Extension settings → Python environment** → select the jar.
3. Burp → **Extensions → Add → Python** → `extensions/burp_avci.py`.
4. Terminal 1: `avci ingest` (listens on 127.0.0.1:9090 only)
5. Terminal 2: `avci` (TUI)

### Mode B: mitmproxy

```bash
avci proxy                       # 127.0.0.1:8080
avci proxy --port 8083           # different port
avci proxy --upstream http://127.0.0.1:8080   # chain into Burp
```

- Point your browser proxy at this address (easy with FoxyProxy).
- **mitmproxy CA certificate:** while the proxy is running, open `http://mitm.it` in the
  browser → download the certificate for your platform → install it with "trust for
  identifying websites".
- In chained mode, the mitmproxy CA alone is enough.

## AI pipeline — three-tier funnel (prefilter → Groq → Kimi K3)

```
all requests → [0] rule-based prefilter (free, milliseconds)
             → [1] Groq triage (batched, every 20s)
             → [2] Groq agent terminal (avci shell — runs commands, tests)
             → [3] Groq auto-test (tries flagged requests itself with curls, no approval but safe-list)
             → [4] still suspicion ≥ 7 → Kimi K3 verification (the only paid tier)
```

1. **Rule-based prefilter (`prefilter.py`):** drops parameterless/bodyless read-only
   requests, telemetry hosts, and obvious noise WITHOUT ever sending them to Groq.
   Deterministic rules (write method +2, JSON body +3, id in path +2, surfaces like
   user/order/price/file +2...). Anything it can't decide on goes to Groq — it takes
   no risk of missing something. Config: `prefilter: { enabled: true, min_score: 2 }`.
   Filtered items show up as "FILTERED" in the Pipeline.
2. **Groq (triage, free tier):** https://console.groq.com → get an API key.
   ```bash
   export GROQ_API_KEY=gsk_...
   ```
   Requests that pass the prefilter go out in batches every `triage.interval` seconds.
   Groq returns a score + reason + test idea. **Groq never sees the full request/response** —
   it sees a compact summary (endpoint + host + 300 chars of body); that saves both
   speed and quota.
3. **Kimi K3 (deep analysis + verification, paid):**
   https://platform.moonshot.ai → top up (min. $1) → get a key.
   ```bash
   export MOONSHOT_API_KEY=sk-...
   ```
   Kicks in at two points: triage scores ≥ `triage.min_score`; and in an agent session,
   if Groq's final verdict reaches `agent.escalate_score` (default 7), the **session
   transcript automatically goes to K3 for verification** — "the agent thinks it found
   something; let K3 confirm".

**Keys are never written to config or code** — environment variables only. Kimi cost
is minimal by design: only whatever survives to the end of the funnel consumes credit.

- **Pipeline tab** (TUI bottom panel, next to jackboot): what went to Groq, what Groq
  said, what/why went to K3 — all as a color-coded live stream. Every event persists
  in the `pipeline_events` table.
- **Running commands from chat:** if you tell jackboot "test this / send the request",
  instead of just talking it proposes a single `bash` command (curl + jq) → approval
  screen (`y`/`n`) → the output drops into the chat and jackboot can comment and chain
  (max 5 commands per message). Same security rules as the agent: out-of-scope hosts
  are auto-rejected, sudo/rm -rf are on the deny list, and every command is logged to
  the Pipeline as "AGENT".
- `o` key: toggle auto-triage on/off. `avci triage`: a single one-shot pass without the
  TUI (ideal for verifying your keys).
- **`avci shell` — the jackboot agent terminal:** default brain is **Groq** (free, fast —
  switch to K3 with `--model deep`). It proposes commands in `bash` blocks (curl + jq
  chains), you approve (`y`), output goes back, and it chains tests. If the suspicion
  score crosses the threshold at the end of the session, the transcript automatically
  goes to Kimi for verification (disable with `--no-escalate`).
  - `avci shell --request-id 42`: starts the session with the context of request #42 in the TUI
  - Every command is shown: `y` run / `n` reject / `d` edit / `q` quit
  - Commands containing out-of-scope hosts are auto-rejected; `sudo`/`rm -rf`/`dd` are on the deny list
  - Session budget: 40 commands by default (change with `--max-cmd`), each command dies after 90s
  - All commands + outputs land in the Pipeline tab as "AGENT" (audit trail)
- If Groq is down or has no key, the TUI doesn't crash; the error prints in the Pipeline
  panel and the flow stops.

## Shortcuts

| Key | Action |
|-----|--------|
| `↑/↓` | select request |
| `a` / `d` | fast analysis (Groq) / deep analysis (Kimi K3) |
| `o` | toggle auto-triage |
| `t` | generate test script → **show** → `y` approval → run isolated |
| `r` | last run ↔ baseline diff + jackboot comment |
| `n` | add a note |
| `f` | save a finding (title/severity/status) |
| `x` | remove selected request from AI context |
| `s` | scope screen |
| `enter` | req/resp side-by-side fullscreen, esc to return |
| `ctrl+q` | quit |

CLI: `avci` (TUI) · `avci ingest` · `avci proxy` · `avci triage` · `avci shell [--request-id N]` · `avci clean [--all]` · `avci scope` · `avci report [--out file.md]`

**Fresh start:** the TUI deletes old request + pipeline records on every launch
(`config.yaml` → `tui: { fresh_start: true }`; set `false` to disable).
Findings and test runs are never auto-deleted. To clean without opening the TUI:
`avci clean` — to wipe everything (findings included): `avci clean --all`.

## Security rules (core)

- **Scope enforcement:** outside `allowed_hosts`, no traffic is recorded and no tests
  run; every host in a generated script is checked — rejected with a reason if outside.
- **Request ceiling:** 50 requests per test by default; exceeding it pops an **extra
  approval screen**.
- **Minimum-PoC:** if a surface has a CONFIRMED finding, generating new tests for that
  surface is blocked — "finding confirmed, move on to reporting".
- **Approved execution:** no script runs without being displayed and approved; runs
  execute as subprocesses in an isolated folder (`~/.avci/runs/`).
- **Audit trail:** all requests, tests, results, notes, and findings live in a
  per-target SQLite database (`~/.avci/avci.db`).

## Config reference (`~/.avci/config.yaml`)

```yaml
allowed_hosts: ["target.com"]     # subdomains included
models:
  fast: { base_url: "https://api.groq.com/openai/v1", model: "openai/gpt-oss-20b", api_key_env: "GROQ_API_KEY" }
  deep: { base_url: "https://api.moonshot.ai/v1", model: "kimi-k3", api_key_env: "MOONSHOT_API_KEY" }
triage:
  enabled: true        # auto-triage loop in the TUI
  interval: 20         # seconds — batch send interval
  min_score: 6         # this score and above escalates to K3
  batch_max: 25        # max requests per pass
prefilter:
  enabled: true        # rule-based prefilter before Groq (free)
  min_score: 2         # below this never reaches Groq
agent:
  escalate_score: 7    # agent sessions at this score auto-verify with K3
tui:
  fresh_start: true    # wipe old request + pipeline records on every launch
limits: { max_requests_per_test: 50 }
proxy:  { port: 8080 }
ingest: { port: 9090 }
db_path: "~/.avci/avci.db"
```

> **Updating an existing config:** if `~/.avci/config.yaml` is left over from a first
> install, the new `models` + `triage` blocks are not added automatically. Either add
> the blocks above by hand (your `allowed_hosts` line is preserved) or delete the file
> and let it regenerate: `rm ~/.avci/config.yaml && avci scope` — then refill
> `allowed_hosts`.

## Reporting

`avci report` generates a markdown draft from findings: Summary / Suggested severity /
Steps to Reproduce / PoC / Impact. **Do not submit a report without reviewing the
Impact section and the program's formatting rules.**

## Development

```bash
pip install -e ".[dev]"
python -m pytest tests/ -q     # 92 tests
```

## Multiple API keys (rotation pool)

Since Groq's limit fills up fast, you can define multiple keys; when one returns
429/402, the SAME request continues with the next key, and if all are cooling down
the pool wraps around. Uninterrupted even in the middle of an agent session.

```bash
export GROQ_API_KEY=gsk_first
export GROQ_API_KEY_2=gsk_second      # up to _3, _4 ... _20
# or all at once: export GROQ_API_KEYS="gsk_a,gsk_b,gsk_c"
```

The same rule applies to `MOONSHOT_API_KEY`. Pool state lives inside the process;
if every key is limited, the error message prints a pool summary.

## Capri bridge (Siber Mod)

A file-based bridge that lets the Capri desktop companion drop jobs for avci.
There is NO per-test approval screen, but the cage applies EXACTLY as before:
out-of-scope hosts, the deny list, and chained/redirected commands are always rejected.

```bash
avci capri          # bridge daemon (foreground; Capri launches it in the background)
avci capri --once   # process the queue for one pass and exit (connection test)
```

Protocol (config: `capri:` block):

- Capri writes a job → `~/.avci/capri_queue/<id>.json`
- The daemon appends the result → `~/.avci/capri_outbox.jsonl` (one JSON per line)
- Journal for you → `~/.avci/siber.log` (every command + summary; also lands in the
  TUI Pipeline tab as a "capri" event)

Job kinds:

```json
{"kind": "status"}
{"kind": "list_requests", "limit": 20}
{"kind": "get_request", "request_id": 42}
{"kind": "command", "command": "curl -s -i https://target/api/user/15"}
{"kind": "auto_test", "request_id": 42, "reason": "id goes straight in the path",
 "test_idea": "try the same request with a second account", "second_id": "15",
 "second_token": "Bearer ...", "max_cmds": 8}
```

`auto_test` runs the Groq agent in chains (curls pass through the auto-approval
filter); if `second_id`/`second_token` are provided, they are passed to the agent as
IDOR twin-account context. The resulting suspicion score is written to the DB.

File layout: `src/avci/` → `config.py`, `normalize.py`, `scope.py`, `db.py`,
`proxy_addon.py`, `ingest.py`, `prefilter.py` (rule-based prefilter), `triage.py`
(Groq→K3 pipeline), `agent.py` (agent terminal), `ai/` (client + jackboot prompts +
engine), `testing/` (generator + runner + diff), `report/`, `tui/app.py`, `cli.py`.
