<div align="center">

# ⚡ CYBER MOD ⚡

### Capri × HUNTER — your desktop companion that hacks with you

**A cyberpunk desktop pet with a full AI web-security copilot wired into its brain.**

`burp traffic` → `AI triage` → `auto tests` → `confirmed findings` → `report draft`

[![Platform](https://img.shields.io/badge/platform-Linux%20(Kali)-blueviolet)](#)
[![Capri](https://img.shields.io/badge/built%20for-Capri%20desktop-ff2d78)](#)
[![License](https://img.shields.io/badge/license-MIT-green)](#)
[![Tests](https://img.shields.io/badge/tests-92%20passing-brightgreen)](#)

<!-- SCREENSHOT: hero — Capri on the desktop with a psycho hunt running in neon terminals -->
<!-- ![hero](docs/hero.png) -->

<!-- VIDEO: 30s demo — right-click → BlackWall → Psycho (auto hacking) → type a target -->
<!-- https://github.com/USER/cyber-mod/assets/.../demo.mp4 -->

</div>

---

## What is this?

**Cyber Mod** turns [Capri](https://github.com/lachydotmcg/capri-desktop) — the desktop pet — into a hunting partner for bug bounty and authorized web security testing:

- 🐾 **Capri** lives on your desktop, narrates every action with a glitchy cyberpunk attitude, opens neon terminals and hunts in them while you watch.
- 🎯 **hunter** is the Python copilot underneath: it watches Burp traffic, scores requests with a 3-tier AI funnel (prefilter → Groq → Kimi K3), generates test scripts, diffs results, and drafts reports.
- 🧱 **BlackWall** is the bridge: right-click Capri → `BlackWall` → pick a mode. One menu. Total war.

> ⚠️ **Authorized scope only.** Use this on bug bounty programs where you have explicit permission. The cage (scope enforcement) is always on — but authorization is on you.

## The modes

| Mode | What happens |
|---|---|
| **With Burp** | hunter ingests your Burp traffic, bulk-triages it with AI, and auto-tests the suspicious requests — inside the cage, no per-test approval |
| **Psycho (auto hacking) → Simple** | nmap + whatweb + nuclei, all at once, each in its own neon terminal |
| **Psycho (auto hacking) → Hard** | parallel waves: recon (subfinder → dnsx → httpx) while the main host burns (nikto, nuclei, port scan), then per-host nuclei + URL harvest + arjun, then verified sensitive-file hunting + jshunter, then sqlmap + dalfox on templated params |

Every window titled `Cyber Mod Capri Terminal — <stage>`. Every command logged. Kill switch: **CTRL+ALT+0** — everything dies instantly.

<!-- SCREENSHOT: the BlackWall menu -->
<!-- ![menu](docs/menu.png) -->

<!-- SCREENSHOT: a Hard hunt mid-run — grid of neon terminals -->
<!-- ![hunt](docs/hunt.png) -->

## Install (Kali Linux)

**1 — Clone this repo:**

```bash
git clone https://github.com/USER/cyber-mod.git
cd cyber-mod
```

**2 — Install hunter (the Python copilot):**

```bash
python3 -m venv ~/.venvs/hunter
source ~/.venvs/hunter/bin/activate
pip install -e ./hunter
hunter --help
```

**3 — Set your keys (free tier is enough to start):**

```bash
export GROQ_API_KEY=gsk_...        # https://console.groq.com  (free — triage brain)
export MOONSHOT_API_KEY=sk-...     # https://platform.moonshot.ai  (paid — deep verification, optional)
```

**4 — Patch & build Capri (.NET 10 SDK required):**

```bash
git clone https://github.com/lachydotmcg/capri-desktop.git
bash cyber-mod/blackwall/apply.sh "$PWD/capri-desktop"   # or: cd capri-desktop && bash ../cyber-mod/blackwall/apply.sh
cd capri-desktop
dotnet build cross/Capri.Cross.csproj -c Release -o out/cross
./out/cross/Capri
```

**5 — Tell Capri where hunter lives (once, only if it's in a venv):**

```bash
echo '{"hunter": "'$HOME'/.venvs/hunter/bin/hunter"}' > ~/.hunter/blackwall.json
```

Done. Right-click the pet → **BlackWall**.

## Usage

```
Right-click Capri → BlackWall → With Burp            # traffic-driven hunting
Right-click Capri → BlackWall → Psycho (auto hacking) → Hard
Chat:  "test example.com"                            # Capri adds it to the cage and dives
Panic: CTRL+ALT+0                                    # instant kill, everything
```

Full hunter CLI: `hunter` (TUI) · `hunter ingest` · `hunter proxy` · `hunter shell` · `hunter triage` · `hunter report` — see [`hunter/README.md`](hunter/README.md).

## Update

One command — pulls the latest Cyber Mod **and** the latest upstream Capri, re-applies the patch, rebuilds:

```bash
bash ~/cyber-mod/blackwall/update.sh
```

> Never use Capri's built-in "Get Capri" button — that installs the vanilla app and wipes the mod. `update.sh` is the way.

## The cage (security model)

- **Scope enforcement:** hosts outside `allowed_hosts` are rejected at every layer — recording, scripts, agent commands. Chat-given hosts are added automatically.
- **Deny list + auto-approval filter** run on every command. No chained redirects out of scope.
- **Proof limits:** sqlmap stops at `--current-user`/`--current-db`. No data dumping, ever.
- **Audit trail:** every command and output lands in `~/.hunter/blackwall.log` + the `pipeline_events` table.

## Repo layout

```
cyber-mod/
├── hunter/      # the AI web-security copilot (Python, TUI + agent + psycho pipeline)
└── blackwall/   # the Capri patch kit (Blackwall.cs + apply.sh + update.sh + HOOKS.md)
```

## License

MIT — but remember: a license doesn't grant you authorization to test. Scope first.
