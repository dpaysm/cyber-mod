# Cyber Mod — Capri × AVCI

Adds a **Black Wall** entry to Capri's right-click menu → containing **With Burp** (normal mode) and **Psycho (auto)** → **Simple / Hard / Off**.

## Normal mode (with Burp)

1. Starts `hunter ingest` and the `hunter capri` bridge in the background by itself.
2. Bulk-triages Burp traffic and starts testing whatever it finds suspicious on its own —
   commands run inside hunter's cage, no approval needed.
3. On IDOR suspicion it asks in chat for the second account id (until it gets an answer).
4. Say "test this site" and it goes on a recon hunt (server profile, ffuf,
   200s, open redirect).
5. When Cyber Mod opens, a live watch terminal appears: every command + output.

## Psycho Mode (standalone hunt)

Pick **Black Wall > Psycho (auto) > Simple** or **Hard** from the menu. Just name a
site in chat — Capri dives straight in with the selected mode and asks nothing else.
It **adds the host you give to the cage (allowed_hosts) itself**; no manual config editing.

- **SIMPLE**: nmap + whatweb + nuclei — all three AT ONCE in separate terminals.
- **HARD** (parallel waves, never idles):
  1. While recon runs in the background (subfinder → dnsx → httpx), the main host is
     instantly under fire: port scan + whatweb + nikto + nuclei.
  2. Deep wave: every host returning 200 (max 20) gets its OWN terminal with nuclei +
     URL harvesting (katana -jc / gau / waybackurls) + arjun hidden-parameter
     mining — all simultaneously.
  3. Analysis wave: sensitive files like .db/.sql/.env/.git from harvest + wayback URLs
     are ACTUALLY downloaded and verified; jshunter hunts endpoints + secrets +
     parameters across all JS files.
  4. Parameterized URLs are reduced to TEMPLATES (a.com/x?id=11 and ?id=12 are the
     same test — it runs once) → sqlmap (parallel waves of 8, --batch)
     + dalfox (XSS).
- No ffuf: its output demands expert analysis; instead there are tools that produce
  findings directly, like jshunter + sqlmap + the sensitive-file hunter.
- Every scan window's title: **Cyber Mod Capri Terminal — <stage>**.
- Capri narrates every action aloud instantly ("[nuclei] → x.y choom."); every line the
  worker writes is read from its now-file.

Rules:

- **English UI**: menus, speech, and log lines are in English for public release.

- **The cage is fixed but feeds itself**: a host you give in chat is automatically
  written to allowed_hosts; subdomains found by subfinder are in scope.
  Hosts arriving from outside chat (browser etc.) that are out of scope are still rejected.
- Commands live in code — the AI only comments and consults when stuck; the model
  doesn't generate commands, so the injection surface is minimal.
- **If a tool is missing** Capri asks: "X is not installed, want me to fetch it?" — say
  "yes" and it installs in a VISIBLE terminal with a `(capri)` prompt (if a sudo password
  is needed, you type it into that window yourself; Capri never sees it). Go tools
  install under `~/.capri/bin`.
- **Wordlists download without asking** (SecLists, ~/.hunter/wordlists).
- Each stage's full output goes to `~/.hunter/psycho/<target>_<date>/NN_tool.txt`;
  summaries collect in **REPORT.txt** in the same folder. Capri shouts out every stage
  and glitches/teleports around the screen while the hunt runs.
- **Consultation ladder when stuck**: deep model → NVIDIA second key
  (`NVIDIA_API_KEY_2`) → Gemini free API (`GEMINI_API_KEY`).
- **Panic: CTRL+ALT+0** (or unchecking the menu item) — the worker and all child
  processes die instantly. Manually: `touch ~/.hunter/PANIC`.

## Installation (Kali)

```bash
# 1. The hunter side (Psycho build):
#    cyber-mod repo → source ~/.venvs/avci/bin/activate → pip install -e ./hunter
#    (your existing venv is fine; the `avci` command keeps working as an alias)
#    allowed_hosts must be filled in ~/.hunter/config.yaml

# 2. Clone Capri + patch + build (.NET 10 SDK required)
git clone https://github.com/lachydotmcg/capri-desktop.git
cd capri-desktop
bash /path/to/blackwall/apply.sh
dotnet build cross/Capri.Cross.csproj -c Release -o out/cross
./out/cross/Capri
```

If your `hunter` command lives inside a venv, once:

```bash
echo '{"hunter": "/home/USER/.venvs/avci/bin/hunter"}' > ~/.hunter/blackwall.json
```

## When Capri updates

```bash
cd capri-desktop
git checkout -- cross/Pet.cs cross/Talk.cs   # revert the hooks (apply.sh re-adds them)
git pull
bash /path/to/blackwall/apply.sh
dotnet build cross/Capri.Cross.csproj -c Release -o out/cross
```

The patch is 1 file + 5 hooks (~11 lines); if it doesn't apply automatically, see `HOOKS.md`.

## Security

No per-test approval, but the cage is fixed: out-of-scope hosts are physically
rejected, and the deny list + auto-approval run on every command. All commands
remain as an audit trail in `~/.hunter/blackwall.log` + the `pipeline_events` table.
Psycho Mode controls only the terminals IT opened; it never touches your
applications and can be cut at any moment with CTRL+ALT+0.

## Small notes (latest version)

- Capri starts with Black Wall OFF on every launch; you enable the Burp mirror and
  Psycho from the right-click menu (your mode preference is remembered).
- In the first install terminal, your sudo password is asked ONCE; if you want, it's
  stored under `~/.capri/.sudo` (chmod 600, readable only by your user) and NEVER
  asked again. Leave it empty and sudo asks by itself each time.
- If a tool can't be installed or you say "no", the hunt doesn't stop: Capri skips
  that tool, tells you the manual install command, and moves on.
- Intel runs in the background of every hunt: Capri tries to identify the target via
  whois/IP and says a single "I know this site"-style sentence.
- All scan lanes run AT ONCE: slow main-host scans (nikto, port scan, testssl) live
  in their own lane; the deep wave and sqlmap don't wait for them. If you close a
  terminal window the hunt doesn't freeze — it continues with the remaining output.
- "Quit Capri" is now an automatic PANIC: the running hunt, the worker, and all tool
  processes are killed, and Black Wall/Psycho are saved as off.
- Capri's messages no longer pile up: a message arriving while the bubble is busy
  queues up and shows in order once the bubble clears. Also, '\n' and ANSI color
  codes in the text are stripped before reaching the bubble — the double-layered
  soup look from line wrapping is fixed.
- A stale lock left by a dead worker now releases by itself — no more
  "turn it off, switch to hard" dance; zombie processes count as dead too.
