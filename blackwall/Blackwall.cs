using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Threading;
using Avalonia.Threading;

namespace CapriDesktop
{
    // Blackwall Mod: Capri's hunter bridge. On/Off from the right-click menu. When
    // on, `hunter ingest` and `hunter capri` run in the background; the bridge
    // outbox is read, new requests are asked to the brain in bulk and the
    // suspicious ones are queued as auto-test jobs. The cage stays on the
    // hunter side: no out-of-scope or deny-listed command can cross the bridge.
    internal static class Blackwall
    {
        internal static bool On;
        private static Pet pet;
        private static DispatcherTimer timer;
        private static Process ingest;
        private static Process bridge;
        private static long offset;
        private static bool queued;
        private static readonly HashSet<int> seen = new HashSet<int>();
        private static readonly HashSet<int> testing = new HashSet<int>();
        private static DateTime lastChatter = DateTime.MinValue;
        private static IdorAsk pending;
        private static readonly Queue<IdorAsk> askQueue = new Queue<IdorAsk>();
        private static string hunting;          // target host while a hunt is running
        private static Process watch;           // live log window
        private static readonly Regex HostInText = new Regex(@"\b((?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,})\b", RegexOptions.IgnoreCase);
        // ---- Psycho Mod ----
        private static bool psychoOn;           // is Psycho Mode on (stored in blackwall_state.json)
        private static string psychoHost;       // target while a hunt is running
        private static string psychoMode = "simple";  // picked from the menu: simple | hard
        private static readonly Dictionary<string, PsychoQ> questions = new Dictionary<string, PsychoQ>();
        private static DateTime lastGlitch = DateTime.MinValue;
        private static int deadTicks;          // worker death-detector counter
        private static string lastNow;         // last narrated psycho_now line (no repeats)
        private static readonly Random rng = new Random();

        // The install question Psycho Mode asks the user ("shall I install?"
        // when a tool is missing). The answer is written to
        // ~/.hunter/psycho_ask/<qid>.answer.
        private sealed class PsychoQ
        {
            internal string Text;
            internal DateTime AskedAt;
            internal int Times;
        }

        // An IDOR question awaiting an answer. Since the Typer hides when it
        // loses focus, the question re-opens every 90s; after 8 unanswered
        // rounds the test runs without the twin account, with its own probe.
        private sealed class IdorAsk
        {
            internal int Rid;
            internal string Why = "";
            internal string How = "";
            internal DateTime AskedAt;
            internal int Times;
        }

        private static string Dir { get {
            string home = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
            string nw = Path.Combine(home, ".hunter"), old = Path.Combine(home, ".avci");
            return Directory.Exists(nw) || !Directory.Exists(old) ? nw : old;  // legacy ~/.avci still works
        } }
        private static string QueueDir { get { return Path.Combine(Dir, "capri_queue"); } }
        private static string Outbox { get { return Path.Combine(Dir, "capri_outbox.jsonl"); } }
        private static string StateFile { get { return Path.Combine(Dir, "blackwall_state.json"); } }

        private static string Avci
        {
            get
            {
                try
                {
                    // blackwall.json (or legacy siber.json): {"hunter": "/path/to/hunter"} — "avci" key still accepted
                    foreach (string name in new[] { "blackwall.json", "siber.json" })
                    {
                        string extra = Path.Combine(Dir, name);
                        if (!File.Exists(extra)) continue;
                        using (JsonDocument doc = JsonDocument.Parse(File.ReadAllText(extra)))
                            foreach (string key in new[] { "hunter", "avci" })
                                if (doc.RootElement.TryGetProperty(key, out JsonElement found)) return found.GetString();
                    }
                }
                catch (Exception) { }
                return "hunter";  // the `avci` CLI alias also still exists
            }
        }

        internal static void Init(Pet owner)
        {
            if (Program.Smoke != null) return;
            pet = owner;
            Load();
            pet.Closed += delegate { Shutdown(); };
            timer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(20) };
            timer.Tick += delegate { Tick(); };
            timer.Start();
            sayTimer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(2) };
            sayTimer.Tick += delegate { FlushSay(); };
            sayTimer.Start();
            if (On) DispatcherTimer.RunOnce(delegate { Start(); }, TimeSpan.FromSeconds(5));
        }

        internal static void Toggle(Pet owner)
        {
            On = !On;
            Save();
            if (On) Start();
            else Stop(true);
        }

        private static void Start()
        {
            Directory.CreateDirectory(QueueDir);
            EnsureDaemons();
            OpenWatch();
            Say("Black Wall is up. I'm watching the Burp mirror; if something smells, I test it myself. Say 'test this site' and I go hunting — my commands stream in the live window.");
        }

        private static void Stop(bool tell)
        {
            foreach (Process p in new[] { ingest, bridge, watch })
                if (p != null && !p.HasExited) try { p.Kill(); } catch (Exception) { }
            ingest = bridge = watch = null;
            hunting = null;
            if (psychoHost != null)
            {
                try { File.WriteAllText(Path.Combine(Dir, "PANIC"), "menu"); } catch (Exception) { }
                psychoHost = null; lastNow = null;
            }
            questions.Clear();
            if (tell) Say("Black Wall is down. Watch is over, choom.");
        }

        // User rule: "Quit Capri" = AUTOMATIC PANIC first. No hunt/worker/
        // tool may linger in the background while the app closes (same
        // mechanism as CTRL+ALT+0: PANIC file + process kill). State is also
        // marked closed so the next launch starts clean — Capri is always
        // born with Black Wall OFF anyway.
        internal static void ShutdownPanic()
        {
            try { File.WriteAllText(Path.Combine(Dir, "PANIC"), "quit"); } catch (Exception) { }
            foreach (Process p in new[] { ingest, bridge, watch })
                if (p != null && !p.HasExited) try { p.Kill(); } catch (Exception) { }
            ingest = bridge = watch = null;
            hunting = null;
            psychoHost = null; lastNow = null;
            questions.Clear();
            On = false;
            psychoOn = false;
            Save();
        }

        // While Blackwall Mod is on, a chat request like "test / scan / check
        // this site" plus a caught host turns into a hunter recon hunt;
        // true = the message was swallowed.
        internal static bool MaybeHunt(string text)
        {
            if (!On || pet == null || text == null) return false;
            string lower = text.ToLowerInvariant();
            // trigger words: Turkish AND English — the chat may use either
            bool istek = lower.Contains("test") || lower.Contains("tara") || lower.Contains("avlan")
                || lower.Contains("incele") || lower.Contains("keşif") || lower.Contains("kesf")
                || lower.Contains("scan") || lower.Contains("hunt") || lower.Contains("check");
            if (!istek) return false;
            Match m = HostInText.Match(text);
            if (!m.Success) return false;
            string host = m.Groups[1].Value.ToLowerInvariant();
            if (hunting != null) { Say("Still busy with " + hunting + " choom — when it's done, " + host + " is next."); return true; }
            EnsureScope(host);   // a host given in chat enters the cage automatically
            hunting = host;
            Log("hunt requested: " + host);
            Say("On it choom — diving into " + host + ": server profile, ffuf fuzzing, 200s, open redirects. My commands stream in the live window and blackwall.log.");
            Enqueue("{\"kind\":\"hunt\",\"host\":" + JsonSerializer.Serialize(host) + "}");
            return true;
        }

        // ----------------------------------------------------------------
        // PSYCHO MODE — Capri hunts alone. A separate menu tick; while on,
        // mentioning a site in chat is enough, Capri asks Simple/Hard.
        // The scan runs in hunter's psycho pipeline (fixed commands, cage
        // enforced). Panic: CTRL+ALT+0 (or untick the menu item).
        // ----------------------------------------------------------------
        internal static bool PsychoOn { get { return psychoOn; } }
        internal static string PsychoMode { get { return psychoMode; } }

        // BlackWall > Psycho (auto hacking) menu: Simple / Hard / Off.


        internal static void SetPsycho(Pet owner, string mode)
        {
            if (mode == "off")
            {
                psychoOn = false;
                Save();
                if (psychoHost != null)
                {
                    try { File.WriteAllText(Path.Combine(Dir, "PANIC"), "menu"); } catch (Exception) { }
                    Say("Panic flag is up — the " + psychoHost + " hunt and all its child processes are dying.");
                    psychoHost = null; lastNow = null;
                }
                questions.Clear();
                Say("Psycho mode off. Back to normal watch, choom.");
                return;
            }
            if (psychoHost != null)
            {
                Say("A hunt is already running on " + psychoHost + " choom — flip Psycho to Off first (or CTRL+ALT+0), then pick a mode. No mid-hunt switching.");
                return;
            }
            if (psychoHost != null && !WorkerAlive())
            {
                // Stale lock: the worker died but psychoHost stayed stuck —
                // don't make the user do the "off then hard" dance, clean it
                // yourself.
                Log("stale psycho lock cleared (worker dead) — was: " + psychoHost);
                psychoHost = null; lastNow = null;
            }
            psychoMode = mode == "hard" ? "hard" : "simple";
            psychoOn = true;
            Save();
            if (!On) Toggle(owner);   // psycho rides on top of black wall
            Say("Psycho mode armed (" + psychoMode.ToUpperInvariant() + "). Just drop me a site name choom — I handle the rest: nmap, subfinder, httpx, nuclei, ffuf, dalfox, nikto... Missing tools? I'll ask; say 'yes' and I install them in my own (capri) terminal. Everything lands in ~/.hunter/psycho/. Kill switch: CTRL+ALT+0.");
        }

        // A host the user gives in chat is added to the cage AUTOMATICALLY —
        // no manual config editing. The cage stays; Capri just writes the
        // "main host" itself (www. prefix stripped, subdomains covered).
        private static void EnsureScope(string host)
        {
            try
            {
                string bare = host.StartsWith("www.") ? host.Substring(4) : host;
                string cfgPath = Path.Combine(Dir, "config.yaml");
                string text = File.Exists(cfgPath) ? File.ReadAllText(cfgPath) : "";
                foreach (string raw in text.Split('\n'))
                {
                    string t = raw.Trim().TrimStart('-').Trim().Trim('"', '\'');
                    if (t.Length > 0 && !t.Contains(" ") && (bare == t || bare.EndsWith("." + t) || t.EndsWith("." + bare))) return;
                }
                // find the allowed_hosts: block, append to the END of its
                // existing - items. (Blindly appending to the end of the file
                // breaks the YAML — happened.)
                string[] lines = text.Split('\n');
                int head = -1;
                for (int i = 0; i < lines.Length; i++)
                    if (lines[i].TrimStart().StartsWith("allowed_hosts:")) { head = i; break; }
                if (head >= 0)
                {
                    int insertAt = head + 1;
                    while (insertAt < lines.Length && lines[insertAt].TrimStart().StartsWith("-")) insertAt++;
                    List<string> list = new List<string>(lines);
                    list.Insert(insertAt, "  - \"" + bare + "\"");
                    text = string.Join("\n", list);
                }
                else
                {
                    text = text.TrimEnd() + "\n\nallowed_hosts:\n  - \"" + bare + "\"\n";
                }
                File.WriteAllText(cfgPath, text);
                Log("scope updated: " + bare + " added to allowed_hosts");
                Say("Added " + bare + " to the cage (allowed_hosts) myself — no manual config, choom.");
            }
            catch (Exception ex) { Log("scope update failed: " + ex.Message); }
        }

        // While psycho is on, a host caught in chat starts directly with the
        // menu's mode; true = the message was swallowed (the Talk.cs hook
        // calls this BEFORE MaybeHunt).
        internal static bool MaybePsycho(string text)
        {
            if (!psychoOn || pet == null || text == null) return false;
            Match m = HostInText.Match(text);
            if (!m.Success) return false;
            string host = m.Groups[1].Value.ToLowerInvariant();
            if (psychoHost != null)
            {
                if (WorkerAlive())
                {
                    Say("Deep in " + psychoHost + " right now choom — wait for it or hit CTRL+ALT+0, then " + host + " gets its turn.");
                    return true;
                }
                // the worker is long dead — I clear the stale lock myself, no dance
                Log("stale psycho lock cleared on new target (worker dead) — was: " + psychoHost);
                psychoHost = null; lastNow = null;
            }
            EnsureScope(host);
            StartPsycho(host, psychoMode);
            return true;
        }

        // Is the worker REALLY alive? Zombie processes pass GetProcessById
        // (killed but unreaped child) — count it dead if the state letter in
        // /proc stat is 'Z'. Without this check a dead worker locks things
        // up as "hunt running" and the user does the off→hard dance.
        internal static bool WorkerAlive()
        {
            try
            {
                string pidFile = Path.Combine(Dir, "psycho_worker.pid");
                if (!File.Exists(pidFile)) return false;
                int pid = int.Parse(File.ReadAllText(pidFile).Trim());
                Process p = Process.GetProcessById(pid);
                if (p.HasExited) return false;
                try
                {
                    string stat = File.ReadAllText("/proc/" + pid + "/stat");
                    int rp = stat.LastIndexOf(')');
                    if (rp >= 0 && rp + 2 < stat.Length && stat[rp + 2] == 'Z') return false;
                }
                catch (Exception) { }   // if /proc is unreadable, assume alive
                return true;
            }
            catch (Exception) { return false; }
        }

        private static void StartPsycho(string host, string mode)
        {
            psychoHost = host;
            deadTicks = 0;
            OpenWatch();   // reopen if the window was closed
            Log("psycho hunt requested: " + host + " (" + mode + ")");
            Say((mode == "hard" ? "HARD mode choom — buckle up, this takes hours. " : "SIMPLE mode, done in a quarter hour. ")
                + host + " is mine now; I'll shout every stage, every output lands as a txt under ~/.hunter/psycho/. Missing tools? I'll ask. CTRL+ALT+0 = panic.");
            Enqueue("{\"kind\":\"psycho\",\"host\":" + JsonSerializer.Serialize(host) + ",\"mode\":" + JsonSerializer.Serialize(mode) + "}");
        }

        // The worker's "tool missing, shall I install?" question — the answer
        // is written to a file,
        // runner oradan okur. Typer odak kaybederse Tick yeniden sorar.
        private static void AskPsychoQ(string qid, string text)
        {
            PsychoQ q;
            if (!questions.TryGetValue(qid, out q)) { q = new PsychoQ { Text = text }; questions[qid] = q; }
            q.AskedAt = DateTime.UtcNow;
            q.Times++;
            pet.Talk.AskFor("(capri setup)", text, delegate(string typed)
            {
                try
                {
                    string adir = Path.Combine(Dir, "psycho_ask");
                    Directory.CreateDirectory(adir);
                    File.WriteAllText(Path.Combine(adir, qid + ".answer"), (typed ?? "").Trim());
                }
                catch (Exception) { }
                questions.Remove(qid);
                Log("install question answered: " + (typed ?? "").Trim());
            });
        }

        // While a psycho hunt runs, Capri "glitches": teleports randomly
        // across the screen.
        private static void GlitchTick()
        {
            if ((DateTime.UtcNow - lastGlitch).TotalSeconds < 45) return;
            lastGlitch = DateTime.UtcNow;
            try
            {
                Avalonia.PixelRect area = pet.Area;
                int w = Math.Max(1, area.Width - 200), hgt = Math.Max(1, area.Height - 200);
                pet.Move(new Avalonia.PixelPoint(area.X + rng.Next(w), area.Y + rng.Next(hgt)));
                pet.SetGlitch(rng.Next(20, 80));
            }
            catch (Exception) { }
        }

        private static readonly string[] PsychoChatter =
        {
            "digging away choom — pulling fingerprints",
            "counting ports, I'll find a way in",
            "wordlists spinning; hidden dirs are dropping one by one",
            "nuclei templates are talking — I'm listening",
            "subdomains keep falling out, all through the cage",
            "full glitch mode right now; watch the log window choom",
        };

        // Opens a terminal window live-tailing blackwall.log while Blackwall Mod is on.
        private static void OpenWatch()
        {
            try
            {
                if (watch != null && !watch.HasExited) return;
                string log = Path.Combine(Dir, "blackwall.log");
                string[][] adaylar = new string[][]
                {
                    new[] { "xfce4-terminal", "--title", "CYBER MOD — live commands", "-e", "tail -n 40 -f '" + log + "'" },
                    new[] { "xterm", "-T", "CYBER MOD — live commands", "-e", "tail", "-n", "40", "-f", log },
                    new[] { "x-terminal-emulator", "-e", "tail", "-n", "40", "-f", log },
                    new[] { "qterminal", "-e", "tail -n 40 -f '" + log + "'" },
                    new[] { "konsole", "-e", "tail", "-n", "40", "-f", log },
                    new[] { "gnome-terminal", "--", "tail", "-n", "40", "-f", log },
                    new[] { "kitty", "tail", "-n", "40", "-f", log },
                };
                foreach (string[] aday in adaylar)
                {
                    try
                    {
                        ProcessStartInfo si = new ProcessStartInfo(aday[0]) { UseShellExecute = false };
                        for (int i = 1; i < aday.Length; i++) si.ArgumentList.Add(aday[i]);
                        watch = Process.Start(si);
                        if (watch != null) { Log("watch window opened: " + aday[0]); return; }
                    }
                    catch (Exception) { }
                }
                Log("watch window failed — follow manually: tail -f " + log);
                Say("I couldn't open the watch window choom — run this yourself to see my every move:  tail -f ~/.hunter/blackwall.log");
            }
            catch (Exception) { }
        }

        internal static void Shutdown()
        {
            // closing from the window follows the same rule as Quit: panic + off
            ShutdownPanic();
        }

        // Every 20 seconds: are the daemons up, did the queue turn, any new
        // requests.
        private static void Tick()
        {
            if (!On || pet == null) return;
            EnsureDaemons();
            Drain();
            Nag();
            // Scoring lives in hunter's triage engine (disciplined JSON + key
            // pool); Capri's own brain refuses to return JSON because of the
            // persona.
            if (!queued) Enqueue("{\"kind\":\"triage\",\"limit\":25}");
            if (testing.Count > 0) MaybeChatter(testing.Count + " suspects in hand, curls are flying choom. Watch me on blackwall.log.");
            else if (hunting != null) MaybeChatter("The hunt on " + hunting + " is live — curl/ffuf flying choom, keep an eye on blackwall.log.");
            // ---- Psycho Mode liveness: glitch + chatter + question watch ----
            if (psychoHost != null)
            {
                GlitchTick();
                // if the worker died silently, notice within 2 ticks (~40s) —
                // zombie processes LOOK alive, WorkerAlive checks /proc
                bool alive = WorkerAlive();
                if (alive) deadTicks = 0;
                else if (++deadTicks >= 2)
                {
                    deadTicks = 0;
                    string lost = psychoHost;
                    psychoHost = null; lastNow = null;
                    Log("psycho worker died silently (" + lost + ")");
                    Say("My psycho worker died on me choom — " + lost + " hunt stopped mid-way. Check ~/.hunter/blackwall.log and ~/.hunter/blackwall-daemons.log; tell me the site again and I'll restart it.");
                }
                // "what's happening right now" — read from the worker's now
                // file. Every NEW line = a new action; Capri says it without
                // waiting (not bound by the 75s chatter brake, only a 4s spam
                // brake).
                string now = null;
                try { string nf = Path.Combine(Dir, "psycho_now.txt"); if (File.Exists(nf)) now = File.ReadAllText(nf).Trim(); } catch (Exception) { }
                if (now != null && now.Length > 0 && now != lastNow)
                {
                    lastNow = now;
                    if ((DateTime.UtcNow - lastChatter).TotalSeconds >= 4)
                    {
                        lastChatter = DateTime.UtcNow;
                        // "PSY host [stage] msg" → let Capri say it in her own words
                        string line = now;
                        if (line.StartsWith("PSY "))
                        {
                            int b = line.IndexOf('[');
                            if (b > 0) line = line.Substring(b);
                        }
                        Say(line + " choom.");
                    }
                }
                else if (now == null || now.Length == 0)
                    MaybeChatter("On " + psychoHost + ": " + PsychoChatter[rng.Next(PsychoChatter.Length)] + ".");
            }
            if (questions.Count > 0)
            {
                List<string> answered = new List<string>();
                foreach (string qid in new List<string>(questions.Keys))
                {
                    // if the answer came another way (or the worker gave up),
                    // drop the question
                    if (File.Exists(Path.Combine(Dir, "psycho_ask", qid + ".answer"))) { answered.Add(qid); continue; }
                    PsychoQ q = questions[qid];
                    if (q.Times < 5 && (DateTime.UtcNow - q.AskedAt).TotalSeconds >= 120)
                        AskPsychoQ(qid, q.Text);
                }
                foreach (string qid in answered) questions.Remove(qid);
            }
        }

        // Re-opens an unanswered IDOR question every 90 seconds; after asking
        // 8 times
        // sonra pes eder ve testi ikiz hesap olmadan kendisi yapar.
        private static void Nag()
        {
            if (pending == null) return;
            if ((DateTime.UtcNow - pending.AskedAt).TotalSeconds < 90) return;
            if (pending.Times >= 8)
            {
                Log("#" + pending.Rid + " got no id — trying without a twin account");
                Say("No id came in choom — I'll try #" + pending.Rid + " on my own.");
                SendTest(pending.Rid, pending.Why, pending.How, null, null);
                pending = null;
                if (askQueue.Count > 0) AskIdor(askQueue.Dequeue());
                return;
            }
            AskIdor(pending);
        }

        private static void AskIdor(IdorAsk ask)
        {
            pending = ask;
            ask.AskedAt = DateTime.UtcNow;
            ask.Times++;
            IdorAsk cur = ask;
            pet.Talk.AskFor("(black wall)", "#" + cur.Rid + " smells like IDOR: " + cur.Why + " Can you give me a second account id? (add a token after a space if needed; leave empty and I'll try myself — I'll keep asking until you answer)", delegate(string typed)
            {
                string secondId = null, secondToken = null;
                typed = (typed ?? "").Trim();
                if (typed.Length > 0)
                {
                    string[] parts = typed.Split(new[] { ' ' }, 2, StringSplitOptions.RemoveEmptyEntries);
                    secondId = parts[0];
                    if (parts.Length > 1) secondToken = parts[1];
                }
                if (pending == cur) pending = null;
                Log("#" + cur.Rid + " user answered" + (secondId != null ? " — second id: " + secondId : " (empty)"));
                SendTest(cur.Rid, cur.Why, cur.How, secondId, secondToken);
                if (askQueue.Count > 0) AskIdor(askQueue.Dequeue());
            });
        }

        // Short status chatter so Blackwall Mod never feels idle — at most once
        // every 75s.
        private static void MaybeChatter(string line)
        {
            if ((DateTime.UtcNow - lastChatter).TotalSeconds < 75) return;
            lastChatter = DateTime.UtcNow;
            Say(line);
        }

        private static void EnsureDaemons()
        {
            if (ingest == null || ingest.HasExited)
                if (!Running(Avci + " ingest") && !Running("avci ingest")) ingest = Spawn("ingest");
            if (bridge == null || bridge.HasExited)
                if (!Running(Avci + " capri") && !Running("avci capri")) bridge = Spawn("capri");
        }

        private static bool Running(string match)
        {
            try
            {
                // Use ArgumentList: splitting "-f " + match string at the
                // space makes pgrep think there are two patterns and explode
                // with "only one pattern".
                ProcessStartInfo start = new ProcessStartInfo("pgrep") { UseShellExecute = false, RedirectStandardOutput = true, CreateNoWindow = true };
                start.ArgumentList.Add("-f");
                start.ArgumentList.Add(match);
                using (Process probe = Process.Start(start))
                {
                    string found = probe.StandardOutput.ReadToEnd();
                    probe.WaitForExit(3000);
                    return found.Trim().Length > 0;
                }
            }
            catch (Exception) { return false; }
        }

        private static readonly object LogLock = new object();
        private static string DaemonLog { get { return Path.Combine(Dir, "blackwall-daemons.log"); } }

        private static void LogLine(string tag, string line)
        {
            try { lock (LogLock) File.AppendAllText(DaemonLog, "[" + tag + "] " + line + "\n"); }
            catch (Exception) { }
        }

        private static Process Spawn(string args)
        {
            try
            {
                // Redirect daemon output to ~/.hunter/blackwall-daemons.log so it's
                // visible what ingest recorded / why it rejected.
                ProcessStartInfo start = new ProcessStartInfo(Avci) { UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true, RedirectStandardError = true };
                start.ArgumentList.Add(args);
                start.Environment["PYTHONUNBUFFERED"] = "1";
                Process proc = Process.Start(start);
                if (proc == null) return null;
                proc.OutputDataReceived += delegate (object s, DataReceivedEventArgs e) { if (e.Data != null) LogLine(args, e.Data); };
                proc.ErrorDataReceived += delegate (object s, DataReceivedEventArgs e) { if (e.Data != null) LogLine(args + "!", e.Data); };
                proc.EnableRaisingEvents = true;
                proc.BeginOutputReadLine();
                proc.BeginErrorReadLine();
                LogLine("cyber", "started: " + Avci + " " + args + " (pid " + proc.Id + ")");
                return proc;
            }
            catch (Exception exc)
            {
                LogLine("cyber!", "failed to start: " + Avci + " " + args + " -> " + exc.Message);
                return null;
            }
        }

        // Drops the job into the bridge queue; the result returns via the
        // outbox.
        private static void Enqueue(string json)
        {
            try
            {
                string id = Guid.NewGuid().ToString("N").Substring(0, 12);
                string body = json.Replace("{", "{\"id\":\"" + id + "\",", StringComparison.Ordinal);
                File.WriteAllText(Path.Combine(QueueDir, id + ".json"), body);
                queued = true;
            }
            catch (Exception) { }
        }

        private static void Drain()
        {
            string path = Outbox;
            if (!File.Exists(path)) { queued = false; return; }
            string fresh;
            try
            {
                using (FileStream stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
                {
                    if (stream.Length < offset) offset = 0;
                    stream.Seek(offset, SeekOrigin.Begin);
                    fresh = new StreamReader(stream).ReadToEnd();
                    offset = stream.Position;
                }
            }
            catch (Exception) { return; }
            foreach (string line in fresh.Split('\n'))
            {
                if (line.Trim().Length == 0) continue;
                try { Handle(JsonDocument.Parse(line).RootElement); }
                catch (Exception) { }
            }
            Save();
        }

        // Write Blackwall's inner decision loop to the same blackwall.log — otherwise
        // you're blind.
        private static void Log(string line)
        {
            try
            {
                string stamp = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss");
                lock (LogLock) File.AppendAllText(Path.Combine(Dir, "blackwall.log"), "[" + stamp + "] capri: " + line + "\n");
            }
            catch (Exception) { }
        }

        private static void Handle(JsonElement result)
        {
            string kind = result.TryGetProperty("kind", out JsonElement k) ? k.GetString() : "";
            bool ok = result.TryGetProperty("ok", out JsonElement o) && o.GetBoolean();
            if (kind == "triage")
            {
                queued = false;
                if (!ok)
                {
                    string terr = result.TryGetProperty("error", out JsonElement te) ? te.GetString() : "?";
                    Log("triage error: " + terr);
                    return;
                }
                int taranan = result.TryGetProperty("taranan", out JsonElement tn) ? tn.GetInt32() : 0;
                int elendi = result.TryGetProperty("elendi", out JsonElement el) ? el.GetInt32() : 0;
                if (taranan > 0 || elendi > 0) Log("triage pass: " + taranan + " scanned, " + elendi + " filtered out");
                int pcount = 0;
                if (result.TryGetProperty("picks", out JsonElement picks) && picks.ValueKind == JsonValueKind.Array) { pcount = picks.GetArrayLength(); Picks(picks); }
                if (pcount == 0 && taranan > 0) MaybeChatter("Sifted " + taranan + " requests, all boring so far choom. Eyes on the wire.");
                return;
            }
            if (kind == "auto_test")
            {
                queued = false;  // yoksa ilk testten sonra list_requests bir daha sorulmaz
                int id = 0, score = -1;
                if (result.TryGetProperty("request", out JsonElement _)) { }
                if (result.TryGetProperty("score", out JsonElement s) && s.ValueKind == JsonValueKind.Number) score = s.GetInt32();
                string transcript = result.TryGetProperty("transcript", out JsonElement t) ? t.GetString() ?? "" : "";
                Match mid = Regex.Match(transcript, @"#(\d+)");
                if (mid.Success) id = int.Parse(mid.Groups[1].Value);
                if (id > 0) testing.Remove(id);
                if (!ok)
                {
                    string err = result.TryGetProperty("error", out JsonElement e) ? e.GetString() : "?";
                    Log("auto-test #" + (id > 0 ? id.ToString() : "?") + " error: " + err);
                    Say("Couldn't finish a test: " + err);
                    return;
                }
                Log("auto-test #" + (id > 0 ? id.ToString() : "?") + " done — score " + (score < 0 ? "?" : score + "/9"));
                if (score >= 7) Say("Look at this choom — scored " + score + "/9. Details in the TUI; I say this one is report-worthy.");
                else if (score >= 4) Say("Test done: " + score + "/9, still suspicious. Keeping it in mind.");
                else Say("Test done: " + (score < 0 ? "?" : score.ToString()) + "/9 — turned out to be nothing, debunked.");
                return;
            }
            if (kind == "hunt")
            {
                queued = false;
                string hhost = hunting ?? "?";
                hunting = null;
                if (!ok)
                {
                    string herr = result.TryGetProperty("error", out JsonElement he) ? he.GetString() : "?";
                    Log("hunt error (" + hhost + "): " + herr);
                    Say("Couldn't finish the hunt choom: " + herr);
                    return;
                }
                int hscore = -1;
                if (result.TryGetProperty("score", out JsonElement hs) && hs.ValueKind == JsonValueKind.Number) hscore = hs.GetInt32();
                Log("hunt done (" + hhost + ") — score " + (hscore < 0 ? "?" : hscore + "/9") + "; full dump in blackwall.log");
                if (hscore >= 7) Say("Hunt done choom — " + hscore + "/9. Serious stuff around " + hhost + ", dump in blackwall.log. Report-worthy.");
                else if (hscore >= 4) Say("Hunt done: " + hscore + "/9 — " + hhost + " stays suspicious. Dump in blackwall.log, keeping it in mind.");
                else Say("Hunt done: " + (hscore < 0 ? "?" : hscore.ToString()) + "/9 — nothing juicy on " + hhost + ". Dump is in blackwall.log anyway.");
                return;
            }
            if (kind == "psycho")
            {
                bool started = result.TryGetProperty("started", out JsonElement ps) && ps.GetBoolean();
                string phost = result.TryGetProperty("host", out JsonElement ph) ? ph.GetString() : (psychoHost ?? "?");
                if (started) { Log("psycho worker in the field: " + phost); return; }
                psychoHost = null; lastNow = null;
                if (!ok)
                {
                    string perr = result.TryGetProperty("error", out JsonElement pe) ? pe.GetString() : "?";
                    Log("psycho error (" + phost + "): " + perr);
                    Say("The psycho hunt broke choom: " + perr);
                    return;
                }
                int pscore = -1;
                if (result.TryGetProperty("score", out JsonElement psc) && psc.ValueKind == JsonValueKind.Number) pscore = psc.GetInt32();
                string report = result.TryGetProperty("report", out JsonElement pr) ? pr.GetString() ?? "" : "";
                string summary = result.TryGetProperty("summary", out JsonElement psum) ? psum.GetString() ?? "" : "";
                Log("psycho hunt done (" + phost + ") — score " + (pscore < 0 ? "?" : pscore + "/9") + "; report: " + report);
                string verdict = pscore >= 7 ? "this is REPORT-WORTHY choom!" : pscore >= 4 ? "stays suspicious, on my mind." : "turned out to be nothing.";
                Say("Psycho hunt done: " + phost + " — " + (pscore < 0 ? "?" : pscore + "/9") + ", " + verdict
                    + (summary.Length > 0 ? " Summary: " + (summary.Length > 300 ? summary.Substring(0, 300) + "…" : summary) : "")
                    + (report.Length > 0 ? " Full report: " + report : ""));
                return;
            }
            if (kind == "question")
            {
                string qid = result.TryGetProperty("qid", out JsonElement q) ? q.GetString() : "";
                string qtext = result.TryGetProperty("text", out JsonElement qt) ? qt.GetString() : "";
                if (qid.Length > 0 && qtext.Length > 0) AskPsychoQ(qid, qtext);
                return;
            }
            if (kind == "command") queued = false;
        }

        // Takes over what triage flagged; for IDOR-smelling ones it asks the
        // user for the second account id, the rest goes straight to auto-test.
        // Scoring was done on the hunter side — the only decision here is
        // "which one are we going into".
        private static void Picks(JsonElement picks)
        {
            int sayi = picks.GetArrayLength();
            if (sayi == 0) return;
            Log("triage flagged " + sayi + " suspects");
            int yorumHakki = 2;  // max 2 AI comments per round — don't burn the brain quota
            foreach (JsonElement pick in picks.EnumerateArray())
            {
                int id;
                try { id = pick.GetProperty("id").GetInt32(); } catch (Exception) { continue; }
                if (testing.Contains(id)) continue;
                testing.Add(id);
                string neden = pick.TryGetProperty("neden", out JsonElement n) ? n.GetString() ?? "" : "";
                string test = pick.TryGetProperty("test", out JsonElement t2) ? t2.GetString() ?? "" : "";
                int skor = pick.TryGetProperty("skor", out JsonElement sk) && sk.ValueKind == JsonValueKind.Number ? sk.GetInt32() : 0;
                string path = pick.TryGetProperty("path", out JsonElement p2) ? p2.GetString() ?? "?" : "?";
                if (yorumHakki-- > 0) CommentOn(id, path, neden, skor);
                string birlesik = (neden + " " + test).ToLowerInvariant();
                bool idor = birlesik.Contains("idor") || birlesik.Contains("bola") || birlesik.Contains("ikinci hesap");
                Log("#" + id + " flagged (" + skor + "/9): " + neden);
                if (idor)
                {
                    Log("#" + id + " IDOR suspicion — asking user for a second account id");
                    IdorAsk ask = new IdorAsk { Rid = id, Why = neden, How = test };
                    if (pending == null) AskIdor(ask);
                    else { askQueue.Enqueue(ask); Log("#" + id + " question queued (another is pending)"); }
                }
                else SendTest(id, neden, test, null, null);
            }
        }

        // Writes a single-sentence comment on the flagged endpoint in Capri's
        // own curious-netrunner tone. Silently skipped if the brain is missing
        // or errors — the comment is decoration, it must not delay the test.
        private static void CommentOn(int id, string path, string neden, int skor)
        {
            try { if (pet.Brain.Model == null) return; } catch (Exception) { return; }
            ThreadPool.QueueUserWorkItem(delegate
            {
                string line = null;
                try
                {
                    line = pet.Brain.Ask(
                        "CYBER MOD comment — not a security test, I just want a one-liner in your own style: "
                        + "this endpoint in the Burp traffic caught my eye: " + path
                        + " (suspicion score " + skor + "/9, reason: " + neden + "). "
                        + "Comment like a curious netrunner, in your own voice, in English, ONE sentence. "
                        + "No technical detail; a gut-feeling comment. Example vibe: \"/user/12... hmmm, this endpoint tickles me.\"");
                }
                catch (Exception) { }
                if (line != null && line.Trim().Length > 0) Say(line.Trim());
            });
        }

        private static void SendTest(int id, string neden, string test, string secondId, string secondToken)
        {
            Log("auto-test queued: #" + id + " — " + neden + (secondId != null ? " (second id: " + secondId + ")" : ""));
            Say("#" + id + " looks suspicious: " + neden + " Starting the test — watch my commands on blackwall.log.");
            string json = "{\"kind\":\"auto_test\",\"request_id\":" + id
                + ",\"reason\":" + JsonSerializer.Serialize(neden)
                + ",\"test_idea\":" + JsonSerializer.Serialize(test)
                + (secondId != null ? ",\"second_id\":" + JsonSerializer.Serialize(secondId) : "")
                + (secondToken != null ? ",\"second_token\":" + JsonSerializer.Serialize(secondToken) : "")
                + "}";
            Enqueue(json);
        }

        // Speech queue: a message arriving while the bubble is busy must NOT
        // CRUSH the previous one — the fix for "answers overlap, messages are
        // unreadable". When the bubble frees up (sayTimer, 2s) the next
        // message shows.
        private static readonly Queue<string> sayQueue = new Queue<string>();
        private static DispatcherTimer sayTimer;
        private static readonly Regex AnsiEscape = new Regex(@"\x1B\[[0-9;?]*[A-Za-z]", RegexOptions.Compiled);

        // The bubble draws a single flat flow: Look.Wrap splits only at
        // spaces, a '\n' INSIDE the text causes hidden row shifts in
        // FormattedText and lines get drawn ON TOP of each other (happened:
        // "Summary: SCORE: ?\n(no report…)" turned into a double-layered
        // soup in the bubble). ANSI color codes in tool output (wafw00f/dnsx)
        // also become garbage characters in the bubble — both are
        // burada temizlenir.
        private static string CleanLine(string line)
        {
            if (line == null) return "";
            string flat = AnsiEscape.Replace(line, " ");
            return string.Join(" ", flat.Split((char[])null, StringSplitOptions.RemoveEmptyEntries));
        }

        private static void Say(string line)
        {
            if (pet == null) return;
            line = CleanLine(line);
            if (line.Length == 0) return;
            Dispatcher.UIThread.Post(delegate
            {
                if (pet.Talk.Quiet) pet.Talk.Answer("(cyber mod)", line);
                else
                {
                    while (sayQueue.Count >= 10) sayQueue.Dequeue();  // drop the oldest against overflow
                    sayQueue.Enqueue(line);
                }
            });
        }

        private static void FlushSay()
        {
            if (pet == null || sayQueue.Count == 0) return;
            if (!pet.Talk.Quiet) return;   // the previous message is still typing/being read
            pet.Talk.Answer("(cyber mod)", sayQueue.Dequeue());
        }

        private static void Load()
        {
            try
            {
                if (!File.Exists(StateFile)) return;
                using (JsonDocument doc = JsonDocument.Parse(File.ReadAllText(StateFile)))
                {
                    JsonElement root = doc.RootElement;
                    // User rule: Capri starts with Black Wall OFF at EVERY
                    // launch — neither the burp mirror nor psycho is active
                    // until the user turns them on from the menu. Only the
                    // preferred psycho mode is remembered.
                    On = false;
                    psychoOn = false;
                    if (root.TryGetProperty("psycho_mode", out JsonElement pm)) psychoMode = pm.GetString() == "hard" ? "hard" : "simple";
                    offset = root.TryGetProperty("offset", out JsonElement f) ? f.GetInt64() : 0;
                    if (root.TryGetProperty("seen", out JsonElement s))
                        foreach (JsonElement id in s.EnumerateArray()) seen.Add(id.GetInt32());
                }
            }
            catch (Exception) { }
        }

        private static void Save()
        {
            try
            {
                Directory.CreateDirectory(Dir);
                File.WriteAllText(StateFile, "{\"on\":" + (On ? "true" : "false")
                    + ",\"psycho\":" + (psychoOn ? "true" : "false")
                    + ",\"psycho_mode\":\"" + psychoMode + "\""
                    + ",\"offset\":" + offset
                    + ",\"seen\":[" + string.Join(",", seen.Take(500)) + "]}");
            }
            catch (Exception) { }
        }
    }
}
