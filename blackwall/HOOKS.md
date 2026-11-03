# Blackwall Mod — hooks (manual application)

`apply.sh` inserts the hooks with `insert_hooks.py`, which anchors on single
stable lines instead of a git context-diff — upstream updates no longer rot
the patch every release. If Capri ever renames an anchor, the script says
which hook failed; add that hook by hand from here.

## 1. Field declaration (Pet.cs, next to the other MenuItem fields)

Below the line `private MenuItem caughtUpItem;`:

```csharp
private MenuItem blackWall;
```

## 2. Startup (Pet.cs ctor, below the `Brain.Bin = OperatingSystem.IsMacOS() ...` line — or below `Talk = new Talk(this);`)

```csharp
Blackwall.Init(this);
```

## 3. BlackWall menu (Pet.cs, inside Menu())

The definition block goes right BEFORE the line `menu.Items.Add(napItem);`
(any other root-menu `menu.Items.Add(...);` line works too):

```csharp
// BlackWall: hunter bridge (patch — comes via apply.sh, re-applied on updates)
blackWall = new MenuItem { Header = "BlackWall" };
MenuItem withBurp = new MenuItem { Header = "With Burp", ToggleType = MenuItemToggleType.CheckBox, IsChecked = Blackwall.On };
withBurp.Click += delegate { Blackwall.Toggle(this); };
MenuItem psychoAuto = new MenuItem { Header = "Psycho (auto hacking)" };
MenuItem psySimple = new MenuItem { Header = "Simple", ToggleType = MenuItemToggleType.Radio, GroupName = "bwpsy", IsChecked = Blackwall.PsychoOn && Blackwall.PsychoMode == "simple" };
psySimple.Click += delegate { Blackwall.SetPsycho(this, "simple"); };
MenuItem psyHard = new MenuItem { Header = "Hard", ToggleType = MenuItemToggleType.Radio, GroupName = "bwpsy", IsChecked = Blackwall.PsychoOn && Blackwall.PsychoMode == "hard" };
psyHard.Click += delegate { Blackwall.SetPsycho(this, "hard"); };
MenuItem psyOff = new MenuItem { Header = "Off", ToggleType = MenuItemToggleType.Radio, GroupName = "bwpsy", IsChecked = !Blackwall.PsychoOn };
psyOff.Click += delegate { Blackwall.SetPsycho(this, "off"); };
psychoAuto.Items.Add(psySimple);
psychoAuto.Items.Add(psyHard);
psychoAuto.Items.Add(psyOff);
blackWall.Items.Add(withBurp);
blackWall.Items.Add(psychoAuto);
```

… and the root-menu add goes right AFTER that same anchor line:

```csharp
menu.Items.Add(blackWall);
```

## 4. Quit = panic (Pet.cs, inside Quit(), below `quitting = true;`)

```csharp
Blackwall.ShutdownPanic();   // rule: quit = automatic CTRL+ALT+0 + off
```

## 5. Hunt trigger + flat bubble text (Talk.cs)

**5a.** Inside the `Typer.Submitted` delegate (in the Talk ctor), replace the
line `if (!Typer.Secret) { pet.Hear(text); return; }` with:

```csharp
// Blackwall Mod hook: in Psycho a site name becomes a hunt job, otherwise "test/scan" goes to recon (patch — comes via apply.sh)
if (!Typer.Secret) { if (Blackwall.MaybePsycho(text) || Blackwall.MaybeHunt(text)) { Typer.Hide(); return; } pet.Hear(text); return; }
```

**5b.** Right above the `internal void Answer(string heard, string answer, double seconds = 0)`
signature, add the Flat helper:

```csharp
// (blackwall) Bubble text is a flat flow: Look.Wrap splits only at
// spaces, a '\n' inside the text causes hidden row shifts in
// FormattedText and lines get drawn ON TOP of each other (happened).
// ANSI color codes also become garbage. Central cleanup: whatever the
// source, every answer passes through here.
private static readonly System.Text.RegularExpressions.Regex FlatAnsi =
    new System.Text.RegularExpressions.Regex(@"\x1B\[[0-9;?]*[A-Za-z]", System.Text.RegularExpressions.RegexOptions.Compiled);

internal static string Flat(string text)
{
    if (text == null) return "";
    string flat = FlatAnsi.Replace(text, " ");
    return string.Join(" ", flat.Split((char[])null, System.StringSplitOptions.RemoveEmptyEntries));
}
```

**5c.** Inside that same `Answer` method, right below its
`if (pet.Away) return;` line:

```csharp
answer = Flat(answer);
if (answer.Length == 0) return;
```

That's all. It's enough for `Blackwall.cs` to sit under `cross/`; no csproj change
is needed (SDK-style project, *.cs compiles automatically). Rebuild:

```bash
dotnet build cross/Capri.Cross.csproj -c Release -o out/cross
```
