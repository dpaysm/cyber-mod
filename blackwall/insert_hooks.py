#!/usr/bin/env python3
"""Blackwall Mod hook inserter.

Capri's upstream moves fast and git context-diffs rot on every release, so
hooks are anchored on single, stable lines instead of 3-line diff context.
Each hook tries its anchors in order; if none match, the script fails loudly
and points at HOOKS.md instead of half-patching the tree.

Usage: python3 insert_hooks.py /path/to/capri-desktop
Idempotent: a tree that already carries the hooks is left untouched.
"""
import re
import sys
from pathlib import Path

# ---------------------------------------------------------------- Pet.cs ---

MENU_BLOCK = """            // BlackWall: hunter bridge (patch — comes via apply.sh, re-applied on updates)
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
"""

# ---------------------------------------------------------------- Talk.cs ---

FLAT_BLOCK = """        // (blackwall) Bubble text is a flat flow: Look.Wrap splits only at
        // spaces, a '\\n' inside the text causes hidden row shifts in
        // FormattedText and lines get drawn ON TOP of each other (happened).
        // ANSI color codes also become garbage. Central cleanup: whatever the
        // source, every answer passes through here.
        private static readonly System.Text.RegularExpressions.Regex FlatAnsi =
            new System.Text.RegularExpressions.Regex(@"\\x1B\\[[0-9;?]*[A-Za-z]", System.Text.RegularExpressions.RegexOptions.Compiled);

        internal static string Flat(string text)
        {
            if (text == null) return "";
            string flat = FlatAnsi.Replace(text, " ");
            return string.Join(" ", flat.Split((char[])null, System.StringSplitOptions.RemoveEmptyEntries));
        }

"""

TYPER_OLD = 'if (!Typer.Secret) { pet.Hear(text); return; }'
TYPER_NEW = ('if (!Typer.Secret) { if (Blackwall.MaybePsycho(text) || Blackwall.MaybeHunt(text)) '
             '{ Typer.Hide(); return; } pet.Hear(text); return; }')

# ------------------------------------------------------------ machinery ---

class HookError(Exception):
    pass


def insert_after(lines, anchor_idx, text):
    lines[anchor_idx + 1:anchor_idx + 1] = [text]


def find_line(lines, needle, start=0):
    for i in range(start, len(lines)):
        if needle in lines[i]:
            return i
    return -1


def find_first(lines, needles, what):
    for needle in needles:
        i = find_line(lines, needle)
        if i >= 0:
            return i
    raise HookError("anchor not found for " + what + " — tried: " + " | ".join(n.strip() for n in needles))


def patch_pet(path):
    text = path.read_text()
    if "blackWall" in text or "siberItem" in text:
        print("[blackwall] Pet.cs hooks already present — skipped.")
        return
    lines = text.split("\n")

    # hook 1: field declaration next to the other menu items
    i = find_first(lines, ["private MenuItem caughtUpItem;", "private MenuItem napItem;"], "Pet.cs field (hook 1)")
    indent = re.match(r"\s*", lines[i]).group(0)
    insert_after(lines, i, indent + "private MenuItem blackWall;")

    # hook 2: Blackwall.Init(this) in the constructor
    i = find_first(lines, ["Brain.Bin = OperatingSystem.IsMacOS()", "Talk = new Talk(this);"], "Pet.cs init (hook 2)")
    indent = re.match(r"\s*", lines[i]).group(0)
    insert_after(lines, i, indent + "Blackwall.Init(this);")

    # hook 3: BlackWall menu — definition block goes right before the root
    # menu add, the add itself right after it (one anchor covers both)
    i = find_first(lines, ["menu.Items.Add(napItem);", "menu.Items.Add(hangItem);", "menu.Items.Add(sitItem);"],
                   "Pet.cs menu (hook 3)")
    indent = re.match(r"\s*", lines[i]).group(0)
    block = [indent + ln.strip() if ln.strip() else ln for ln in MENU_BLOCK.rstrip("\n").split("\n")]
    lines[i:i] = block
    # re-locate the anchor line (it moved down by len(block))
    anchor = None
    for needle in ["menu.Items.Add(napItem);", "menu.Items.Add(hangItem);", "menu.Items.Add(sitItem);"]:
        anchor = find_line(lines, needle)
        if anchor >= 0:
            break
    insert_after(lines, anchor, indent + "menu.Items.Add(blackWall);")

    # hook 4: quit = automatic panic (CTRL+ALT+0) + off
    i = find_first(lines, ["quitting = true;"], "Pet.cs quit (hook 4)")
    indent = re.match(r"\s*", lines[i]).group(0)
    insert_after(lines, i, indent + "Blackwall.ShutdownPanic();   // rule: quit = automatic CTRL+ALT+0 + off")

    path.write_text("\n".join(lines))
    print("[blackwall] Pet.cs hooks added (BlackWall menu, init, quit-panic).")


def patch_talk(path):
    text = path.read_text()
    if "Blackwall.MaybePsycho" in text:
        print("[blackwall] Talk.cs hook already present — skipped.")
        return
    if TYPER_OLD not in text:
        raise HookError("anchor not found for Talk.cs typer hook (hook 5): " + TYPER_OLD)
    text = text.replace(
        TYPER_OLD,
        "// Blackwall Mod hook: in Psycho a site name becomes a hunt job, otherwise \"test/scan\" goes to recon "
        "(patch — comes via apply.sh)\n                " + TYPER_NEW,
        1)

    lines = text.split("\n")
    sig = find_first(lines, ["internal void Answer(string heard, string answer, double seconds = 0)"],
                     "Talk.cs Answer signature (hook 5)")
    # the flattening goes after the "if (pet.Away) return;" INSIDE Answer —
    # the same line also sits in Thinking(), so search below the signature
    away = find_line(lines, "if (pet.Away) return;", start=sig)
    if away < 0:
        raise HookError("anchor not found for Talk.cs Answer body (hook 5): if (pet.Away) return;")
    indent = re.match(r"\s*", lines[away]).group(0)
    insert_after(lines, away, indent + "answer = Flat(answer);")
    insert_after(lines, away + 1, indent + "if (answer.Length == 0) return;")
    # the Flat helper sits right above Answer's signature line
    block = [ln for ln in FLAT_BLOCK.rstrip("\n").split("\n")]
    lines[sig:sig] = block
    path.write_text("\n".join(lines))
    print("[blackwall] Talk.cs hooks added (hunt + psycho trigger, flat bubble text).")


def main():
    root = Path(sys.argv[1] if len(sys.argv) > 1 else ".").resolve()
    pet, talk = root / "cross" / "Pet.cs", root / "cross" / "Talk.cs"
    for f in (pet, talk):
        if not f.is_file():
            raise HookError(str(f) + " missing — is " + str(root) + " the capri-desktop root?")
    patch_pet(pet)
    patch_talk(talk)


if __name__ == "__main__":
    try:
        main()
    except HookError as exc:
        print("[blackwall] WARNING: " + str(exc))
        print("[blackwall] Capri changed upstream — add the hooks by hand: blackwall/HOOKS.md")
        sys.exit(1)
