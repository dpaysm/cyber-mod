"""External tool registry — presence check + install recipe.

For each tool: which binary to look for, which install commands to try in
which order. Install commands run in a VISIBLE terminal in the (capri)
area; if sudo needs a password the user types it there by hand — Capri
never sees, asks for, or stores the password.

Go-based tools install under GOBIN=~/.capri/bin; that directory is also
searched during PATH checks. This keeps Capri's own area (~/.capri)
isolated from the user's system.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

CAPRI_HOME = Path("~/.capri").expanduser()
CAPRI_BIN = CAPRI_HOME / "bin"
WORDLIST_DIR = Path("~/.avci/wordlists").expanduser()

# Wordlists: local candidate paths → if not found, downloaded from this URL
# into ~/.avci/wordlists. (User rule: for fuzzing/wordlists, if the file is
# missing it downloads AUTOMATICALLY, no questions asked.)
WORDLISTS: dict[str, dict] = {
    "common": {
        "paths": [
            "/usr/share/wordlists/dirb/common.txt",
            "/usr/share/seclists/Discovery/Web-Content/common.txt",
        ],
        "url": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt",
    },
    "big": {
        "paths": [
            "/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt",
            "/usr/share/wordlists/seclists/Discovery/Web-Content/raft-medium-directories.txt",
        ],
        "url": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/raft-medium-directories.txt",
    },
    "params": {
        "paths": [
            "/usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt",
        ],
        "url": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/burp-parameter-names.txt",
    },
}


@dataclass(frozen=True)
class Tool:
    name: str                      # binary name
    install: tuple[str, ...]       # install commands to try in order
    apt: str | None = None         # kali apt package name (shown in logs)
    go: str | None = None          # go install path (shown in logs)


GO_BIN = "GOBIN=$HOME/.capri/bin"

# ISOLATED venv for pip-based tools — when the shell Capri was launched
# from has a venv (e.g. (avci)) hijacking python3, "pip install --user"
# used to explode: "Can not perform a '--user' install. User site-packages
# are not visible in this virtualenv." Installs now always go to this clean
# venv and binaries are shimmed under ~/.capri/bin. python3-venv is pulled
# via apt if missing.
PYVENV = ("(python3 -m venv $HOME/.capri/tools/pyvenv 2>/dev/null || "
          "(sudo apt-get install -y python3-venv && python3 -m venv $HOME/.capri/tools/pyvenv))")
PYVENV_BIN = "$HOME/.capri/tools/pyvenv/bin"

TOOLS: dict[str, Tool] = {
    "nmap": Tool("nmap", (
        "sudo apt-get install -y nmap",
    ), apt="nmap"),
    "whatweb": Tool("whatweb", (
        "sudo apt-get install -y whatweb",
    ), apt="whatweb"),
    "jq": Tool("jq", (
        "sudo apt-get install -y jq",
    ), apt="jq"),
    "curl": Tool("curl", (
        "sudo apt-get install -y curl",
    ), apt="curl"),
    "nuclei": Tool("nuclei", (
        "sudo apt-get install -y nuclei",
        f"{GO_BIN} go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
    ), apt="nuclei", go="github.com/projectdiscovery/nuclei/v3/cmd/nuclei"),
    "subfinder": Tool("subfinder", (
        "sudo apt-get install -y subfinder",
        f"{GO_BIN} go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
    ), apt="subfinder", go="github.com/projectdiscovery/subfinder/v2/cmd/subfinder"),
    "httpx": Tool("httpx", (
        f"{GO_BIN} go install github.com/projectdiscovery/httpx/cmd/httpx@latest",
        "sudo apt-get install -y httpx",
    ), go="github.com/projectdiscovery/httpx/cmd/httpx"),
    "dnsx": Tool("dnsx", (
        f"{GO_BIN} go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest",
        "sudo apt-get install -y dnsx",
    ), go="github.com/projectdiscovery/dnsx/cmd/dnsx"),
    "naabu": Tool("naabu", (
        f"{GO_BIN} go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest",
        "sudo apt-get install -y naabu",
    ), go="github.com/projectdiscovery/naabu/v2/cmd/naabu"),
    "katana": Tool("katana", (
        f"{GO_BIN} go install github.com/projectdiscovery/katana/cmd/katana@latest",
    ), go="github.com/projectdiscovery/katana/cmd/katana"),
    "gau": Tool("gau", (
        f"{GO_BIN} go install github.com/lc/gau/v2/cmd/gau@latest",
        "sudo apt-get install -y gau",
    ), go="github.com/lc/gau/v2/cmd/gau"),
    "waybackurls": Tool("waybackurls", (
        f"{GO_BIN} go install github.com/tomnomnom/waybackurls@latest",
    ), go="github.com/tomnomnom/waybackurls"),
    "dalfox": Tool("dalfox", (
        "sudo apt-get install -y dalfox",
        f"{GO_BIN} go install github.com/hahwul/dalfox/v2@latest",
    ), apt="dalfox", go="github.com/hahwul/dalfox/v2"),
    "nikto": Tool("nikto", (
        "sudo apt-get install -y nikto",
        # apt olmazsa: repo klonu + shim (perl scripti, derleme yok)
        "(git -C $HOME/.capri/tools/nikto pull -q 2>/dev/null || git clone --depth 1 https://github.com/sullo/nikto $HOME/.capri/tools/nikto)"
        " && printf '#!/bin/bash\\nexec perl \"$HOME/.capri/tools/nikto/program/nikto.pl\" \"$@\"\\n' > $HOME/.capri/bin/nikto"
        " && chmod +x $HOME/.capri/bin/nikto",
    ), apt="nikto"),
    "testssl.sh": Tool("testssl.sh", (
        "sudo apt-get install -y testssl.sh",
        # apt olmazsa: repo klonu + shim (derleme gerektirmez, bash scripti)
        "(git -C $HOME/.capri/tools/testssl.sh pull -q 2>/dev/null || git clone --depth 1 https://github.com/testssl/testssl.sh $HOME/.capri/tools/testssl.sh)"
        " && printf '#!/bin/bash\\nexec \"$HOME/.capri/tools/testssl.sh/testssl.sh\" \"$@\"\\n' > $HOME/.capri/bin/testssl.sh"
        " && chmod +x $HOME/.capri/bin/testssl.sh",
    ), apt="testssl.sh"),
    "sqlmap": Tool("sqlmap", (
        "sudo apt-get install -y sqlmap",
        # apt olmazsa: repo klonu + shim (saf python, kurulum gerektirmez)
        "(git -C $HOME/.capri/tools/sqlmap pull -q 2>/dev/null || git clone --depth 1 https://github.com/sqlmapproject/sqlmap $HOME/.capri/tools/sqlmap)"
        " && printf '#!/bin/bash\\nexec python3 \"$HOME/.capri/tools/sqlmap/sqlmap.py\" \"$@\"\\n' > $HOME/.capri/bin/sqlmap"
        " && chmod +x $HOME/.capri/bin/sqlmap",
    ), apt="sqlmap"),
    "jshunter": Tool("jshunter", (
        f"{GO_BIN} go install github.com/cc1a2b/jshunter/cmd/jshunter@latest",
    ), go="github.com/cc1a2b/jshunter/cmd/jshunter"),
    "arjun": Tool("arjun", (
        "sudo apt-get install -y arjun",
        # pip --user EXPLODES INSIDE A VENV ("--user not visible in
        # virtualenv") — use the isolated tool venv + shim, no PATH/venv
        # contamination
        PYVENV + " && " + PYVENV_BIN + "/pip install -q arjun"
        " && printf '#!/bin/bash\\nexec \"$HOME/.capri/tools/pyvenv/bin/arjun\" \"$@\"\\n' > $HOME/.capri/bin/arjun"
        " && chmod +x $HOME/.capri/bin/arjun",
    ), apt="arjun"),
    "wafw00f": Tool("wafw00f", (
        "sudo apt-get install -y wafw00f",
        PYVENV + " && " + PYVENV_BIN + "/pip install -q wafw00f"
        " && printf '#!/bin/bash\\nexec \"$HOME/.capri/tools/pyvenv/bin/wafw00f\" \"$@\"\\n' > $HOME/.capri/bin/wafw00f"
        " && chmod +x $HOME/.capri/bin/wafw00f",
    ), apt="wafw00f"),
    "gf": Tool("gf", (
        f"{GO_BIN} go install github.com/tomnomnom/gf@latest",
    ), go="github.com/tomnomnom/gf"),
    "corsy": Tool("corsy", (
        # Corsy has no setup.py (pip git+... explodes) — clone + drop a shim.
        # requests installs into the ISOLATED venv: pip --user was exploding
        # inside a venv (when Capri starts from a shell with the (avci) venv
        # active, python3 becomes that venv's python and --user installs get
        # rejected — happened in practice).
        "mkdir -p $HOME/.capri/tools $HOME/.capri/bin"
        " && (git -C $HOME/.capri/tools/Corsy pull -q 2>/dev/null || git clone --depth 1 https://github.com/s0md3v/Corsy $HOME/.capri/tools/Corsy)"
        " && " + PYVENV + " && " + PYVENV_BIN + "/pip install -q -r $HOME/.capri/tools/Corsy/requirements.txt"
        " && printf '#!/bin/bash\\nexec \"$HOME/.capri/tools/pyvenv/bin/python3\" \"$HOME/.capri/tools/Corsy/corsy.py\" \"$@\"\\n' > $HOME/.capri/bin/corsy"
        " && chmod +x $HOME/.capri/bin/corsy",
    ), apt=None),
    "whois": Tool("whois", (
        "sudo apt-get install -y whois",
    ), apt="whois"),
    "subzy": Tool("subzy", (
        f"{GO_BIN} go install github.com/PentestPad/subzy@latest",
    ), go="github.com/PentestPad/subzy"),
}


def ensure_gf_patterns() -> bool:
    """gf patterns (~/.gf) — if missing, pull from the Gf-Patterns repo
    AUTOMATICALLY (no questions asked)."""
    gf_dir = Path("~/.gf").expanduser()
    if gf_dir.is_dir() and any(gf_dir.glob("*.json")):
        return True
    try:
        gf_dir.mkdir(parents=True, exist_ok=True)
        r = subprocess.run(
            "git clone --depth 1 https://github.com/1ndianl33t/Gf-Patterns /tmp/gf-patterns "
            f"&& cp /tmp/gf-patterns/*.json {gf_dir}/ && rm -rf /tmp/gf-patterns",
            shell=True, timeout=120,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        return r.returncode == 0 and any(gf_dir.glob("*.json"))
    except (subprocess.TimeoutExpired, OSError):
        return False


def search_path() -> str:
    """Capri area + pip --user directory (~/.local/bin) + normal PATH.

    ~/.local/bin IS A MUST: binaries of tools installed with
    pip install --user (corsy, arjun, wafw00f) land there and are usually
    NOT on the daemon PATH — otherwise you get 'installed but not found'.
    """
    local_bin = str(Path("~/.local/bin").expanduser())
    return str(CAPRI_BIN) + os.pathsep + local_bin + os.pathsep + os.environ.get("PATH", "")


def which(name: str) -> str | None:
    """Is the binary there? First ~/.capri/bin, then the system PATH."""
    return shutil.which(name, path=search_path())


# Some names may exist on the system as COMPLETELY DIFFERENT tools — being
# "present" is not enough, identity is verified. (httpx: the Python HTTP
# client vs the projectdiscovery scanner — if it's the wrong one the recon
# chain silently breaks!)
IDENTITY: dict[str, tuple[str, str]] = {
    # tool: (signature looked for in -h output) — pd httpx has the
    # '-l, -list' flag, python httpx does not.
    "httpx": "-list",
    # a corsy shim may exist but be broken inside (prints a traceback if
    # requests is missing). argparse help starts with "usage:"; a traceback
    # never contains that word.
    "corsy": "usage:",
}


def identity_ok(name: str, path: str) -> bool:
    """Is the found binary really the tool we want?"""
    sig = IDENTITY.get(name)
    if not sig:
        return True
    try:
        r = subprocess.run([path, "-h"], capture_output=True, text=True, timeout=10)
        return sig in (r.stdout + r.stderr)
    except (OSError, subprocess.TimeoutExpired):
        return False


def missing(names: list[str]) -> list[str]:
    return [n for n in names if which(n) is None]


def ensure_dirs() -> None:
    CAPRI_BIN.mkdir(parents=True, exist_ok=True)
    WORDLIST_DIR.mkdir(parents=True, exist_ok=True)


def ensure_wordlist(key: str) -> Path | None:
    """Find the wordlist; if missing, download AUTOMATICALLY (no questions
    asked). None if it can't be downloaded."""
    spec = WORDLISTS[key]
    for cand in spec["paths"]:
        p = Path(cand)
        if p.is_file() and p.stat().st_size > 0:
            return p
    ensure_dirs()
    dest = WORDLIST_DIR / Path(spec["url"]).name
    if dest.is_file() and dest.stat().st_size > 0:
        return dest
    try:
        import httpx
        with httpx.stream("GET", spec["url"], timeout=120, follow_redirects=True) as r:
            r.raise_for_status()
            with dest.open("wb") as fh:
                for chunk in r.iter_bytes():
                    fh.write(chunk)
        return dest if dest.stat().st_size > 0 else None
    except Exception:
        return None


SUDO_PWFILE = CAPRI_HOME / ".sudo"


def ensure_sudo_helper() -> Path:
    """capri-sudo: feeds the saved password to sudo -S if there is one,
    otherwise hands off to plain sudo.

    The password lives on the USER'S own machine, readable only by their
    user (chmod 600) at ~/.capri/.sudo — Capri/logs/AI never see it. The
    user explicitly asked for this; it's asked once on the first install
    terminal.
    """
    CAPRI_BIN.mkdir(parents=True, exist_ok=True)
    helper = CAPRI_BIN / "capri-sudo"
    helper.write_text(
        "#!/bin/bash\n"
        "# (capri) sudo helper — use the saved password if any, else hand off.\n"
        "# If the saved password is WRONG and a terminal exists: warn, ask interactively (self-heals).\n"
        f'PWFILE="{SUDO_PWFILE}"\n'
        'if [ -s "$PWFILE" ]; then\n'
        '  if cat "$PWFILE" | sudo -S -p "" "$@"; then exit 0; fi\n'
        '  if [ -t 0 ]; then\n'
        '    echo "[capri] saved sudo password FAILED — type it manually this time:"\n'
        '    exec sudo "$@"\n'
        "  fi\n"
        "  exit 1\n"
        "elif [ -t 0 ]; then\n"
        '  exec sudo "$@"\n'
        "else\n"
        '  exec sudo -n "$@"\n'
        "fi\n",
        encoding="utf-8",
    )
    helper.chmod(0o700)
    return helper


def sudo_password_saved() -> bool:
    try:
        return SUDO_PWFILE.is_file() and SUDO_PWFILE.stat().st_size > 0
    except OSError:
        return False


def read_sudo_password() -> str | None:
    """First line of the file (a trailing \n added by editors is ignored)."""
    try:
        pw = SUDO_PWFILE.read_text(encoding="utf-8").splitlines()[0].strip()
        return pw or None
    except (OSError, IndexError):
        return None


def sudo_password_valid() -> bool:
    """Does the saved password still pass sudo?"""
    pw = read_sudo_password()
    return bool(pw) and validate_sudo(pw)


def validate_sudo(password: str, timeout: int = 15) -> bool:
    """Does the password really pass sudo? (-k: ignore the cache)"""
    try:
        r = subprocess.run(
            ["sudo", "-k", "-S", "-p", "", "-v"],
            input=password + "\n", capture_output=True, text=True, timeout=timeout,
        )
        return r.returncode == 0
    except (subprocess.TimeoutExpired, OSError):
        return False


def save_sudo_password(password: str) -> None:
    """~/.capri/.sudo — sadece sahibi okur/yazar (chmod 600)."""
    CAPRI_HOME.mkdir(parents=True, exist_ok=True)
    SUDO_PWFILE.write_text(password, encoding="utf-8")
    SUDO_PWFILE.chmod(0o600)


# Password is asked ONCE on the first install terminal — left empty,
# sudo keeps asking itself every time (as before).
_PW_CAPTURE = (
    'if [ ! -s "$HOME/.capri/.sudo" ]; then '
    'echo "[capri] installs need sudo. Type your password ONCE — stored only on THIS machine '
    'at ~/.capri/.sudo (chmod 600), never sent anywhere. Leave empty to let sudo ask every time."; '
    'read -s -p "[capri] sudo password: " pw; echo; '
    'if [ -n "$pw" ] && echo "$pw" | sudo -S -p "" -v 2>/dev/null; then '
    '(umask 177; printf \'%s\' "$pw" > "$HOME/.capri/.sudo"); echo "[capri] saved — sudo will never ask again."; '
    'else echo "[capri] not saved (empty or wrong) — sudo will ask when needed."; fi; fi; '
)


# Neon banner printed at the top of every (capri) terminal — the vibe is
# mandatory. Written with real ESC bytes; the rcfile side prints it.
_BANNER = (
    "\033[35m   ▄████▄▓██   ██▓ ▄▄▄▄   ▓█████  ██▀███   ███▄ ▄███▓ ▒█████  ▓█████▄\n"
    "\033[35m  ▒██▀ ▀█ ▒██  ██▒▓█████▄ ▓█   ▀ ▓██ ▒ ██▒▓██▒▀█▀ ██▒▒██▒  ██▒▒██▀ ██▌\n"
    "\033[35m  ▒▓█    ▄ ▒██ ██░▒██▒ ▄██▒███   ▓██ ░▄█ ▒▓██    ▓██░▒██░  ██▒░██   █▌\n"
    "\033[35m  ▒▓▓▄ ▄██░ ▐██▓░▒██░█▀  ▒▓█  ▄ ▒██▀▀█▄  ▒██    ▒██ ▒██   ██░░▓█▄   ▌\n"
    "\033[35m  ▒ ▓███▀ ░ ░██▒░░▓█  ▀█▓░▒████▒░██▓ ▒██▒▒██▒   ░██▒░ ████▓▒░░▒████▓\n"
    "\033[31m  ░ ░▒ ▒  ░ ░▓  ░░▒▓███▀▒░░ ▒░ ░░ ▒▓ ░▒▓░░ ▒░   ░  ░░ ▒░▒░▒░  ░▒▓▒ ▒ ▒\n"
    "\033[36m      ══════════════  psycho deck :: capri ✦ avcı  ══════════════\n"
    "\033[36m        hunt loud · leave nothing · panic = CTRL+ALT+0\033[0m\n"
)


def rcfile_path() -> Path:
    """bash rcfile with the (capri) prompt — visible terminals open with it."""
    CAPRI_HOME.mkdir(parents=True, exist_ok=True)
    ensure_sudo_helper()
    rc = CAPRI_HOME / "bashrc"
    rc.write_text(
        "# (capri) area — Psycho Mode terminals open with this\n"
        "[ -f ~/.bashrc ] && source ~/.bashrc\n"
        f"export PATH={CAPRI_BIN}:$HOME/.local/bin:$PATH\n"
        f"export GOBIN={CAPRI_BIN}\n"
        "export PS1='\\[\\e[35m\\]┌──(capri㉿avcı)-[\\w]\\n└─$\\[\\e[0m\\] '\n"
        f"cd {CAPRI_HOME} 2>/dev/null\n"
        # banner once per terminal, above the prompt
        f"printf '%s\\n' {_shell_quote(_BANNER)}\n",
        encoding="utf-8",
    )
    return rc


# Visible terminal candidates — same order as OpenWatch on the Capri side.
WINDOW_TITLE = "Cyber Mod Capri Terminal"
_TERMINALS = [
    ("xfce4-terminal", ["--title", WINDOW_TITLE, "-e"]),
    ("xterm", ["-T", WINDOW_TITLE, "-e"]),
    ("x-terminal-emulator", ["-e"]),
    ("qterminal", ["-e"]),
    ("konsole", ["-e"]),
    ("gnome-terminal", ["--"]),
    ("kitty", []),
]


# Window position grid — rotated so each new terminal lands in a different
# region of the screen's middle band (no stacking on top of each other).
# Middle area assuming 1920x1080; slight jitter for a tiled effect.
import itertools
import random

# 130x32 windows take ~1040x512 pixels — a layout that fits 1920x1080.
_POS_GRID = [
    (40, 40), (840, 40),
    (40, 520), (840, 520),
    (440, 280), (440, 700),
]
_pos_cycle = itertools.count()


def _next_geometry() -> str:
    """Next window geometry (130x32+X+Y) — grid + jitter. Big and tall:
    user rule, no small terminals."""
    x, y = _POS_GRID[next(_pos_cycle) % len(_POS_GRID)]
    return f"130x32+{x + random.randint(-30, 30)}+{y + random.randint(-20, 20)}"


def _geo_args(term: str) -> list[str]:
    """Geometry arguments for terminals that support positioning."""
    if term == "xfce4-terminal":
        return [f"--geometry={_next_geometry()}"]
    if term == "xterm":
        return ["-geometry", _next_geometry()]
    if term == "gnome-terminal":
        return [f"--geometry={_next_geometry()}"]
    return []


def open_install_terminal(command: str) -> bool:
    """Runs the install command in a VISIBLE terminal in the (capri) area.

    sudo calls in the command are rewritten to capri-sudo: if the password
    was saved before it is NEVER asked; the first time it's asked from the
    user ONCE (~/.capri/.sudo, chmod 600). If left empty sudo asks itself
    as before.
    """
    rc = rcfile_path()
    inner = command
    if "sudo " in command:
        inner = _PW_CAPTURE + command.replace("sudo ", "capri-sudo ")
    bash = f"bash --rcfile {rc} -i -c {_shell_quote(inner + '; echo; echo \"[capri] install done — you can close this window\"; read -r _')}"
    for term, args in _TERMINALS:
        exe = shutil.which(term)
        if not exe:
            continue
        try:
            subprocess.Popen(
                [exe, *_geo_args(term), *args, bash],
                start_new_session=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            return True
        except OSError:
            continue
    return False


def install_background(command: str, timeout: int = 600) -> tuple[bool, str]:
    """Last resort if a visible terminal can't be opened: capri-sudo in the
    background (with the saved password if any, else sudo -n / NOPASSWD)."""
    ensure_sudo_helper()
    cmd = command.replace("sudo ", "capri-sudo ")
    try:
        r = subprocess.run(
            cmd, shell=True, timeout=timeout,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
            env={**os.environ, "GOBIN": str(CAPRI_BIN), "PATH": search_path()},
        )
        return r.returncode == 0, (r.stdout or "")[-2000:]
    except (subprocess.TimeoutExpired, OSError) as exc:
        return False, str(exc)


def _shell_quote(s: str) -> str:
    return "'" + s.replace("'", "'\\''") + "'"


def open_text_file(path: Path) -> bool:
    """Open the file in the default text editor — long AI answers land in
    the 'notepad' through here."""
    try:
        subprocess.Popen(["xdg-open", str(path)], start_new_session=True,
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return True
    except OSError:
        return False


def _term_argv(exe: str, term: str, title: str, inner: str) -> list[str]:
    """Argument vector per terminal — the command runs in bash with the
    (capri) rcfile."""
    rc = str(rcfile_path())
    if term == "xfce4-terminal":
        return [exe, "--title", f"{WINDOW_TITLE} — {title}", *_geo_args(term), "-e",
                f"bash --rcfile {_shell_quote(rc)} -i -c {_shell_quote(inner)}"]
    if term == "xterm":
        return [exe, "-T", f"{WINDOW_TITLE} — {title}", *_geo_args(term), "-e", "bash", "--rcfile", rc, "-i", "-c", inner]
    if term == "gnome-terminal":
        return [exe, *_geo_args(term), "--", "bash", "--rcfile", rc, "-i", "-c", inner]
    if term == "kitty":
        return [exe, "bash", "--rcfile", rc, "-i", "-c", inner]
    return [exe, "-e", "bash", "--rcfile", rc, "-i", "-c", inner]


def open_run_terminal(title: str, inner: str) -> bool:
    """Runs the command in a VISIBLE terminal in the (capri) area.

    The window closes when the command ends (inner sets that up). Some
    terminals (xfce4) fork immediately, so waiting on the process is NOT
    the caller's job — the runner watches the .done marker file. True if
    the terminal could be opened.
    """
    for term, _args in _TERMINALS:
        exe = shutil.which(term)
        if not exe:
            continue
        try:
            subprocess.Popen(
                _term_argv(exe, term, title, inner),
                start_new_session=True,
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            )
            return True
        except OSError:
            continue
    return False
