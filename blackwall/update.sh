#!/usr/bin/env bash
# ============================================================================
# Cyber Mod — one-command auto updater
#
# What it does:
#   1. Pulls the latest cyber-mod repo (hunter + blackwall) from GitHub.
#   2. Reinstalls hunter into its venv (pip install -e; `avci` alias kept).
#   3. Reverts the Capri hooks, pulls upstream capri-desktop, re-applies the
#      blackwall patch, and rebuilds Capri.
#
# Usage:
#   bash update.sh                # update everything
#   bash update.sh --hunter-only    # update just the hunter side
#   bash update.sh --capri-only   # update just the Capri side
#
# Override the defaults with env vars if your paths differ:
#   CYBER_MOD_DIR   — where the cyber-mod repo lives   (default: auto — the repo this script is in)
#   CAPRI_DIR       — where capri-desktop lives        (default: <repo>/capri-desktop)
#   HUNTER_VENV     — the hunter python venv         (default: ~/.venvs/hunter)
# ============================================================================

set -euo pipefail

# Defaults follow the README layout: this script lives in <repo>/blackwall/,
# capri-desktop is cloned next to it inside the repo root.
SELF_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CYBER_MOD_DIR="${CYBER_MOD_DIR:-$(dirname "$SELF_DIR")}"
CAPRI_DIR="${CAPRI_DIR:-$CYBER_MOD_DIR/capri-desktop}"
HUNTER_VENV="${HUNTER_VENV:-$HOME/.venvs/hunter}"

DO_HUNTER=1; DO_CAPRI=1
case "${1:-}" in
    --hunter-only)  DO_CAPRI=0 ;;
    --capri-only) DO_HUNTER=0 ;;
    "")           ;;
    *) echo "usage: bash update.sh [--hunter-only|--capri-only]"; exit 1 ;;
esac

say() { printf '\033[36m[cyber-mod]\033[0m %s\n' "$*"; }
die() { printf '\033[31m[cyber-mod] ERROR:\033[0m %s\n' "$*" >&2; exit 1; }

# ------------------------------------------------------------ pull the repo
say "pulling latest cyber-mod → $CYBER_MOD_DIR"
if [ -d "$CYBER_MOD_DIR/.git" ]; then
    git -C "$CYBER_MOD_DIR" pull --ff-only || die "git pull failed — commit/stash your local edits first"
else
    die "$CYBER_MOD_DIR is not a git clone. Clone it first:
       git clone https://github.com/<you>/cyber-mod.git $CYBER_MOD_DIR"
fi

# ---------------------------------------------------------------- hunter side
if [ "$DO_HUNTER" = "1" ]; then
    say "reinstalling hunter (venv: $HUNTER_VENV)"
    [ -f "$HUNTER_VENV/bin/pip" ] || die "venv not found at $HUNTER_VENV — set HUNTER_VENV=..."
    "$HUNTER_VENV/bin/pip" install -q -e "$CYBER_MOD_DIR/hunter"
    say "hunter updated → $("$HUNTER_VENV/bin/hunter" --version 2>/dev/null || echo ok)"
fi

# --------------------------------------------------------------- capri side
if [ "$DO_CAPRI" = "1" ]; then
    [ -d "$CAPRI_DIR/.git" ] || die "capri-desktop clone not found at $CAPRI_DIR — set CAPRI_DIR=..."
    say "reverting hooks + pulling upstream capri-desktop"
    git -C "$CAPRI_DIR" checkout -- cross/Pet.cs cross/Talk.cs 2>/dev/null || true
    git -C "$CAPRI_DIR" pull --ff-only || die "capri-desktop pull failed"
    say "re-applying blackwall patch"
    bash "$CYBER_MOD_DIR/blackwall/apply.sh" "$CAPRI_DIR"
    say "rebuilding Capri (.NET 10)"
    if ! command -v dotnet >/dev/null 2>&1; then
        die "dotnet not on PATH — install the .NET 10 SDK first"
    fi
    dotnet build "$CAPRI_DIR/cross/Capri.Cross.csproj" -c Release -o "$CAPRI_DIR/out/cross" --nologo -v q
    say "Capri rebuilt → $CAPRI_DIR/out/cross/Capri"
fi

say "done. restart Capri if it was running — hunt loud, leave nothing."
