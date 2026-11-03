#!/usr/bin/env bash
# Blackwall Mod patch — applies to a fresh clone of Capri.
#
# Usage:
#   git clone https://github.com/lachydotmcg/capri-desktop.git
#   bash /path/to/blackwall/apply.sh /path/to/capri-desktop
#   dotnet build cross/Capri.Cross.csproj -c Release -o out/cross
#
# When Capri updates: git pull && bash /path/to/blackwall/apply.sh && rebuild.
# The hooks are anchored on single stable lines (insert_hooks.py), so upstream
# churn no longer breaks the patch on every release; if Capri ever renames an
# anchor the script says so and points at HOOKS.md.
set -e
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TARGET="${1:-.}"
cd "$TARGET" || { echo "ERROR: capri-desktop not found at $TARGET"; exit 1; }

[ -d cross ] || { echo "ERROR: $TARGET is not the capri-desktop root (cross/ not found)."; exit 1; }
[ -f cross/Pet.cs ] || { echo "ERROR: cross/Pet.cs missing under $TARGET — is that the right repo?"; exit 1; }
[ -f cross/Talk.cs ] || { echo "ERROR: cross/Talk.cs missing under $TARGET — is that the right repo?"; exit 1; }

rm -f cross/Siber.cs   # remove stale copy from the siber-mod era (class renamed)
cp "$HERE/Blackwall.cs" cross/Blackwall.cs

python3 "$HERE/insert_hooks.py" "$TARGET"

echo "[blackwall] Done. Build:"
echo "  dotnet build cross/Capri.Cross.csproj -c Release -o out/cross"
