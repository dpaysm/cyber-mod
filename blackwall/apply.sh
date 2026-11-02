#!/usr/bin/env bash
# Blackwall Mod patch — applies to a fresh clone of Capri.
#
# Usage:
#   git clone https://github.com/lachydotmcg/capri-desktop.git
#   bash /path/to/blackwall/apply.sh /path/to/capri-desktop
#   dotnet build cross/Capri.Cross.csproj -c Release -o out/cross
#
# When Capri updates: git pull && bash /path/to/blackwall/apply.sh && rebuild.
set -e
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TARGET="${1:-.}"
cd "$TARGET" || { echo "ERROR: capri-desktop not found at $TARGET"; exit 1; }

[ -d cross ] || { echo "ERROR: $TARGET is not the capri-desktop root (cross/ not found)."; exit 1; }
[ -f cross/Pet.cs ] || { echo "ERROR: cross/Pet.cs missing under $TARGET — is that the right repo?"; exit 1; }
[ -f cross/Talk.cs ] || { echo "ERROR: cross/Talk.cs missing under $TARGET — is that the right repo?"; exit 1; }

rm -f cross/Siber.cs   # remove stale copy from the siber-mod era (class renamed)
cp "$HERE/Blackwall.cs" cross/Blackwall.cs
ok=1

# Pet.cs hooks (Black Wall menu + startup).
# "Already patched" is detected three ways: the blackWall marker, the old
# siberItem marker, or if the patch applies in REVERSE (= patch already there).
if grep -q "blackWall\|siberItem" cross/Pet.cs || git apply -R --check "$HERE/blackwall.patch" 2>/dev/null; then
    echo "[blackwall] Pet.cs hooks already present — skipped."
elif git apply --check "$HERE/blackwall.patch" 2>/dev/null; then
    git apply "$HERE/blackwall.patch"
    echo "[blackwall] Pet.cs hooks added (Black Wall menu)."
else
    echo "[blackwall] WARNING: Pet.cs changed upstream, automatic patch did not apply."
    echo "[blackwall] To add by hand: $HERE/HOOKS.md (hooks 1-4)"
    ok=0
fi

# Talk.cs hook (hunt trigger: "test this site")
if grep -q "Blackwall.MaybePsycho" cross/Talk.cs || git apply -R --check "$HERE/blackwall-talk.patch" 2>/dev/null; then
    echo "[blackwall] Talk.cs hook already present — skipped."
elif git apply --check "$HERE/blackwall-talk.patch" 2>/dev/null; then
    git apply "$HERE/blackwall-talk.patch"
    echo "[blackwall] Talk.cs hook added (hunt + psycho trigger)."
else
    echo "[blackwall] WARNING: Talk.cs changed upstream, automatic patch did not apply."
    echo "[blackwall] To add by hand: $HERE/HOOKS.md (hook 5)"
    ok=0
fi

[ "$ok" -eq 1 ] || exit 1
echo "[blackwall] Done. Build:"
echo "  dotnet build cross/Capri.Cross.csproj -c Release -o out/cross"
