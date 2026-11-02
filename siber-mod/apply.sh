#!/usr/bin/env bash
# Siber Mod patch — applies to a fresh clone of Capri.
#
# Usage:
#   git clone https://github.com/lachydotmcg/capri-desktop.git
#   cd capri-desktop
#   bash /path/to/siber-mod/apply.sh
#   dotnet build cross/Capri.Cross.csproj -c Release -o out/cross
#
# When Capri updates: git pull && bash /path/to/siber-mod/apply.sh && rebuild.
set -e
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

[ -d cross ] || { echo "ERROR: run from the capri-desktop root (cross/ not found)."; exit 1; }
[ -f cross/Pet.cs ] || { echo "ERROR: cross/Pet.cs missing — are you in the right repo?"; exit 1; }
[ -f cross/Talk.cs ] || { echo "ERROR: cross/Talk.cs missing — are you in the right repo?"; exit 1; }

cp "$HERE/Siber.cs" cross/Siber.cs
ok=1

# Pet.cs hooks (Black Wall menu + startup).
# "Already patched" is detected three ways: the blackWall marker, the old
# siberItem marker, or if the patch applies in REVERSE (= patch already there).
if grep -q "blackWall\|siberItem" cross/Pet.cs || git apply -R --check "$HERE/siber-mod.patch" 2>/dev/null; then
    echo "[siber-mod] Pet.cs hooks already present — skipped."
elif git apply --check "$HERE/siber-mod.patch" 2>/dev/null; then
    git apply "$HERE/siber-mod.patch"
    echo "[siber-mod] Pet.cs hooks added (Black Wall menu)."
else
    echo "[siber-mod] WARNING: Pet.cs changed upstream, automatic patch did not apply."
    echo "[siber-mod] To add by hand: $HERE/HOOKS.md (hooks 1-4)"
    ok=0
fi

# Talk.cs hook (hunt trigger: "test this site")
if grep -q "Siber.MaybePsycho" cross/Talk.cs || git apply -R --check "$HERE/siber-mod-talk.patch" 2>/dev/null; then
    echo "[siber-mod] Talk.cs hook already present — skipped."
elif git apply --check "$HERE/siber-mod-talk.patch" 2>/dev/null; then
    git apply "$HERE/siber-mod-talk.patch"
    echo "[siber-mod] Talk.cs hook added (hunt + psycho trigger)."
else
    echo "[siber-mod] WARNING: Talk.cs changed upstream, automatic patch did not apply."
    echo "[siber-mod] To add by hand: $HERE/HOOKS.md (hook 5)"
    ok=0
fi

[ "$ok" -eq 1 ] || exit 1
echo "[siber-mod] Done. Build:"
echo "  dotnet build cross/Capri.Cross.csproj -c Release -o out/cross"
