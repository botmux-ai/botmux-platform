#!/bin/sh
# Assemble the installer the platform serves (BOTMUX_INSTALLER_FILE). A private
# edition (scripts/edition.sh) may ship an install profile: install/defaults.sh
# replaces install.sh's "# @install-profile defaults" line and
# install/functions.sh its "# @install-profile functions" line. Without one the
# output is install.sh as is.
#   sh scripts/build-installer.sh [output]    (default: dist/install.sh)
set -eu

ROOT=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
OUT=${1:-$ROOT/dist/install.sh}
. "$ROOT/scripts/edition.sh"
EDITION_DIR=$(edition_dir)
PROFILE=${EDITION_DIR:+$EDITION_DIR/install}

mkdir -p "$(dirname "$OUT")"
if [ -n "$PROFILE" ] && [ -d "$PROFILE" ]; then
  for part in defaults functions; do
    [ -f "$PROFILE/$part.sh" ] || { printf '%s/%s.sh is missing\n' "$PROFILE" "$part" >&2; exit 1; }
    [ "$(grep -cx "# @install-profile $part" "$ROOT/install.sh")" = 1 ] || {
      printf 'install.sh needs exactly one "# @install-profile %s" line\n' "$part" >&2
      exit 1
    }
  done
  awk -v defaults="$PROFILE/defaults.sh" -v functions="$PROFILE/functions.sh" '
    $0 == "# @install-profile defaults" { while ((getline line < defaults) > 0) print line; next }
    $0 == "# @install-profile functions" { while ((getline line < functions) > 0) print line; next }
    { print }
  ' "$ROOT/install.sh" > "$OUT.tmp"
else
  cp "$ROOT/install.sh" "$OUT.tmp"
fi
sh -n "$OUT.tmp"
chmod 755 "$OUT.tmp"
mv "$OUT.tmp" "$OUT"
