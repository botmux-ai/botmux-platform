#!/bin/sh
# Build and run the backend for local development (npm run dev): the private
# edition's entrypoint when there is one (scripts/edition.sh), otherwise the
# self-hosted cmd/botmux-platform. An edition may export the environment its
# entrypoint expects from hooks/dev-env.sh.
set -eu
export GOTOOLCHAIN="${GOTOOLCHAIN:-local}"
ROOT=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
. "$ROOT/scripts/edition.sh"
EDITION_DIR=$(edition_dir)
BIN="$ROOT/dist/bin/botmux-platform-dev"
mkdir -p "$ROOT/dist/bin"
(cd "${EDITION_DIR:-$ROOT}" && go build -o "$BIN" ./cmd/botmux-platform)
sh "$ROOT/scripts/build-installer.sh"
export BOTMUX_INSTALLER_FILE="${BOTMUX_INSTALLER_FILE:-$ROOT/dist/install.sh}"
if [ -n "$EDITION_DIR" ] && [ -f "$EDITION_DIR/hooks/dev-env.sh" ]; then
  . "$EDITION_DIR/hooks/dev-env.sh"
fi
cd "$ROOT"
exec "$BIN"
