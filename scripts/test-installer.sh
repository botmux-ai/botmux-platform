#!/bin/sh
# Installer tests: the suite against install.sh, then the private edition's
# install/install.test.mjs against its assembled installer when it has one
# (scripts/build-installer.sh).
set -eu

ROOT=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
sh -n "$ROOT/install.sh"
node "$ROOT/scripts/install.test.mjs"
. "$ROOT/scripts/edition.sh"
EDITION_DIR=$(edition_dir)
if [ -n "$EDITION_DIR" ] && [ -f "$EDITION_DIR/install/install.test.mjs" ]; then
  node "$EDITION_DIR/install/install.test.mjs"
fi
