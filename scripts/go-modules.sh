#!/bin/sh
# Run one go command in every Go module of the platform: the root module and,
# when present, the private edition module (scripts/edition.sh).
#   sh scripts/go-modules.sh test -race ./...
set -eu
export GOTOOLCHAIN="${GOTOOLCHAIN:-local}"
ROOT=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
. "$ROOT/scripts/edition.sh"
EDITION_DIR=$(edition_dir)
for dir in "$ROOT" ${EDITION_DIR:+"$EDITION_DIR"}; do
  printf '==> go %s (%s)\n' "$*" "${dir#"$ROOT"}" >&2
  (cd "$dir" && go "$@")
done
