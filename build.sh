#!/bin/sh
# Go/Hertz backend build entrypoint used by local development and CI.
set -eu

ROOT=$(CDPATH= cd -- "$(dirname "$0")" && pwd)
exec sh "$ROOT/scripts/build-platform.sh"
