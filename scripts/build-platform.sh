#!/bin/sh
# Build and test the backend for the independent Go/Hertz artifact.
set -eu

# Never let CI silently download a newer Go toolchain: the service contract is
# Go 1.22+, and dependency drift must fail visibly during review.
export GOTOOLCHAIN="${GOTOOLCHAIN:-local}"
# A CI compile image can have a newer glibc than the runtime image. None
# of the backend dependencies require native code, so produce a static ELF and
# avoid a binary that starts locally but dies on GLIBC_2.32/2.34 at rollout.
export CGO_ENABLED=0

ROOT=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
OUT="$ROOT/dist/bin"

command -v go >/dev/null 2>&1 || {
  printf 'Go 1.22+ is required to build botmux-platform\n' >&2
  exit 1
}

go_version=$(go env GOVERSION)
go_numeric=${go_version#go}
go_major=${go_numeric%%.*}
go_rest=${go_numeric#*.}
go_minor=${go_rest%%.*}
case "$go_major:$go_minor" in
  *[!0-9:]*|:) printf 'unable to parse Go version: %s\n' "$go_version" >&2; exit 1 ;;
esac
if [ "$go_major" -lt 1 ] || { [ "$go_major" -eq 1 ] && [ "$go_minor" -lt 22 ]; }; then
  printf 'Go 1.22+ is required, found %s\n' "$go_version" >&2
  exit 1
fi

# A private edition (scripts/edition.sh) builds its own entrypoint; otherwise
# the self-hosted cmd/botmux-platform is built.
. "$ROOT/scripts/edition.sh"
BUILD_DIR=$(edition_dir)
BUILD_DIR=${BUILD_DIR:-$ROOT}

sh "$ROOT/scripts/go-modules.sh" test ./...
mkdir -p "$OUT"
(cd "$BUILD_DIR" && go build -trimpath -o "$OUT/botmux-platform" ./cmd/botmux-platform)
chmod 755 "$OUT/botmux-platform"
go version -m "$OUT/botmux-platform" | grep -q 'CGO_ENABLED=0' || {
  printf 'backend binary was not built with CGO_ENABLED=0\n' >&2
  exit 1
}
sh "$ROOT/scripts/build-installer.sh"
