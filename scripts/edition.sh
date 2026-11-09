# Sourced by the build scripts. A private edition is a directory ext/<name>/
# with its own Go module and cmd/botmux-platform entrypoint. Optionally it has
#   frontend/           modules behind the @edition alias (vite.config.ts)
#   hooks/dev-env.sh    environment for scripts/dev.sh
#   hooks/smoke.mjs     server environment and checks for scripts/smoke.mjs
#   install/            installer profile and its tests (scripts/build-installer.sh)
# The first one found is used; BOTMUX_EDITION=oss ignores it and
# BOTMUX_EDITION=<name> picks ext/<name>. Prints nothing for the open-source
# edition.
edition_dir() {
  case "${BOTMUX_EDITION:-}" in
    oss) return 0 ;;
    '')
      for dir in "$ROOT"/ext/*/; do
        [ -f "${dir}go.mod" ] || continue
        printf '%s\n' "${dir%/}"
        return 0
      done
      ;;
    *)
      [ -f "$ROOT/ext/$BOTMUX_EDITION/go.mod" ] || {
        printf 'BOTMUX_EDITION=%s needs ext/%s/go.mod\n' "$BOTMUX_EDITION" "$BOTMUX_EDITION" >&2
        return 64
      }
      printf '%s\n' "$ROOT/ext/$BOTMUX_EDITION"
      ;;
  esac
}
