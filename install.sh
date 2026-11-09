#!/bin/sh
# botmux one-click installer for macOS, Linux, and WSL.
#
# Installs into the current user's ~/.local tree, reuses existing tools, and
# leaves the two interactive QR scans to `botmux setup` (app creation + Open
# Platform automation). Optional AI CLIs are best-effort: botmux itself and its
# runtime are the only hard requirements.

set -eu

# An edition's install profile is spliced in at the two @install-profile lines
# (scripts/build-installer.sh): its defaults here, before the environment is
# read, and its functions after the last function definition, so it can
# override any of them.
# @install-profile defaults

INSTALL_ROOT="${BOTMUX_INSTALL_ROOT:-$HOME/.local}"
BIN_DIR="$INSTALL_ROOT/bin"
NODE_ROOT="$INSTALL_ROOT/share/botmux"
NODE_REQUIRED_MAJOR=22
NODE_VERSION_EXPLICIT=0
[ "${BOTMUX_NODE_VERSION+x}" = x ] && NODE_VERSION_EXPLICIT=1
NODE_VERSION_SPEC="${BOTMUX_NODE_VERSION:-22}"
NODE_MANAGER_REQUEST="${BOTMUX_NODE_MANAGER:-auto}"
NODE_DIST_BASE="${BOTMUX_NODE_DIST_BASE:-https://nodejs.org/dist/latest-v22.x}"
BOTMUX_PACKAGE="${BOTMUX_PACKAGE:-botmux@latest}"
# botmux 3.18+ 以 bun 单文件二进制分发（自带运行时，装它本身不需要 Node）。默认调用 botmux
# 官方安装器装这个二进制（校验和/musl 探测/运行探针/原子替换都由它负责），失败再回退 npm。
# BOTMUX_INSTALL_METHOD=npm 可强制走 npm。
BOTMUX_INSTALL_METHOD="${BOTMUX_INSTALL_METHOD:-auto}"
BOTMUX_RELEASE_REPO="${BOTMUX_RELEASE_REPO:-deepcoldy/botmux}"
BOTMUX_RELEASE_VERSION="${BOTMUX_RELEASE_VERSION:-latest}"
BOTMUX_BIN_DIR="${BOTMUX_INSTALL_DIR:-$HOME/.botmux/bin}"
# botmux 官方单二进制安装器。直连失败时由 run_with_network_retry 经 BOTMUX_HTTP_PROXY（如已配置）重试。
BOTMUX_INSTALLER_URL="${BOTMUX_INSTALLER_URL:-https://raw.githubusercontent.com/deepcoldy/botmux/master/install.sh}"
# Botmux 平台地址，仅用于收尾的绑定引导（去平台点「绑定新机器」拿码）；平台给出的安装命令会带上它。
BOTMUX_PLATFORM_URL="${BOTMUX_PLATFORM_URL:-}"
# 本脚本的下载地址：`curl | sh` 时异步预热 worker 没有脚本文件可复制，按它重新下载。
SCRIPT_URL="${BOTMUX_INSTALL_SCRIPT_URL:-${BOTMUX_PLATFORM_URL:+$BOTMUX_PLATFORM_URL/install.sh}}"
CODEX_INSTALL_URL="${CODEX_INSTALL_URL:-https://chatgpt.com/codex/install.sh}"
CODEX_PACKAGE="${CODEX_PACKAGE:-@openai/codex@latest}"
CODEX_REGISTRY="${CODEX_REGISTRY:-https://registry.npmjs.org}"
# Node 版本管理器 fnm：默认安装并用它装 Node（不再直接解压 tarball 到用户目录）。
FNM_INSTALL_URL="${BOTMUX_FNM_INSTALL_URL:-https://fnm.vercel.app/install}"
FNM_INSTALL_DIR="${BOTMUX_FNM_INSTALL_DIR:-$HOME/.local/share/fnm}"
LARK_CLI_PACKAGE="${LARK_CLI_PACKAGE:-@larksuite/cli@latest}"
LARK_CLI_REGISTRY="${LARK_CLI_REGISTRY:-https://registry.npmjs.org}"
# node-gyp 下载 node 头文件/预编译二进制的镜像（disturl），默认不设。
# 用 ${VAR-默认} 而非 ${VAR:-默认}：仅「未设置」时取默认，显式设为空串则关闭镜像。
NODE_GYP_MIRROR="${BOTMUX_NODE_GYP_MIRROR-}"
# 联网失败后重试一次所用的 HTTP 代理；不设则不重试。
FALLBACK_HTTP_PROXY="${BOTMUX_HTTP_PROXY:-}"
FALLBACK_NO_PROXY="${BOTMUX_NO_PROXY:-localhost,127.0.0.1,::1}"
DISABLE_PROXY_FALLBACK="${BOTMUX_DISABLE_PROXY_FALLBACK:-0}"
PROXY_FALLBACK_ACTIVE=0
CURL_CONNECT_TIMEOUT_SEC="${BOTMUX_CURL_CONNECT_TIMEOUT_SEC:-5}"
CURL_TRANSFER_TIMEOUT_SEC="${BOTMUX_CURL_TRANSFER_TIMEOUT_SEC:-30}"
CURL_RETRY_COUNT="${BOTMUX_CURL_RETRY_COUNT:-3}"
CURL_RETRY_DELAY_SEC="${BOTMUX_CURL_RETRY_DELAY_SEC:-1}"

# `brew install` otherwise performs an implicit git fetch before doing useful
# work. On some remote dev hosts that fetch can hang indefinitely even when
# ordinary HTTPS and bottle downloads are healthy. The installer process is
# ephemeral, so these do not modify the user's persistent Homebrew
# configuration.
HOMEBREW_NO_AUTO_UPDATE="${HOMEBREW_NO_AUTO_UPDATE:-1}"
HOMEBREW_NO_ENV_HINTS="${HOMEBREW_NO_ENV_HINTS:-1}"
HOMEBREW_BIN_CANDIDATES="${BOTMUX_HOMEBREW_BIN_CANDIDATES:-/opt/homebrew/bin/brew /usr/local/bin/brew}"
export HOMEBREW_NO_AUTO_UPDATE HOMEBREW_NO_ENV_HINTS

DRY_RUN=0
INSTALL_AGENTS=1
WARMUP_CODEX=1
WAIT_AGENT_WARMUP=0
AGENT_WARMUP_WORKER=0
WARMUP_STATE_DIR="${BOTMUX_WARMUP_STATE_DIR:-${XDG_STATE_HOME:-$HOME/.local/state}/botmux}"
WARMUP_LOG_FILE="$WARMUP_STATE_DIR/agent-warmup.log"
WARMUP_PID_FILE="$WARMUP_STATE_DIR/agent-warmup.pid"
WARMUP_DONE_FILE="$WARMUP_STATE_DIR/agent-warmup.done"
WARMUP_AUTH_FILE="$WARMUP_STATE_DIR/agent-warmup-auth.txt"
WARMUP_RESULT_FILE="$WARMUP_STATE_DIR/agent-warmup-result.txt"
RUN_SETUP=1
RUN_START=1
INSTALL_SYSTEM_DEPS=1
# node-pty 现场编译所需的 Python/C 工具链：botmux 3.18 起走 bun 二进制不再编译，默认不再
# 主动安装这两类系统包（仍会装 tmux/bubblewrap）。设为 1 可恢复旧行为，给需要 node-gyp
# 现场编译的 agent CLI 铺路。
INSTALL_BUILD_DEPS="${BOTMUX_INSTALL_BUILD_DEPS:-0}"
DEFAULT_CLI="auto"
# 可选 agent CLI，按 setup 默认预选的优先顺序排列。
AGENT_CLIS="codex claude-code"
WARMUP_AGENT_NAMES="Codex"

usage() {
  cat <<'EOF'
botmux 一键安装（macOS / Linux / WSL）

用法:
  curl -fsSL --connect-timeout 5 --max-time 20 --retry 5 --retry-delay 1 --retry-max-time 60 <平台地址>/install.sh | BOTMUX_PLATFORM_URL=<平台地址> sh && export PATH="$HOME/.local/bin:$PATH"
  sh install.sh [选项]

选项:
  --default-cli <id>  setup 默认预选：auto | codex | claude-code
  --no-agents         不安装 Claude Code / Codex / lark-cli
  --no-codex-warmup   不自动首次打开并验证 Codex
  --wait-agent-warmup 等待 Codex 预热完成（默认后台异步，不阻塞安装）
  --no-setup          只安装，不运行飞书配置向导
  --no-start          配置后不启动 daemon，也不注册开机自启
  --no-system-deps    不预装系统 tmux / bubblewrap / macOS Homebrew
  --dry-run           只显示计划，不写文件、不安装、不扫码
  -h, --help          显示帮助

环境变量:
  BOTMUX_PLATFORM_URL         Botmux 平台地址（收尾的绑定引导用）
  BOTMUX_PACKAGE              覆盖 npm 安装目标（默认 botmux@latest）
  BOTMUX_INSTALL_METHOD       auto（默认，调官方安装器装二进制、失败回退 npm）| npm（强制走 npm）
  BOTMUX_RELEASE_REPO         二进制来源仓库（默认 deepcoldy/botmux）
  BOTMUX_RELEASE_VERSION      二进制版本 tag（默认 latest）
  BOTMUX_INSTALL_DIR          botmux 二进制安装目录（默认 ~/.botmux/bin）
  BOTMUX_INSTALLER_URL        botmux 官方单二进制安装器地址
  BOTMUX_INSTALL_ROOT         用户级安装根目录（默认 ~/.local）
  BOTMUX_INSTALL_SCRIPT_URL   本脚本地址，curl | sh 时异步预热按它重新下载（默认 $BOTMUX_PLATFORM_URL/install.sh）
  BOTMUX_NODE_MANAGER         auto | fnm | nvm | brew | volta | mise | asdf | standalone
  BOTMUX_NODE_VERSION         Node 管理器安装的版本（默认 22）
  CODEX_PACKAGE               Codex npm 包（默认 @openai/codex@latest）
  CODEX_REGISTRY              Codex 主安装源（默认 https://registry.npmjs.org）
  LARK_CLI_PACKAGE            lark-cli npm 包（默认 @larksuite/cli@latest）
  LARK_CLI_REGISTRY           lark-cli 安装源（默认 https://registry.npmjs.org）
  BOTMUX_FNM_INSTALL_URL      fnm 安装脚本地址
  BOTMUX_FNM_INSTALL_DIR      fnm 安装目录（默认 ~/.local/share/fnm）
  BOTMUX_INSTALL_BUILD_DEPS=1 额外安装 Python≥3.8 与 C/C++ 工具链（botmux 3.18+ 走 bun
                             二进制、本身不再需要；仅为可能现场编译的 agent CLI 铺路）
  BOTMUX_NODE_GYP_MIRROR      node-gyp 下载 node 头文件的镜像（disturl，默认不设）
  BOTMUX_HTTP_PROXY           联网失败后重试一次所用的 HTTP 代理（默认不设）
  BOTMUX_NO_PROXY             代理生效时不走代理的地址列表
  BOTMUX_DISABLE_PROXY_FALLBACK=1  禁止联网失败后自动启用代理
  BOTMUX_CURL_CONNECT_TIMEOUT_SEC   curl 建连超时（默认 5 秒）
  BOTMUX_CURL_TRANSFER_TIMEOUT_SEC  curl 单次传输超时（默认 30 秒）
  BOTMUX_CURL_RETRY_COUNT           curl 快速重试次数（默认 3）
EOF
}

log() { printf '\033[32m[botmux]\033[0m %s\n' "$*"; }
warn() { printf '\033[33m[botmux]\033[0m %s\n' "$*" >&2; }
die() { printf '\033[31m[botmux]\033[0m %s\n' "$*" >&2; exit 1; }

# Extension points for an install profile (see the top of this file).
# profile_parse_arg handles one more option: it returns 0 after setting
# PROFILE_ARGS_USED to the number of arguments it consumed.
profile_parse_arg() { return 1; }
profile_agent_logged_in() { return 1; }
profile_installed_cli() { return 1; }
profile_login_hint() { :; }
profile_remote_install_requested() { return 1; }
profile_remote_install() { :; }

validate_install_user() {
  [ -n "${HOME:-}" ] || die "HOME 未设置，无法确定当前用户的安装目录"
  install_uid=$(id -u 2>/dev/null) || die "无法通过 id -u 读取当前用户 uid"
  if [ "$DRY_RUN" -eq 0 ]; then
    mkdir -p "$INSTALL_ROOT" || die "无法创建安装目录 $INSTALL_ROOT"
    [ -w "$INSTALL_ROOT" ] || die "当前用户无权写入 ${INSTALL_ROOT}；请修复目录归属或设置 BOTMUX_INSTALL_ROOT"
  fi
  if [ "$install_uid" -eq 0 ]; then
    log "检测到 root 用户：用户级文件写入 ${HOME}，系统依赖直接以当前身份安装"
  else
    log "检测到非 root 用户（uid=${install_uid}）：核心组件安装到 ${INSTALL_ROOT}；仅 tmux 等缺失的系统依赖可能请求 sudo"
  fi
}

activate_proxy_fallback() {
  [ "$PROXY_FALLBACK_ACTIVE" -eq 0 ] || return 0
  [ "$DISABLE_PROXY_FALLBACK" != 1 ] || return 1
  [ -n "$FALLBACK_HTTP_PROXY" ] || return 1

  http_proxy=$FALLBACK_HTTP_PROXY
  https_proxy=$FALLBACK_HTTP_PROXY
  HTTP_PROXY=$FALLBACK_HTTP_PROXY
  HTTPS_PROXY=$FALLBACK_HTTP_PROXY
  no_proxy=$FALLBACK_NO_PROXY
  NO_PROXY=$FALLBACK_NO_PROXY
  export http_proxy https_proxy HTTP_PROXY HTTPS_PROXY no_proxy NO_PROXY
  PROXY_FALLBACK_ACTIVE=1
  warn "已临时启用 HTTP 代理重试；BOTMUX_NO_PROXY 中的地址继续直连"
}

run_with_network_retry() {
  label=$1
  shift
  if "$@"; then
    return 0
  else
    rc=$?
  fi
  if [ "$PROXY_FALLBACK_ACTIVE" -eq 1 ] || [ "$DISABLE_PROXY_FALLBACK" = 1 ] || [ -z "$FALLBACK_HTTP_PROXY" ]; then
    return "$rc"
  fi
  warn "$label 首次失败，使用 HTTP 代理重试一次"
  activate_proxy_fallback || return "$rc"
  "$@"
}

run_with_fallback_proxy() {
  env \
    http_proxy="$FALLBACK_HTTP_PROXY" https_proxy="$FALLBACK_HTTP_PROXY" \
    HTTP_PROXY="$FALLBACK_HTTP_PROXY" HTTPS_PROXY="$FALLBACK_HTTP_PROXY" \
    no_proxy="$FALLBACK_NO_PROXY" NO_PROXY="$FALLBACK_NO_PROXY" \
    "$@"
}

# Homebrew bootstrap and bottles live on public hosts that are commonly slow
# or unreachable from restricted networks. With BOTMUX_HTTP_PROXY set, try the
# proxy first for these operations, but keep a direct retry so a transient
# proxy outage does not make a normally reachable Mac worse. Unlike activate_proxy_fallback, this scopes
# the proxy to one command and does not overwrite the user's shell environment.
run_with_proxy_preferred() {
  label=$1
  shift
  if [ "$PROXY_FALLBACK_ACTIVE" -eq 1 ] || [ "$DISABLE_PROXY_FALLBACK" = 1 ] || [ -z "$FALLBACK_HTTP_PROXY" ]; then
    "$@"
    return
  fi
  log "$label 优先使用 HTTP 代理"
  if run_with_fallback_proxy "$@"; then
    return 0
  else
    rc=$?
  fi
  warn "$label 通过 HTTP 代理失败，使用当前网络重试一次"
  if "$@"; then return 0; fi
  return "$rc"
}

download_script() {
  url=$1
  output=$2
  command -v curl >/dev/null 2>&1 || die "需要 curl 下载 $url"
  run_with_network_retry "下载 $url" curl -fsSL \
    --connect-timeout "$CURL_CONNECT_TIMEOUT_SEC" \
    --max-time "$CURL_TRANSFER_TIMEOUT_SEC" \
    --retry "$CURL_RETRY_COUNT" \
    --retry-delay "$CURL_RETRY_DELAY_SEC" \
    --retry-max-time 60 \
    "$url" -o "$output"
}

download_script_proxy_preferred() {
  url=$1
  output=$2
  command -v curl >/dev/null 2>&1 || die "需要 curl 下载 $url"
  run_with_proxy_preferred "下载 $url" curl -fsSL \
    --connect-timeout "$CURL_CONNECT_TIMEOUT_SEC" \
    --max-time "$CURL_TRANSFER_TIMEOUT_SEC" \
    --retry "$CURL_RETRY_COUNT" \
    --retry-delay "$CURL_RETRY_DELAY_SEC" \
    --retry-max-time 60 \
    "$url" -o "$output"
}

has_tty() {
  [ -t 0 ] || [ -t 1 ] || [ -t 2 ] || ( : </dev/tty ) 2>/dev/null
}

# 交互式子命令（botmux setup 的菜单、Homebrew 等）该不该额外 `</dev/tty`。
#
# ⚠️ 关键区别，踩过线上事故：`</dev/tty` 只在【stdin 不是终端】时才需要——典型是
# `curl install.sh | sh`，此时 stdin 是管道，子命令读不到键盘，必须显式接回真实终端。
# 但如果 stdin 本身已经是终端（含被外层工具放进子 PTY 运行的场景），再 `</dev/tty` 就是
# 【第二个读者】去抢同一份按键：外层正在读 /dev/tty 并转发进子 PTY，我们又直连 /dev/tty，
# 方向键/Enter/Esc 会被两边分食 —— 表现是 setup 菜单完全没反应（真实用户反馈）。
#
# 所以判据是 `[ -t 0 ]` 而不是 has_tty()：has_tty 只要 stdout/stderr 是终端就为真，
# 无法区分「stdin 是管道」和「stdin 已是终端」这两种相反的情况。
#
# 用法：needs_tty_redirect && cmd </dev/tty || cmd
stdin_is_interactive() {
  [ -t 0 ]
}
needs_tty_redirect() {
  # stdin 已是终端 → 不要抢；否则若能打开 /dev/tty 就接回来。
  stdin_is_interactive && return 1
  ( : </dev/tty ) 2>/dev/null
}

shell_profile() {
  case "${SHELL:-}" in
    */zsh) printf '%s\n' "$HOME/.zshrc" ;;
    */bash) printf '%s\n' "$HOME/.bashrc" ;;
    *)
      if [ "$NODE_OS" = darwin ]; then printf '%s\n' "$HOME/.zprofile"
      else printf '%s\n' "$HOME/.profile"
      fi
      ;;
  esac
}

ensure_user_path() {
  profile=$(shell_profile)
  line=$(printf 'export PATH="%s:$PATH"' "$BIN_DIR")
  if [ "$DRY_RUN" -eq 1 ]; then
    log "将确保 $BIN_DIR 在 PATH，并写入 $profile"
    return
  fi
  mkdir -p "$BIN_DIR" "$NODE_ROOT"
  if [ ! -f "$profile" ] || ! grep -F "$line" "$profile" >/dev/null 2>&1; then
    {
      printf '\n# botmux user binaries\n'
      printf '%s\n' "$line"
    } >> "$profile"
    log "已把 ~/.local/bin 写入 $profile"
  fi
}

ensure_profile_path_prefix() {
  prefix=$1
  marker=$2
  profile=$(shell_profile)
  line=$(printf 'export PATH="%s:$PATH"' "$prefix")
  if [ ! -f "$profile" ] || ! grep -F "$line" "$profile" >/dev/null 2>&1; then
    {
      printf '\n# %s\n' "$marker"
      printf '%s\n' "$line"
    } >> "$profile"
    log "已把 $prefix 写入 $profile"
  fi
}

# 往一个 shell 启动文件追加「把 ~/.botmux/bin 加进 PATH」的幂等语句。
# 写的是 case 判断而非裸 `export PATH=...:$PATH`：后者在 re-source / 嵌套 shell（.bash_profile
# 里 source .bashrc 是常见写法）会反复前插、PATH 越滚越长。目录用单引号包裹，避免路径里的
# `$(...)`/反引号/$VAR 在每次 shell 启动时被求值执行。
write_botmux_path_entry() {
  entry_file=$1
  case "$entry_file" in
    *conf.d/botmux.fish)
      mkdir -p "$(dirname "$entry_file")" 2>/dev/null || true
      # fish 不是 POSIX：用 contains 做存在判断 + set -gx 赋值。
      entry_line="contains '$botmux_bin_dir' \$PATH; or set -gx PATH '$botmux_bin_dir' \$PATH  # added by botmux installer"
      ;;
    *)
      entry_line="case \":\$PATH:\" in *:'$botmux_bin_dir':*) ;; *) export PATH='$botmux_bin_dir'\":\$PATH\" ;; esac  # added by botmux installer"
      ;;
  esac
  if { printf '\n%s\n' "$entry_line"; } >> "$entry_file" 2>/dev/null; then
    log "已把 ${botmux_bin_dir} 写入 ${entry_file}（botmux postinstall 未写入，install.sh 兜底）"
  else
    warn "兜底写入 ${entry_file} 失败；可手动执行: export PATH=\"${botmux_bin_dir}:\$PATH\""
  fi
}

# 判定 Linux 的 C 库是否为 musl（Alpine 及多数 slim 镜像）。glibc 版二进制在 musl 上根本
# 跑不起来（loader 直接报错且不说原因），所以选错比不装更糟。
# ldd 存在时【两个方向都权威】：glibc 与 musl 都自带 ldd——它说 musl 就是 musl，说别的就
# 一定不是。这点很关键：glibc 发行版可以合法地【安装】musl（Debian/Ubuntu 的 musl-tools，
# 交叉编译常用），那会在顶层留下 /lib/ld-musl-*，仅看文件会误判成 musl。
# 文件探测只作为完全没有 ldd 的镜像（distroless 类）的兜底，且保守：只在确实观察到时才认。
# 调用 botmux 官方单二进制安装器（deepcoldy/botmux 的 install.sh）。
#
# 为什么调它而不是自己实现：os/arch 选型、musl 探测（含「Debian 装了 musl-tools 也有
# /lib/ld-musl-*，不能只看这个文件」这类坑）、SHA-256 校验（Release 未发布校验和时告警继续）、
# `--version` 运行探针（GLIBC 符号版本不匹配只有真跑才暴露）、原子 rename 替换、以及写各类
# shell 启动文件——这些上游都已实现且更权威。此前这里是把那套逻辑抄了一份（85 行），上游一改
# 就会悄悄落后；而且抄的过程中我们自己多加了个 `-s` 把进度条也关掉了（用户实测反馈）。
#
# 我们只在【外面】补两件上游没有的事：
#   1) HTTP 代理回退（BOTMUX_HTTP_PROXY）——包一层 https_proxy 即可，不需要改上游；
#   2) 失败回退 npm——判它退出码。上游失败即 exit，正好作为信号。
# 上游写启动文件与我们的 ensure_botmux_bin_path 不冲突：后者开头就扫启动文件，
# 只要任一文件已含 .botmux/bin 就直接 return，上游先写过它自然变 no-op。
#
# 成功返回 0；任何一步失败返回非 0，由调用方回退 npm。
install_botmux_binary() {
  command -v curl >/dev/null 2>&1 || { warn "未找到 curl，无法下载 botmux 二进制"; return 1; }

  if [ "$DRY_RUN" -eq 1 ]; then
    log "将执行 botmux 官方安装器 ${BOTMUX_INSTALLER_URL}（装到 ${BOTMUX_BIN_DIR}）"
    return 0
  fi

  botmux_tmp=$(mktemp -d "${TMPDIR:-/tmp}/botmux-bin.XXXXXX") || return 1
  botmux_installer="$botmux_tmp/install.sh"

  # 先把安装器脚本抓下来再跑，而不是 `curl | sh`：能区分「脚本没下下来」和「脚本跑失败」，
  # 也让下载这步复用我们的超时/重试/代理回退。
  if ! download_script "$BOTMUX_INSTALLER_URL" "$botmux_installer"; then
    warn "下载 botmux 官方安装器失败（${BOTMUX_INSTALLER_URL}）"
    rm -rf "$botmux_tmp"
    return 1
  fi

  # 上游用 curl 默认进度表（-fSL，没有 -s），170MB 下载全程可见，不需要我们再做 TTY 判断。
  # BOTMUX_INSTALL_DIR/BOTMUX_REPO/BOTMUX_VERSION 是上游认的三个 env，把我们的配置映射过去。
  log "安装/升级 botmux（官方单二进制安装器）"
  if run_with_network_retry "botmux 二进制安装" env \
      BOTMUX_INSTALL_DIR="$BOTMUX_BIN_DIR" \
      BOTMUX_REPO="$BOTMUX_RELEASE_REPO" \
      BOTMUX_VERSION="$BOTMUX_RELEASE_VERSION" \
      sh "$botmux_installer"; then
    rm -rf "$botmux_tmp"
    return 0
  fi
  warn "botmux 官方安装器执行失败"
  rm -rf "$botmux_tmp"
  return 1
}

# botmux 3.18 起，全局 `botmux` 命令是 ~/.botmux/bin/botmux 这个 launcher（指向 bun 平台
# 二进制）——不再是 ~/.local/bin 里的 npm shim（主包已无 bin 字段）。首选由 botmux 的
# postinstall 用它自带的周全逻辑把该目录写进各 shell 启动文件（bash 同时写 .bashrc 与登录
# 文件、zsh 写 .zshenv、fish 写 conf.d、防注入、幂等）。此函数只做【兜底】：postinstall 因故
# 完全没写（旧 npm 静默、写权限、tarball 缺文件等）时补一次，并对齐 botmux 的目标文件选择，
# 关键是 bash 必须同时覆盖交互(.bashrc)与登录(首个存在的 .bash_profile/.bash_login/.profile)
# 两类 shell——只写一个会让「重开终端 / ssh 直连」其一读不到 botmux。
ensure_botmux_bin_path() {
  botmux_bin_dir="$HOME/.botmux/bin"
  if [ "$DRY_RUN" -eq 1 ]; then
    log "将确保 $botmux_bin_dir 在 PATH（若 botmux postinstall 未写入则兜底补写）"
    return
  fi
  # 已持久化就不重复：扫所有可能被 postinstall 写过的启动文件，任一已含 .botmux/bin 即认定
  # 生效。匹配固定子串而非绝对路径——postinstall 写绝对路径，但也可能是 $HOME/~ 形式。
  # 不看「当前进程 PATH」：装完 botmux 后主流程已把该目录塞进本进程 PATH，与是否落盘无关。
  for candidate in "$HOME/.zshrc" "$HOME/.zshenv" "$HOME/.zprofile" "$HOME/.bashrc" \
                   "$HOME/.bash_profile" "$HOME/.bash_login" "$HOME/.profile" \
                   "$HOME/.config/fish/conf.d/botmux.fish" "$HOME/.config/fish/config.fish"; do
    [ -f "$candidate" ] || continue
    grep -F ".botmux/bin" "$candidate" >/dev/null 2>&1 && return 0
  done

  # postinstall 没能写——按用户登录 shell 选目标文件补写。用与 botmux 相同的幂等 case 语句
  # （不会在 re-source / 嵌套 shell 里重复前插 PATH）。
  # 逐个目标文件写入。用函数而非「空格拼接字符串 + 词分割」来传多个目标：HOME 含空格时
  # `for x in $list` 会把一个路径裂成两个，写进错误的文件（macOS 用户名带空格是真实场景）。
  botmux_shell=$(basename "${SHELL:-}" 2>/dev/null || printf '')
  case "$botmux_shell" in
    *zsh*)  write_botmux_path_entry "${ZDOTDIR:-$HOME}/.zshenv" ;;
    *fish*) write_botmux_path_entry "${XDG_CONFIG_HOME:-$HOME/.config}/fish/conf.d/botmux.fish" ;;
    *bash*)
      # bash 登录只读 .bash_profile→.bash_login→.profile 的第一个【已存在】者（凭空创建
      # 靠前的那个会屏蔽用户既有登录配置）；交互只读 .bashrc。两类不相交，都要写。
      botmux_login=""
      for f in "$HOME/.bash_profile" "$HOME/.bash_login" "$HOME/.profile"; do
        [ -f "$f" ] && { botmux_login="$f"; break; }
      done
      [ -n "$botmux_login" ] || botmux_login="$HOME/.bash_profile"
      write_botmux_path_entry "$HOME/.bashrc"
      [ "$botmux_login" = "$HOME/.bashrc" ] || write_botmux_path_entry "$botmux_login"
      ;;
    *)      write_botmux_path_entry "$HOME/.profile" ;;  # sh/ksh/dash/未知：POSIX .profile 最通用
  esac
}

node_major() {
  node_bin=$(command -v node 2>/dev/null || true)
  [ -n "$node_bin" ] || return 1
  "$node_bin" -p 'Number(process.versions.node.split(".")[0])' 2>/dev/null
}

# Botmux depends on node-pty, whose macOS support follows the Node versions
# exercised by VS Code. Reuse supported LTS lines by default instead of any
# arbitrarily newer Current release: Node 25 has produced hard aborts followed
# by node-pty `posix_spawnp failed` during installer warmup. An explicit
# BOTMUX_NODE_VERSION remains an escape hatch and is matched by major version.
node_runtime_supported() {
  major=$(node_major 2>/dev/null || printf '0')
  case "$major" in ''|*[!0-9]*) return 1 ;; esac
  if [ "$NODE_VERSION_EXPLICIT" -eq 1 ]; then
    requested_major=${NODE_VERSION_SPEC%%.*}
    case "$requested_major" in
      ''|*[!0-9]*) ;;
      *) [ "$major" -eq "$requested_major" ] 2>/dev/null; return ;;
    esac
  fi
  case "$major" in 22|24) return 0 ;; *) return 1 ;; esac
}

# 判断给定解释器（命令名或绝对路径）是否为 Python≥3.8。
python_is_modern() {
  command -v "$1" >/dev/null 2>&1 || return 1
  "$1" -c 'import sys; sys.exit(0 if sys.version_info[:2] >= (3, 8) else 1)' >/dev/null 2>&1
}

# 供告警/报错展示当前 python3 的版本信息。
python3_version_desc() {
  if command -v python3 >/dev/null 2>&1; then python3 --version 2>&1; else printf '未安装'; fi
}

# node-gyp（编译 botmux 的原生依赖 node-pty）自带的 gyp 需要 Python≥3.8——它用了 walrus
# 运算符 `:=`，旧的 python/python2 会直接抛 SyntaxError。打印第一个版本达标的解释器路径，
# 找不到则返回非 0。除 python3/python 外还要探带版本号的名字：老发行版装 python3.11 等
# 版本号包时不会改变默认 python3 指向。
find_modern_python() {
  for python_candidate in python3 python3.13 python3.12 python3.11 python3.10 python3.9 python3.8 python; do
    python_path=$(command -v "$python_candidate" 2>/dev/null) || continue
    if python_is_modern "$python_path"; then
      printf '%s\n' "$python_path"
      return 0
    fi
  done
  return 1
}

# 为可能触发 node-gyp 现场编译的 npm 安装锁定 Python 与下载镜像：
#   1) 确保 node-gyp 用的 Python≥3.8——旧 python/python2 会触发 gyp 的 walrus 语法错误；
#   2) 配置 node 头文件的镜像（BOTMUX_NODE_GYP_MIRROR → disturl），规避 node-gyp 下载超时。
# 注意：botmux 自 3.18 起走 bun 单文件二进制分发（平台子包），主包已摘掉 node-pty，
# 安装 botmux 本身不再现场编译。此函数保留是为可选 agent CLI（claude/codex 等
# 仍走 npm，个别版本可能带原生依赖）尽力铺好编译环境——但缺 Python 不再阻断安装。
# node-gyp 选 Python 的优先级：NODE_GYP_FORCE_PYTHON > npm_config_python(--python) > PYTHON > PATH。
# 已显式配置且达标就尊重；不达标则用 find_modern_python 顶掉，并对齐会抢优先级的那几个变量。
configure_native_build_env() {
  # node-gyp 选 Python 的优先级：NODE_GYP_FORCE_PYTHON > npm_config_python(--python) > PYTHON > PATH。
  # 按此顺序挑第一个「达标(≥3.8)」的解释器（不是第一个非空的）——高优先级配置无效时，
  # 仍要能落到低优先级但有效的显式配置；都不达标再退回 PATH 搜索。
  chosen_python=""
  configured_top=""
  for candidate_python in "${NODE_GYP_FORCE_PYTHON:-}" "${npm_config_python:-}" "${PYTHON:-}"; do
    [ -n "$candidate_python" ] || continue
    [ -n "$configured_top" ] || configured_top="$candidate_python"
    if python_is_modern "$candidate_python"; then chosen_python="$candidate_python"; break; fi
  done
  [ -n "$chosen_python" ] || chosen_python=$(find_modern_python 2>/dev/null || true)

  if [ -n "$chosen_python" ]; then
    [ -z "$configured_top" ] || [ "$configured_top" = "$chosen_python" ] || \
      warn "已配置的 Python（${configured_top}）低于 3.8 或不可用；本次安装改用 ${chosen_python} 以避免 node-gyp 语法错误"
    export npm_config_python="$chosen_python"
    # NODE_GYP_FORCE_PYTHON/PYTHON 优先级 ≥ npm_config_python，其中 FORCE 还会禁用 node-gyp 的
    # 回退；若已被设置且非选中值，会盖掉上面的修正，需一并对齐到选中的解释器。
    [ -z "${NODE_GYP_FORCE_PYTHON:-}" ] || export NODE_GYP_FORCE_PYTHON="$chosen_python"
    [ -z "${PYTHON:-}" ] || export PYTHON="$chosen_python"
    log "node-gyp 将使用 Python: $chosen_python ($("$chosen_python" --version 2>&1))"
  else
    # 过去 botmux 依赖 node-pty 现场编译，缺 Python≥3.8 会以一大段 node-gyp 报错收场，
    # 故在此硬阻断。3.18 起 botmux 走 bun 二进制、不再编译，缺 Python 不应再阻断安装——
    # 降级为告警：只有个别 agent CLI 若带原生依赖才可能受影响，届时按提示补 Python 即可。
    warn "未找到 Python ≥3.8（当前 python3: $(python3_version_desc)）；安装 botmux 本身不需要它。若之后某个 agent CLI 需 node-gyp 现场编译才会失败，可届时安装 python3(≥3.8) 与 C/C++ 工具链。"
  fi

  # node-gyp 真正读取的是 npm_config_disturl（只有 npm_config_* 才映射成 --dist-url），裸 disturl
  # 仅作兼容。用户已配任一（含自定义镜像）则归一到两者、完全尊重；都未配再套 NODE_GYP_MIRROR
  # （为空=关闭）。
  if [ -n "${disturl:-}" ] || [ -n "${npm_config_disturl:-}" ]; then
    resolved_disturl="${npm_config_disturl:-${disturl:-}}"
    export disturl="$resolved_disturl"
    export npm_config_disturl="$resolved_disturl"
  elif [ -n "$NODE_GYP_MIRROR" ]; then
    export disturl="$NODE_GYP_MIRROR"
    export npm_config_disturl="$NODE_GYP_MIRROR"
  fi
}

load_nvm() {
  if command -v nvm >/dev/null 2>&1; then return 0; fi
  nvm_script="${NVM_DIR:-$HOME/.nvm}/nvm.sh"
  if [ ! -f "$nvm_script" ]; then
    current_node=$(command -v node 2>/dev/null || true)
    case "$current_node" in
      */.nvm/versions/node/*) nvm_script="${current_node%%/versions/node/*}/nvm.sh" ;;
    esac
  fi
  [ -f "$nvm_script" ] || return 1
  set +u
  # shellcheck disable=SC1090
  . "$nvm_script"
  set -u
  command -v nvm >/dev/null 2>&1
}

# 把 fnm 的 shell 集成写进启动文件，让新开的 shell 也能直接用 node/npm。
# fnm env 输出的是 export + 一个 PATH 前插，重复 source 会让 PATH 越滚越长，故用 marker 幂等。
ensure_fnm_shell_integration() {
  fnm_bin=$1
  profile=$(shell_profile)
  marker="# botmux fnm"
  [ -f "$profile" ] && grep -F "$marker" "$profile" >/dev/null 2>&1 && return 0
  case "$profile" in
    *.zshrc|*.zprofile) fnm_shell=zsh ;;
    *.bashrc|*.profile) fnm_shell=bash ;;
    *) fnm_shell=bash ;;
  esac
  {
    printf '\n%s\n' "$marker"
    printf 'export PATH="%s:$PATH"\n' "$(dirname "$fnm_bin")"
    printf 'command -v fnm >/dev/null 2>&1 && eval "$(fnm env --shell %s)"\n' "$fnm_shell"
  } >> "$profile"
  log "已把 fnm 环境写入 $profile"
}

# 安装 fnm（Node 版本管理器）。默认走官方安装脚本装到 ~/.local/share/fnm。
install_fnm() {
  if command -v fnm >/dev/null 2>&1; then
    ensure_fnm_shell_integration "$(command -v fnm)"
    return 0
  fi
  # 官方安装器默认装到 ~/.local/share/fnm；--skip-shell 由我们自己写 profile（幂等且可控）。
  if [ -x "$FNM_INSTALL_DIR/fnm" ]; then
    PATH="$FNM_INSTALL_DIR:$PATH"; export PATH
    ensure_fnm_shell_integration "$FNM_INSTALL_DIR/fnm"
    return 0
  fi
  log "安装 fnm（Node 版本管理器）"
  if [ "$DRY_RUN" -eq 1 ]; then
    log "将从 $FNM_INSTALL_URL 安装 fnm 到 $FNM_INSTALL_DIR"
    return 0
  fi
  tmp_fnm=$(mktemp "${TMPDIR:-/tmp}/botmux-fnm.XXXXXX") || return 1
  # ⚠️ 必须用 bash 跑：官方安装器 shebang 是 #!/bin/bash，其 parse_args 用了 [[ ]]。
  # 在 dash/sh 下 `[[: not found`，参数解析整段失效 —— --skip-shell 不生效，它会自己往
  # .bashrc 追加一段 fnm 初始化（和我们写的重复），--install-dir 也会被忽略。
  fnm_runner=$(command -v bash 2>/dev/null || true)
  if [ -z "$fnm_runner" ]; then
    rm -f "$tmp_fnm"
    warn "未找到 bash（fnm 官方安装器依赖 bash），回退到用户目录独立安装 Node"
    return 1
  fi
  if download_script "$FNM_INSTALL_URL" "$tmp_fnm" && \
     run_with_network_retry "fnm 安装" "$fnm_runner" "$tmp_fnm" --install-dir "$FNM_INSTALL_DIR" --skip-shell; then
    rm -f "$tmp_fnm"
    PATH="$FNM_INSTALL_DIR:$PATH"; export PATH
    if command -v fnm >/dev/null 2>&1; then
      ensure_fnm_shell_integration "$(command -v fnm)"
      log "已安装 fnm $(fnm --version 2>/dev/null | head -n 1)"
      return 0
    fi
  fi
  rm -f "$tmp_fnm"
  warn "fnm 安装失败，将回退到用户目录独立安装 Node"
  return 1
}

detect_node_manager() {
  case "$NODE_MANAGER_REQUEST" in
    auto) ;;
    fnm|nvm|brew|volta|mise|asdf|standalone) printf '%s\n' "$NODE_MANAGER_REQUEST"; return ;;
    *) die "BOTMUX_NODE_MANAGER 不支持: $NODE_MANAGER_REQUEST" ;;
  esac

  current_node=$(command -v node 2>/dev/null || true)
  case "$current_node" in
    "$NODE_ROOT"/*|"$BIN_DIR"/node) printf '%s\n' standalone; return ;;
    */.fnm/*|*/fnm_multishells/*) printf '%s\n' fnm; return ;;
    */.nvm/versions/node/*) printf '%s\n' nvm; return ;;
    */.volta/*) printf '%s\n' volta; return ;;
    */.asdf/*) printf '%s\n' asdf; return ;;
    */.local/share/mise/*|*/mise/installs/*) printf '%s\n' mise; return ;;
  esac
  if command -v brew >/dev/null 2>&1; then
    brew_prefix=$(brew --prefix 2>/dev/null || true)
    if [ -n "$brew_prefix" ]; then
      case "$current_node" in "$brew_prefix"/*) printf '%s\n' brew; return ;; esac
    fi
  fi

  # Node 可能没有在非交互 shell 中激活；此时优先复用用户已经安装的管理器。
  command -v fnm >/dev/null 2>&1 && { printf '%s\n' fnm; return; }
  load_nvm >/dev/null 2>&1 && { printf '%s\n' nvm; return; }
  command -v volta >/dev/null 2>&1 && { printf '%s\n' volta; return; }
  command -v mise >/dev/null 2>&1 && { printf '%s\n' mise; return; }
  command -v asdf >/dev/null 2>&1 && { printf '%s\n' asdf; return; }
  command -v brew >/dev/null 2>&1 && { printf '%s\n' brew; return; }
  printf '%s\n' standalone
}

remove_standalone_node_links() {
  for bin in node npm npx corepack; do
    link="$BIN_DIR/$bin"
    [ -L "$link" ] || continue
    target=$(readlink "$link" 2>/dev/null || true)
    case "$target" in "$NODE_ROOT"/*) rm -f "$link" ;; esac
  done
}

upgrade_node_with_manager() {
  manager=$1
  log "检测到 Node 管理方式: ${manager}；沿用该方式升级到 Node.js $NODE_VERSION_SPEC"
  case "$manager" in
    fnm)
      command -v fnm >/dev/null 2>&1 || return 1
      run_with_network_retry "fnm 安装 Node.js" fnm install "$NODE_VERSION_SPEC" || return 1
      fnm default "$NODE_VERSION_SPEC" || return 1
      eval "$(fnm env --shell bash)" || return 1
      fnm use "$NODE_VERSION_SPEC" || return 1
      ;;
    nvm)
      load_nvm || return 1
      run_with_network_retry "nvm 安装 Node.js" nvm install "$NODE_VERSION_SPEC" || return 1
      nvm alias default "$NODE_VERSION_SPEC" >/dev/null || return 1
      nvm use "$NODE_VERSION_SPEC" >/dev/null || return 1
      ;;
    brew)
      command -v brew >/dev/null 2>&1 || return 1
      # 兼容性修复必须在【任何首次 brew install】之前——ensure_node 早于
      # ensure_homebrew_for_tmux 执行，以前那次 repair 放在后者里，导致「Node 由 brew 管理」
      # 的机器会先撞上旧 brew 的问题（真实用户就是装 node 拉起 openssl@3 时炸的）。
      repair_homebrew_macos_compat
      current_node=$(command -v node 2>/dev/null || true)
      current_major=$(node_major 2>/dev/null || printf '0')
      target_major=${NODE_VERSION_SPEC%%.*}
      case "$target_major" in ''|*[!0-9]*) target_major=$NODE_REQUIRED_MAJOR ;; esac
      case "$current_node" in
        */opt/node@*/*|*/Cellar/node@*/*)
          brew_formula="node@${target_major}"
          run_brew_with_dsl_retry "Homebrew 安装 Node.js" brew install "$brew_formula" || return 1
          brew_versioned=1
          ;;
        *)
          # Homebrew's unversioned `node` tracks Current. If it is already
          # newer than the requested stable line, `brew upgrade node` cannot
          # downgrade it; install the versioned formula and put it first.
          if [ "$current_major" -gt "$target_major" ] 2>/dev/null; then
            brew_formula="node@${target_major}"
            brew_versioned=1
            run_brew_with_dsl_retry "Homebrew 安装 Node.js" brew install "$brew_formula" || return 1
          else
            brew_formula=node
            brew_versioned=0
            if brew list --versions node >/dev/null 2>&1; then
              run_brew_with_dsl_retry "Homebrew 升级 Node.js" brew upgrade node || return 1
            else
              run_brew_with_dsl_retry "Homebrew 安装 Node.js" brew install node || return 1
            fi
          fi
          ;;
      esac
      brew_node_prefix=$(brew --prefix "$brew_formula" 2>/dev/null) || return 1
      PATH="$brew_node_prefix/bin:$PATH"
      export PATH
      if [ "$brew_versioned" -eq 1 ]; then
        ensure_profile_path_prefix "$brew_node_prefix/bin" "botmux: Homebrew Node.js $NODE_VERSION_SPEC"
      fi
      ;;
    volta)
      command -v volta >/dev/null 2>&1 || return 1
      run_with_network_retry "Volta 安装 Node.js" volta install "node@$NODE_VERSION_SPEC" || return 1
      VOLTA_HOME="${VOLTA_HOME:-$HOME/.volta}"
      PATH="$VOLTA_HOME/bin:$PATH"
      export VOLTA_HOME PATH
      ;;
    mise)
      command -v mise >/dev/null 2>&1 || return 1
      run_with_network_retry "mise 安装 Node.js" mise use --global "node@$NODE_VERSION_SPEC" || return 1
      mise_node_dir=$(mise where "node@$NODE_VERSION_SPEC" 2>/dev/null) || return 1
      PATH="$mise_node_dir/bin:$PATH"
      export PATH
      ;;
    asdf)
      command -v asdf >/dev/null 2>&1 || return 1
      asdf_version=$(asdf latest nodejs "$NODE_VERSION_SPEC" 2>/dev/null) || return 1
      [ -n "$asdf_version" ] || return 1
      run_with_network_retry "asdf 安装 Node.js" asdf install nodejs "$asdf_version" || return 1
      if asdf set -u nodejs "$asdf_version" >/dev/null 2>&1; then :
      else asdf global nodejs "$asdf_version" >/dev/null 2>&1 || return 1
      fi
      asdf_node_dir=$(asdf where nodejs "$asdf_version" 2>/dev/null) || return 1
      PATH="$asdf_node_dir/bin:$PATH"
      export PATH
      ;;
    standalone) return 1 ;;
    *) return 1 ;;
  esac
  hash -r 2>/dev/null || true
  remove_standalone_node_links
  node_runtime_supported
}

install_standalone_node() {
  log "使用用户目录独立安装 Node.js ${NODE_VERSION_SPEC}（不会改系统目录）"
  if [ "$DRY_RUN" -eq 1 ]; then
    log "将从 $NODE_DIST_BASE 下载并校验 Node.js ($NODE_OS-$NODE_ARCH) 到 $NODE_ROOT"
    return
  fi

  command -v curl >/dev/null 2>&1 || die "安装 Node.js 需要 curl"
  command -v tar >/dev/null 2>&1 || die "安装 Node.js 需要 tar"
  tmp=$(mktemp -d "${TMPDIR:-/tmp}/botmux-node.XXXXXX")
  manifest="$tmp/SHASUMS256.txt"
  base=$NODE_DIST_BASE
  download_script "$base/SHASUMS256.txt" "$manifest"
  filename=$(awk -v suffix="-$NODE_OS-$NODE_ARCH.tar.xz" '$2 ~ suffix "$" { print $2; exit }' "$manifest")
  [ -n "$filename" ] || { rm -rf "$tmp"; die "Node.js $NODE_VERSION_SPEC 没有 $NODE_OS-$NODE_ARCH 构建"; }
  archive="$tmp/$filename"
  download_script "$base/$filename" "$archive"
  expected=$(awk -v file="$filename" '$2 == file { print $1; exit }' "$manifest")
  if command -v sha256sum >/dev/null 2>&1; then
    actual=$(sha256sum "$archive" | awk '{print $1}')
  elif command -v shasum >/dev/null 2>&1; then
    actual=$(shasum -a 256 "$archive" | awk '{print $1}')
  else
    rm -rf "$tmp"
    die "安装 Node.js 需要 sha256sum 或 shasum"
  fi
  [ "$actual" = "$expected" ] || { rm -rf "$tmp"; die "Node.js 下载校验失败"; }

  tar -xJf "$archive" -C "$tmp"
  extracted="$tmp/${filename%.tar.xz}"
  version=$("$extracted/bin/node" --version)
  destination="$NODE_ROOT/node-$version-$NODE_OS-$NODE_ARCH"
  if [ ! -d "$destination" ]; then
    mv "$extracted" "$destination"
  fi
  for bin in node npm npx corepack; do
    [ -e "$destination/bin/$bin" ] && ln -sf "$destination/bin/$bin" "$BIN_DIR/$bin"
  done
  rm -rf "$tmp"
  log "已安装 Node.js $version 到 $destination"
}

ensure_node() {
  major=$(node_major 2>/dev/null || printf '0')
  if node_runtime_supported; then
    log "复用 Node.js $(node --version) ($(command -v node))"
    return
  fi

  if [ "$major" -ge "$NODE_REQUIRED_MAJOR" ] 2>/dev/null && [ "$NODE_VERSION_EXPLICIT" -eq 0 ]; then
    warn "检测到 Node.js $(node --version)；当前安装链路仅复用 Node 22/24 LTS，将切换到 Node.js $NODE_VERSION_SPEC"
  fi

  manager=$(detect_node_manager)
  # detect 给出 standalone 有两种情况：(a) 当前 node 就是之前装在 NODE_ROOT/BIN_DIR 的独立
  # 安装 —— 沿用它；(b) 机器上没有任何 Node 管理器，兜底才回落 standalone。(b) 会直接解压官方
  # tarball 到用户目录，装出来的 Node 之后无法换版本、也不归任何管理器管，所以默认改成先装
  # fnm 再由 fnm 装 Node。用户显式指定 BOTMUX_NODE_MANAGER 时完全尊重，不插手；fnm 装不上
  # 仍回退 standalone。
  if [ "$manager" = standalone ] && [ "$NODE_MANAGER_REQUEST" = auto ]; then
    existing_node=$(command -v node 2>/dev/null || true)
    case "$existing_node" in
      "$NODE_ROOT"/*|"$BIN_DIR"/node) ;;                      # (a) 沿用已有独立安装
      *) install_fnm && manager=fnm ;;                        # (b) 默认改走 fnm
    esac
  fi
  if [ "$DRY_RUN" -eq 1 ]; then
    if [ "$manager" = standalone ]; then
      install_standalone_node
    else
      log "检测到 Node.js ${major:-0}，将沿用 $manager 升级到 Node.js $NODE_VERSION_SPEC"
    fi
    return
  fi

  if [ "$manager" != standalone ] && upgrade_node_with_manager "$manager"; then
    log "Node.js 已通过 $manager 升级为 $(node --version) ($(command -v node))"
    return
  fi
  if [ "$manager" != standalone ]; then
    warn "$manager 升级未成功，回退到用户目录独立安装；不会覆盖该管理器的配置"
  fi
  install_standalone_node
}

npm_user_install() {
  if [ "$DRY_RUN" -eq 1 ]; then
    printf '+ npm install -g --prefix %s' "$INSTALL_ROOT"
    printf ' %s' "$@"
    printf '\n'
    return 0
  fi
  run_with_network_retry "npm 安装 $*" npm install -g --prefix "$INSTALL_ROOT" "$@"
}

activate_homebrew_path() {
  if command -v brew >/dev/null 2>&1; then return 0; fi
  for brew_bin in $HOMEBREW_BIN_CANDIDATES; do
    [ -x "$brew_bin" ] || continue
    brew_shellenv=$($brew_bin shellenv 2>/dev/null || true)
    if [ -n "$brew_shellenv" ]; then eval "$brew_shellenv"
    else PATH="$(dirname "$brew_bin"):$PATH"; export PATH
    fi
    hash -r 2>/dev/null || true
    command -v brew >/dev/null 2>&1 && return 0
  done
  return 1
}

homebrew_runtime_compatible() {
  brew config >/dev/null 2>&1
}

# 旧 Homebrew 遇到「已用新 DSL 的 formula」会直接报错中止，典型是
#   Error: ... undefined method `post_install_steps' for ... FormulaNamespace...
# 成因：formula 仓（homebrew-core）滚动更新，而本机 brew 主程序很旧、不认识新 DSL。
# 这种情况下 `brew config` 是【成功】的（macOS 版本能识别），所以
# repair_homebrew_macos_compat 那套「只在 brew config 报 unknown macOS 时才修」检查不出来
# ——真实用户就是这样被卡住的（openssl@3 作为 node 的依赖被拉起时炸）。
# 另外我们默认设了 HOMEBREW_NO_AUTO_UPDATE=1（为避免每次 brew install 前隐式 git fetch 卡住），
# 这同时也抑制了 Homebrew 本来会自愈的自动更新，等于把这个坑放大了。
#
# 故：把所有 brew install/upgrade 都包一层——首次失败且错误像 DSL 不兼容，就更新 Homebrew
# 并【只重试一次】。非 DSL 类失败原样返回，让调用方拿到它自己的精确报错。
brew_error_is_stale_dsl() {
  grep -qE "undefined method .* for .*Formula|unknown method|NoMethodError|invalid formula|Please update Homebrew|outdated Homebrew" "$1" 2>/dev/null
}

run_brew_with_dsl_retry() {
  brew_label=$1
  shift
  brew_log=$(mktemp "${TMPDIR:-/tmp}/botmux-brew-run.XXXXXX")
  # 先【裸跑一次】而不是直接交给 run_with_network_retry：DSL 不兼容跟网络无关，
  # 套着网络重试会先白跑一整次代理重试（brew install 很慢），才轮到更新 Homebrew。
  if "$@" >"$brew_log" 2>&1; then
    cat "$brew_log"; rm -f "$brew_log"; return 0
  fi
  brew_rc=$?
  if brew_error_is_stale_dsl "$brew_log"; then
    cat "$brew_log" >&2
    rm -f "$brew_log"
    warn "${brew_label}失败，报错像是本机 Homebrew 过旧、不认识新版 formula 语法；先更新 Homebrew 再重试一次"
    if ! run_homebrew_compat_update; then
      warn "Homebrew 更新失败；保留原始报错"
      return "$brew_rc"
    fi
    hash -r 2>/dev/null || true
    run_with_network_retry "${brew_label}（更新 Homebrew 后重试）" "$@"
    return $?
  fi
  # 不是 DSL 问题：交回既有的「失败切代理重试一次」链路，行为与改动前一致。
  cat "$brew_log" >&2
  rm -f "$brew_log"
  run_with_network_retry "$brew_label" "$@"
}

run_homebrew_compat_update() {
  if [ "$PROXY_FALLBACK_ACTIVE" -eq 1 ] || [ "$DISABLE_PROXY_FALLBACK" = 1 ] || [ -z "$FALLBACK_HTTP_PROXY" ]; then
    if brew update; then return 0; else homebrew_update_rc=$?; fi
    hash -r 2>/dev/null || true
    if homebrew_runtime_compatible; then
      warn "Homebrew 主程序已更新；忽略不影响 tmux 安装的附加 tap 更新错误"
      return 0
    fi
    return "$homebrew_update_rc"
  fi

  log "Homebrew 更新 优先使用 HTTP 代理"
  if run_with_fallback_proxy brew update; then return 0; else homebrew_update_rc=$?; fi
  hash -r 2>/dev/null || true
  if homebrew_runtime_compatible; then
    warn "Homebrew 主程序已通过 HTTP 代理更新；忽略不影响 tmux 安装的附加 tap 更新错误"
    return 0
  fi

  warn "Homebrew 更新通过 HTTP 代理失败，使用当前网络重试一次"
  if brew update; then return 0; else homebrew_update_rc=$?; fi
  hash -r 2>/dev/null || true
  if homebrew_runtime_compatible; then
    warn "Homebrew 主程序已更新；忽略不影响 tmux 安装的附加 tap 更新错误"
    return 0
  fi
  return "$homebrew_update_rc"
}

repair_homebrew_macos_compat() {
  command -v brew >/dev/null 2>&1 || return 0
  brew_check_log=$(mktemp "${TMPDIR:-/tmp}/botmux-brew-check.XXXXXX")
  if brew config >"$brew_check_log" 2>&1; then
    rm -f "$brew_check_log"
    return 0
  fi
  if ! grep -q 'unknown or unsupported macOS version' "$brew_check_log"; then
    # A non-version-related `brew config` failure should not prevent the
    # actual install command from trying and reporting its own precise error.
    rm -f "$brew_check_log"
    return 0
  fi

  macos_version=$(sw_vers -productVersion 2>/dev/null || printf 'unknown')
  log "现有 Homebrew 版本无法识别 macOS ${macos_version}，先更新 Homebrew"
  if ! run_homebrew_compat_update; then
    rm -f "$brew_check_log"
    die "Homebrew 更新失败，无法为当前 macOS 安装 tmux"
  fi
  hash -r 2>/dev/null || true
  if ! brew config >"$brew_check_log" 2>&1; then
    cat "$brew_check_log" >&2
    rm -f "$brew_check_log"
    die "Homebrew 更新后仍无法识别 macOS ${macos_version}"
  fi
  rm -f "$brew_check_log"
  log "Homebrew 已更新并支持当前 macOS"
}

ensure_homebrew_for_tmux() {
  [ "$NODE_OS" = darwin ] || return 0
  [ "$INSTALL_SYSTEM_DEPS" -eq 1 ] || return 0
  command -v tmux >/dev/null 2>&1 && return 0
  activate_homebrew_path || true
  command -v tmux >/dev/null 2>&1 && return 0
  install_uid=$(id -u 2>/dev/null) || die "无法通过 id -u 读取当前用户 uid"
  if [ "$install_uid" -eq 0 ]; then
    die "macOS 的 Homebrew 不支持 root 安装 tmux；请先用普通 macOS 用户安装 tmux，再重新运行"
  fi
  if [ "$DRY_RUN" -eq 1 ]; then
    if command -v brew >/dev/null 2>&1; then log "macOS 未检测到 tmux；将通过 Homebrew 安装"
    else log "macOS 未检测到 tmux/Homebrew；将先安装 Homebrew（配置了 BOTMUX_HTTP_PROXY 时优先走代理），再安装 tmux"
    fi
    return 0
  fi

  if ! command -v brew >/dev/null 2>&1; then
    tmp=$(mktemp "${TMPDIR:-/tmp}/botmux-homebrew.XXXXXX")
    download_script_proxy_preferred "https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh" "$tmp"
    if needs_tty_redirect; then
      run_with_proxy_preferred "Homebrew 安装" env NONINTERACTIVE=1 /bin/bash "$tmp" </dev/tty
    else
      run_with_proxy_preferred "Homebrew 安装" env NONINTERACTIVE=1 /bin/bash "$tmp"
    fi
    rm -f "$tmp"
    activate_homebrew_path || die "Homebrew 安装完成但当前 shell 找不到 brew"
  fi

  repair_homebrew_macos_compat
  log "macOS 安装系统依赖 tmux"
  # 走代理优先，但同样要接住「brew 过旧、formula DSL 领先」——tmux 自身依赖链
  # （如 openssl@3）也可能命中新 DSL。
  if ! run_with_proxy_preferred "Homebrew 安装 tmux" brew install tmux; then
    warn "Homebrew 安装 tmux 首次失败，尝试更新 Homebrew 后重试一次"
    if run_homebrew_compat_update; then
      hash -r 2>/dev/null || true
      run_with_proxy_preferred "Homebrew 安装 tmux（更新后重试）" brew install tmux \
        || die "Homebrew 安装 tmux 失败"
    else
      die "Homebrew 安装 tmux 失败"
    fi
  fi
  hash -r 2>/dev/null || true
  command -v tmux >/dev/null 2>&1 || die "Homebrew 已返回成功，但当前 shell 仍找不到 tmux"
  log "tmux 已通过 Homebrew 安装：$(tmux -V 2>/dev/null || printf 'version unknown')"
}

find_system_bwrap() {
  old_ifs=$IFS
  IFS=:
  for path_dir in $PATH; do
    IFS=$old_ifs
    [ -n "$path_dir" ] || path_dir=.
    candidate="$path_dir/bwrap"
    if [ -x "$candidate" ] && ! "$candidate" --version 2>/dev/null | grep -qi 'built for Codex'; then
      printf '%s\n' "$candidate"
      return 0
    fi
    IFS=:
  done
  IFS=$old_ifs
  return 1
}

# 老发行版（如 Debian 10）的 `python3` 包只提供 <3.8，apt 会因「已是最新」直接报成功；
# 源里的 ≥3.8 通常是带版本号的包（python3.11 等，装为 /usr/bin/python3.11，不改默认
# python3）。按新到旧逐个尝试，直到 find_modern_python 能找到达标解释器；全部失败返回非 0。
install_versioned_python() {
  ivp_manager=$1
  ivp_privilege=$2
  case "$ivp_manager" in
    apt-get) ivp_candidates="python3.12 python3.11 python3.10 python3.9 python3.8" ;;
    dnf|yum) ivp_candidates="python3.12 python3.11 python3.9 python39 python38" ;;
    zypper) ivp_candidates="python312 python311 python310 python39" ;;
    *) return 1 ;; # pacman/apk 的 python(3) 本身即新版，没有带版本号的包可试
  esac
  for ivp_package in $ivp_candidates; do
    log "尝试通过 $ivp_manager 安装带版本号的 Python: $ivp_package"
    case "$ivp_manager" in
      apt-get) ivp_argv="$ivp_privilege apt-get install -y $ivp_package" ;;
      dnf) ivp_argv="$ivp_privilege dnf install -y $ivp_package" ;;
      yum) ivp_argv="$ivp_privilege yum install -y $ivp_package" ;;
      zypper) ivp_argv="$ivp_privilege zypper install -y $ivp_package" ;;
    esac
    # 源里没有该包属预期失败，静默换下一个候选；ivp_argv 只含上面挑选的安装器字面量。
    # shellcheck disable=SC2086
    if $ivp_argv >/dev/null 2>&1; then
      hash -r 2>/dev/null || true
      if find_modern_python >/dev/null 2>&1; then return 0; fi
    fi
  done
  return 1
}

ensure_linux_system_deps_preflight() {
  [ "$NODE_OS" = linux ] || return 0
  [ "$INSTALL_SYSTEM_DEPS" -eq 1 ] || return 0

  need_tmux=0
  command -v tmux >/dev/null 2>&1 || need_tmux=1
  system_bwrap=$(find_system_bwrap 2>/dev/null || true)
  need_bwrap=0
  [ -n "$system_bwrap" ] || need_bwrap=1
  # botmux 3.18 起走 bun 单文件二进制、不再现场编译 node-pty，故默认不为编译安装 Python/
  # 工具链。仅当显式 BOTMUX_INSTALL_BUILD_DEPS=1（为可能需 node-gyp 的 agent CLI 铺路）时才探测。
  need_python=0
  need_toolchain=0
  if [ "$INSTALL_BUILD_DEPS" -eq 1 ]; then
    find_modern_python >/dev/null 2>&1 || need_python=1
    if ! { command -v cc >/dev/null 2>&1 || command -v gcc >/dev/null 2>&1; } \
       || ! { command -v c++ >/dev/null 2>&1 || command -v g++ >/dev/null 2>&1; } \
       || ! command -v make >/dev/null 2>&1; then
      need_toolchain=1
    fi
  fi

  [ "$need_tmux" -eq 1 ] || [ "$need_bwrap" -eq 1 ] || [ "$need_python" -eq 1 ] || [ "$need_toolchain" -eq 1 ] || return 0

  install_uid=$(id -u 2>/dev/null) || die "无法通过 id -u 读取当前用户 uid"
  if [ "$install_uid" -eq 0 ]; then
    privilege=""
  elif command -v sudo >/dev/null 2>&1 && sudo -n true >/dev/null 2>&1; then
    privilege="sudo -n"
  else
    # Do not introduce an extra password prompt here. Botmux can still offer
    # its interactive tmux fallback; Codex can use its bundled bubblewrap.
    return 0
  fi

  manager=""
  for candidate in apt-get dnf yum pacman apk zypper; do
    if command -v "$candidate" >/dev/null 2>&1; then manager=$candidate; break; fi
  done
  [ -n "$manager" ] || return 0

  # python 与工具链的包名在各发行版不同，需按包管理器拼装。
  packages=""
  [ "$need_tmux" -eq 1 ] && packages="tmux"
  [ "$need_bwrap" -eq 1 ] && packages="${packages:+$packages }bubblewrap"
  case "$manager" in
    apt-get)
      [ "$need_python" -eq 1 ] && packages="${packages:+$packages }python3"
      [ "$need_toolchain" -eq 1 ] && packages="${packages:+$packages }build-essential"
      ;;
    dnf|yum|zypper)
      [ "$need_python" -eq 1 ] && packages="${packages:+$packages }python3"
      [ "$need_toolchain" -eq 1 ] && packages="${packages:+$packages }gcc-c++ make"
      ;;
    pacman)
      [ "$need_python" -eq 1 ] && packages="${packages:+$packages }python"
      [ "$need_toolchain" -eq 1 ] && packages="${packages:+$packages }gcc make"
      ;;
    apk)
      [ "$need_python" -eq 1 ] && packages="${packages:+$packages }python3"
      [ "$need_toolchain" -eq 1 ] && packages="${packages:+$packages }build-base"
      ;;
  esac
  [ -n "$packages" ] || return 0

  if [ "$DRY_RUN" -eq 1 ]; then
    log "Linux 检测到可无交互使用 ${manager}；将安装系统依赖: $packages"
    return 0
  fi

  log "Linux 使用系统包管理器 $manager 安装依赖: $packages"
  case "$manager" in
    apt-get)
      # shellcheck disable=SC2086
      run_with_network_retry "apt 更新软件索引" $privilege apt-get update || true
      # shellcheck disable=SC2086
      argv="$privilege apt-get install -y $packages"
      ;;
    dnf) argv="$privilege dnf install -y $packages" ;;
    yum) argv="$privilege yum install -y $packages" ;;
    pacman) argv="$privilege pacman -S --noconfirm $packages" ;;
    apk) argv="$privilege apk add $packages" ;;
    zypper) argv="$privilege zypper install -y $packages" ;;
  esac
  # argv contains only installer-owned literals selected above.
  # shellcheck disable=SC2086
  if run_with_network_retry "$manager 安装 Linux 系统依赖" $argv; then
    hash -r 2>/dev/null || true
    if command -v tmux >/dev/null 2>&1; then
      log "tmux 已通过 $manager 安装：$(tmux -V 2>/dev/null || printf 'version unknown')"
    fi
    system_bwrap=$(find_system_bwrap 2>/dev/null || true)
    if [ -n "$system_bwrap" ]; then
      log "bubblewrap 已通过 $manager 安装：$($system_bwrap --version 2>/dev/null || printf 'version unknown') ($system_bwrap)"
    fi
    command -v tmux >/dev/null 2>&1 || warn "tmux 安装命令成功但 PATH 中仍未找到，将交给 Botmux 继续检测"
    [ -n "$system_bwrap" ] || warn "bubblewrap 安装命令成功但 PATH 中仍未找到系统版本；Codex 将暂用 bundled bubblewrap"
  else
    warn "$manager 安装 Linux 系统依赖未成功；Botmux/Codex 将使用各自 fallback"
  fi

  # 不论主安装成败都要兜底：主安装可能因别的包（如 bubblewrap 不在源里）整体失败，
  # 也可能「成功」但发行版 `python3` 包本身 <3.8——两种情况都改试带版本号的包。
  # 仅在显式要求装编译依赖（INSTALL_BUILD_DEPS=1）时才走这段；botmux 本身不需要。
  if [ "$need_python" -eq 1 ] && ! find_modern_python >/dev/null 2>&1; then
    if install_versioned_python "$manager" "$privilege"; then
      versioned_python=$(find_modern_python)
      log "已安装 Python: $versioned_python ($("$versioned_python" --version 2>&1))"
    else
      warn "系统源未能提供 Python ≥3.8（当前 python3: $(python3_version_desc)）；如某 agent CLI 需 node-gyp 现场编译将失败"
    fi
  fi
}

linux_linger_enabled() {
  linger_user=$1
  loginctl show-user "$linger_user" --property=Linger 2>/dev/null | grep -q '^Linger=yes$'
}

ensure_linux_linger() {
  [ "$NODE_OS" = linux ] || return 0
  command -v loginctl >/dev/null 2>&1 || {
    warn "系统未提供 loginctl，无法自动开启 Linger；登出后 Botmux 服务可能停止"
    return 0
  }

  linger_user=$(id -un 2>/dev/null) || {
    warn "无法确定当前用户名，跳过自动开启 Linger"
    return 0
  }
  if linux_linger_enabled "$linger_user"; then
    log "Linger 已启用：Botmux 服务可跨登出和重启常驻"
    return 0
  fi

  install_uid=$(id -u 2>/dev/null) || {
    warn "无法读取当前用户 uid，跳过自动开启 Linger"
    return 0
  }
  linger_command_ok=0
  if [ "$install_uid" -eq 0 ]; then
    loginctl enable-linger "$linger_user" && linger_command_ok=1
  elif command -v sudo >/dev/null 2>&1 && sudo -n true >/dev/null 2>&1; then
    sudo -n loginctl enable-linger "$linger_user" && linger_command_ok=1
  else
    warn "当前用户没有免密 sudo，无法自动开启 Linger；登出后 Botmux 服务可能停止"
    warn "可稍后运行: sudo loginctl enable-linger ${linger_user}"
    return 0
  fi

  if [ "$linger_command_ok" -eq 1 ] && linux_linger_enabled "$linger_user"; then
    log "已自动开启 Linger：Botmux 服务可跨登出和重启常驻"
  else
    warn "Linger 自动开启未生效；可稍后运行: sudo loginctl enable-linger ${linger_user}"
  fi
}

agent_logged_in() {
  case "$1" in
    codex)
      command -v codex >/dev/null 2>&1 && codex_has_official_subscription
      ;;
    claude-code) command -v claude >/dev/null 2>&1 && claude auth status >/dev/null 2>&1 ;;
    *) profile_agent_logged_in "$1" ;;
  esac
}

installed_cli() {
  case "$1" in
    codex) command -v codex >/dev/null 2>&1 ;;
    claude-code) command -v claude >/dev/null 2>&1 ;;
    *) profile_installed_cli "$1" ;;
  esac
}

detect_preferred_cli() {
  for cli in $AGENT_CLIS; do
    if agent_logged_in "$cli"; then printf '%s\n' "$cli"; return; fi
  done
  for cli in $AGENT_CLIS; do
    if installed_cli "$cli"; then printf '%s\n' "$cli"; return; fi
  done
  printf '%s\n' "${AGENT_CLIS%% *}"
}

install_claude() {
  if command -v claude >/dev/null 2>&1; then
    log "复用 Claude Code $(claude --version 2>/dev/null | head -n 1)"
    return
  fi
  log "安装 Claude Code"
  npm_user_install "@anthropic-ai/claude-code@latest" || warn "Claude Code 安装失败，可稍后重试"
}

codex_version() {
  codex --version 2>/dev/null | awk '{
    for (i=1; i<=NF; i++) if ($i ~ /^v?[0-9]+\.[0-9]+\.[0-9]+/) {
      sub(/^v/, "", $i); print $i; exit
    }
  }'
}

version_is_newer() {
  latest=$1
  current=$2
  node -e '
    const base = (v) => v.replace(/^v/, "").split("-")[0].split(".").map(Number);
    const [a,b] = [base(process.argv[1]), base(process.argv[2])];
    for (let i=0; i<3; i++) {
      if ((a[i]||0) > (b[i]||0)) process.exit(0);
      if ((a[i]||0) < (b[i]||0)) process.exit(1);
    }
    const latestStable = !process.argv[1].includes("-");
    const currentPrerelease = process.argv[2].includes("-");
    process.exit(latestStable && currentPrerelease ? 0 : 1);
  ' "$latest" "$current"
}

install_codex_from_registry() {
  npm install -g --prefix "$INSTALL_ROOT" "$CODEX_PACKAGE" --registry "$CODEX_REGISTRY"
}

install_codex() {
  if command -v codex >/dev/null 2>&1; then
    current=$(codex_version)
    log "检测到现有 Codex ${current:-version unknown} ($(command -v codex))"
    if [ "$DRY_RUN" -eq 1 ]; then
      log "将查询 ${CODEX_REGISTRY}；仅在存在更高稳定版时更新 Codex"
      return
    fi
    latest=$(run_with_network_retry "查询 Codex 最新版本" \
      npm view "$CODEX_PACKAGE" version --registry "$CODEX_REGISTRY" 2>/dev/null || true)
    if [ -z "$latest" ]; then
      warn "无法查询 Codex 最新版本，继续复用现有版本"
      return
    fi
    if [ -z "$current" ] || version_is_newer "$latest" "$current"; then
      log "更新 Codex：${current:-unknown} → ${latest}（${CODEX_REGISTRY}）"
      if install_codex_from_registry; then
        hash -r 2>/dev/null || true
        log "Codex 更新完成：$(codex --version 2>/dev/null | head -n 1)"
      else
        warn "Codex 更新失败，保留现有可用版本 $current"
      fi
    else
      log "Codex 已是最新稳定版（${current}）"
    fi
    return
  fi
  log "安装 Codex（优先使用 npm 源 ${CODEX_REGISTRY}）"
  if [ "$DRY_RUN" -eq 1 ]; then
    printf '+ npm install -g --prefix %s %s --registry %s\n' "$INSTALL_ROOT" "$CODEX_PACKAGE" "$CODEX_REGISTRY"
    printf '# 上述失败后：下载 %s 并运行（配置了 BOTMUX_HTTP_PROXY 时经代理）\n' "$CODEX_INSTALL_URL"
    return
  fi

  if install_codex_from_registry; then
    hash -r 2>/dev/null || true
    if command -v codex >/dev/null 2>&1; then
      log "Codex 已通过 npm 源安装：$(codex --version 2>/dev/null | head -n 1)"
      return
    fi
    warn "npm 返回成功但未找到 codex 命令，改用 OpenAI 官方安装器"
  else
    warn "从 npm 源安装 Codex 失败，改用 OpenAI 官方安装器"
  fi

  if [ "$DISABLE_PROXY_FALLBACK" != 1 ]; then
    activate_proxy_fallback || true
  else
    warn "已禁用自动代理，将使用用户当前网络尝试公网安装器"
  fi
  log "尝试 Codex 公网 fallback（OpenAI 官方 standalone installer）"
  tmp=$(mktemp "${TMPDIR:-/tmp}/botmux-codex.XXXXXX")
  if download_script "$CODEX_INSTALL_URL" "$tmp" && \
     run_with_network_retry "Codex 安装" sh "$tmp"; then :
  else warn "Codex 安装失败，可稍后重试"; fi
  rm -f "$tmp"
}

codex_has_official_subscription() {
  command -v codex >/dev/null 2>&1 || return 1
  status=$(codex login status 2>&1 || true)
  printf '%s\n' "$status" | grep -qi 'logged in using chatgpt'
}

configure_codex_access() {
  command -v codex >/dev/null 2>&1 || return 0
  if codex_has_official_subscription; then
    log "检测到 Codex 已通过 ChatGPT 官方订阅登录"
    return 0
  fi
  warn "Codex 未检测到 ChatGPT 官方订阅登录；Codex CLI 已安装，首次使用前需自行完成认证"
}

warmup_agent_tui() {
  agent_name=$1
  agent_bin=$2
  warmup_timeout_sec="${BOTMUX_AGENT_WARMUP_TIMEOUT_SEC:-120}"
  botmux_module_root="$INSTALL_ROOT/lib/node_modules/botmux"
  node_pty_module=$(node -e '
    try { process.stdout.write(require.resolve("node-pty", { paths: [process.argv[1]] })); }
    catch { process.exit(1); }
  ' "$botmux_module_root" 2>/dev/null || true)
  if [ -z "$node_pty_module" ]; then
    warn "未找到 Botmux 自带的 node-pty，跳过 $agent_name 后台预热"
    return 1
  fi

  log "后台预热 ${agent_name}：首次打开并确认欢迎页、目录和 hooks 信任（最长 ${warmup_timeout_sec} 秒）"
  warmup_script=$(mktemp "${TMPDIR:-/tmp}/botmux-agent-warmup.XXXXXX.cjs")
  cat > "$warmup_script" <<'NODE'
const pty = require(process.env.BOTMUX_NODE_PTY_MODULE);

const bin = process.env.BOTMUX_AGENT_BIN;
const cwd = process.env.BOTMUX_AGENT_CWD;
const agentName = process.env.BOTMUX_AGENT_NAME;
const warmupTimeoutMs = Math.max(30, Number(process.env.BOTMUX_AGENT_WARMUP_TIMEOUT_SEC) || 120) * 1000;
const env = { ...process.env, TERM: 'xterm-256color', COLORTERM: 'truecolor' };
delete env.BOTMUX_NODE_PTY_MODULE;
delete env.BOTMUX_AGENT_BIN;
delete env.BOTMUX_AGENT_CWD;
delete env.BOTMUX_AGENT_NAME;
delete env.BOTMUX_AGENT_WARMUP_TIMEOUT_SEC;

let child;
try {
  child = pty.spawn(bin, ['--no-alt-screen'], {
    name: 'xterm-256color', cols: 100, rows: 32, cwd, env,
  });
} catch (error) {
  const message = error instanceof Error ? error.message : String(error);
  console.error(`[botmux] ${agentName} 预热启动失败: ${message}`);
  process.exit(2);
}
let screen = '';
let stage = 0;
let finishing = false;
let settled = false;

function plain(value) {
  return value
    .replace(/\x1b\][^\x07]*(?:\x07|\x1b\\)/g, '')
    .replace(/\x1b\[[0-?]*[ -/]*[@-~]/g, '')
    .replace(/\r/g, '');
}
function pressEnter(nextStage) {
  stage = Math.max(stage, nextStage);
  screen = '';
  child.write('\r');
}
function finishOk() {
  if (finishing) return;
  finishing = true;
  // Codex intentionally requires Ctrl-C twice to quit an idle TUI.
  setTimeout(() => child.write('\x03'), 200);
  setTimeout(() => child.write('\x03\x03'), 700);
  setTimeout(() => { try { child.kill(); } catch {} }, 2500);
}

child.onData((chunk) => {
  screen = (screen + plain(chunk)).slice(-30000);

  if (stage <= 1 && !screen.includes('Sign in with') && screen.includes('Press') &&
      (screen.includes('Before you start') || screen.includes('Welcome to Codex'))) {
    pressEnter(2);
    return;
  }
  // Cursor-addressed redraws can split the question text in captured output;
  // the two option labels are stable and unique to the directory-trust page.
  if (stage < 3 && screen.includes('Yes, continue') && screen.includes('No,') && screen.includes('quit')) {
    pressEnter(3);
    return;
  }
  if (stage < 4 && screen.includes('Hooks need review') && screen.includes('Trust all and continue')) {
    // Current Codex releases preselect option 2 here; Enter persists trust.
    pressEnter(4);
    return;
  }
  if (screen.includes('Context 100% left') || screen.includes('Write tests for @filename') || screen.includes('Tip: Use /hooks')) {
    finishOk();
  }
});

const heartbeat = setInterval(() => {
  const detail = stage < 3
    ? '首次启动确认'
    : stage < 4
      ? 'hooks 信任确认'
      : '主界面就绪';
  process.stderr.write(`[botmux] ${agentName} 预热仍在等待${detail}（当前阶段 ${stage}）…\n`);
}, 30000);

const timeout = setTimeout(() => {
  if (settled) return;
  console.error(`${agentName} warmup timed out at stage ${stage}`);
  try { child.kill(); } catch {}
}, warmupTimeoutMs);

child.onExit(() => {
  settled = true;
  clearTimeout(timeout);
  clearInterval(heartbeat);
  process.exit(finishing ? 0 : 2);
});
NODE

  if BOTMUX_NODE_PTY_MODULE="$node_pty_module" \
    BOTMUX_AGENT_BIN="$agent_bin" \
    BOTMUX_AGENT_CWD="$HOME" \
    BOTMUX_AGENT_NAME="$agent_name" \
    BOTMUX_AGENT_WARMUP_TIMEOUT_SEC="$warmup_timeout_sec" \
    node "$warmup_script" </dev/null; then
    log "$agent_name 首次启动预热完成"
    result=0
  else
    result=$?
    warn "$agent_name 后台预热未完成；安装不受影响，首次使用时可能仍需手动确认"
  fi
  rm -f "$warmup_script"
  return "$result"
}

verify_codex_health() {
  report=$(codex doctor --json 2>/dev/null || true)
  if [ -z "$report" ]; then
    warn "Codex doctor 未返回结果，无法完成自动健康检查"
    return 1
  fi
  if printf '%s' "$report" | node -e '
    let s=""; process.stdin.on("data",d=>s+=d).on("end",()=>{
      try {
        const r=JSON.parse(s), c=r.checks||{};
        const required=["installation","config.load"];
        if (process.env.BOTMUX_CODEX_OFFICIAL === "1") required.push("auth.credentials");
        const bad=required.some(k=>!c[k] || c[k].status==="fail");
        const providerBad=c["network.provider_reachability"]?.status === "fail";
        process.exit(bad || providerBad ? 1 : 0);
      } catch { process.exit(1); }
    });
  '; then
    log "Codex doctor 核心检查通过"
    return 0
  fi
  warn "Codex 已能启动，但 doctor 仍报告配置/认证/模型网络异常；可运行 codex doctor --summary 排查"
  return 1
}

warmup_codex() {
  [ "$WARMUP_CODEX" -eq 1 ] || return 0
  command -v codex >/dev/null 2>&1 || { warn "Codex 未安装成功，跳过首次启动验证"; return 0; }
  if [ "$DRY_RUN" -eq 1 ]; then
    log "将后台首次打开 Codex，并运行 codex doctor 健康检查"
    return 0
  fi
  if ! codex_has_official_subscription; then
    warn "Codex 尚未登录 ChatGPT 官方订阅，跳过 TUI 预热以避免卡在登录页"
    return 0
  fi
  if warmup_agent_tui Codex "$(command -v codex)"; then warmup_mark_done Codex; fi
  if codex_has_official_subscription; then BOTMUX_CODEX_OFFICIAL=1
  else BOTMUX_CODEX_OFFICIAL=0
  fi
  export BOTMUX_CODEX_OFFICIAL
  verify_codex_health || true
  unset BOTMUX_CODEX_OFFICIAL
}

run_agent_warmups() {
  warmup_codex
}

agent_warmup_enabled() {
  [ "$WARMUP_CODEX" -eq 1 ]
}

# Extra flags handing the parent's warmup choices to the detached worker.
agent_warmup_worker_args() { :; }

# 记录「本次真的预热了哪些 agent」。DONE_FILE 只表示 worker 跑完了，不代表真做了事：
# codex 未登录 ChatGPT 官方订阅会直接跳过，没装的 agent 也会跳过。全都跳过时若仍报
# 「预热已完成」就是假信息，所以把实际预热过的 agent 名字写进这个文件，由收尾据实播报。
warmup_mark_done() {
  [ -n "${WARMUP_RESULT_FILE:-}" ] || return 0
  # 同步路径（--wait-agent-warmup / 主流程直跑）不会经过 worker 的 mkdir，这里自己兜底建目录，
  # 且任何失败都不能影响安装——这只是一行播报用的记录。
  mkdir -p "$WARMUP_STATE_DIR" 2>/dev/null || return 0
  printf '%s\n' "$1" >> "$WARMUP_RESULT_FILE" 2>/dev/null || true
}

run_agent_warmup_worker() {
  umask 077
  mkdir -p "$WARMUP_STATE_DIR"
  BOTMUX_AGENT_WARMUP_AUTH_FILE="$WARMUP_AUTH_FILE"
  export BOTMUX_AGENT_WARMUP_AUTH_FILE
  run_agent_warmups
  rm -f "$WARMUP_AUTH_FILE"
  : > "$WARMUP_DONE_FILE"
  rm -f "$WARMUP_PID_FILE"
  log "异步预热任务结束"
}

persist_warmup_worker_script() {
  worker_dir="$INSTALL_ROOT/share/botmux/installer"
  worker_script="$worker_dir/install.sh"
  worker_tmp="$worker_script.$$"
  mkdir -p "$worker_dir"
  if [ -f "$0" ] && [ "$(sed -n '1p' "$0" 2>/dev/null || true)" = '#!/bin/sh' ]; then
    cp "$0" "$worker_tmp"
  else
    # `curl install.sh | sh` 没有可复制的脚本文件，只能按 SCRIPT_URL 重新下载。
    [ -n "$SCRIPT_URL" ] || return 1
    download_script "$SCRIPT_URL" "$worker_tmp"
  fi
  chmod 700 "$worker_tmp"
  mv "$worker_tmp" "$worker_script"
  printf '%s\n' "$worker_script"
}

start_agent_warmups_async() {
  agent_warmup_enabled || return 0
  if [ "$DRY_RUN" -eq 1 ]; then
    log "将把 ${WARMUP_AGENT_NAMES} 首次启动预热放到后台，不阻塞安装"
    return 0
  fi
  mkdir -p "$WARMUP_STATE_DIR"
  chmod 700 "$WARMUP_STATE_DIR" 2>/dev/null || true
  if [ -f "$WARMUP_PID_FILE" ]; then
    old_warmup_pid=$(cat "$WARMUP_PID_FILE" 2>/dev/null || true)
    case "$old_warmup_pid" in
      ''|*[!0-9]*) ;;
      *)
        if kill -0 "$old_warmup_pid" 2>/dev/null; then
          log "${WARMUP_AGENT_NAMES} 异步预热已在运行（pid=${old_warmup_pid}，日志: ${WARMUP_LOG_FILE}）"
          return 0
        fi
        ;;
    esac
  fi

  worker_script=$(persist_warmup_worker_script) || {
    warn "无法准备异步预热脚本；改为当前进程预热"
    run_agent_warmups
    return 0
  }
  rm -f "$WARMUP_DONE_FILE" "$WARMUP_AUTH_FILE" "$WARMUP_RESULT_FILE"
  : > "$WARMUP_LOG_FILE"
  chmod 600 "$WARMUP_LOG_FILE" 2>/dev/null || true
  set -- --agent-warmup-worker --no-setup --no-start --no-system-deps
  [ "$WARMUP_CODEX" -eq 1 ] || set -- "$@" --no-codex-warmup
  set -- "$@" $(agent_warmup_worker_args)
  nohup env \
    BOTMUX_INSTALL_ROOT="$INSTALL_ROOT" \
    BOTMUX_WARMUP_STATE_DIR="$WARMUP_STATE_DIR" \
    BOTMUX_AGENT_WARMUP_TIMEOUT_SEC="${BOTMUX_AGENT_WARMUP_TIMEOUT_SEC:-600}" \
    PATH="$PATH" \
    /bin/sh "$worker_script" "$@" \
    > "$WARMUP_LOG_FILE" 2>&1 </dev/null &
  warmup_pid=$!
  printf '%s\n' "$warmup_pid" > "$WARMUP_PID_FILE"
  log "${WARMUP_AGENT_NAMES} 首次启动预热已转入后台（pid=${warmup_pid}），不再阻塞安装"
  log "预热日志: $WARMUP_LOG_FILE"
}

report_agent_warmup_status() {
  [ "$INSTALL_AGENTS" -eq 1 ] || return 0
  [ "$WAIT_AGENT_WARMUP" -eq 0 ] || return 0
  agent_warmup_enabled || return 0
  if [ -f "$WARMUP_DONE_FILE" ]; then
    # DONE_FILE 只说明 worker 跑完了。真正预热过的 agent 记在 RESULT_FILE 里——
    # codex 未登录官方订阅、agent 未安装等情况会跳过预热，此时不能报「预热已完成」。
    warmed=""
    if [ -s "$WARMUP_RESULT_FILE" ]; then
      warmed=$(tr '\n' ' ' < "$WARMUP_RESULT_FILE" | sed 's/ *$//; s/ /\//g')
    fi
    if [ -n "$warmed" ]; then
      log "$warmed 后台预热已完成"
    else
      log "后台预热任务已结束（无需预热：agent 未安装或尚未登录，不影响使用）"
    fi
    return 0
  fi
  if [ -s "$WARMUP_AUTH_FILE" ]; then
    warn "后台预热需要一次授权（安装和 Botmux 使用不受阻塞）："
    cat "$WARMUP_AUTH_FILE" >&2
  fi
  log "${WARMUP_AGENT_NAMES} 仍在后台预热；查看进度: tail -f $WARMUP_LOG_FILE"
}

ensure_lark_cli() {
  if command -v lark-cli >/dev/null 2>&1; then
    log "复用 lark-cli ($(command -v lark-cli))"
    return 0
  fi
  log "安装 lark-cli ($LARK_CLI_PACKAGE)"
  npm_user_install "$LARK_CLI_PACKAGE" "--registry=$LARK_CLI_REGISTRY" \
    || { warn "lark-cli 安装失败，可稍后重试: npm i -g --prefix $INSTALL_ROOT $LARK_CLI_PACKAGE --registry=$LARK_CLI_REGISTRY"; return 1; }
}

# lark-cli 走它自带 app 的用户 OAuth（拿用户身份 token），与 botmux 机器人的 app 身份是两套东西，
# 不复用机器人凭证。装好即可、未登录只提示：登录需要浏览器扫码，不在主流程内发起，以保持全程
# 只有 botmux setup 的两次飞书扫码。
install_lark_cli() {
  ensure_lark_cli || return 0
  if [ "$DRY_RUN" -eq 1 ]; then
    log "将检测 lark-cli 登录态并按需打印登录引导"
    return 0
  fi
  if command -v lark-cli >/dev/null 2>&1; then
    if lark-cli auth status >/dev/null 2>&1; then
      log "lark-cli 已登录"
    else
      warn "lark-cli 尚未登录；如需使用请运行: lark-cli auth login （浏览器扫码授权你的飞书身份）"
    fi
  fi
}

install_extra_clis() {
  install_lark_cli
}

# @install-profile functions

while [ "$#" -gt 0 ]; do
  case "$1" in
    --default-cli)
      [ "$#" -ge 2 ] || die "--default-cli 缺少取值"
      DEFAULT_CLI="$2"
      shift 2
      ;;
    --default-cli=*) DEFAULT_CLI=${1#*=}; shift ;;
    --no-agents) INSTALL_AGENTS=0; shift ;;
    # 已移除 Codex Bridge，此选项保留为 no-op：老版 install.sh 的递归调用会带上它，
    # 不接住会命中下面的「未知参数」直接 die。
    --no-codex-bridge) shift ;;
    --no-codex-warmup) WARMUP_CODEX=0; shift ;;
    --wait-agent-warmup) WAIT_AGENT_WARMUP=1; shift ;;
    --agent-warmup-worker) AGENT_WARMUP_WORKER=1; WAIT_AGENT_WARMUP=1; shift ;;
    --no-setup) RUN_SETUP=0; shift ;;
    --no-start) RUN_START=0; shift ;;
    --no-system-deps) INSTALL_SYSTEM_DEPS=0; shift ;;
    --dry-run) DRY_RUN=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *)
      PROFILE_ARGS_USED=0
      profile_parse_arg "$@" || die "未知参数: $1（用 --help 查看）"
      shift "$PROFILE_ARGS_USED"
      ;;
  esac
done

default_cli_known=0
for cli in auto $AGENT_CLIS; do
  [ "$DEFAULT_CLI" != "$cli" ] || default_cli_known=1
done
[ "$default_cli_known" -eq 1 ] || die "--default-cli 只接受 auto、$(printf '%s' "$AGENT_CLIS" | sed 's/ /、/g')"

OS_NAME=${BOTMUX_INSTALL_OS:-$(uname -s)}
ARCH_NAME=${BOTMUX_INSTALL_ARCH:-$(uname -m)}
case "$OS_NAME" in
  Darwin) NODE_OS=darwin ;;
  Linux) NODE_OS=linux ;;
  *) die "暂不支持 ${OS_NAME}；Windows 请在 WSL 中运行本脚本" ;;
esac
case "$ARCH_NAME" in
  x86_64|amd64) NODE_ARCH=x64 ;;
  arm64|aarch64) NODE_ARCH=arm64 ;;
  *) die "暂不支持 CPU 架构 ${ARCH_NAME}（支持 x64 / arm64）" ;;
esac

# 当前进程 PATH 纳入 ~/.local/bin（Node/agent CLI 的 npm bin）。
# 注意：这里【故意不加】~/.botmux/bin——botmux 3.18+ 的 postinstall 只在「~/.botmux/bin
# 不在进程 PATH」时才把它写进各 shell 启动文件（它自带周全的多文件逻辑：bash 同时写
# .bashrc 与登录文件、zsh 写 .zshenv、fish 写 conf.d、防注入、幂等 marker）。若在装 botmux
# 前就把该目录塞进本进程 PATH，会抑制 postinstall 的持久化，只能退回本脚本的兜底。
# 装完 botmux 后再把 ~/.botmux/bin 加进【当前进程】PATH（供后续 botmux start/setup 解析）。
export PATH="$BIN_DIR:$PATH"

if [ "$AGENT_WARMUP_WORKER" -eq 1 ]; then
  run_agent_warmup_worker
  exit 0
fi

validate_install_user
ensure_user_path
ensure_node

# Capture the user's usable CLI before installing optional alternatives. This
# is the default bot choice unless --default-cli explicitly overrides it.
PREFERRED_CLI=$(detect_preferred_cli)

if profile_remote_install_requested; then
  profile_remote_install
  exit 0
fi

ensure_homebrew_for_tmux
ensure_linux_system_deps_preflight
configure_native_build_env

# 装 botmux：优先直接下 bun 单文件二进制（免 Node、带校验、自带 musl 适配），失败回退 npm。
# 注意 agent CLI（claude/codex/lark-cli）仍走 npm，所以 Node 链路依然需要。
botmux_installed_via=""
if [ "$BOTMUX_INSTALL_METHOD" != npm ]; then
  log "安装/升级 Botmux（二进制方式，无需 Node）"
  if install_botmux_binary; then
    botmux_installed_via=binary
  else
    warn "二进制方式安装 Botmux 未成功，回退 npm（${BOTMUX_PACKAGE}）"
  fi
fi
if [ -z "$botmux_installed_via" ]; then
  log "安装/升级 Botmux ($BOTMUX_PACKAGE)"
  npm_user_install "$BOTMUX_PACKAGE"
  botmux_installed_via=npm
fi
# 装完再把 launcher 目录加进【当前进程】PATH，供本脚本后续的 botmux start/setup/autostart
# 解析（3.18+ 主包无 npm shim，botmux 只在 ~/.botmux/bin/botmux）。放在安装之后，才不会
# 抑制 npm 路径下 botmux postinstall 对启动文件的持久化（见脚本顶部 export PATH 处说明）。
case ":${PATH}:" in *":$HOME/.botmux/bin:"*) ;; *) export PATH="$HOME/.botmux/bin:$PATH" ;; esac
# 兜底写 PATH：二进制方式由本脚本负责（官方安装器那套 PATH 逻辑不在我们的下载路径里），
# npm 方式则优先由 botmux postinstall 写、这里只在它没写时补。
ensure_botmux_bin_path

if [ "$INSTALL_AGENTS" -eq 1 ]; then
  install_claude
  install_codex
  configure_codex_access
  install_extra_clis
  if [ "$WAIT_AGENT_WARMUP" -eq 1 ]; then
    run_agent_warmups
  else
    start_agent_warmups_async
  fi
fi

if [ "$DEFAULT_CLI" != auto ]; then
  PREFERRED_CLI=$DEFAULT_CLI
elif ! installed_cli "$PREFERRED_CLI" && [ "$DRY_RUN" -eq 0 ]; then
  PREFERRED_CLI=$(detect_preferred_cli)
fi
log "默认机器人 CLI: $PREFERRED_CLI"

if [ "$DRY_RUN" -eq 1 ]; then
  [ "$RUN_SETUP" -eq 0 ] || printf '+ botmux setup --default-cli %s\n' "$PREFERRED_CLI"
  [ "$RUN_START" -eq 0 ] || {
    printf '+ botmux start\n'
    printf '+ botmux autostart enable\n'
  }
  log "dry-run 完成，未修改系统"
  exit 0
fi

if ! agent_logged_in "$PREFERRED_CLI"; then
  warn "$PREFERRED_CLI 已安装但尚未认证；为保持全程只有飞书两次扫码，安装器不会自动发起额外登录。"
  case "$PREFERRED_CLI" in
    codex) warn "如首次消息提示未登录，运行: codex login" ;;
    claude-code) warn "如首次消息提示未登录，运行: claude auth login" ;;
    *) profile_login_hint "$PREFERRED_CLI" ;;
  esac
fi

if [ "$RUN_SETUP" -eq 1 ]; then
  if [ -f "$HOME/.botmux/bots.json" ] || [ -f "$HOME/.botmux/.env" ]; then
    log "检测到现有 Botmux 配置，跳过扫码 setup"
  else
    log "开始配置默认机器人；接下来只需扫描两次飞书二维码"
    # stdin 已是终端（含外层工具的子 PTY）就直接继承，不要再 </dev/tty 抢按键——否则菜单
    # 方向键/Enter 会被外层的输入转发和我们同时读走，表现为完全无响应。
    if needs_tty_redirect; then botmux setup --default-cli "$PREFERRED_CLI" </dev/tty
    else botmux setup --default-cli "$PREFERRED_CLI"
    fi
  fi
fi

BOTMUX_STARTED=0
if [ "$RUN_START" -eq 1 ]; then
  # 「还没扫码生成配置」是完全正常的中间状态（setup 被跳过、用户中途退出扫码、--no-setup
  # 等都会走到这里），不该让整个安装脚本中止。以前这里是 die，结果脚本提前退出，后面的
  # PATH 提示、bind 引导一句都打不出来——用户实测就是装完啥提示没有、敲 botmux 全是懵的。
  if [ ! -f "$HOME/.botmux/bots.json" ] && [ ! -f "$HOME/.botmux/.env" ]; then
    warn "尚未生成 Botmux 配置，跳过 botmux start（安装本身已完成）"
    warn "配置好后运行: botmux setup   然后: botmux start"
  else
    run_with_network_retry "Botmux 启动及系统依赖安装" botmux start
    BOTMUX_STARTED=1
    ensure_linux_linger
    if ! botmux autostart enable; then
      warn "开机自启注册失败；daemon 已启动，可稍后手动运行 botmux autostart enable"
    fi
  fi
fi

log "安装完成。状态: botmux status；日志: botmux logs"
report_agent_warmup_status
# 收尾必打的 PATH 提示。
# ⚠️ 这里【不能】用 `command -v botmux` 判断：主流程早就把 ~/.botmux/bin 塞进了本进程
# PATH（供脚本自己调 botmux start/setup），所以这个检查永远为真、提示永远不打——而用户
# 的当前 shell 根本没有这个目录，装完敲 botmux 就是 command not found。
# 正确的判据是「用户【当前这个 shell】里能不能解析到」，而 curl | sh 是子进程、
# 无论如何都改不了父 shell 的环境（官方 botmux 安装器同样只能提示"重开终端"）。
# 所以：只要写过启动文件，就无条件提示一次怎么在当前终端立刻生效。
botmux_cmd_path="$HOME/.botmux/bin"
printf '\n'
warn "botmux 已装好，但【当前这个终端】还没加载它——curl | sh 跑在子进程里，改不了你所在 shell 的 PATH。"
warn "二选一即可立刻可用："
warn "  1) 重开一个终端（启动文件已写好，新终端自动生效）"
warn "  2) 当前终端执行: export PATH=\"${botmux_cmd_path}:${BIN_DIR}:\$PATH\""

# 绑定引导。此前脚本全文一次都没提过 bind，用户装完只看到 status/logs，不知道还要把这台机器
# 绑到自己账号下（这也是"能不能自动 bind"这个疑问的由来）。
# 安装器【无法】代劳：绑定码在浏览器里生成、与用户的飞书登录态绑定，短 TTL 单次使用；
# botmux 侧也明确拒绝非宿主终端消费绑定凭证（AI CLI 会话被直接挡掉）。
# 顺序上 bind 不依赖 daemon：bind 当场把码换成 machine token 落盘，daemon 在跑就顺带通知它
# 立即重连、不在跑则下次 start 自然读到（见 botmux src/platform/bind.ts）。
if [ ! -f "$HOME/.botmux/platform.json" ]; then
  printf '\n'
  log "下一步：把这台机器绑定到你的账号（安装器无法代劳，绑定码只在你自己的浏览器里）"
  log "  1) 浏览器打开 ${BOTMUX_PLATFORM_URL:-你的 Botmux 平台} ，点「绑定新机器」拿绑定码（5 分钟内有效）"
  log "  2) 在【这台机器的终端】执行: botmux bind <绑定码>"
  if [ "$BOTMUX_STARTED" -eq 0 ]; then
    log "  （尚未生成配置：先 botmux setup 扫码，再 botmux start；bind 与它们先后无所谓）"
  fi
fi
