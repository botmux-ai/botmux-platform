import assert from 'node:assert/strict';
import { chmodSync, existsSync, mkdtempSync, mkdirSync, readFileSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

// The installer suite. Run directly it tests install.sh; an edition's own
// installer test imports the harness and runGenericTests() to run the same
// cases against its assembled installer (scripts/build-installer.sh).
const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const systemPath = '/usr/bin:/bin:/usr/sbin:/sbin';
const testProxy = 'http://proxy.example.test:3128';
const testNoProxy = 'localhost,127.0.0.1,.corp.example.test';
let installer = join(repoRoot, 'install.sh');
let defaultArgs = [];
let agentMocks = [];

/**
 * Points the suite at another installer. `args` are passed on every run
 * unless a case sets its own `extraArgs`; `agentMocks` names extra agent CLIs
 * mockInstalledAgents provides so the installer never downloads them.
 */
export function useInstaller(path, { args = [], agents = [] } = {}) {
  installer = path;
  defaultArgs = args;
  agentMocks = agents;
}

export function executable(path, body) {
  writeFileSync(path, `#!/bin/sh\nset -eu\n${body}\n`);
  chmodSync(path, 0o755);
}

export function fixture({ uid = 1000, nodeMajor = 20 } = {}) {
  const root = mkdtempSync(join(tmpdir(), 'botmux-installer-test-'));
  const bin = join(root, 'bin');
  const home = join(root, 'home');
  const state = join(root, 'state');
  mkdirSync(bin, { recursive: true });
  mkdirSync(home, { recursive: true });
  mkdirSync(state, { recursive: true });
  writeFileSync(join(state, 'node-major'), String(nodeMajor));

  executable(join(bin, 'id'), `
case "\${1:-}" in
  -u) printf '%s\\n' '${uid}' ;;
  -un) printf '%s\\n' 'testuser' ;;
  *) /usr/bin/id "$@" ;;
esac`);
  executable(join(bin, 'node'), `
major=$(cat "$TEST_STATE/node-major")
case "\${1:-}" in
  -p) printf '%s\\n' "$major" ;;
  --version) printf 'v%s.0.0\\n' "$major" ;;
  -e)
    [ "$#" -lt 4 ] && exit 0
    [ "$3" != "$4" ]
    ;;
  *) exit 0 ;;
esac`);
  executable(join(bin, 'npm'), `
printf 'npm https=%s no_proxy=%s\\n' "\${HTTPS_PROXY:-}" "\${NO_PROXY:-}" >> "$TEST_STATE/calls"
exit 0`);
  executable(join(bin, 'sudo'), 'echo "sudo must not be called" >&2; exit 99');

  const env = {
    ...process.env,
    HOME: home,
    // A build host may source its own nvm before running tests, so process.env.NVM_DIR can
    // point outside the fixture. Keep every fixture inside its temporary HOME.
    NVM_DIR: join(home, '.nvm'),
    SHELL: '/bin/sh',
    PATH: `${bin}:${systemPath}`,
    TEST_BIN: bin,
    TEST_REAL_NODE: process.execPath,
    TEST_STATE: state,
    BOTMUX_INSTALL_ROOT: join(home, '.local'),
    BOTMUX_INSTALL_OS: 'Linux',
    // 默认让固件走 npm 安装路径：二进制路径要真的 curl GitHub Release（~170MB），既慢又依赖
    // 外网，不适合单测。二进制路径由 testBotmuxBinaryInstall* 用注入的 curl mock 单独覆盖。
    BOTMUX_INSTALL_METHOD: 'npm',
    BOTMUX_INSTALL_ARCH: 'x86_64',
    http_proxy: '',
    https_proxy: '',
    HTTP_PROXY: '',
    HTTPS_PROXY: '',
    no_proxy: '',
    NO_PROXY: '',
  };
  return { root, bin, home, state, env };
}

export function run(f, extraEnv = {}, options = {}) {
  const args = [...(options.extraArgs ?? defaultArgs)];
  if (!options.agents) args.push('--no-agents');
  if (options.codexWarmup === false) args.push('--no-codex-warmup');
  if (options.waitAgentWarmup) args.push('--wait-agent-warmup');
  args.push('--no-setup');
  if (!options.start) args.push('--no-start');
  if (!options.systemDeps) args.push('--no-system-deps');
  const result = spawnSync('sh', [installer, ...args], {
    env: { ...f.env, ...extraEnv },
    encoding: 'utf8',
    timeout: 10_000,
  });
  const output = `${result.stdout}\n${result.stderr}`;
  assert.equal(result.status, 0, output);
  return output;
}

export function mockInstalledAgents(f) {
  for (const agent of ['claude', ...agentMocks]) executable(join(f.bin, agent), `echo "${agent} mock"`);
}

export function calls(f) {
  return readFileSync(join(f.state, 'calls'), 'utf8');
}

export function exposeHostTools(f, tools) {
  for (const tool of tools) {
    const hostTool = [`/bin/${tool}`, `/usr/bin/${tool}`].find(existsSync);
    assert.ok(hostTool, `missing host tool: ${tool}`);
    symlinkSync(hostTool, join(f.bin, tool));
  }
}

function testFnmUpgrade() {
  const f = fixture({ nodeMajor: 18 });
  try {
    executable(join(f.bin, 'fnm'), `
printf 'fnm %s\\n' "$*" >> "$TEST_STATE/calls"
case "\${1:-}" in
  install) printf '22' > "$TEST_STATE/node-major" ;;
  env) printf 'export PATH="%s:$PATH"\\n' "$TEST_BIN" ;;
esac`);
    const output = run(f);
    assert.match(output, /沿用该方式升级到 Node\.js 22/);
    assert.match(output, /已通过 fnm 升级为 v22\.0\.0/);
    assert.match(calls(f), /fnm install 22/);
    assert.match(calls(f), /fnm default 22/);
    assert.match(calls(f), /fnm use 22/);
  } finally {
    rmSync(f.root, { recursive: true, force: true });
  }
}

// 机器上没有任何 Node 管理器时的默认路径。改动前会直接回落 standalone（解压官方 tarball 到
// 用户目录，之后无法换版本）；现在应先装 fnm、再由 fnm 装 Node。
function testNoManagerInstallsFnmByDefault() {
  const f = fixture({ nodeMajor: 18 });
  try {
    const fnmDir = join(f.root, 'fnm-home');
    // 冒充 fnm 官方安装器：被 curl 下载后执行，把一个可用的 fnm 落到 --install-dir。
    executable(join(f.bin, 'curl'), `
printf 'curl %s\\n' "$*" >> "$TEST_STATE/calls"
out=""; url=""
while [ "$#" -gt 0 ]; do
  case "$1" in
    -o) out=$2; shift 2 ;;
    https://*|http://*) url=$1; shift ;;
    *) shift ;;
  esac
done
case "$url" in
  *fnm*)
    [ -n "$out" ] || exit 1
    cat > "$out" <<'FNMINSTALLER'
#!/bin/bash
set -eu
# 复刻官方安装器的关键特征：parse_args 用 [[ ]]，只有以 bash 执行才解析得了参数。
# 若 install.sh 退回用 sh 跑，这里会报 [[ not found 而拿不到 --install-dir/--skip-shell，
# 用例随即失败——正是线上踩过的那个坑。
dir=""
skip_shell=""
while [[ $# -gt 0 ]]; do
  case $1 in
    --install-dir) dir=$2; shift 2 ;;
    --skip-shell) skip_shell=true; shift ;;
    *) shift ;;
  esac
done
[ -n "$dir" ] || { echo 'fnm installer: --install-dir not parsed' >&2; exit 92; }
[ -n "$skip_shell" ] || { echo 'fnm installer: --skip-shell not parsed' >&2; exit 93; }
mkdir -p "$dir"
cat > "$dir/fnm" <<'FNMBIN'
#!/bin/sh
printf 'fnm %s\\n' "$*" >> "$TEST_STATE/calls"
case "\${1:-}" in
  install) printf '22' > "$TEST_STATE/node-major" ;;
  env) printf 'export PATH="%s:$PATH"\\n' "$TEST_BIN" ;;
  --version) echo 'fnm 1.38.1' ;;
esac
FNMBIN
chmod 755 "$dir/fnm"
FNMINSTALLER
    chmod 755 "$out"
    ;;
  *) exit 1 ;;
esac`);
    const output = run(f, { BOTMUX_FNM_INSTALL_DIR: fnmDir });
    assert.match(output, /安装 fnm（Node 版本管理器）/);
    assert.match(calls(f), /fnm install 22/, output);
    assert.match(output, /已通过 fnm 升级为 v22\.0\.0/, output);
    // 不应再走 standalone 解压路径
    assert.doesNotMatch(output, /使用用户目录独立安装 Node\.js/, output);
    // fnm 的 shell 集成要写进 profile，否则新开 shell 里没有 node
    assert.match(readFileSync(join(f.home, '.profile'), 'utf8'), /botmux fnm/);
  } finally {
    rmSync(f.root, { recursive: true, force: true });
  }
}

// 用户显式指定管理器时不要被 fnm 默认逻辑抢走：BOTMUX_NODE_MANAGER=standalone 应仍走
// 用户目录独立安装，且完全不去装 fnm。curl mock 保证一旦真去下 fnm 安装器就会失败暴露。
function testExplicitStandaloneStillHonored() {
  const f = fixture({ nodeMajor: 18 });
  try {
    executable(join(f.bin, 'curl'), `
printf 'curl %s\\n' "$*" >> "$TEST_STATE/calls"
case "$*" in
  *fnm*) echo 'fnm installer must not be downloaded' >&2; exit 91 ;;
esac
exit 1`);
    const result = spawnSync('sh', [installer, '--no-agents', '--no-setup', '--no-start', '--no-system-deps', '--dry-run'], {
      env: { ...f.env, BOTMUX_NODE_MANAGER: 'standalone' },
      encoding: 'utf8',
      timeout: 10_000,
    });
    const output = `${result.stdout}\n${result.stderr}`;
    assert.equal(result.status, 0, output);
    assert.doesNotMatch(output, /安装 fnm（Node 版本管理器）/, output);
    assert.match(output, /独立安装 Node\.js/, output);
  } finally {
    rmSync(f.root, { recursive: true, force: true });
  }
}

function testNvmUpgrade() {
  const f = fixture({ nodeMajor: 20 });
  try {
    const nvmDir = join(f.home, '.nvm');
    mkdirSync(nvmDir, { recursive: true });
    writeFileSync(join(nvmDir, 'nvm.sh'), `
nvm() {
  printf 'nvm %s\\n' "$*" >> "$TEST_STATE/calls"
  case "\${1:-}" in
    install) printf '22' > "$TEST_STATE/node-major" ;;
    alias)
      case "\${2:-}" in
        default) ;;
      esac
      ;;
  esac
}
`);
    const output = run(f);
    assert.match(output, /Node 管理方式: nvm/);
    assert.match(output, /已通过 nvm 升级为 v22\.0\.0/);
    assert.match(calls(f), /nvm install 22/);
    assert.match(calls(f), /nvm alias default 22/);
  } finally {
    rmSync(f.root, { recursive: true, force: true });
  }
}

function testBrewUpgrade() {
  const f = fixture({ nodeMajor: 20 });
  try {
    const brewPrefix = join(f.root, 'brew');
    mkdirSync(join(brewPrefix, 'bin'), { recursive: true });
    // The active Node path must be inside the Homebrew prefix for auto-detection.
    rmSync(join(f.bin, 'node'));
    executable(join(brewPrefix, 'bin', 'node'), `
major=$(cat "$TEST_STATE/node-major")
case "\${1:-}" in -p) echo "$major" ;; --version) echo "v$major.0.0" ;; esac`);
    executable(join(f.bin, 'brew'), `
printf 'brew %s\\n' "$*" >> "$TEST_STATE/calls"
case "\${1:-}:\${2:-}" in
  --prefix:) echo "$TEST_BREW_PREFIX" ;;
  --prefix:node) echo "$TEST_BREW_PREFIX" ;;
  list:--versions) echo 'node 20.0.0' ;;
  upgrade:node) printf '22' > "$TEST_STATE/node-major" ;;
  *) exit 0 ;;
esac`);
    f.env.PATH = `${brewPrefix}/bin:${f.bin}:${systemPath}`;
    const output = run(f, { TEST_BREW_PREFIX: brewPrefix });
    assert.match(output, /Node 管理方式: brew/);
    assert.match(output, /已通过 brew 升级为 v22\.0\.0/);
    assert.match(calls(f), /brew upgrade node/);
  } finally {
    rmSync(f.root, { recursive: true, force: true });
  }
}

function testNewerBrewNodeSwitchesToSupportedLts() {
  const f = fixture({ nodeMajor: 25 });
  try {
    const brewPrefix = join(f.root, 'brew');
    const currentBin = join(brewPrefix, 'bin');
    const ltsBin = join(brewPrefix, 'opt', 'node@22', 'bin');
    mkdirSync(currentBin, { recursive: true });
    mkdirSync(ltsBin, { recursive: true });
    rmSync(join(f.bin, 'node'));
    for (const dir of [currentBin, ltsBin]) {
      executable(join(dir, 'node'), `
major=$(cat "$TEST_STATE/node-major")
case "\${1:-}" in -p) echo "$major" ;; --version) echo "v$major.0.0" ;; esac`);
    }
    executable(join(f.bin, 'brew'), `
printf 'brew %s\\n' "$*" >> "$TEST_STATE/calls"
case "\${1:-}:\${2:-}" in
  --prefix:) echo "$TEST_BREW_PREFIX" ;;
  --prefix:node@22) echo "$TEST_BREW_PREFIX/opt/node@22" ;;
  install:node@22) printf '22' > "$TEST_STATE/node-major" ;;
  *) exit 0 ;;
esac`);
    f.env.PATH = `${currentBin}:${f.bin}:${systemPath}`;
    const output = run(f, { TEST_BREW_PREFIX: brewPrefix });
    assert.match(output, /当前安装链路仅复用 Node 22\/24 LTS/);
    assert.match(output, /已通过 brew 升级为 v22\.0\.0/);
    assert.match(calls(f), /brew install node@22/);
    assert.match(readFileSync(join(f.home, '.profile'), 'utf8'), /node@22\/bin/);
  } finally {
    rmSync(f.root, { recursive: true, force: true });
  }
}

function testVersionedBrewUpgradePersistsPath() {
  const f = fixture({ nodeMajor: 20 });
  try {
    const brewPrefix = join(f.root, 'brew');
    const oldBin = join(brewPrefix, 'opt', 'node@20', 'bin');
    const newBin = join(brewPrefix, 'opt', 'node@22', 'bin');
    mkdirSync(oldBin, { recursive: true });
    mkdirSync(newBin, { recursive: true });
    rmSync(join(f.bin, 'node'));
    for (const dir of [oldBin, newBin]) {
      executable(join(dir, 'node'), `
major=$(cat "$TEST_STATE/node-major")
case "\${1:-}" in -p) echo "$major" ;; --version) echo "v$major.0.0" ;; esac`);
    }
    executable(join(f.bin, 'brew'), `
printf 'brew %s\\n' "$*" >> "$TEST_STATE/calls"
case "\${1:-}:\${2:-}" in
  --prefix:) echo "$TEST_BREW_PREFIX" ;;
  --prefix:node@22) echo "$TEST_BREW_PREFIX/opt/node@22" ;;
  install:node@22) printf '22' > "$TEST_STATE/node-major" ;;
  *) exit 0 ;;
esac`);
    f.env.PATH = `${oldBin}:${f.bin}:${systemPath}`;
    const output = run(f, { TEST_BREW_PREFIX: brewPrefix });
    assert.match(output, /已通过 brew 升级为 v22\.0\.0/);
    assert.match(calls(f), /brew install node@22/);
    assert.match(readFileSync(join(f.home, '.profile'), 'utf8'), /node@22\/bin/);
  } finally {
    rmSync(f.root, { recursive: true, force: true });
  }
}

function testMacInstallsHomebrewAndTmuxViaPreferredProxy() {
  const f = fixture({ uid: 1000, nodeMajor: 22 });
  try {
    exposeHostTools(f, ['cat', 'chmod', 'cp', 'env', 'grep', 'mkdir', 'mktemp', 'rm', 'sh']);
    f.env.PATH = f.bin;
    const homebrewInstaller = join(f.state, 'homebrew-install.sh');
    executable(homebrewInstaller, `
printf 'homebrew-install https=%s no_proxy=%s noninteractive=%s\\n' "\${HTTPS_PROXY:-}" "\${NO_PROXY:-}" "\${NONINTERACTIVE:-}" >> "$TEST_STATE/calls"
printf '%s\\n' \\
  '#!/bin/sh' \\
  'printf "brew %s https=%s no_proxy=%s\\n" "$*" "\${HTTPS_PROXY:-}" "\${NO_PROXY:-}" >> "$TEST_STATE/calls"' \\
  'case "$*" in' \\
  '  "install tmux") printf "#!/bin/sh\\nprintf \\"tmux 3.4\\\\n\\"\\n" > "$TEST_BIN/tmux"; chmod +x "$TEST_BIN/tmux" ;;' \\
  'esac' > "$TEST_BIN/brew"
chmod +x "$TEST_BIN/brew"`);
    executable(join(f.bin, 'curl'), `
out=''
url=''
while [ "$#" -gt 0 ]; do
  case "$1" in
    -o) out=$2; shift 2 ;;
    http*) url=$1; shift ;;
    *) shift ;;
  esac
done
printf 'curl url=%s https=%s no_proxy=%s\\n' "$url" "\${HTTPS_PROXY:-}" "\${NO_PROXY:-}" >> "$TEST_STATE/calls"
cp "$TEST_HOMEBREW_INSTALLER" "$out"`);

    const output = run(f, {
      BOTMUX_INSTALL_OS: 'Darwin',
      BOTMUX_HOMEBREW_BIN_CANDIDATES: '/nonexistent/brew',
      BOTMUX_HTTP_PROXY: testProxy,
      BOTMUX_NO_PROXY: testNoProxy,
      TEST_HOMEBREW_INSTALLER: homebrewInstaller,
    }, { systemDeps: true });
    const log = calls(f);
    assert.match(log, /curl url=https:\/\/raw\.githubusercontent\.com\/Homebrew\/install\/HEAD\/install\.sh https=http:\/\/proxy\.example\.test:3128/);
    assert.match(log, /homebrew-install https=http:\/\/proxy\.example\.test:3128 .*noninteractive=1/);
    assert.match(log, /brew config https= no_proxy=/);
    assert.match(log, /brew install tmux https=http:\/\/proxy\.example\.test:3128/);
    assert.match(log, /no_proxy=.*\.corp\.example\.test/);
    assert.match(output, /tmux 已通过 Homebrew 安装：tmux 3\.4/);
    assert.doesNotMatch(output, /使用当前网络重试一次/);
  } finally {
    rmSync(f.root, { recursive: true, force: true });
  }
}

function testMacUpdatesStaleHomebrewForNewMacOS() {
  const f = fixture({ uid: 1000, nodeMajor: 22 });
  try {
    exposeHostTools(f, ['cat', 'chmod', 'env', 'grep', 'mkdir', 'mktemp', 'rm', 'sh']);
    executable(join(f.bin, 'sw_vers'), `
[ "\${1:-}" = -productVersion ] && printf '26.5.1\\n'`);
    executable(join(f.bin, 'brew'), `
printf 'brew %s https=%s no_proxy=%s\\n' "$*" "\${HTTPS_PROXY:-}" "\${NO_PROXY:-}" >> "$TEST_STATE/calls"
case "$*" in
  config)
    if [ ! -f "$TEST_STATE/brew-updated" ]; then
      printf 'MacOSVersion::Error: unknown or unsupported macOS version: "26.5.1"\\n' >&2
      exit 1
    fi
    ;;
  update)
    : > "$TEST_STATE/brew-updated"
    printf 'Error: homebrew/homebrew-cask-fonts does not exist!\\n' >&2
    exit 42
    ;;
  'install tmux')
    [ -f "$TEST_STATE/brew-updated" ] || exit 88
    printf '#!/bin/sh\\nprintf "tmux 3.4\\\\n"\\n' > "$TEST_BIN/tmux"
    chmod +x "$TEST_BIN/tmux"
    ;;
esac`);
    f.env.PATH = f.bin;

    const output = run(f, { BOTMUX_INSTALL_OS: 'Darwin', BOTMUX_HTTP_PROXY: testProxy, BOTMUX_NO_PROXY: testNoProxy }, { systemDeps: true });
    const log = calls(f);
    assert.match(output, /现有 Homebrew 版本无法识别 macOS 26\.5\.1，先更新 Homebrew/);
    assert.match(output, /Homebrew 已更新并支持当前 macOS/);
    assert.match(output, /Homebrew 主程序已通过 HTTP 代理更新；忽略不影响 tmux 安装的附加 tap 更新错误/);
    assert.match(log, /brew update https=http:\/\/proxy\.example\.test:3128/);
    assert.match(log, /brew install tmux https=http:\/\/proxy\.example\.test:3128/);
    assert.ok(log.indexOf('brew update') < log.indexOf('brew install tmux'));
    assert.equal((log.match(/brew update/g) || []).length, 1);
    assert.doesNotMatch(output, /使用当前网络重试一次/);
  } finally {
    rmSync(f.root, { recursive: true, force: true });
  }
}

function testProxyFallback() {
  const f = fixture({ nodeMajor: 22 });
  try {
    executable(join(f.bin, 'npm'), `
count_file="$TEST_STATE/npm-count"
count=0; [ ! -f "$count_file" ] || count=$(cat "$count_file")
count=$((count + 1)); echo "$count" > "$count_file"
printf 'npm https=%s no_proxy=%s\\n' "\${HTTPS_PROXY:-}" "\${NO_PROXY:-}" >> "$TEST_STATE/calls"
[ "$count" -ge 2 ]`);
    const output = run(f, { BOTMUX_HTTP_PROXY: testProxy, BOTMUX_NO_PROXY: testNoProxy });
    assert.match(output, /使用 HTTP 代理重试一次/);
    const lines = calls(f).trim().split('\n');
    assert.equal(lines.length, 2);
    assert.match(lines[0], /https= no_proxy=/);
    assert.match(lines[1], /https=http:\/\/proxy\.example\.test:3128/);
    assert.match(lines[1], /\.corp\.example\.test/);
  } finally {
    rmSync(f.root, { recursive: true, force: true });
  }
}

function testCodexUsesRegistryFirst() {
  const f = fixture({ nodeMajor: 22 });
  try {
    mockInstalledAgents(f);
    executable(join(f.bin, 'npm'), `
printf 'npm %s https=%s\\n' "$*" "\${HTTPS_PROXY:-}" >> "$TEST_STATE/calls"
case "$*" in
  *'@openai/codex@latest'*)
    mkdir -p "$BOTMUX_INSTALL_ROOT/bin"
    printf '#!/bin/sh\\necho codex-registry-mock\\n' > "$BOTMUX_INSTALL_ROOT/bin/codex"
    chmod +x "$BOTMUX_INSTALL_ROOT/bin/codex"
    ;;
esac`);
    const output = run(f, { CODEX_REGISTRY: 'https://npm.example.test' }, { agents: true, codexWarmup: false });
    assert.match(output, /优先使用 npm 源 https:\/\/npm\.example\.test/);
    assert.match(output, /Codex 已通过 npm 源安装/);
    assert.match(calls(f), /@openai\/codex@latest --registry https:\/\/npm\.example\.test/);
    assert.doesNotMatch(output, /公网 fallback/);
  } finally {
    rmSync(f.root, { recursive: true, force: true });
  }
}

function testCodexPublicFallbackUsesProxy() {
  const f = fixture({ nodeMajor: 22 });
  try {
    mockInstalledAgents(f);
    executable(join(f.bin, 'npm'), `
printf 'npm %s https=%s\\n' "$*" "\${HTTPS_PROXY:-}" >> "$TEST_STATE/calls"
case "$*" in *'@openai/codex@latest'*) exit 42 ;; esac
exit 0`);
    executable(join(f.bin, 'curl'), `
out=''; url=''
while [ "$#" -gt 0 ]; do
  case "$1" in
    -o) out=$2; shift 2 ;;
    http*) url=$1; shift ;;
    *) shift ;;
  esac
done
printf 'curl url=%s https=%s\\n' "$url" "\${HTTPS_PROXY:-}" >> "$TEST_STATE/calls"
printf '#!/bin/sh\\nexit 0\\n' > "$out"
mkdir -p "$BOTMUX_INSTALL_ROOT/bin"
printf '#!/bin/sh\\necho codex-public-mock\\n' > "$BOTMUX_INSTALL_ROOT/bin/codex"
chmod +x "$BOTMUX_INSTALL_ROOT/bin/codex"`);
    const output = run(f, { BOTMUX_HTTP_PROXY: testProxy }, { agents: true, codexWarmup: false });
    assert.match(output, /从 npm 源安装 Codex 失败/);
    assert.match(output, /公网 fallback/);
    assert.match(calls(f), /curl url=https:\/\/chatgpt\.com\/codex\/install\.sh https=http:\/\/proxy\.example\.test:3128/);
  } finally {
    rmSync(f.root, { recursive: true, force: true });
  }
}

function testExistingClaudeAndCodexAreReused() {
  const f = fixture({ nodeMajor: 22 });
  try {
    mockInstalledAgents(f);
    executable(join(f.bin, 'codex'), `
case "\${1:-}" in
  --version) echo 'codex-cli 0.144.1' ;;
  login) echo 'Logged in using ChatGPT' ;;
esac`);
    executable(join(f.bin, 'npm'), `
printf 'npm %s\\n' "$*" >> "$TEST_STATE/calls"
case "$*" in *'view @openai/codex@latest version'*) echo '0.144.1' ;; esac`);
    const output = run(f, {}, { agents: true, codexWarmup: false });
    assert.match(output, /复用 Claude Code/);
    assert.match(output, /Codex 已是最新稳定版（0\.144\.1）/);
    assert.match(output, /ChatGPT 官方订阅登录/);
    assert.doesNotMatch(calls(f), /install .*@openai\/codex/);
  } finally {
    rmSync(f.root, { recursive: true, force: true });
  }
}

function testExistingCodexUpdatesFromRegistry() {
  const f = fixture({ nodeMajor: 22 });
  try {
    mockInstalledAgents(f);
    writeFileSync(join(f.state, 'codex-version'), '0.120.0');
    executable(join(f.bin, 'codex'), `
case "\${1:-}" in
  --version) printf 'codex-cli %s\\n' "$(cat "$TEST_STATE/codex-version")" ;;
  login) echo 'Logged in using ChatGPT' ;;
esac`);
    executable(join(f.bin, 'npm'), `
printf 'npm %s\\n' "$*" >> "$TEST_STATE/calls"
case "$*" in
  *'view @openai/codex@latest version'*) echo '0.144.1' ;;
  *'install -g'*'@openai/codex@latest'*) printf '0.144.1' > "$TEST_STATE/codex-version" ;;
esac`);
    const output = run(f, { CODEX_REGISTRY: 'https://npm.example.test' }, { agents: true, codexWarmup: false });
    assert.match(output, /更新 Codex：0\.120\.0 → 0\.144\.1/);
    assert.match(output, /Codex 更新完成：codex-cli 0\.144\.1/);
    assert.match(calls(f), /install -g .*@openai\/codex@latest --registry https:\/\/npm\.example\.test/);
  } finally {
    rmSync(f.root, { recursive: true, force: true });
  }
}

function testCodexWarmupAndDoctorWiring() {
  const f = fixture({ nodeMajor: 22 });
  try {
    mockInstalledAgents(f);
    executable(join(f.bin, 'codex'), `
case "\${1:-}" in
  --version) echo 'codex-cli 0.144.1' ;;
  login) echo 'Logged in using ChatGPT' ;;
  doctor) printf '%s\\n' '{"checks":{"installation":{"status":"ok"},"config.load":{"status":"ok"},"auth.credentials":{"status":"ok"},"network.provider_reachability":{"status":"ok"}}}' ;;
esac`);
    executable(join(f.bin, 'npm'), `case "$*" in *'view @openai/codex@latest version'*) echo '0.144.1' ;; esac`);
    executable(join(f.bin, 'node'), `
case "\${1:-}" in
  -p) echo 22 ;;
  --version) echo v22.0.0 ;;
  -e) printf '%s\\n' "$TEST_STATE/fake-node-pty.js" ;;
  *.cjs)
    grep -q 'Trust all and continue' "$1"
    printf 'warmup name=%s bin=%s\\n' "$BOTMUX_AGENT_NAME" "$BOTMUX_AGENT_BIN" >> "$TEST_STATE/calls"
    ;;
esac`);
    const output = run(f, {}, { agents: true, waitAgentWarmup: true });
    assert.match(output, /后台预热 Codex/);
    assert.match(output, /Codex 首次启动预热完成/);
    assert.match(output, /Codex doctor 核心检查通过/);
    assert.match(calls(f), /warmup name=Codex bin=.*codex/);
  } finally {
    rmSync(f.root, { recursive: true, force: true });
  }
}

function testLinuxTmuxPrefersPasswordlessSystemManager() {
  const f = fixture({ uid: 1000, nodeMajor: 22 });
  try {
    // Isolate PATH from the test host's own tmux while retaining the handful
    // of external POSIX tools exercised by this scenario.
    exposeHostTools(f, ['cat', 'chmod', 'grep', 'mkdir', 'sh']);
    executable(join(f.bin, 'apt-get'), 'exit 0');
    f.env.PATH = f.bin;
    mkdirSync(join(f.home, '.local', 'bin'), { recursive: true });
    executable(join(f.home, '.local', 'bin', 'bwrap'), 'echo "bubblewrap built for Codex"');
    executable(join(f.bin, 'brew'), 'echo "brew must not be called" >&2; exit 98');
    executable(join(f.bin, 'sudo'), `
printf 'sudo %s no_auto_update=%s\\n' "$*" "\${HOMEBREW_NO_AUTO_UPDATE:-}" >> "$TEST_STATE/calls"
case "$*" in
  '-n true') exit 0 ;;
  *'apt-get install -y tmux bubblewrap'*)
    printf '#!/bin/sh\\necho tmux 3.3a\\n' > "$TEST_BIN/tmux"
    chmod +x "$TEST_BIN/tmux"
    printf '#!/bin/sh\\necho bubblewrap 0.8.0\\n' > "$TEST_BIN/bwrap"
    chmod +x "$TEST_BIN/bwrap"
    printf '#!/bin/sh\\ncase "$1" in -c) exit 0 ;; --version) echo "Python 3.11.2" ;; esac\\n' > "$TEST_BIN/python3"
    chmod +x "$TEST_BIN/python3"
    exit 0
    ;;
  *) exit 0 ;;
esac`);
    const output = run(f, {}, { systemDeps: true });
    // botmux 3.18+ 走 bun 二进制、本身不再现场编译 node-pty，默认系统依赖只含 tmux/bubblewrap，
    // 不再主动装 python3/build-essential（除非显式 BOTMUX_INSTALL_BUILD_DEPS=1）。
    assert.match(output, /Linux 使用系统包管理器 apt-get 安装依赖: tmux bubblewrap/);
    assert.doesNotMatch(output, /python3 build-essential/);
    assert.match(output, /tmux 已通过 apt-get 安装/);
    assert.match(output, /bubblewrap 已通过 apt-get 安装/);
    assert.match(output, new RegExp(`bubblewrap 0\\.8\\.0 \\(${f.bin.replaceAll('/', '\\/')}\\/bwrap\\)`));
    assert.match(calls(f), /sudo -n apt-get install -y tmux bubblewrap no_auto_update=1/);
    assert.doesNotMatch(output, /brew must not be called/);
  } finally {
    rmSync(f.root, { recursive: true, force: true });
  }
}

function testVersionedPythonInstallFallback() {
  const f = fixture({ uid: 1000, nodeMajor: 22 });
  try {
    exposeHostTools(f, ['cat', 'chmod', 'cp', 'grep', 'mkdir', 'sh']);
    executable(join(f.bin, 'apt-get'), 'exit 0');
    f.env.PATH = f.bin;
    // npm mock 记录 node-gyp 实际拿到的 Python。
    executable(join(f.bin, 'npm'), `
printf 'npm python=%s\\n' "\${npm_config_python:-}" >> "$TEST_STATE/calls"
exit 0`);
    // 预先备好一个 ≥3.8 的解释器 mock，由 sudo 在装 python3.11 时“落盘”。
    executable(join(f.state, 'python3.11.staged'), `
case "\${1:-}" in
  -c) exit 0 ;;
  --version) echo 'Python 3.11.9' ;;
esac`);
    executable(join(f.bin, 'sudo'), `
printf 'sudo %s\\n' "$*" >> "$TEST_STATE/calls"
case "$*" in
  '-n true') exit 0 ;;
  *'install -y python3.12'*) exit 0 ;;
  *'install -y python3.11'*) cp "$TEST_STATE/python3.11.staged" "$TEST_BIN/python3.11"; exit 0 ;;
  *) exit 0 ;;
esac`);
    const output = run(f, { BOTMUX_INSTALL_BUILD_DEPS: '1' }, { systemDeps: true });
    // python3.12 “安装成功”但没产生 ≥3.8 解释器 → 继续候选；python3.11 落盘 → 命中。
    assert.match(output, /尝试通过 apt-get 安装带版本号的 Python: python3\.12/);
    assert.match(output, /尝试通过 apt-get 安装带版本号的 Python: python3\.11/);
    assert.match(output, /已安装 Python: .*python3\.11 \(Python 3\.11\.9\)/);
    assert.match(output, /node-gyp 将使用 Python: .*python3\.11/);
    assert.match(calls(f), /sudo -n apt-get install -y python3\.12/);
    assert.match(calls(f), /sudo -n apt-get install -y python3\.11/);
    assert.doesNotMatch(calls(f), /install -y python3\.10/);
    assert.match(calls(f), /npm python=.*\/python3\.11/);
  } finally {
    rmSync(f.root, { recursive: true, force: true });
  }
}

function testVersionedPythonFallbackAfterMainInstallFailure() {
  const f = fixture({ uid: 1000, nodeMajor: 22 });
  try {
    exposeHostTools(f, ['cat', 'chmod', 'cp', 'grep', 'mkdir', 'sh']);
    executable(join(f.bin, 'apt-get'), 'exit 0');
    f.env.PATH = f.bin;
    // npm mock 记录 node-gyp 实际拿到的 Python。
    executable(join(f.bin, 'npm'), `
printf 'npm python=%s\\n' "\${npm_config_python:-}" >> "$TEST_STATE/calls"
exit 0`);
    executable(join(f.state, 'python3.11.staged'), `
case "\${1:-}" in
  -c) exit 0 ;;
  --version) echo 'Python 3.11.9' ;;
esac`);
    // 主安装整体失败（如 bubblewrap 不在源里拖垮整个 apt 事务）→ 版本号 Python 兜底仍须执行。
    executable(join(f.bin, 'sudo'), `
printf 'sudo %s\\n' "$*" >> "$TEST_STATE/calls"
case "$*" in
  '-n true') exit 0 ;;
  *'install -y tmux'*) exit 100 ;;
  *'install -y python3.12'*) exit 100 ;;
  *'install -y python3.11'*) cp "$TEST_STATE/python3.11.staged" "$TEST_BIN/python3.11"; exit 0 ;;
  *) exit 0 ;;
esac`);
    const output = run(f, { BOTMUX_INSTALL_BUILD_DEPS: '1' }, { systemDeps: true });
    assert.match(output, /安装 Linux 系统依赖未成功/);
    assert.match(output, /已安装 Python: .*python3\.11 \(Python 3\.11\.9\)/);
    assert.match(output, /node-gyp 将使用 Python: .*python3\.11/);
    assert.match(calls(f), /npm python=.*\/python3\.11/);
  } finally {
    rmSync(f.root, { recursive: true, force: true });
  }
}

function testContinuesWithoutModernPythonOnLinux() {
  // botmux 3.18+ 走 bun 单文件二进制、主包已摘掉 node-pty，安装 botmux 本身不再现场编译。
  // 因此拿不到 Python≥3.8 时不再硬停，而是继续安装、仅告警（编译仅可能影响个别 agent CLI）。
  for (const arch of ['aarch64', 'x86_64']) {
    const f = fixture({ uid: 1000, nodeMajor: 22 });
    try {
      exposeHostTools(f, ['cat', 'chmod', 'grep', 'mkdir', 'sh']);
      // npm mock：记录被调用，证明安装没有在 Python 检查处中止。
      executable(join(f.bin, 'npm'), `
printf 'npm %s\\n' "$*" >> "$TEST_STATE/calls"
exit 0`);
      f.env.PATH = f.bin;
      f.env.BOTMUX_INSTALL_ARCH = arch;
      const result = spawnSync('sh', [installer, '--no-agents', '--no-setup', '--no-start', '--no-system-deps'], {
        env: f.env,
        encoding: 'utf8',
        timeout: 10_000,
      });
      const output = `${result.stdout}\n${result.stderr}`;
      assert.equal(result.status, 0, `arch=${arch} should NOT abort\n${output}`);
      assert.match(output, /安装 botmux 本身不需要它/, `arch=${arch}`);
      assert.doesNotMatch(output, /node-pty 的 npm 包不含 Linux 预编译/, `arch=${arch}`);
      assert.ok(existsSync(join(f.state, 'calls')), `arch=${arch}: npm 应照常执行（未被 Python 检查中止）`);
    } finally {
      rmSync(f.root, { recursive: true, force: true });
    }
  }
}

function testLinuxLingerUsesPasswordlessSudo() {
  const f = fixture({ uid: 1000, nodeMajor: 22 });
  try {
    mkdirSync(join(f.home, '.botmux'), { recursive: true });
    writeFileSync(join(f.home, '.botmux', 'bots.json'), '{}');
    writeFileSync(join(f.state, 'linger'), 'no');
    executable(join(f.bin, 'botmux'), `
printf 'botmux %s\n' "$*" >> "$TEST_STATE/calls"
exit 0`);
    executable(join(f.bin, 'loginctl'), `
case "\${1:-}" in
  show-user) printf 'Linger=%s\n' "$(cat "$TEST_STATE/linger")" ;;
  *) echo "loginctl must run through sudo for non-root" >&2; exit 98 ;;
esac`);
    executable(join(f.bin, 'sudo'), `
printf 'sudo %s\n' "$*" >> "$TEST_STATE/calls"
case "$*" in
  '-n true') exit 0 ;;
  '-n loginctl enable-linger testuser') printf 'yes' > "$TEST_STATE/linger" ;;
  *) exit 97 ;;
esac`);

    const output = run(f, {}, { start: true });
    assert.match(output, /已自动开启 Linger/);
    assert.match(calls(f), /sudo -n loginctl enable-linger testuser/);
    assert.match(calls(f), /botmux autostart enable/);
  } finally {
    rmSync(f.root, { recursive: true, force: true });
  }
}

function testLinuxLingerRunsDirectlyAsRoot() {
  const f = fixture({ uid: 0, nodeMajor: 22 });
  try {
    mkdirSync(join(f.home, '.botmux'), { recursive: true });
    writeFileSync(join(f.home, '.botmux', 'bots.json'), '{}');
    writeFileSync(join(f.state, 'linger'), 'no');
    executable(join(f.bin, 'botmux'), 'exit 0');
    executable(join(f.bin, 'loginctl'), `
printf 'loginctl %s\n' "$*" >> "$TEST_STATE/calls"
case "\${1:-}" in
  show-user) printf 'Linger=%s\n' "$(cat "$TEST_STATE/linger")" ;;
  enable-linger) printf 'yes' > "$TEST_STATE/linger" ;;
esac`);

    const output = run(f, {}, { start: true });
    assert.match(output, /已自动开启 Linger/);
    assert.match(calls(f), /loginctl enable-linger testuser/);
    assert.doesNotMatch(output, /sudo must not be called/);
  } finally {
    rmSync(f.root, { recursive: true, force: true });
  }
}

function testAgentWarmupDefaultsToDetachedWorker() {
  const f = fixture({ nodeMajor: 22 });
  try {
    mockInstalledAgents(f);
    executable(join(f.bin, 'codex'), `
case "\${1:-}" in
  --version) echo 'codex-cli 0.144.1' ;;
  login) echo 'Logged in using ChatGPT' ;;
esac`);
    executable(join(f.bin, 'npm'), `case "$*" in *'view @openai/codex@latest version'*) echo '0.144.1' ;; esac`);
    // The parent must not wait for the detached worker. Replacing nohup with a
    // long-lived process makes accidental synchronous execution immediately visible.
    executable(join(f.bin, 'nohup'), 'exec /bin/sleep 30');
    const startedAt = Date.now();
    const output = run(f, {}, { agents: true });
    const elapsedMs = Date.now() - startedAt;
    assert.match(output, /首次启动预热已转入后台/);
    assert.match(output, /仍在后台预热/);
    assert.ok(elapsedMs < 3_000, `async warmup blocked for ${elapsedMs}ms`);
    const pidPath = join(f.home, '.local', 'state', 'botmux', 'agent-warmup.pid');
    const pid = Number(readFileSync(pidPath, 'utf8'));
    if (Number.isInteger(pid) && pid > 1) {
      try { process.kill(pid, 'SIGTERM'); } catch {}
    }
  } finally {
    rmSync(f.root, { recursive: true, force: true });
  }
}

// 收尾播报必须反映「是否真的预热了」。worker 无论是否真做事都会写 DONE_FILE，
// 所以不能只凭它就报「后台预热已完成」——codex 未登录官方订阅会跳过预热，
// 没装的 agent 也会跳过，全都跳过时那句话是假的（用户实际截图反馈的问题）。
// 用 --wait-agent-warmup 走同步路径：不经过 nohup 后台 worker，避免父进程与 worker 的竞态。
function testWarmupStatusReflectsWhatActuallyWarmed() {
  const f = fixture({ nodeMajor: 22 });
  try {
    mockInstalledAgents(f);
    // codex 未登录官方订阅 → warmup_codex 直接跳过，不写 RESULT
    executable(join(f.bin, 'codex'), `
case "\${1:-}" in
  --version) echo 'codex-cli 0.144.1' ;;
  login) echo 'Not logged in' ;;
esac`);
    executable(join(f.bin, 'npm'), `case "$*" in *'view @openai/codex@latest version'*) echo '0.144.1' ;; esac`);
    const output = run(f, {}, { agents: true, waitAgentWarmup: true });
    assert.doesNotMatch(output, /后台预热已完成/, output);
    assert.match(output, /跳过 TUI 预热|未检测到 ChatGPT 官方订阅/, output);
  } finally {
    rmSync(f.root, { recursive: true, force: true });
  }
}

// 反过来：DONE 存在且 RESULT 里记了名字时，要如实报出预热了谁。
// 这里直接验证 report_agent_warmup_status 的判定逻辑（预置状态文件，不跑完整安装）。
function testWarmupStatusNamesWarmedAgents() {
  const f = fixture({ nodeMajor: 22 });
  try {
    const stateDir = join(f.home, '.local', 'state', 'botmux');
    mkdirSync(stateDir, { recursive: true });
    writeFileSync(join(stateDir, 'agent-warmup.done'), '');
    writeFileSync(join(stateDir, 'agent-warmup-result.txt'), 'Codex\n');
    // 只抽出被测函数运行，避免依赖完整安装流程的时序
    const src = readFileSync(installer, 'utf8');
    const fn = src.slice(src.indexOf('report_agent_warmup_status() {'));
    const body = fn.slice(0, fn.indexOf('\n}\n') + 3);
    const harness = `#!/bin/sh
set -eu
log() { printf '[botmux] %s\\n' "$*"; }
warn() { printf '[botmux] %s\\n' "$*" >&2; }
agent_warmup_enabled() { :; }
INSTALL_AGENTS=1; WAIT_AGENT_WARMUP=0; WARMUP_AGENT_NAMES=Codex
WARMUP_STATE_DIR="${stateDir}"
WARMUP_DONE_FILE="$WARMUP_STATE_DIR/agent-warmup.done"
WARMUP_AUTH_FILE="$WARMUP_STATE_DIR/agent-warmup-auth.txt"
WARMUP_RESULT_FILE="$WARMUP_STATE_DIR/agent-warmup-result.txt"
WARMUP_LOG_FILE="$WARMUP_STATE_DIR/agent-warmup.log"
${body}
report_agent_warmup_status
`;
    const probe = join(f.root, 'probe.sh');
    writeFileSync(probe, harness);
    const r = spawnSync('sh', [probe], { encoding: 'utf8', timeout: 10_000 });
    const out = `${r.stdout}\n${r.stderr}`;
    assert.equal(r.status, 0, out);
    assert.match(out, /Codex 后台预热已完成/, out);
    assert.doesNotMatch(out, /无需预热/, out);

    // RESULT 为空（什么都没预热）时不能谎报「已完成」
    writeFileSync(join(stateDir, 'agent-warmup-result.txt'), '');
    const r2 = spawnSync('sh', [probe], { encoding: 'utf8', timeout: 10_000 });
    const out2 = `${r2.stdout}\n${r2.stderr}`;
    assert.equal(r2.status, 0, out2);
    assert.match(out2, /无需预热/, out2);
    assert.doesNotMatch(out2, /后台预热已完成/, out2);
  } finally {
    rmSync(f.root, { recursive: true, force: true });
  }
}

function testInstallCommandActivatesCurrentShellPath() {
  const source = readFileSync(installer, 'utf8');
  const app = readFileSync(join(repoRoot, 'frontend/src/edition/app.ts'), 'utf8');
  for (const value of [source, app]) {
    assert.match(value, /install\.sh \| BOTMUX_PLATFORM_URL=\S+ sh && export PATH="\$HOME\/\.local\/bin:\$PATH"/);
    assert.match(value, /--connect-timeout 5 --max-time 20 --retry 5 --retry-delay 1 --retry-max-time 60/);
  }
}

/** Asserts the fast curl timeout/retry policy; shared with other download scripts. */
export function assertFastCurlRetryPolicy(value) {
  assert.match(value, /CURL_CONNECT_TIMEOUT_SEC="\$\{BOTMUX_CURL_CONNECT_TIMEOUT_SEC:-5\}"/);
  assert.match(value, /--connect-timeout "\$CURL_CONNECT_TIMEOUT_SEC"/);
  assert.match(value, /--max-time "\$CURL_TRANSFER_TIMEOUT_SEC"/);
  assert.match(value, /--retry "\$CURL_RETRY_COUNT"/);
}

function testCurlDownloadsUseFastRetryPolicy() {
  assertFastCurlRetryPolicy(readFileSync(installer, 'utf8'));
}

/** Asserts no `$VAR` runs straight into a non-ASCII character (dash reads it as part of the name). */
export function assertShellVariablesBraced(file) {
  const source = readFileSync(file, 'utf8');
  assert.doesNotMatch(
    source,
    /\$[A-Za-z_][A-Za-z0-9_]*[^\x00-\x7F]/u,
    `${file} contains an unbraced shell variable immediately followed by a non-ASCII character`,
  );
}

function testShellVariablesBeforeNonAsciiAreBraced() {
  assertShellVariablesBraced(installer);
}

// 回归：收尾必须提示「当前终端还没加载 botmux」。
// 曾有 bug：这个提示的条件写成 `if ! command -v botmux`，但主流程早就把 ~/.botmux/bin
// 塞进了本进程 PATH（供安装期调 botmux start/setup），检查永远为真、提示永远不打。
// 单测当时看不出来——npm 是 mock、botmux 二进制根本不存在，command -v 失败所以提示照打；
// 只有真机装成功（二进制真存在）才暴露：用户装完敲 botmux 得到 command not found 却毫无提示。
// 所以这里必须【模拟出真机那个条件】：让 botmux 命令在 PATH 上真实可解析，再要求提示仍然打印。
function testPathHintAlwaysPrintedEvenWhenBotmuxResolvable() {
  const f = fixture({ nodeMajor: 22 });
  try {
    // 让 botmux 在安装过程中可解析（等价于真机二进制装好后的状态）
    const botmuxBin = join(f.home, '.botmux', 'bin');
    mkdirSync(botmuxBin, { recursive: true });
    executable(join(botmuxBin, 'botmux'), 'echo "botmux mock"');
    executable(join(f.bin, 'botmux'), 'echo "botmux mock"');
    const output = run(f);
    assert.match(output, /当前这个终端/, output);
    assert.match(output, /export PATH=/, output);
    assert.match(output, /重开一个终端/, output);
  } finally {
    rmSync(f.root, { recursive: true, force: true });
  }
}

function testBotmuxBinPathPersistedWhenPostinstallDidNot() {
  // 回归：botmux 3.18+ 全局命令是 ~/.botmux/bin/botmux（launcher），其 PATH 首选由 botmux
  // postinstall 写启动文件。install.sh 主流程会把 ~/.botmux/bin 注入「当前进程 PATH」（供安装期
  // botmux start/setup 解析）。曾有 bug：兜底函数据此误判「已在 PATH」而跳过写启动文件，导致
  // postinstall 没写时（这里 npm 是 mock、必然没写）用户重开终端 botmux 不可用。
  // 该测试锁定：无论进程 PATH 是否已含，只要启动文件里没有，就必须兜底持久化一次。
  for (const uid of [0, 1000]) {
    const f = fixture({ uid, nodeMajor: 22 });
    try {
      const output = run(f);
      // fixture 的 SHELL=/bin/sh → 兜底走 *) 分支写 ~/.profile。
      const persisted = readFileSync(join(f.home, '.profile'), 'utf8');
      assert.match(persisted, /\.botmux\/bin/, `uid=${uid}: ~/.botmux/bin 必须被持久化到启动文件`);
      assert.match(output, /install\.sh 兜底/, `uid=${uid}: 应打印兜底写入日志`);
      // 兜底写的是幂等 case 行（一行里 .botmux/bin 字面出现两次），按「含 marker 的行数」判重复。
      const lines = (persisted.match(/# added by botmux installer/g) || []).length;
      assert.equal(lines, 1, `uid=${uid}: 兜底行应只写一次，实际 ${lines}`);
      // 幂等语句要真幂等：PATH 已含该目录时，source 这行不得再前插。
      assert.match(persisted, /case ":\$PATH:" in .*botmux\/bin/, `uid=${uid}: 应写幂等 case 语句而非裸 export`);
    } finally {
      rmSync(f.root, { recursive: true, force: true });
    }
  }
}

function testBotmuxBinPathNotDuplicatedWhenPostinstallWrote() {
  // 另一半：postinstall 已把 ~/.botmux/bin 写进某个启动文件时，install.sh 不得重复写。
  const f = fixture({ uid: 1000, nodeMajor: 22 });
  try {
    // 模拟 postinstall 已写 .profile（fixture SHELL=/bin/sh → 兜底目标也是 .profile）。
    writeFileSync(join(f.home, '.profile'), 'export PATH="$HOME/.botmux/bin:$PATH"\n');
    const output = run(f);
    const persisted = readFileSync(join(f.home, '.profile'), 'utf8');
    // 已有用户自己的 .botmux/bin 行 → 兜底应识别并跳过，不追加自己的 marker 行。
    assert.doesNotMatch(persisted, /# added by botmux installer/, '已持久化时不应再追加兜底行');
    assert.doesNotMatch(output, /install\.sh 兜底/, '已持久化时不应再打印兜底日志');
  } finally {
    rmSync(f.root, { recursive: true, force: true });
  }
}

function testBotmuxBinaryInstallPreferredOverNpm() {
  // botmux 3.18+ 是 bun 单文件二进制：默认应调【官方安装器】装它（免 Node），不走 npm。
  // 这里 mock 的是「curl 下官方 install.sh」这一步——curl 返回一个假的官方安装器脚本，
  // 它读 BOTMUX_INSTALL_DIR 并在其中落一个可执行的假 botmux，模拟上游真实行为。
  const f = fixture({ uid: 1000, nodeMajor: 22 });
  try {
    exposeHostTools(f, ['cat', 'chmod', 'cp', 'grep', 'mkdir', 'mktemp', 'mv', 'rm', 'sh', 'cut']);
    executable(join(f.bin, 'curl'), `
out=""; url=""
while [ "$#" -gt 0 ]; do
  case "$1" in
    -o) out="$2"; shift 2 ;;
    http*) url="$1"; shift ;;
    *) shift ;;
  esac
done
printf 'curl %s\\n' "$url" >> "$TEST_STATE/calls"
case "$url" in
  *deepcoldy/botmux/master/install.sh)
    cat > "$out" <<'OFFICIAL'
#!/bin/sh
set -eu
printf 'official-installer repo=%s version=%s dir=%s\\n' \\
  "\${BOTMUX_REPO:-}" "\${BOTMUX_VERSION:-}" "\${BOTMUX_INSTALL_DIR:-}" >> "$TEST_STATE/calls"
mkdir -p "$BOTMUX_INSTALL_DIR"
printf '#!/bin/sh\\necho 9.9.9-fake\\n' > "$BOTMUX_INSTALL_DIR/botmux"
chmod +x "$BOTMUX_INSTALL_DIR/botmux"
echo "✅ installed botmux → $BOTMUX_INSTALL_DIR/botmux"
OFFICIAL
    chmod +x "$out"
    exit 0 ;;
  *) exit 22 ;;
esac`);
    // npm mock 记录是否被调用——二进制成功时不应出现 botmux 的 npm 安装。
    executable(join(f.bin, 'npm'), `
printf 'npm %s\\n' "$*" >> "$TEST_STATE/calls"
exit 0`);
    f.env.PATH = `${f.bin}:${systemPath}`;
    const output = run(f, { BOTMUX_INSTALL_METHOD: 'auto' });

    assert.match(output, /官方单二进制安装器|官方安装器/, '应走官方安装器路径');
    assert.doesNotMatch(output, /回退 npm/, '二进制成功时不应回退 npm');
    // 二进制落到 ~/.botmux/bin/botmux 且可执行。
    const installed = join(f.home, '.botmux', 'bin', 'botmux');
    assert.ok(existsSync(installed), 'botmux 应安装到 ~/.botmux/bin/botmux');
    // 拉的是官方安装器地址
    assert.match(calls(f), /curl .*deepcoldy\/botmux\/master\/install\.sh/);
    // 我们的三个配置必须映射成上游认的 env 传进去
    assert.match(calls(f), /official-installer repo=deepcoldy\/botmux version=latest dir=.*\.botmux\/bin/,
      '应把 REPO/VERSION/INSTALL_DIR 传给官方安装器');
    // 没有用 npm 装 botmux（agent CLI 的 npm 调用不在此用例里，已 --no-agents）。
    assert.doesNotMatch(calls(f), /npm .*botmux@/, '不应再用 npm 安装 botmux');
  } finally {
    rmSync(f.root, { recursive: true, force: true });
  }
}

function testBotmuxBinaryFailureFallsBackToNpm() {
  // 官方安装器下载不到（无网络等）时，必须回退 npm，安装不能中断。
  const f = fixture({ uid: 1000, nodeMajor: 22 });
  try {
    exposeHostTools(f, ['cat', 'chmod', 'grep', 'mkdir', 'mktemp', 'rm', 'sh']);
    executable(join(f.bin, 'curl'), `
printf 'curl %s\\n' "$*" >> "$TEST_STATE/calls"
exit 22`);   // 一律失败
    executable(join(f.bin, 'npm'), `
printf 'npm %s\\n' "$*" >> "$TEST_STATE/calls"
exit 0`);
    f.env.PATH = `${f.bin}:${systemPath}`;
    const output = run(f, { BOTMUX_INSTALL_METHOD: 'auto' });

    assert.match(output, /回退 npm/, '二进制失败应回退 npm');
    assert.match(calls(f), /npm .*botmux@latest/, '回退后应用 npm 安装 botmux');
  } finally {
    rmSync(f.root, { recursive: true, force: true });
  }
}

// 官方安装器【跑起来了但失败】（非下载失败）也必须回退 npm，而不是让安装中断。
function testOfficialInstallerRunFailureFallsBackToNpm() {
  const f = fixture({ uid: 1000, nodeMajor: 22 });
  try {
    exposeHostTools(f, ['cat', 'chmod', 'grep', 'mkdir', 'mktemp', 'rm', 'sh']);
    executable(join(f.bin, 'curl'), `
out=""; url=""
while [ "$#" -gt 0 ]; do
  case "$1" in
    -o) out="$2"; shift 2 ;;
    http*) url="$1"; shift ;;
    *) shift ;;
  esac
done
printf 'curl %s\\n' "$url" >> "$TEST_STATE/calls"
case "$url" in
  *deepcoldy/botmux/master/install.sh)
    printf '#!/bin/sh\\necho "no build for this platform" >&2\\nexit 1\\n' > "$out"
    chmod +x "$out"
    exit 0 ;;
  *) exit 22 ;;
esac`);
    executable(join(f.bin, 'npm'), `
printf 'npm %s\\n' "$*" >> "$TEST_STATE/calls"
exit 0`);
    f.env.PATH = `${f.bin}:${systemPath}`;
    const output = run(f, { BOTMUX_INSTALL_METHOD: 'auto' });
    assert.match(output, /官方安装器执行失败/, output);
    assert.match(output, /回退 npm/, output);
    assert.match(calls(f), /npm .*botmux@latest/, '应回退 npm');
  } finally {
    rmSync(f.root, { recursive: true, force: true });
  }
}

// 回归：缺配置（没扫码）时 botmux start 应【跳过而非中止安装】。
// 曾是 die，脚本直接退出，后面的 PATH 提示与 bind 引导一句都打不出来——用户实测就是
// 装完毫无提示、敲 botmux 全是 command not found，两个 bug 叠在一起。
function testMissingConfigSkipsStartInsteadOfAborting() {
  const f = fixture({ uid: 1000, nodeMajor: 22 });
  try {
    executable(join(f.bin, 'botmux'), 'echo "botmux mock"');
    // 走 start 分支（不加 --no-start），且不生成任何 bots.json/.env
    const result = spawnSync('sh', [installer, '--no-agents', '--no-setup', '--no-system-deps'], {
      env: f.env, encoding: 'utf8', timeout: 30_000,
    });
    const output = `${result.stdout}\n${result.stderr}`;
    assert.equal(result.status, 0, `缺配置不应让安装失败退出\n${output}`);
    assert.match(output, /跳过 botmux start/, output);
    assert.match(output, /botmux setup/, output);
    // 关键：必须仍然走到收尾，把 PATH 提示和 bind 引导打出来
    assert.match(output, /当前这个终端/, `缺配置时仍须打印 PATH 提示\n${output}`);
    assert.match(output, /botmux bind/, `缺配置时仍须打印 bind 引导\n${output}`);
  } finally {
    rmSync(f.root, { recursive: true, force: true });
  }
}

// 收尾必须引导绑定；已绑定（platform.json 存在）则不再啰嗦。
function testBindGuidanceShownOnlyWhenUnbound() {
  const f = fixture({ uid: 1000, nodeMajor: 22 });
  try {
    const unbound = run(f);
    assert.match(unbound, /绑定新机器/, unbound);
    assert.match(unbound, /botmux bind <绑定码>/, unbound);
    assert.match(unbound, /安装器无法代劳/, unbound);
  } finally {
    rmSync(f.root, { recursive: true, force: true });
  }
  const g = fixture({ uid: 1000, nodeMajor: 22 });
  try {
    mkdirSync(join(g.home, '.botmux'), { recursive: true });
    writeFileSync(join(g.home, '.botmux', 'platform.json'), '{"machineToken":"x"}');
    const bound = run(g);
    assert.doesNotMatch(bound, /botmux bind <绑定码>/, `已绑定不应再提示 bind\n${bound}`);
  } finally {
    rmSync(g.root, { recursive: true, force: true });
  }
}

// 回归：交互式子命令不得在「stdin 已是终端」时再 `</dev/tty`。
// 线上事故：外层工具在子 PTY 里跑 install.sh，它正读 /dev/tty 转发进来，
// 我们又 `botmux setup ... </dev/tty` 直连同一个 /dev/tty，两个读者分食按键 →
// setup 菜单方向键/Enter/Esc 完全无响应（真实用户截图）。
// 判据必须是 `-t 0`（stdin 是否终端），而不是 has_tty（stdout/stderr 是终端就为真，
// 区分不了「stdin 是管道」和「stdin 已是终端」这两种相反情形）。
function testNoTtyStealWhenStdinAlreadyInteractive() {
  const source = readFileSync(installer, 'utf8');
  // 所有交互式子命令的 </dev/tty 都必须由 needs_tty_redirect 把关，不能再用 has_tty
  const risky = source
    .split('\n')
    .map((line, i) => ({ line, no: i + 1 }))
    .filter(({ line }) => /if has_tty; then.*<\/dev\/tty/.test(line));
  assert.equal(risky.length, 0,
    `这些行仍用 has_tty 决定是否 </dev/tty，会在外层工具的子 PTY 内抢按键:\n${
      risky.map(r => `  ${r.no}: ${r.line.trim()}`).join('\n')}`);
  assert.match(source, /needs_tty_redirect\(\) \{/, '应定义 needs_tty_redirect');
  assert.match(source, /stdin_is_interactive && return 1/, 'stdin 已是终端时必须不重定向');

  // 三种场景下的真实行为（把两个函数抽出来单独跑，不依赖完整安装流程）
  const probeDir = mkdtempSync(join(tmpdir(), 'botmux-tty-probe-'));
  try {
    const probe = join(probeDir, 'probe.sh');
    writeFileSync(probe, `#!/bin/sh
stdin_is_interactive() { [ -t 0 ]; }
needs_tty_redirect() { stdin_is_interactive && return 1; ( : </dev/tty ) 2>/dev/null; }
needs_tty_redirect && echo REDIRECT || echo INHERIT
`);
    // stdin 被重定向到 /dev/null 且无可用 /dev/tty（测试进程环境）→ 只能继承，不该重定向
    const r = spawnSync('sh', [probe], {
      encoding: 'utf8', timeout: 10_000, stdio: ['ignore', 'pipe', 'pipe'],
    });
    assert.match(`${r.stdout}`.trim(), /INHERIT|REDIRECT/,
      `探针应有输出\n${r.stdout}${r.stderr}`);
    // 关键断言：stdin 是终端时绝不能选 REDIRECT。用 sh -c 'exec < /dev/null' 无法造终端，
    // 故此处只锁定「非终端 stdin 不会误判成已交互」——终端场景由上面的静态断言覆盖。
    assert.doesNotMatch(`${r.stdout}`, /^REDIRECT$/m,
      `无可用 tty 时不应声称需要重定向\n${r.stdout}`);
  } finally {
    rmSync(probeDir, { recursive: true, force: true });
  }
}

// 回归：`brew config` 成功、但 formula 已用新 DSL 而本机 brew 太旧 → 必须更新后重试一次。
// 真实用户场景：装 Node 时拉起 openssl@3，旧 brew 不认识 post_install_steps，直接中止。
// 旧代码检查不出来——repair_homebrew_macos_compat 只在 brew config 报 unknown macOS 时才修，
// 而这里 brew config 是成功的；且那次 repair 还排在 ensure_homebrew_for_tmux 里、晚于 ensure_node。
function testMacStaleBrewFormulaDslRetriesAfterUpdate() {
  const f = fixture({ uid: 1000, nodeMajor: 18 });   // 18 → 需要升级 Node，走 brew 分支
  try {
    exposeHostTools(f, ['cat', 'chmod', 'env', 'grep', 'mkdir', 'mktemp', 'rm', 'sh']);
    executable(join(f.bin, 'sw_vers'), `
[ "\${1:-}" = -productVersion ] && printf '15.3.1\\n'`);
    // 让 node 看起来是 brew 管的（走 brew 分支而不是 fnm）
    const brewPrefix = join(f.root, 'brew');
    mkdirSync(join(brewPrefix, 'bin'), { recursive: true });
    rmSync(join(f.bin, 'node'));
    executable(join(brewPrefix, 'bin', 'node'), `
major=$(cat "$TEST_STATE/node-major")
case "\${1:-}" in -p) echo "$major" ;; --version) echo "v$major.0.0" ;; esac`);
    executable(join(f.bin, 'brew'), `
printf 'brew %s\\n' "$*" >> "$TEST_STATE/calls"
case "$*" in
  config) exit 0 ;;                       # ← 关键：config 成功，老逻辑因此完全不修
  --prefix) echo "$TEST_BREW_PREFIX" ;;
  --prefix*) echo "$TEST_BREW_PREFIX" ;;
  update) : > "$TEST_STATE/brew-updated"; exit 0 ;;
  install*|upgrade*)
    if [ ! -f "$TEST_STATE/brew-updated" ]; then
      printf "Error: undefined method \\\`post_install_steps' for an instance of Formulary::FormulaNamespace\\n" >&2
      exit 1
    fi
    printf '22' > "$TEST_STATE/node-major"
    ;;
  list*) exit 1 ;;
esac`);
    f.env.PATH = `${brewPrefix}/bin:${f.bin}`;
    const output = run(f, { BOTMUX_INSTALL_OS: 'Darwin', BOTMUX_NODE_MANAGER: 'brew', TEST_BREW_PREFIX: brewPrefix });
    const log = calls(f);
    assert.match(output, /Homebrew 过旧|不认识新版 formula 语法/, output);
    // 必须真的更新过；且 DSL 错误应【第一次就识别】，不白跑一次代理重试
    assert.match(log, /brew update/, log);
    const attemptsBeforeUpdate = (log.slice(0, log.indexOf('brew update')).match(/brew (install|upgrade) node/g) || []).length;
    assert.equal(attemptsBeforeUpdate, 1,
      `DSL 错误应第一次就识别并去更新，不该先白跑代理重试；实际更新前跑了 ${attemptsBeforeUpdate} 次\n${log}`);
    // 只重试一次：更新后再跑一次即止
    const attempts = (log.match(/brew (install|upgrade) node/g) || []).length;
    assert.equal(attempts, 2, `应恰好「失败一次 + 更新后重试一次」，实际 ${attempts} 次\n${log}`);
  } finally {
    rmSync(f.root, { recursive: true, force: true });
  }
}

// 非 DSL 类的 brew 失败不该触发更新——否则每个偶发网络错误都白跑一次 brew update。
// 此时按既有行为回退 standalone 安装 Node，安装流程不中断。
function testMacNonDslBrewFailureDoesNotUpdate() {
  const f = fixture({ uid: 1000, nodeMajor: 18 });
  try {
    exposeHostTools(f, ['cat', 'chmod', 'env', 'grep', 'mkdir', 'mktemp', 'rm', 'sh', 'tar']);
    executable(join(f.bin, 'sw_vers'), `
[ "\${1:-}" = -productVersion ] && printf '15.3.1\\n'`);
    // standalone 回退会下载 Node tarball：给一个 curl mock 让它「成功」，
    // 否则会 die "安装 Node.js 需要 curl"，掩盖本用例真正要断言的东西。
    executable(join(f.bin, 'curl'), `
out=""
while [ "$#" -gt 0 ]; do
  case "$1" in -o) out="$2"; shift 2 ;; *) shift ;; esac
done
[ -n "$out" ] && : > "$out"
exit 0`);
    const brewPrefix = join(f.root, 'brew');
    mkdirSync(join(brewPrefix, 'bin'), { recursive: true });
    rmSync(join(f.bin, 'node'));
    executable(join(brewPrefix, 'bin', 'node'), `
major=$(cat "$TEST_STATE/node-major")
case "\${1:-}" in -p) echo "$major" ;; --version) echo "v$major.0.0" ;; esac`);
    executable(join(f.bin, 'brew'), `
printf 'brew %s\\n' "$*" >> "$TEST_STATE/calls"
case "$*" in
  config) exit 0 ;;
  --prefix*) echo "$TEST_BREW_PREFIX" ;;
  update) : > "$TEST_STATE/brew-updated"; exit 0 ;;
  install*|upgrade*) printf 'Error: Failed to download resource "node"\\n' >&2; exit 1 ;;
  list*) exit 1 ;;
esac`);
    f.env.PATH = `${brewPrefix}/bin:${f.bin}`;
    const result = spawnSync('sh', [installer, '--no-agents', '--no-setup', '--no-start', '--no-system-deps'], {
      env: { ...f.env, BOTMUX_INSTALL_OS: 'Darwin', BOTMUX_NODE_MANAGER: 'brew', TEST_BREW_PREFIX: brewPrefix },
      encoding: 'utf8', timeout: 30_000,
    });
    const output = `${result.stdout}\n${result.stderr}`;
    const log = calls(f);
    // 核心断言：非 DSL 失败绝不触发 brew update
    assert.doesNotMatch(log, /brew update/,
      `非 DSL 失败不应触发 brew update\n${log}`);
    // 且应按既有行为回退 standalone，而不是中止在 brew 这一步
    assert.match(output, /回退到用户目录独立安装/, output);
  } finally {
    rmSync(f.root, { recursive: true, force: true });
  }
}

function testRootAndNonRootPaths() {
  for (const uid of [0, 1000]) {
    const f = fixture({ uid, nodeMajor: 22 });
    try {
      const output = run(f);
      assert.match(output, uid === 0 ? /检测到 root 用户/ : /检测到非 root 用户/);
      assert.doesNotMatch(output, /sudo must not be called/);
    } finally {
      rmSync(f.root, { recursive: true, force: true });
    }
  }
}

function testNativeBuildEnvMirrorAndPython() {
  const mirror = 'https://mirror.example.test/node';
  const esc = (s) => s.replaceAll('/', '\\/');
  const modernPy = `
case "\${1:-}" in
  -c) exit 0 ;;
  --version) echo 'Python 3.11.0' ;;
esac`;
  const oldPy = `
case "\${1:-}" in
  -c) exit 1 ;;
  --version) echo 'Python 3.6.0' ;;
esac`;

  // npm mock 把 configure_native_build_env 设定的 node-gyp 环境写进 calls，供断言实际生效值。
  function envFixture() {
    const f = fixture({ nodeMajor: 22 });
    // 隔离外层继承的 env（fixture 展开了 process.env），避免宿主的 disturl/python 配置污染断言；
    // 各 case 自行注入需要的变量。
    for (const k of ['NODE_GYP_FORCE_PYTHON', 'npm_config_python', 'PYTHON', 'disturl', 'npm_config_disturl', 'BOTMUX_NODE_GYP_MIRROR']) {
      delete f.env[k];
    }
    executable(join(f.bin, 'npm'), `
printf 'npm python=%s force=%s disturl=%s ncdisturl=%s\\n' "\${npm_config_python:-}" "\${NODE_GYP_FORCE_PYTHON:-}" "\${disturl:-}" "\${npm_config_disturl:-}" >> "$TEST_STATE/calls"
exit 0`);
    return f;
  }

  // 配置的镜像同时写入 disturl 与 node-gyp 真正读取的 npm_config_disturl。
  let f = envFixture();
  try {
    run(f, { BOTMUX_NODE_GYP_MIRROR: mirror });
    assert.match(calls(f), new RegExp(`disturl=${esc(mirror)} ncdisturl=${esc(mirror)}`));
  } finally { rmSync(f.root, { recursive: true, force: true }); }

  // 空串关闭镜像（P2）：BOTMUX_NODE_GYP_MIRROR='' → disturl 保持为空。
  f = envFixture();
  try {
    run(f, { BOTMUX_NODE_GYP_MIRROR: '' });
    assert.match(calls(f), /disturl= ncdisturl=$/m);
  } finally { rmSync(f.root, { recursive: true, force: true }); }

  // 用户已设的 disturl 优先，不被镜像覆盖。
  f = envFixture();
  try {
    run(f, { disturl: 'https://mirror.example/node', npm_config_disturl: 'https://mirror.example/node' });
    assert.match(calls(f), /disturl=https:\/\/mirror\.example\/node /);
  } finally { rmSync(f.root, { recursive: true, force: true }); }

  // 仅设裸 disturl → 归一同步到 node-gyp 真正读取的 npm_config_disturl（P2 二轮）。
  f = envFixture();
  try {
    run(f, { disturl: 'https://bare.example/node' });
    assert.match(calls(f), /disturl=https:\/\/bare\.example\/node ncdisturl=https:\/\/bare\.example\/node/);
  } finally { rmSync(f.root, { recursive: true, force: true }); }

  // 已配置的有效 Python(≥3.8) 保持不动。
  f = envFixture();
  try {
    executable(join(f.bin, 'goodpy'), modernPy);
    run(f, { npm_config_python: join(f.bin, 'goodpy') });
    assert.match(calls(f), new RegExp(`python=${esc(join(f.bin, 'goodpy'))} `));
  } finally { rmSync(f.root, { recursive: true, force: true }); }

  // 配置了旧 Python(<3.8) → 被 PATH 上的 python3 顶掉（P1）。
  f = envFixture();
  try {
    executable(join(f.bin, 'python3'), modernPy);
    executable(join(f.bin, 'oldpy'), oldPy);
    run(f, { npm_config_python: join(f.bin, 'oldpy') });
    assert.match(calls(f), new RegExp(`python=${esc(join(f.bin, 'python3'))} `));
    assert.doesNotMatch(calls(f), /python=.*oldpy/);
  } finally { rmSync(f.root, { recursive: true, force: true }); }

  // NODE_GYP_FORCE_PYTHON 指向旧 Python：优先级最高也要被一并对齐（P1）。
  f = envFixture();
  try {
    executable(join(f.bin, 'python3'), modernPy);
    executable(join(f.bin, 'oldpy'), oldPy);
    run(f, { NODE_GYP_FORCE_PYTHON: join(f.bin, 'oldpy') });
    assert.match(calls(f), new RegExp(`force=${esc(join(f.bin, 'python3'))} `));
    assert.match(calls(f), new RegExp(`python=${esc(join(f.bin, 'python3'))} `));
  } finally { rmSync(f.root, { recursive: true, force: true }); }

  // 高优先级 FORCE 无效、但低优先级 npm_config_python 有效 → 落到有效值并对齐 FORCE（P1 二轮）。
  f = envFixture();
  try {
    executable(join(f.bin, 'goodpy'), modernPy);
    executable(join(f.bin, 'oldpy'), oldPy);
    run(f, { NODE_GYP_FORCE_PYTHON: join(f.bin, 'oldpy'), npm_config_python: join(f.bin, 'goodpy') });
    assert.match(calls(f), new RegExp(`force=${esc(join(f.bin, 'goodpy'))} `));
    assert.match(calls(f), new RegExp(`python=${esc(join(f.bin, 'goodpy'))} `));
    assert.doesNotMatch(calls(f), /oldpy/);
  } finally { rmSync(f.root, { recursive: true, force: true }); }
}

// 公开版默认只访问公网 npm：不设 HTTP 代理、不套 node-gyp 镜像，绑定引导不凭空编平台地址。
function testPublicDefaults() {
  const f = fixture({ nodeMajor: 22 });
  try {
    for (const k of ['disturl', 'npm_config_disturl', 'BOTMUX_NODE_GYP_MIRROR', 'BOTMUX_HTTP_PROXY', 'BOTMUX_PLATFORM_URL', 'CODEX_REGISTRY', 'LARK_CLI_REGISTRY']) {
      delete f.env[k];
    }
    mockInstalledAgents(f);
    executable(join(f.bin, 'codex'), `
case "\${1:-}" in
  --version) echo 'codex-cli 0.144.1' ;;
  login) echo 'Logged in using ChatGPT' ;;
esac`);
    executable(join(f.bin, 'npm'), `
printf 'npm %s disturl=%s https=%s\\n' "$*" "\${npm_config_disturl:-}" "\${HTTPS_PROXY:-}" >> "$TEST_STATE/calls"
case "$*" in *'view @openai/codex@latest version'*) echo '0.144.1' ;; esac`);
    const output = run(f, {}, { agents: true, codexWarmup: false });
    assert.match(calls(f), /view @openai\/codex@latest version --registry https:\/\/registry\.npmjs\.org/);
    assert.match(calls(f), /@larksuite\/cli@latest --registry=https:\/\/registry\.npmjs\.org/);
    assert.doesNotMatch(calls(f), /disturl=\S|https=\S/);
    assert.match(output, /浏览器打开 你的 Botmux 平台/, output);
  } finally {
    rmSync(f.root, { recursive: true, force: true });
  }
}

export function runGenericTests() {
  testFnmUpgrade();
  testNoManagerInstallsFnmByDefault();
  testExplicitStandaloneStillHonored();
  testNvmUpgrade();
  testBrewUpgrade();
  testNewerBrewNodeSwitchesToSupportedLts();
  testVersionedBrewUpgradePersistsPath();
  testMacInstallsHomebrewAndTmuxViaPreferredProxy();
  testMacUpdatesStaleHomebrewForNewMacOS();
  testProxyFallback();
  testCodexUsesRegistryFirst();
  testCodexPublicFallbackUsesProxy();
  testExistingClaudeAndCodexAreReused();
  testExistingCodexUpdatesFromRegistry();
  testCodexWarmupAndDoctorWiring();
  testLinuxTmuxPrefersPasswordlessSystemManager();
  testVersionedPythonInstallFallback();
  testVersionedPythonFallbackAfterMainInstallFailure();
  testContinuesWithoutModernPythonOnLinux();
  testLinuxLingerUsesPasswordlessSudo();
  testLinuxLingerRunsDirectlyAsRoot();
  testAgentWarmupDefaultsToDetachedWorker();
  testWarmupStatusReflectsWhatActuallyWarmed();
  testWarmupStatusNamesWarmedAgents();
  testCurlDownloadsUseFastRetryPolicy();
  testShellVariablesBeforeNonAsciiAreBraced();
  testBotmuxBinaryInstallPreferredOverNpm();
  testBotmuxBinaryFailureFallsBackToNpm();
  testOfficialInstallerRunFailureFallsBackToNpm();
  testMissingConfigSkipsStartInsteadOfAborting();
  testBindGuidanceShownOnlyWhenUnbound();
  testNoTtyStealWhenStdinAlreadyInteractive();
  testMacStaleBrewFormulaDslRetriesAfterUpdate();
  testMacNonDslBrewFailureDoesNotUpdate();
  testRootAndNonRootPaths();
  testPathHintAlwaysPrintedEvenWhenBotmuxResolvable();
  testBotmuxBinPathPersistedWhenPostinstallDidNot();
  testBotmuxBinPathNotDuplicatedWhenPostinstallWrote();
  testNativeBuildEnvMirrorAndPython();
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  runGenericTests();
  testInstallCommandActivatesCurrentShellPath();
  testPublicDefaults();
  console.log('installer tests: Node managers, Codex reuse/update/warmup, tmux, Linger, native-build-env, proxy, lark-cli, root/non-root ✓');
}
