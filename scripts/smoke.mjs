// 端到端冒烟测试：拉起 Go/Hertz 平台，
// 再模拟 dashboard + daemon 隧道客户端，
// 跑通 绑定 → 隧道 → 反代(HTTP + 终端 WS) 全链路。
// 用法：npm run test:smoke
// 也可针对已启动的服务：BOTMUX_SMOKE_BASE_URL=http://127.0.0.1:8123 node scripts/smoke.mjs
import http from 'http';
import https from 'https';
import net from 'net';
import { spawn } from 'child_process';
import { existsSync, readdirSync } from 'fs';
import { tmpdir } from 'os';
import { dirname, resolve } from 'path';
import { fileURLToPath, pathToFileURL } from 'url';
import { WebSocket, WebSocketServer, createWebSocketStream } from 'ws';

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..');
// The private edition the build picks (scripts/edition.sh) may add server
// environment and checks for what it ships, from hooks/smoke.mjs.
const edition = await (async () => {
  const requested = process.env.BOTMUX_EDITION || '';
  if (requested === 'oss') return {};
  const ext = resolve(repoRoot, 'ext');
  const names = requested ? [requested] : existsSync(ext) ? readdirSync(ext).sort() : [];
  const name = names.find((n) => existsSync(resolve(ext, n, 'go.mod')));
  const hooks = name ? resolve(ext, name, 'hooks/smoke.mjs') : '';
  return hooks && existsSync(hooks) ? import(pathToFileURL(hooks).href) : {};
})();
const serverRoot = resolve(process.env.BOTMUX_SMOKE_SERVER_ROOT || repoRoot);
const smokeBackend = 'go';
const PORT = Number(process.env.BOTMUX_SMOKE_PORT || 8123);
const DASH_PORT = Number(process.env.BOTMUX_SMOKE_DASH_PORT || 7991);
const ROOT_HOST = process.env.BOTMUX_SMOKE_ROOT_HOST || 'lvh.me';
const SECRET = 'smoke-secret-fixed';
const externalBase = process.env.BOTMUX_SMOKE_BASE_URL || '';
const target = new URL(externalBase || `http://127.0.0.1:${PORT}`);
const targetPort = Number(target.port || (target.protocol === 'https:' ? 443 : 80));
const APEX_HOST = process.env.BOTMUX_SMOKE_APEX_HOST || (externalBase ? target.hostname : 'localhost');
const requestTransport = target.protocol === 'https:' ? https : http;
const wsBase = new URL(target.origin);
wsBase.protocol = target.protocol === 'https:' ? 'wss:' : 'ws:';
let failures = 0;
let dashboardHealthy = true;
let nextDataDialDelayMs = 0;
const ok = (c, m) => { if (!c) { failures++; console.error('  ✗', m); } else console.log('  ✓', m); };
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
// Keep later gates running when one endpoint regresses to a non-JSON response;
// the surrounding status/field assertion still records the original failure.
const jsonBody = (body) => { try { return JSON.parse(body); } catch { return {}; } };
const wsOpen = (ws, timeout = 3000) => new Promise((resolve, reject) => {
  const t = setTimeout(() => reject(new Error('websocket open timeout')), timeout);
  ws.once('open', () => { clearTimeout(t); resolve(); });
  ws.once('error', (e) => { clearTimeout(t); reject(e); });
});
const wsMessage = (ws, timeout = 3000) => new Promise((resolve, reject) => {
  const t = setTimeout(() => reject(new Error('websocket message timeout')), timeout);
  ws.once('message', (data, isBinary) => { clearTimeout(t); resolve({ data, isBinary }); });
  ws.once('error', (e) => { clearTimeout(t); reject(e); });
});
const wsClose = (ws, timeout = 3000) => new Promise((resolve, reject) => {
  const t = setTimeout(() => reject(new Error('websocket close timeout')), timeout);
  ws.once('close', (code, reason) => { clearTimeout(t); resolve({ code, reason: reason.toString() }); });
});

// ---- 模拟机器本地 dashboard（http + 一个 /term WS 回显）----
function startMockDashboard() {
  const calls = { update: 0, restart: 0, authenticated: true, restartBody: null };
  const srv = http.createServer(async (req, res) => {
    if (req.url === '/__health' && !dashboardHealthy) {
      res.writeHead(503, { 'content-type': 'text/plain' });
      res.end('unhealthy');
      return;
    }
    if (req.method === 'POST' && req.url === '/api/update/run') {
      calls.update++;
      calls.authenticated &&= (req.headers.cookie || '').includes('botmux_dashboard_token=mock-dash-token');
      if (calls.update === 2) {
        res.writeHead(409, { 'content-type': 'application/json' });
        res.end(JSON.stringify({ ok: false, error: 'update_in_flight' }));
        return;
      }
      if (calls.update === 4) {
        res.writeHead(404, { 'content-type': 'application/json' });
        res.end(JSON.stringify({ ok: false, error: 'not_found' }));
        return;
      }
      const changed = calls.update !== 3;
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(JSON.stringify({
        ok: true,
        oldVersion: changed ? '2.79.1' : '2.111.0',
        newVersion: '2.111.0',
        changed,
      }));
      return;
    }
    if (req.method === 'POST' && req.url === '/api/update/restart') {
      calls.restart++;
      calls.authenticated &&= (req.headers.cookie || '').includes('botmux_dashboard_token=mock-dash-token');
      const chunks = [];
      for await (const chunk of req) chunks.push(chunk);
      calls.restartBody = JSON.parse(Buffer.concat(chunks).toString('utf8'));
      if (calls.restart === 3) {
        req.socket.destroy();
        return;
      }
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ ok: true }));
      return;
    }
    res.writeHead(200, { 'content-type': 'text/html', 'set-cookie': 'dash_internal=should_be_stripped' });
    res.end('<html>MOCK_DASHBOARD_OK path=' + req.url + '</html>');
  });
  const wss = new WebSocketServer({ server: srv, path: '/term' });
  wss.on('connection', (ws) => ws.on('message', (d) => ws.send('echo:' + d.toString())));
  return new Promise((r) => srv.listen(DASH_PORT, () => r({ srv, calls })));
}

// ---- 模拟 daemon：控制连接 + 收到 open-stream 后拨数据连接桥接到本地 dashboard ----
function startMockDaemon(machineToken) {
  const ctrl = new WebSocket(new URL(`/tunnel/control?token=${encodeURIComponent(machineToken)}`, wsBase));
  let teams = [];
  const bots = [{ appId: 'cli_smoke001', openId: 'ou_smoke', name: '冒烟bot' }];
  const reg = (type) => ctrl.send(JSON.stringify({ type, name: 'smoke-mac', botmuxVersion: '2.79.1', dashboardToken: 'mock-dash-token', dashboardPort: DASH_PORT, memberships: teams, bots }));
  ctrl.on('open', () => reg('register'));
  ctrl.on('message', (raw) => {
    let msg; try { msg = JSON.parse(raw.toString()); } catch { return; }
    if (msg.type === 'open-stream') {
      const delayMs = nextDataDialDelayMs;
      nextDataDialDelayMs = 0;
      const dial = () => {
        const data = new WebSocket(new URL(`/tunnel/data?token=${encodeURIComponent(machineToken)}&stream=${msg.streamId}`, wsBase));
        data.on('open', () => {
          const dup = createWebSocketStream(data);
          const tcp = net.connect(DASH_PORT, '127.0.0.1');
          dup.pipe(tcp); tcp.pipe(dup);
          const kill = () => { try { dup.destroy(); } catch {} try { tcp.destroy(); } catch {} };
          dup.on('error', kill); tcp.on('error', kill);
        });
      };
      if (delayMs > 0) setTimeout(dial, delayMs);
      else dial();
    } else if (msg.type === 'join-team') {
      if (!teams.some((t) => t.teamId === msg.teamId)) teams.push({ teamId: msg.teamId, teamName: msg.teamName });
      reg('heartbeat');
    } else if (msg.type === 'leave-team') {
      teams = teams.filter((t) => t.teamId !== msg.teamId);
      reg('heartbeat');
    }
  });
  return ctrl;
}

// ---- HTTP 工具：可控 Host 头 + 抓 set-cookie ----
function req({ path, method = 'GET', host = APEX_HOST, headers = {}, body }) {
  return new Promise((resolve, reject) => {
    const r = requestTransport.request({
      host: target.hostname,
      port: targetPort,
      path,
      method,
      headers: { host, ...headers },
    }, (res) => {
      const chunks = [];
      res.on('data', (c) => chunks.push(c));
      res.on('end', () => resolve({
        status: res.statusCode, headers: res.headers,
        setCookies: res.headers['set-cookie'] || [], body: Buffer.concat(chunks).toString('utf8'),
      }));
    });
    r.on('error', reject);
    if (body) r.write(body);
    r.end();
  });
}
const cookieVal = (setCookies, name) => {
  for (const c of setCookies) { const m = c.match(new RegExp('^' + name + '=([^;]*)')); if (m) return m[1]; }
  return null;
};

async function main() {
  const { srv: dash, calls: dashboardCalls } = await startMockDashboard();
  let server = null;
  let serverFailure = null;
  let daemon = null;
  try {
    if (!externalBase) {
      const serverEntry = resolve(process.env.BOTMUX_SMOKE_GO_BIN || resolve(serverRoot, 'dist/bin/botmux-platform'));
      if (!existsSync(serverEntry)) {
        throw new Error(`${smokeBackend} 服务入口不存在：${serverEntry}；请先构建对应后端`);
      }
      server = spawn(serverEntry, [], {
        cwd: serverRoot,
        env: {
          ...process.env,
          PORT: String(PORT),
          PORT0: String(PORT),
          STATUSZ_DIR: process.env.BOTMUX_SMOKE_STATUSZ_DIR || tmpdir(),
          STATUSZ_NAME: `botmux-platform-smoke-${process.pid}-${PORT}`,
          SIGNING_SECRET: SECRET,
          PUBLIC_BASE_URL: `http://${ROOT_HOST}:${PORT}`,
          NODE_ENV: 'development',
          DEV_LOGIN: 'true',
          COOKIE_SECURE: 'false',
          MONGODB_URI: '',
          REDIS_URL: '',
          TEAMSYNC_FEISHU_WRITES: '1',
          WEB_DIR: resolve(serverRoot, 'dist/web'),
          // A packaged artifact ships the assembled installer as install.sh.
          BOTMUX_INSTALLER_FILE: resolve(serverRoot, serverRoot === repoRoot ? 'dist/install.sh' : 'install.sh'),
          ...edition.serverEnv?.({ serverRoot, repoRoot }),
        },
        stdio: ['ignore', 'inherit', 'inherit'],
      });
      server.once('exit', (code, signal) => {
        serverFailure = new Error(`${smokeBackend} 服务提前退出：code=${code ?? ''} signal=${signal || ''}`);
        if (code && code !== 0) console.error(serverFailure.message);
      });
      server.once('error', (e) => {
        serverFailure = new Error(`${smokeBackend} 服务启动失败：${e.message}`);
        console.error(serverFailure.message);
      });
    }

    // 不用固定 sleep：两套运行时首次启动都可能有抖动，以 healthz 为真正就绪门。
    const readyDeadline = Date.now() + Number(process.env.BOTMUX_SMOKE_READY_TIMEOUT_MS || 10_000);
    while (true) {
      try {
        const health = await req({ path: '/healthz' });
        if (health.status === 200 && health.body === 'ok') break;
      } catch { /* 服务尚未监听 */ }
      if (serverFailure) throw serverFailure;
      if (Date.now() >= readyDeadline) throw new Error(`等待 ${smokeBackend} 服务就绪超时：${target.origin}`);
      await sleep(100);
    }

    // A 健康
    ok((await req({ path: '/healthz' })).body === 'ok', 'healthz');

    // A2 一键安装器：新机器无平台登录态，所以下载接口必须公开可取、禁止缓存。
    const installer = await req({ path: '/install.sh' });
    ok(installer.status === 200 && installer.body.startsWith('#!/bin/sh'), '一键安装脚本可免登录下载');
    ok(installer.headers['content-type']?.startsWith('text/x-shellscript'), '安装脚本 content-type 正确');
    ok(installer.headers['cache-control'] === 'no-store', '安装脚本禁缓存');
    // ae50c77 起二进制安装委托给 botmux 官方单二进制安装器，失败再回退 npm。
    ok(installer.body.includes('BOTMUX_INSTALLER_URL') && installer.body.includes('BOTMUX_INSTALL_METHOD'), '安装器调用 botmux 官方安装器并保留 npm 回退');
    ok(installer.body.includes('BOTMUX_NODE_MANAGER') && installer.body.includes('upgrade_node_with_manager'), '安装器携带既有 Node 管理器升级逻辑');
    ok(!installer.body.includes('CURRENT_UID') && installer.body.includes('install_uid=$(id -u') && installer.body.includes('validate_install_user'), '安装器按调用点读取 uid，兼容 set -u');
    ok(installer.body.includes('version_is_newer') && installer.body.includes('codex_has_official_subscription'), 'Codex 复用时检查更新和官方订阅');
    ok(installer.body.includes('verify_codex_health'), 'Codex 保留 doctor 健康检查');
    ok(installer.body.includes('HOMEBREW_NO_AUTO_UPDATE') && installer.body.includes('ensure_linux_system_deps_preflight') && installer.body.includes('bubblewrap'), 'Linux 预装 tmux 与 Codex bubblewrap 依赖');
    ok(installer.body.includes('run_with_proxy_preferred') && installer.body.includes('NONINTERACTIVE=1') && installer.body.includes('repair_homebrew_macos_compat') && installer.body.includes('brew update') && installer.body.includes('brew install tmux'), 'macOS 通过研发代理补齐/更新 Homebrew 与 tmux');
    const installerCached = await req({ path: '/install.sh', headers: { 'if-none-match': installer.headers.etag } });
    ok(installerCached.status === 304, '安装脚本支持 ETag 条件请求');
    const installerApi = await req({ path: '/api/install.sh', method: 'HEAD' });
    ok(installerApi.status === 200 && Number(installerApi.headers['content-length']) > 0, 'API 别名支持 HEAD');
    const installerPost = await req({ path: '/install.sh', method: 'POST' });
    ok(installerPost.status === 405 && installerPost.headers.allow === 'GET, HEAD', '安装脚本拒绝非读取方法');

    await edition.check?.({ req, ok, sleep, wsBase, wsOpen, wsMessage, wsClose, installer });


    // B 未登录
    ok((await req({ path: '/api/machines' })).status === 401, '未登录 /api/machines 401');

    // C devLogin
    const login = await req({ path: '/auth/login' });
    const sess = cookieVal(login.setCookies, 'botmux_platform_session');
    ok(login.status === 302 && !!sess, 'devLogin 拿到会话 cookie');
    const C = {
      cookie: `botmux_platform_session=${sess}`,
      origin: `http://${ROOT_HOST}:${PORT}`,
    };

    // D 绑定
    const bc = JSON.parse((await req({ path: '/api/bind-code', method: 'POST', headers: C })).body);
    ok(!!bc.code, '拿到绑定码(blob)');
    // daemon 会从 blob 解出 token；冒烟里同样解一下
    const blob = JSON.parse(Buffer.from(bc.code, 'base64url').toString('utf8'));
    ok(blob.u && blob.t, 'blob 含平台地址+token');
    const bind = JSON.parse((await req({ path: '/api/bind', method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ code: blob.t }) })).body);
    ok(!!bind.machineToken && !!bind.machineId, '绑定换取 machineToken');

    // E daemon 上线
    daemon = startMockDaemon(bind.machineToken);
    await new Promise((r) => setTimeout(r, 600));

    // F 机器列表
    const ml = JSON.parse((await req({ path: '/api/machines', headers: C })).body);
    ok(ml.machines.length === 1 && ml.machines[0].machineId === bind.machineId, '机器出现在列表');
    ok(ml.machines[0].botmuxVersion === '2.79.1' && !ml.machines[0].stale, '版本上报 + 在线');

    // F2 一键升级：仅 owner 可触发，经鉴权隧道调用 dashboard update，并在变更后自动重启。
    const upgradeAnon = await req({ path: `/api/machines/${bind.machineId}/upgrade`, method: 'POST' });
    ok(upgradeAnon.status === 401, '未登录不能一键升级机器');
    const upgradeNonJson = await req({ path: `/api/machines/${bind.machineId}/upgrade`, method: 'POST', headers: C });
    ok(upgradeNonJson.status === 415, '一键升级拒绝可被跨站表单触发的非 JSON 请求');
    const upgradeRes = await req({
      path: `/api/machines/${bind.machineId}/upgrade`,
      method: 'POST',
      headers: { ...C, 'content-type': 'application/json' },
      body: '{}',
    });
    const upgrade = jsonBody(upgradeRes.body);
    ok(upgradeRes.status === 200 && upgrade.ok && upgrade.changed && upgrade.restarting, '一键升级后自动重启');
    ok(dashboardCalls.update === 1 && dashboardCalls.restart === 1 && dashboardCalls.authenticated, '升级请求带 dashboard 鉴权且只调用一次');
    ok(dashboardCalls.restartBody?.update?.oldVersion === '2.79.1' && dashboardCalls.restartBody?.update?.newVersion === '2.111.0', '重启携带升级版本信息');
    const upgradeBusy = await req({
      path: `/api/machines/${bind.machineId}/upgrade`,
      method: 'POST',
      headers: { ...C, 'content-type': 'application/json' },
      body: '{}',
    });
    ok(upgradeBusy.status === 409 && jsonBody(upgradeBusy.body).error === 'update_in_flight', '升级中的机器透传 409 且不重复重启');
    ok(dashboardCalls.restart === 1, '升级冲突时不调用重启');
    const upgradeNoChange = await req({
      path: `/api/machines/${bind.machineId}/upgrade`,
      method: 'POST',
      headers: { ...C, 'content-type': 'application/json' },
      body: '{}',
    });
    const noChange = jsonBody(upgradeNoChange.body);
    ok(upgradeNoChange.status === 200 && !noChange.changed && noChange.restarting, '安装已最新时仍重启以应用磁盘版本');
    const upgradeUnsupported = await req({
      path: `/api/machines/${bind.machineId}/upgrade`,
      method: 'POST',
      headers: { ...C, 'content-type': 'application/json' },
      body: '{}',
    });
    ok(upgradeUnsupported.status === 400 && jsonBody(upgradeUnsupported.body).error === 'upgrade_not_supported', '旧版 dashboard 归一为不支持一键升级');
    ok(dashboardCalls.restart === 2, '旧版 dashboard 不触发重启');
    const upgradeRestartFailed = await req({
      path: `/api/machines/${bind.machineId}/upgrade`,
      method: 'POST',
      headers: { ...C, 'content-type': 'application/json' },
      body: '{}',
    });
    const restartFailed = jsonBody(upgradeRestartFailed.body);
    ok(upgradeRestartFailed.status === 502 && restartFailed.error === 'restart_failed' && restartFailed.updateInstalled, '重启连接失败保留升级已安装状态');

    // G 打开：首条数据连接故意延迟到 6s 通用 API 超时之后，验证探活专用预算覆盖
    // daemon 的两波拨号边界（3s + 150ms + 3s），不会把合法的第二波慢成功误报为不可达。
    nextDataDialDelayMs = 6200;
    const delayedOpen = await req({ path: `/api/machines/${bind.machineId}/open`, method: 'POST', headers: C });
    const open = jsonBody(delayedOpen.body);
    ok(delayedOpen.status === 200 && !!open.openUrl && open.openUrl.includes(`m-${bind.machineId}.${ROOT_HOST}`), '6.2s 慢数据连接仍拿到子域 openUrl');

    dashboardHealthy = false;
    const unhealthyOpen = await req({ path: `/api/machines/${bind.machineId}/open`, method: 'POST', headers: C });
    const unhealthyOpenBody = jsonBody(unhealthyOpen.body);
    ok(unhealthyOpen.status === 503 && unhealthyOpenBody.error === 'dashboard_unreachable', 'dashboard 探活失败时拒绝打开');
    dashboardHealthy = true;
    const recoveredOpen = await req({ path: `/api/machines/${bind.machineId}/open`, method: 'POST', headers: C });
    ok(recoveredOpen.status === 200 && !!jsonBody(recoveredOpen.body).openUrl, 'dashboard 恢复后可再次打开');

    // H ticket 引导（在机器子域上）
    const ticket = new URL(open.openUrl).searchParams.get('ticket');
    const subHost = `m-${bind.machineId}.${ROOT_HOST}`;
    const opened = await req({ path: `/__open?ticket=${encodeURIComponent(ticket)}`, host: subHost });
    const proxyCookie = cookieVal(opened.setCookies, 'botmux_proxy_session');
    ok(opened.status === 302 && !!proxyCookie, 'ticket 换取 proxy cookie');

    // I 反代 HTTP
    const proxied = await req({ path: '/anything', host: subHost, headers: { cookie: `botmux_proxy_session=${proxyCookie}` } });
    ok(proxied.body.includes('MOCK_DASHBOARD_OK'), '反代到 dashboard HTML');
    ok(!('set-cookie' in proxied.headers), 'dashboard 的 set-cookie 已被剥离');

    // I2 未授权子域
    const noauth = await req({ path: '/x', host: subHost });
    ok(noauth.status === 401, '子域无 proxy cookie → 401');

    // J 反代终端 WS
    await new Promise((resolve) => {
      const ws = new WebSocket(new URL('/term', wsBase), { headers: { host: subHost, cookie: `botmux_proxy_session=${proxyCookie}` } });
      const t = setTimeout(() => { ok(false, 'WS 反代超时'); resolve(); }, 3000);
      ws.on('open', () => ws.send('ping'));
      ws.on('message', (d) => { ok(d.toString() === 'echo:ping', '终端 WS 反代回显'); clearTimeout(t); ws.close(); resolve(); });
      ws.on('error', (e) => { ok(false, 'WS 反代错误 ' + e.message); clearTimeout(t); resolve(); });
    });

    // K 团队（person-level）：创建（人加入，无需在线机器）→ 列表/名册 → 邀请→接受 → 退出
    const created = JSON.parse((await req({ path: '/api/teams', method: 'POST', headers: { ...C, 'content-type': 'application/json' }, body: JSON.stringify({ name: '冒烟队' }) })).body);
    ok(!!created.teamId, '创建团队（人加入）');
    await sleep(400);
    const teams = JSON.parse((await req({ path: '/api/teams', headers: C })).body);
    ok(teams.teams.some((t) => t.teamId === created.teamId), '团队出现在我的团队列表');
    const roster = JSON.parse((await req({ path: `/api/teams/${created.teamId}/roster`, headers: C })).body);
    ok(roster.members.length === 1 && roster.members[0].machines.length === 1, '团队名册含本人机器');

    // K2 团队按需选 bot：默认不加入（inTeam=false）→ 手动 add → inTeam=true → remove → inTeam=false
    const mac = roster.members[0].machines[0];
    ok((mac.bots || []).length === 1 && mac.bots[0].inTeam === false, '默认无 bot 加入团队（inTeam=false）');
    const ref = { machineId: mac.machineId, appId: mac.bots[0].appId };
    const jpost = (o) => ({ headers: { ...C, 'content-type': 'application/json' }, body: JSON.stringify(o) });
    const addR = await req({ path: `/api/teams/${created.teamId}/bots`, method: 'POST', ...jpost({ add: [ref] }) });
    ok(addR.status === 200, '添加 bot 到团队');
    const rosterA = JSON.parse((await req({ path: `/api/teams/${created.teamId}/roster`, headers: C })).body);
    ok(rosterA.members[0].machines[0].bots[0].inTeam === true, '添加后 inTeam=true');
    const emptyR = await req({ path: `/api/teams/${created.teamId}/bots`, method: 'POST', ...jpost({}) });
    ok(emptyR.status === 400, '无增删被拒（400）');
    const notMine = await req({ path: `/api/teams/${created.teamId}/bots`, method: 'POST', ...jpost({ add: [{ machineId: 'deadbeefdeadbeef', appId: 'cli_other' }] }) });
    ok(notMine.status === 403, '加非自己名下机器的 bot 被拒（403）');
    const rmR = await req({ path: `/api/teams/${created.teamId}/bots`, method: 'POST', ...jpost({ remove: [ref] }) });
    ok(rmR.status === 200, '从团队移除 bot');
    const rosterB = JSON.parse((await req({ path: `/api/teams/${created.teamId}/roster`, headers: C })).body);
    ok(rosterB.members[0].machines[0].bots[0].inTeam === false, '移除后 inTeam=false');

    const inv = JSON.parse((await req({ path: `/api/teams/${created.teamId}/invite`, method: 'POST', headers: C })).body);
    ok(!!inv.invite, '生成邀请 token');
    const acc = await req({ path: '/api/teams/accept', method: 'POST', headers: { ...C, 'content-type': 'application/json' }, body: JSON.stringify({ invite: inv.invite }) });
    ok(acc.status === 200, '接受邀请（推送 join-team）');
    const badInv = await req({ path: '/api/teams/accept', method: 'POST', headers: { ...C, 'content-type': 'application/json' }, body: JSON.stringify({ invite: 'garbage' }) });
    ok(badInv.status === 400, '坏邀请被拒');
    // 1408b50 起创建人禁止退出（解散权唯一持有者），smoke 里同一账号既是创建人：
    // 退出应被拒，清场改走「解散」。
    const lv = await req({ path: `/api/teams/${created.teamId}/leave`, method: 'POST', headers: C });
    ok(lv.status === 403, '创建人退出被拒（403）');
    const db = await req({ path: `/api/teams/${created.teamId}`, method: 'DELETE', headers: C });
    ok(db.status === 200, '创建人解散团队');
    await sleep(400);
    const after = JSON.parse((await req({ path: '/api/teams', headers: C })).body);
    ok(!after.teams.some((t) => t.teamId === created.teamId), '解散后团队消失');
  } catch (e) {
    failures++; console.error('异常', e);
  } finally {
    try { daemon?.terminate(); } catch { /* already closed */ }
    if (server && server.exitCode === null) {
      server.kill('SIGTERM');
      await Promise.race([
        new Promise((resolve) => server.once('exit', resolve)),
        sleep(3000).then(() => { if (server.exitCode === null) server.kill('SIGKILL'); }),
      ]);
    }
    await Promise.race([
      new Promise((resolve) => dash.close(resolve)),
      sleep(2000).then(() => { dash.closeAllConnections?.(); }),
    ]);
  }

  console.log(failures ? `\n冒烟失败：${failures} 项` : '\n冒烟全过 ✅');
  process.exit(failures ? 1 : 0);
}
main();
