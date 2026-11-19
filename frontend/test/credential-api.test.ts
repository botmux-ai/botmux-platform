import test from 'node:test';
import assert from 'node:assert/strict';
import { createCredentialApi, credentialOwner, CredentialApiError, MAX_REQUESTED_SCOPES, requestedScopesFrom, requestIdFrom, type PlatformCard } from '../src/credential-api';

function jsonResponse(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } });
}

test('?scope= 解析：空格/逗号分隔、可重复、去重保序、丢掉不合法的名字', () => {
  assert.deepEqual(requestedScopesFrom('?scope=base%3Arecord%3Aread+base%3Afield%3Aread'), ['base:record:read', 'base:field:read']);
  assert.deepEqual(
    requestedScopesFrom('?scope=base:record:read,bitable:app&scope=base:record:read%20offline_access&scope=bad%20name&scope=a:b%26c'),
    ['base:record:read', 'bitable:app', 'offline_access'],
  );
  assert.deepEqual(requestedScopesFrom(''), []);
  assert.deepEqual(requestedScopesFrom('?authorized=lark-cli'), []);
  const many = Array.from({ length: MAX_REQUESTED_SCOPES + 5 }, (_, i) => `s:${i}`).join(' ');
  assert.equal(requestedScopesFrom(`?scope=${encodeURIComponent(many)}`).length, MAX_REQUESTED_SCOPES);
});

test('authorize：带 scopes 时作为 JSON 正文发出，不带时没有正文（老行为）', async () => {
  const calls: Array<{ input: string; init?: RequestInit }> = [];
  const api = createCredentialApi(async (input, init) => {
    calls.push({ input: String(input), init });
    return jsonResponse(200, { url: 'https://open.feishu.test/authorize' });
  });
  await api.authorize('lark-cli');
  await api.authorize('lark-cli', []);
  await api.authorize('lark-cli', ['base:record:read']);
  assert.equal(calls[0].init?.body, undefined);
  assert.equal(calls[1].init?.body, undefined);
  assert.equal(calls[2].init?.body, JSON.stringify({ scopes: ['base:record:read'] }));
  assert.equal(calls[2].init?.method, 'POST');
});

test('scope_not_enabled 把未开通的 scope 列表带给页面', async () => {
  const api = createCredentialApi(async () => jsonResponse(409, { error: 'scope_not_enabled', scopes: ['bitable:app', 3] }));
  await assert.rejects(api.authorize('lark-cli', ['bitable:app']), (e: unknown) => {
    assert.ok(e instanceof CredentialApiError);
    assert.equal(e.code, 'scope_not_enabled');
    assert.deepEqual(e.scopes, ['bitable:app']);
    return true;
  });
});

test('complete：按平台轮询设备码登录', async () => {
  const calls: string[] = [];
  const api = createCredentialApi(async (input, init) => {
    calls.push(`${init?.method} ${String(input)} ${String(init?.body)}`);
    return jsonResponse(200, { state: 'pending', authUrl: 'https://sso.test/v' });
  });
  const r = await api.complete('device-cli', 'cp_1');
  assert.equal(r.state, 'pending');
  assert.deepEqual(calls, ['POST /api/credentials/device-cli/complete {"pendingId":"cp_1"}']);
});

test('站点授权走独立的 /region 路由，撤销整张卡不带站点', async () => {
  const calls: string[] = [];
  const api = createCredentialApi(async (input, init) => {
    calls.push(`${init?.method} ${String(input)} ${String(init?.body)}`);
    return jsonResponse(200, { ok: true, removed: true, pendingId: 'cp_1', authUrl: 'https://sso.test/v' });
  });
  await api.authorizeRegion('device-cli', 'eu');
  await api.revokeRegion('device-cli', 'eu');
  await api.revoke('device-cli');
  assert.deepEqual(calls, [
    'POST /api/credentials/device-cli/region {"region":"eu"}',
    'DELETE /api/credentials/device-cli/region?region=eu undefined',
    'DELETE /api/credentials/device-cli undefined',
  ]);
});

test('站点登录的记录和进行中的授权归到所属卡片', () => {
  const region = { region: 'eu', site: 'eu-west', platform: 'device-cli--eu-west', title: '欧洲站点' };
  const cards: PlatformCard[] = [
    { platform: 'lark-cli', flow: 'oauth', available: true, title: '飞书', description: '' },
    { platform: 'device-cli', flow: 'device', available: true, title: 'Device', description: '', regions: [region] },
  ];
  assert.equal(credentialOwner(cards, 'device-cli')?.card.platform, 'device-cli');
  assert.equal(credentialOwner(cards, 'device-cli')?.region, undefined);
  assert.deepEqual(credentialOwner(cards, 'device-cli--eu-west'), { card: cards[1], region });
  assert.equal(credentialOwner(cards, 'device-cli--nowhere'), undefined);
});

test('授权请求：读取、允许、撤销机器允许走各自的路由', async () => {
  const calls: string[] = [];
  const api = createCredentialApi(async (input, init) => {
    calls.push(`${init?.method ?? 'GET'} ${String(input)} ${String(init?.body)}`);
    return jsonResponse(200, { ok: true, removed: true });
  });
  await api.getRequest('cr_0123456789abcdef01234567');
  await api.allowRequest('cr_0123456789abcdef01234567');
  await api.revokeMachine('m 1/x');
  assert.deepEqual(calls, [
    'GET /api/credentials/requests/cr_0123456789abcdef01234567 undefined',
    'POST /api/credentials/requests/cr_0123456789abcdef01234567/allow undefined',
    'DELETE /api/credentials/machines/m%201%2Fx undefined',
  ]);
});

test('授权请求的错误码和 stale_session 的登录地址带给页面', async () => {
  const gone = createCredentialApi(async () => jsonResponse(409, { error: 'machine_ownership_changed' }));
  await assert.rejects(gone.allowRequest('cr_0123456789abcdef01234567'), (e: unknown) => e instanceof CredentialApiError && e.status === 409 && e.code === 'machine_ownership_changed');
  const stale = createCredentialApi(async () => jsonResponse(401, { error: 'stale_session', loginUrl: '/auth/login' }));
  await assert.rejects(stale.allowRequest('cr_0123456789abcdef01234567'), (e: unknown) => e instanceof CredentialApiError && e.code === 'stale_session' && e.loginUrl === '/auth/login');
});

test('?request= 只接受平台发出的请求编号', () => {
  assert.equal(requestIdFrom('?request=cr_0123456789abcdef01234567'), 'cr_0123456789abcdef01234567');
  assert.equal(requestIdFrom('?scope=a:b&request=cr_0123456789abcdef01234567&x=1'), 'cr_0123456789abcdef01234567');
  assert.equal(requestIdFrom(''), undefined);
  assert.equal(requestIdFrom('?request='), undefined);
  assert.equal(requestIdFrom('?request=cr_short'), undefined);
  assert.equal(requestIdFrom('?request=../../x'), undefined);
  assert.equal(requestIdFrom('?request=CR_0123456789ABCDEF01234567'), undefined);
});
