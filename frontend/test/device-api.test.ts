import test from 'node:test';
import assert from 'node:assert/strict';
import { ApiError, createApiRequest, loginHrefFor } from '../src/api';
import { createDeviceApi, DeviceApiError } from '../src/device-api';
import { acceptInviteAndClearOnSuccess, urlWithoutInvite } from '../src/invite-flow';
import { shouldUseMobileShell } from '../src/route';

function jsonResponse(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } });
}

test('设备 API 只走同源 cookie/no-store，确认与吊销 POST 不携带凭证正文', async () => {
  const calls: Array<{ input: string; init?: RequestInit }> = [];
  const api = createDeviceApi(async (input, init) => {
    calls.push({ input: String(input), init });
    if (String(input) === '/api/devices') return jsonResponse(200, { devices: [] });
    if (String(input).endsWith('/approve')) return jsonResponse(200, { status: 'approved' });
    return jsonResponse(200, { ok: true });
  });

  await api.listDevices();
  await api.decideGrant('a'.repeat(16), 'approve');
  await api.revokeDevice(`d-${'b'.repeat(16)}`);

  assert.deepEqual(calls.map((c) => c.input), [
    '/api/devices',
    `/api/devices/grants/${'a'.repeat(16)}/approve`,
    `/api/devices/d-${'b'.repeat(16)}/revoke`,
  ]);
  for (const call of calls) {
    assert.equal(call.init?.credentials, 'same-origin');
    assert.equal(call.init?.cache, 'no-store');
    assert.equal(call.init?.body, undefined);
    assert.equal(call.init?.headers, undefined);
  }
});

test('设备 API 保留服务端错误码和登录地址，页面可区分 fresh SSO', async () => {
  const api = createDeviceApi(async () => jsonResponse(401, { error: 'stale_session', loginUrl: '/auth/login' }));
  await assert.rejects(
    () => api.listDevices(),
    (e: unknown) => e instanceof DeviceApiError && e.status === 401 && e.code === 'stale_session' && e.loginUrl === '/auth/login',
  );
});

test('公共 API 在业务调用方读 JSON 前拦截 stale_session，并携当前完整 URL 重登', async () => {
  let navigatedTo = '';
  const request = createApiRequest(
    async () => jsonResponse(401, { error: 'stale_session', loginUrl: '/auth/login' }),
    () => ({ pathname: '/', search: '?invite=invite-token&desktop=1', hash: '#teams' }),
    (href) => { navigatedTo = href; },
  );

  const expected = '/auth/login?next=%2F%3Finvite%3Dinvite-token%26desktop%3D1%23teams';
  await assert.rejects(
    () => request('/api/teams/accept', { method: 'POST' }).then((r) => r.json()),
    (e: unknown) => e instanceof ApiError
      && e.status === 401
      && e.code === 'stale_session'
      && e.loginUrl === expected,
  );
  assert.equal(navigatedTo, expected);
  assert.equal(loginHrefFor({ pathname: '/devices/confirm', search: '?grant=abc', hash: '#detail' }),
    '/auth/login?next=%2Fdevices%2Fconfirm%3Fgrant%3Dabc%23detail');
});

test('公共 API 不拦截普通 401，保持既有未登录调用语义', async () => {
  let navigated = false;
  const request = createApiRequest(
    async () => jsonResponse(401, { error: 'unauthenticated' }),
    () => ({ pathname: '/', search: '', hash: '' }),
    () => { navigated = true; },
  );
  const response = await request('/api/me');
  assert.equal(response.status, 401);
  assert.equal(navigated, false);
});

test('邀请仅在接受成功后清理；失败/重登保留 invite 供续接', async () => {
  const events: string[] = [];
  const accepted = await acceptInviteAndClearOnSuccess(
    async () => { events.push('request'); return { status: 200, teamName: '设备组' }; },
    () => { events.push('clear'); },
  );
  assert.equal(accepted.teamName, '设备组');
  assert.deepEqual(events, ['request', 'clear']);

  let cleared = false;
  const rejected = await acceptInviteAndClearOnSuccess(
    async () => ({ status: 404 }),
    () => { cleared = true; },
  );
  assert.equal(rejected.status, 404);
  assert.equal(cleared, false);

  await assert.rejects(
    () => acceptInviteAndClearOnSuccess(
      async () => { throw new ApiError(401, 'stale_session', '/auth/login?next=invite'); },
      () => { cleared = true; },
    ),
    (e: unknown) => e instanceof ApiError && e.code === 'stale_session',
  );
  assert.equal(cleared, false);
  assert.equal(
    urlWithoutInvite({ pathname: '/', search: '?invite=secret&desktop=1', hash: '#teams' }),
    '/?desktop=1#teams',
  );
});

test('mobile 路由：显式入口始终启用；窄屏首页启用但不截获邀请和 desktop override', () => {
  assert.equal(shouldUseMobileShell('/mobile', '', false), true);
  assert.equal(shouldUseMobileShell('/', '', true), true);
  assert.equal(shouldUseMobileShell('/', '?invite=abc', true), false);
  assert.equal(shouldUseMobileShell('/', '?desktop=1', true), false);
  assert.equal(shouldUseMobileShell('/', '', false), false);
  assert.equal(shouldUseMobileShell('/devices', '', true), false);
});
