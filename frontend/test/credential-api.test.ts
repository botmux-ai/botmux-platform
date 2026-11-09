import test from 'node:test';
import assert from 'node:assert/strict';
import { createCredentialApi, CredentialApiError, MAX_REQUESTED_SCOPES, requestedScopesFrom } from '../src/credential-api';

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
