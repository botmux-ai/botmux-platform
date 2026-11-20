import test from 'node:test';
import assert from 'node:assert/strict';
import { externalBotErrorText, validateExternalBotInput } from '../src/api';

test('外部机器人登记：前端校验与服务端规则一致', () => {
  const ok = { appId: 'cli_0123456789abcdef', name: 'Outside' };
  assert.equal(validateExternalBotInput(ok), null);
  assert.equal(validateExternalBotInput({ ...ok, appId: '  cli_0123456789abcdef  ', name: ' Outside ' }), null);
  assert.equal(validateExternalBotInput({ ...ok, unionId: 'on_0123456789abcdef' }), null);
  // 空 union_id 等于不填。
  assert.equal(validateExternalBotInput({ ...ok, unionId: '   ' }), null);

  assert.notEqual(validateExternalBotInput({ ...ok, appId: 'ou_0123456789abcdef' }), null);
  assert.notEqual(validateExternalBotInput({ ...ok, appId: 'cli_short' }), null);
  assert.notEqual(validateExternalBotInput({ ...ok, name: '   ' }), null);
  // open_id 只对单个应用有效，不能当跨应用身份。
  assert.notEqual(validateExternalBotInput({ ...ok, unionId: 'ou_0123456789abcdef' }), null);
});

test('外部机器人错误码：已知码给人话，未知码保留原码', () => {
  for (const code of ['registered_by_other', 'already_team_bot', 'botmux_bot', 'not_registrant', 'too_many_external_bots']) {
    const text = externalBotErrorText(code);
    assert.ok(text.length > 0);
    assert.ok(!text.includes(code), `${code} 应翻译成人话：${text}`);
  }
  assert.ok(externalBotErrorText('brand_new_code').includes('brand_new_code'));
  assert.ok(externalBotErrorText(undefined).length > 0);
});
