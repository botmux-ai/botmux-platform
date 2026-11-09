import test from 'node:test';
import assert from 'node:assert/strict';
import { machineVersionStatus } from '../src/machine-version';

test('machineVersionStatus：占位版本显示「版本未知」且不提示升级', () => {
  for (const v of ['0.0.0', 'v0.0.0', 'unknown', '', undefined, null, 'dev-build']) {
    assert.deepEqual(machineVersionStatus(v, '3.56.0'), { label: '版本未知', unknown: true, outdated: false }, String(v));
  }
});

test('machineVersionStatus：只有确实低于最新版本才提示升级', () => {
  assert.equal(machineVersionStatus('3.55.0', '3.56.0').outdated, true);
  assert.equal(machineVersionStatus('3.56.0', '3.56.0').outdated, false);
  assert.equal(machineVersionStatus('3.57.0-beta.1', '3.56.0').outdated, false);
  assert.equal(machineVersionStatus('v3.9.9', '3.10.0').outdated, true);
  assert.equal(machineVersionStatus('3.55.0', '').outdated, false);
  assert.equal(machineVersionStatus('3.55.0', '3.56.0').label, '3.55.0');
});
