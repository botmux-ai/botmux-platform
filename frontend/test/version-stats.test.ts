import test from 'node:test';
import assert from 'node:assert/strict';
import type { VersionStats } from '../src/api';
import { buildVersionRows, formatPercent } from '../src/version-stats';

const c = (machines: number, users: number) => ({ machines, users });

const stats: VersionStats = {
  generatedAt: 0,
  latestVersion: '1.3.0',
  totals: { online: c(6, 3), active7d: c(10, 8), all: c(12, 9) },
  versions: [
    { version: '1.3.0', online: c(1, 1), active7d: c(2, 2), all: c(2, 2), atOrAbove: { online: c(1, 1), active7d: c(2, 2), all: c(2, 2) } },
    // u 在 1.3.0 与 1.2.0 各有机器：累计用户按并集去重，不是 2+4
    { version: '1.2.0', online: c(5, 3), active7d: c(6, 4), all: c(6, 4), atOrAbove: { online: c(6, 3), active7d: c(8, 5), all: c(8, 5) } },
    { version: '1.1.0', online: c(0, 0), active7d: c(2, 2), all: c(4, 4), atOrAbove: { online: c(6, 3), active7d: c(10, 7), all: c(12, 9) } },
  ],
};

test('buildVersionRows：占比、累计占比取后端去重值（不逐行相加）、最新/最多人用标记', () => {
  const rows = buildVersionRows(stats, 'active7d', 'users');
  assert.deepEqual(
    rows.map((r) => [r.version, r.count, r.otherCount, r.share, r.cumulativeShare, r.isLatest, r.isTop]),
    [
      ['1.3.0', 2, 2, 0.25, 0.25, true, false],
      ['1.2.0', 4, 6, 0.5, 0.625, false, true],
      ['1.1.0', 2, 2, 0.25, 0.875, false, false],
    ],
  );
});

test('buildVersionRows：剔除本窗口为 0 的版本；并列最多时取更新的版本', () => {
  const rows = buildVersionRows(stats, 'online', 'users');
  assert.deepEqual(rows.map((r) => r.version), ['1.3.0', '1.2.0']);
  const tie = buildVersionRows(stats, 'all', 'users');
  assert.equal(tie.find((r) => r.isTop)?.version, '1.2.0');
  const tie2 = buildVersionRows(
    { ...stats, versions: [stats.versions[0], { ...stats.versions[2], active7d: c(2, 2) }] },
    'active7d',
    'users',
  );
  assert.equal(tie2.find((r) => r.isTop)?.version, '1.3.0');
});

test('buildVersionRows：后端未给累计值（无法比较的版本）→ cumulativeShare 为 null', () => {
  const rows = buildVersionRows(
    { ...stats, versions: [...stats.versions, { version: 'unknown', online: c(0, 0), active7d: c(1, 1), all: c(1, 1), atOrAbove: null }] },
    'active7d',
    'machines',
  );
  assert.equal(rows.find((r) => r.version === 'unknown')?.cumulativeShare, null);
  assert.equal(rows.find((r) => r.version === '1.3.0')?.cumulativeShare, 0.2);
});

test('formatPercent', () => {
  assert.equal(formatPercent(0), '0%');
  assert.equal(formatPercent(0.004), '<1%');
  assert.equal(formatPercent(0.055), '5.5%');
  assert.equal(formatPercent(0.5), '50%');
  assert.equal(formatPercent(1), '100%');
});
