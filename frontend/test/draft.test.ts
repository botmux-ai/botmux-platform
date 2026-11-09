import test from 'node:test';
import assert from 'node:assert/strict';
import { stashDraft, takeDraft, clearDraft, saveWithDraft, inviteScopeDraftKey } from '../src/draft';
import { ApiError } from '../src/api';

// draft.ts 依赖浏览器的 sessionStorage；Node 测试环境没有，装一个最小内存实现。
// draft.ts 只在函数体内触碰 sessionStorage，import 时不触碰，故装在模块顶层即可。
class MemStorage {
  private m = new Map<string, string>();
  getItem(k: string): string | null {
    return this.m.has(k) ? this.m.get(k)! : null;
  }
  setItem(k: string, v: string): void {
    this.m.set(k, String(v));
  }
  removeItem(k: string): void {
    this.m.delete(k);
  }
  clear(): void {
    this.m.clear();
  }
}
(globalThis as unknown as { sessionStorage: MemStorage }).sessionStorage = new MemStorage();

test.beforeEach(() => {
  (globalThis as unknown as { sessionStorage: MemStorage }).sessionStorage.clear();
});

test('takeDraft 恢复空数组草稿（清空全部 bot 的意图不能丢）', () => {
  stashDraft('team-bots:t1', []);
  const got = takeDraft<string[]>('team-bots:t1');
  // 关键：空数组必须原样恢复，而不是被当成「无草稿」→ null。
  assert.deepEqual(got, []);
  assert.notEqual(got, null);
});

test('takeDraft 一次性：读完即删', () => {
  stashDraft('k', { a: 1 });
  assert.deepEqual(takeDraft('k'), { a: 1 });
  assert.equal(takeDraft('k'), null);
});

test('takeDraft 对不存在的键返回 null', () => {
  assert.equal(takeDraft('missing'), null);
});

test('saveWithDraft 成功后清除草稿', async () => {
  await saveWithDraft('k', [1, 2], async () => {});
  assert.equal(takeDraft('k'), null); // 已被 clearDraft 清掉
});

test('saveWithDraft 命中 stale_session：保留草稿供重登回来恢复，且不 rethrow', async () => {
  await saveWithDraft('k', ['x'], async () => {
    throw new ApiError(401, 'stale_session', '/auth/login');
  });
  // 正在整页跳转重登：草稿必须留住，回来才能恢复。
  assert.deepEqual(takeDraft<string[]>('k'), ['x']);
});

test('saveWithDraft 其它错误：清除草稿并 rethrow', async () => {
  await assert.rejects(
    saveWithDraft('k', ['x'], async () => {
      throw new Error('boom');
    }),
    /boom/,
  );
  assert.equal(takeDraft('k'), null);
});

test('clearDraft 幂等，不抛', () => {
  stashDraft('k', 1);
  clearDraft('k');
  clearDraft('k');
  assert.equal(takeDraft('k'), null);
});

test('搜人增量授权 query 按团队键往返恢复（含空搜索词）', () => {
  // 模拟 InvitePanel.goAuthorizeSearch 跳授权前的暂存 → TeamCard 挂载时的恢复。
  const key = inviteScopeDraftKey('team-abc');
  assert.equal(key, 'invite-scope:team-abc');
  stashDraft(key, 'zhang');
  assert.equal(takeDraft<string>(key), 'zhang'); // 授权回跳后回填搜索词
  // 空搜索词也要能恢复（用户还没输入就点了授权）→ 空串而非 null，才会自动重开弹窗。
  stashDraft(key, '');
  assert.equal(takeDraft<string>(key), '');
});
