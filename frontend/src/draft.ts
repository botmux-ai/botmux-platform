// 敏感保存前把弹窗草稿暂存到 sessionStorage。
//
// 背景：高敏写（团队机器人清单 / 管理员 / 问题板表单）在新鲜登录过期时会整页跳飞书重登
// （见 api.ts createApiRequest 的 location.href）。整页跳转销毁 React 弹窗里的勾选/草稿，
// 回来只恢复了 URL、恢复不了弹窗内容——这正是用户抱怨的「跳走回来勾选没了」。
//
// sessionStorage 跨同标签页导航（含这趟 OAuth 往返）存活、关标签即清，正好用来接力：
// 保存前 stash → 命中 stale_session（要跳转）就保留 → 回来 takeDraft 恢复并重开弹窗；
// 保存成功或其它非跳转错误则立刻清掉(弹窗还在，实时 state 才是真相)。

import { ApiError } from './api';

const PREFIX = 'botmux_draft:';
// 超过此时限的草稿不再自动恢复：避免很久以前留下、没走完重登的陈旧草稿覆盖用户新意图。
const MAX_AGE_MS = 30 * 60_000;

interface DraftEnvelope<T> {
  v: T;
  at: number;
}

export function stashDraft(key: string, value: unknown): void {
  try {
    const env: DraftEnvelope<unknown> = { v: value, at: Date.now() };
    sessionStorage.setItem(PREFIX + key, JSON.stringify(env));
  } catch {
    // 隐私模式禁用 storage / 超配额：放弃暂存，不影响保存本身。
  }
}

/** 读取并删除草稿（一次性）。不存在 / 过期 / 解析失败都返回 null。 */
export function takeDraft<T>(key: string): T | null {
  try {
    const raw = sessionStorage.getItem(PREFIX + key);
    if (raw == null) return null;
    sessionStorage.removeItem(PREFIX + key);
    const env = JSON.parse(raw) as DraftEnvelope<T>;
    if (!env || typeof env.at !== 'number' || Date.now() - env.at > MAX_AGE_MS) return null;
    return env.v;
  } catch {
    return null;
  }
}

export function clearDraft(key: string): void {
  try {
    sessionStorage.removeItem(PREFIX + key);
  } catch {
    // ignore
  }
}

/** 搜人增量授权前暂存 {teamId→搜索词} 的键；授权回跳后据此重开邀请弹窗并恢复搜索词。 */
export function inviteScopeDraftKey(teamId: string): string {
  return `invite-scope:${teamId}`;
}

/**
 * 包裹一次敏感保存的草稿生命周期：
 * - 保存前 stash 当前草稿；
 * - save() 正常返回(成功 or 内部已处理的业务错误) → 清除暂存(弹窗仍在，实时 state 才是真相)；
 * - save() 抛 stale_session（api 层已 location.href 跳重登）→ 保留暂存并静默返回，
 *   让草稿熬过这趟 OAuth 往返，回来后由 takeDraft 恢复；不 rethrow，避免跳转中的未捕获拒绝；
 * - 其它意外抛出 → 清除暂存并原样抛出。
 */
export async function saveWithDraft(
  key: string,
  draft: unknown,
  save: () => Promise<void>,
): Promise<void> {
  stashDraft(key, draft);
  try {
    await save();
    clearDraft(key);
  } catch (e) {
    if (e instanceof ApiError && e.code === 'stale_session') return; // 正在跳转，保留暂存
    clearDraft(key);
    throw e;
  }
}
